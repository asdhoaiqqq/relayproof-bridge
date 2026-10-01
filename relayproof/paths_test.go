package relayproof

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The two routing paths that a colon-joined key cannot tell apart, and the two
// that a NUL-joined key cannot tell apart. nonce is 7 for all of them.
var ambiguousColonPaths = [][2]string{{"a:b", "c"}, {"a", "b:c"}}
var ambiguousNULPaths = [][2]string{{"a\x00b", "c"}, {"a", "b\x00c"}}

// TestConsumeTokenIsInjective guards the encoding itself: the four ambiguous
// paths plus a same-path repeat produce four distinct tokens and one equal
// pair, never relying on forbidding or rewriting chain names.
func TestConsumeTokenIsInjective(t *testing.T) {
	seen := map[string]string{}
	add := func(label, from, to string, nonce uint64) consumeToken {
		tok := newConsumeToken(from, to, nonce)
		key := tok.marshal()
		if other, dup := seen[key]; dup {
			t.Fatalf("%s and %s share one consumption token: %q -> %q nonce %d", label, other, from, to, nonce)
		}
		seen[key] = label
		return tok
	}
	t1 := add("colon-1", ambiguousColonPaths[0][0], ambiguousColonPaths[0][1], 7)
	add("colon-2", ambiguousColonPaths[1][0], ambiguousColonPaths[1][1], 7)
	t3 := add("nul-1", ambiguousNULPaths[0][0], ambiguousNULPaths[0][1], 7)
	add("nul-2", ambiguousNULPaths[1][0], ambiguousNULPaths[1][1], 7)

	if t1 == t3 {
		t.Fatalf("distinct paths collapsed: %+v == %+v", t1, t3)
	}
	again := newConsumeToken(ambiguousColonPaths[0][0], ambiguousColonPaths[0][1], 7)
	if again != t1 {
		t.Fatalf("the same (from,to,nonce) must compare equal")
	}
	if again.marshal() != t1.marshal() {
		t.Fatalf("the same triple must serialize identically")
	}
}

// TestVerifyAmbiguousPathsDistinct covers the in-memory entry point: both
// ambiguous pairs deliver, and only a genuine repeat of the same triple is a
// replay.
func TestVerifyAmbiguousPathsDistinct(t *testing.T) {
	headers := map[string]Header{}
	for _, pair := range append(append([][2]string{}, ambiguousColonPaths...), ambiguousNULPaths...) {
		headers[pair[0]] = Header{Chain: pair[0], Height: 100, Trusted: true}
	}
	consumed := map[string]bool{}
	msgs := []Message{
		{ID: "c1", From: "a:b", To: "c", Nonce: 7, ProofAt: 10},
		{ID: "c2", From: "a", To: "b:c", Nonce: 7, ProofAt: 10},
		{ID: "n1", From: "a\x00b", To: "c", Nonce: 7, ProofAt: 10},
		{ID: "n2", From: "a", To: "b\x00c", Nonce: 7, ProofAt: 10},
	}
	for _, m := range msgs {
		d := Verify(headers, m, consumed)
		if d.Status != "delivered" {
			t.Fatalf("distinct path %s rejected as %s: %s", m.ID, d.Status, d.Reason)
		}
	}
	if d := Verify(headers, msgs[2], consumed); d.Status != "rejected" ||
		!strings.Contains(d.Reason, "replay") {
		t.Fatalf("genuine repeat must be a replay, got %s: %s", d.Status, d.Reason)
	}
}

// TestQueueAmbiguousPathsDistinct drives both pairs through the durable queue
// in one advance: all four succeed concurrently-in-order, while a fifth
// message on an already consumed triple is a replay pointing at the real
// winner. Relationships survive restart and log compaction.
func TestQueueAmbiguousPathsDistinct(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range []string{"a:b", "a", "a\x00b"} {
		if err := q.RegisterSource(chain); err != nil {
			t.Fatal(err)
		}
		if err := q.UpsertHeader(Header{Chain: chain, Height: 100, Trusted: true}); err != nil {
			t.Fatal(err)
		}
	}
	type sub struct{ id, from, to string }
	subs := []sub{
		{"c1", "a:b", "c"},
		{"c2", "a", "b:c"},
		{"n1", "a\x00b", "c"},
		{"n2", "a", "b\x00c"},
		{"dup", "a:b", "c"}, // exact same triple as c1
	}
	for _, s := range subs {
		if _, err := q.Submit(env(s.id, s.from, s.to, 7, 10, 0)); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Result{}
	for _, r := range rep.Results {
		got[r.ID] = r
	}
	for _, s := range subs[:4] {
		if got[s.id].Status != StatusSuccess {
			t.Fatalf("%s (%q -> %q) must succeed, got %+v", s.id, s.from, s.to, got[s.id])
		}
	}
	if got["dup"].Status != StatusReplay || !strings.Contains(got["dup"].Reason, "c1") {
		t.Fatalf("dup must be replay attributed to c1, got %+v", got["dup"])
	}
	if len(q.consumed) != 4 {
		t.Fatalf("want exactly 4 consumed triples, got %d: %v", len(q.consumed), q.consumed)
	}
	// Queries keep the full, unmodified chain names.
	if r, _ := q.Query("n1"); r.From != "a\x00b" || r.To != "c" {
		t.Fatalf("NUL chain name rewritten: %q -> %q", r.From, r.To)
	}
	if r, _ := q.Query("c2"); r.From != "a" || r.To != "b:c" {
		t.Fatalf("colon chain name rewritten: %q -> %q", r.From, r.To)
	}

	// Force a compaction, then reopen: all four successes stay distinct and
	// terminal, and a new id on either consumed triple still replays.
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen compacted dir: %v", err)
	}
	defer q2.Close()
	if len(q2.consumed) != 4 {
		t.Fatalf("consumed triples lost across compaction: %v", q2.consumed)
	}
	for _, s := range subs[:4] {
		if r := statusOf(t, q2, s.id); r.Status != StatusSuccess {
			t.Fatalf("%s lost success after compaction: %s", s.id, r.Status)
		}
	}
	if _, err := q2.Submit(env("c1-again", "a:b", "c", 7, 10, 0)); err != nil {
		t.Fatal(err)
	}
	rep, err = q2.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	var again Result
	for _, r := range rep.Results {
		if r.ID == "c1-again" {
			again = r
		}
	}
	if again.Status != StatusReplay || !strings.Contains(again.Reason, "c1") {
		t.Fatalf("same triple under new id must replay at c1 after reopen, got %+v", again)
	}
}

// writeLegacyLog writes a V1 log exactly as older builds did, using the
// NUL-joined consumeKey on success entries. The first entry is the version
// record; callers supply the rest.
func writeLegacyLog(t *testing.T, dir string, entries ...*logEntry) string {
	t.Helper()
	path := filepath.Join(dir, logName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, compactFileMode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(logMagic); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if _, err := f.Write(encodeFrame(mustMarshal(e))); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// legacySuccessEntries is the realistic old-log scenario: x succeeded on
// "a␀b"->"c" nonce 7; r was *mis-recorded* as replay on "a"->"b␀c" nonce 7
// because both paths flattened to the same NUL-joined key; w is mid-backoff.
// The shared flattened key is: "a" NUL "b" NUL "c" NUL "7".
func legacyCollisionEntries() []*logEntry {
	key := legacyNonceKey("a\x00b", "c", 7)
	if key != legacyNonceKey("a", "b\x00c", 7) {
		panic("test setup: legacy keys are supposed to collide")
	}
	return []*logEntry{
		{T: kindSource, Chain: "a\x00b"},
		{T: kindHeader, Chain: "a\x00b", Height: 100, Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "x", From: "a\x00b", To: "c", Nonce: 7, ProofAt: 10},
		{T: kindResult, Now: 1000, ID: "x", Status: StatusSuccess, Reason: "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeKey: key, ConsumeBy: "x"},
		{T: kindSubmit, Seq: 1, ID: "r", From: "a", To: "b\x00c", Nonce: 7, ProofAt: 10},
		{T: kindResult, Now: 1000, ID: "r", Status: StatusReplay,
			Reason: "nonce combination already consumed by message x", Attempts: 1},
		{T: kindSubmit, Seq: 2, ID: "w", From: "a\x00b", To: "c", Nonce: 9, ProofAt: 5000},
		{T: kindResult, Now: 1000, ID: "w", Status: StatusWaiting,
			Reason:   "waiting for trusted header covering height 5000 (current 100)",
			Attempts: 1, NextRetry: 2000},
		{T: kindAdvance, Now: 1000},
	}
}

// TestLegacyRawLogOpensDirectly covers migration of an uncompacted old log:
// historical success consumes only its own triple, the historical replay
// stays a replay (same state/reason/id, no auto-redelivery, id not reusable),
// the other path that merely shared the flattened key delivers under a new
// id, and scheduling/order/advance time are fully preserved.
func TestLegacyRawLogOpensDirectly(t *testing.T) {
	dir := t.TempDir()
	writeLegacyLog(t, dir, legacyCollisionEntries()...)

	q, err := Open(dir)
	if err != nil {
		t.Fatalf("old directory must open directly: %v", err)
	}
	defer q.Close()

	if len(q.consumed) != 1 {
		t.Fatalf("only x's own triple may be consumed, got %v", q.consumed)
	}
	if winner := q.consumed[newConsumeToken("a\x00b", "c", 7)]; winner != "x" {
		t.Fatalf("x's historical consumption lost or misattributed: %q", winner)
	}
	if _, taken := q.consumed[newConsumeToken("a", "b\x00c", 7)]; taken {
		t.Fatalf("the other path must not be considered consumed after migration")
	}
	// The historical replay record is preserved verbatim and its id is dead.
	if r := statusOf(t, q, "r"); r.Status != StatusReplay ||
		!strings.Contains(r.Reason, "message x") {
		t.Fatalf("historical replay record not preserved: %+v", r)
	}
	if _, err := q.Submit(env("r", "a", "b\x00c", 7, 10, 0)); !errors.Is(err, ErrTerminal) {
		t.Fatalf("replay id must not be reusable, got %v", err)
	}
	// Live scheduling and processing time are restored intact.
	if q.Now() != 1000 {
		t.Fatalf("last advance time lost: %d", q.Now())
	}
	if r := statusOf(t, q, "w"); r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != 2000 {
		t.Fatalf("waiting schedule lost: %+v", r)
	}
	if len(q.order) != 1 || q.order[0] != "w" {
		t.Fatalf("live order not reconstructed: %v", q.order)
	}

	// Register the other path's source/header, then submit it with new ids:
	// the distinct path delivers; the exact historical triple still replays
	// attributed to the actual winner x.
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("z", "a", "b\x00c", 7, 10, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("x2", "a\x00b", "c", 7, 10, 0)); err != nil {
		t.Fatal(err)
	}
	rep, err := q.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Result{}
	for _, r := range rep.Results {
		got[r.ID] = r
	}
	if got["z"].Status != StatusSuccess {
		t.Fatalf("the other path sharing the old flattened key must deliver, got %+v", got["z"])
	}
	if got["x2"].Status != StatusReplay || !strings.Contains(got["x2"].Reason, "x") {
		t.Fatalf("same historical triple under new id must replay at x, got %+v", got["x2"])
	}
	if got["w"].Status != StatusWaiting || statusOf(t, q, "w").Attempts != 2 {
		t.Fatalf("w should have taken one more waiting attempt: %+v", got["w"])
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen after writing new-format records onto an old log: history must not
	// deliver again and the new consumption relationships must hold.
	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen mixed log: %v", err)
	}
	defer q2.Close()
	if len(q2.consumed) != 2 {
		t.Fatalf("want x and z consumed after migration, got %v", q2.consumed)
	}
	rep, err = q2.Advance(3000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		if r.Status == StatusSuccess {
			t.Fatalf("historical success delivered again: %+v", r)
		}
	}
	for _, id := range []string{"x", "z"} {
		if r := statusOf(t, q2, id); r.Status != StatusSuccess {
			t.Fatalf("%s must remain success after reopen: %s", id, r.Status)
		}
	}
}

// TestLegacyCompactedLogOpensDirectly covers migration of an already
// compacted old directory (kindState snapshot entries with the legacy key).
func TestLegacyCompactedLogOpensDirectly(t *testing.T) {
	key := legacyNonceKey("a\x00b", "c", 7)
	entries := []*logEntry{
		{T: kindSource, Chain: "a\x00b"},
		{T: kindHeader, Chain: "a\x00b", Height: 100, Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "x", From: "a\x00b", To: "c", Nonce: 7, ProofAt: 10},
		{T: kindState, Now: 1000, ID: "x", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeKey: key, ConsumeBy: "x"},
		{T: kindSubmit, Seq: 1, ID: "r", From: "a", To: "b\x00c", Nonce: 7, ProofAt: 10},
		{T: kindState, Now: 1000, ID: "r", Status: StatusReplay,
			Reason: "nonce combination already consumed by message x", Attempts: 1},
		{T: kindAdvance, Now: 1000},
	}
	dir := t.TempDir()
	writeLegacyLog(t, dir, entries...)

	q, err := Open(dir)
	if err != nil {
		t.Fatalf("old compacted directory must open directly: %v", err)
	}
	defer q.Close()
	if winner := q.consumed[newConsumeToken("a\x00b", "c", 7)]; winner != "x" {
		t.Fatalf("x consumption not restored from old snapshot: %v", q.consumed)
	}
	if _, taken := q.consumed[newConsumeToken("a", "b\x00c", 7)]; taken {
		t.Fatalf("other path must not be consumed by old snapshot")
	}
	if r := statusOf(t, q, "r"); r.Status != StatusReplay ||
		!strings.Contains(r.Reason, "message x") {
		t.Fatalf("historical replay snapshot not preserved: %+v", r)
	}
	if r := statusOf(t, q, "x"); r.Status != StatusSuccess {
		t.Fatalf("historical success snapshot changed: %s", r.Status)
	}

	// Continuing writes on an old compacted log, then compacting again, must
	// keep everything consistent across yet another reopen.
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("z", "a", "b\x00c", 7, 10, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(2000); err != nil {
		t.Fatal(err)
	}
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen recompacted log: %v", err)
	}
	defer q2.Close()
	if r := statusOf(t, q2, "z"); r.Status != StatusSuccess {
		t.Fatalf("z lost after recompaction: %s", r.Status)
	}
	if len(q2.consumed) != 2 {
		t.Fatalf("consumed triples wrong after recompaction: %v", q2.consumed)
	}
}

// TestLegacyInconsistentSuccessRejected verifies that an old success record
// whose consume key does not match its own message content is rejected as
// corrupt — for both raw result entries and compacted state entries — with
// the on-disk bytes left untouched.
func TestLegacyInconsistentSuccessRejected(t *testing.T) {
	cases := map[string][]*logEntry{
		"raw result": {
			{T: kindSource, Chain: "a"},
			{T: kindSubmit, Seq: 0, ID: "x", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			// Key claims a different nonce than the message itself.
			{T: kindResult, Now: 1000, ID: "x", Status: StatusSuccess, Attempts: 1,
				ConsumeKey: legacyNonceKey("a", "b", 2), ConsumeBy: "x"},
		},
		"raw result wrong by": {
			{T: kindSource, Chain: "a"},
			{T: kindSubmit, Seq: 0, ID: "x", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "x", Status: StatusSuccess, Attempts: 1,
				ConsumeKey: legacyNonceKey("a", "b", 1), ConsumeBy: "y"},
		},
		"compacted state": {
			{T: kindSource, Chain: "a"},
			{T: kindSubmit, Seq: 0, ID: "x", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			{T: kindState, Now: 1000, ID: "x", Status: StatusSuccess, Attempts: 1,
				ConsumeKey: legacyNonceKey("a", "c", 1), ConsumeBy: "x"},
		},
		"new triple mismatch": {
			{T: kindSource, Chain: "a"},
			{T: kindSubmit, Seq: 0, ID: "x", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "x", Status: StatusSuccess, Attempts: 1,
				ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 9, ConsumeBy: "x"},
		},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeLegacyLog(t, dir, entries...)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			q, err := Open(dir)
			if !errors.Is(err, ErrCorrupt) {
				if q != nil {
					q.Close()
				}
				t.Fatalf("want ErrCorrupt, got %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("inconsistent directory must be preserved byte-for-byte")
			}
		})
	}
}

// TestConcurrentDistinctPathsNoCrossInterference: two distinct triples under
// concurrent submission (including the colon-ambiguous names) must yield
// exactly one success each, while every same-triple contender is a replay.
func TestConcurrentDistinctPathsNoCrossInterference(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	for _, chain := range []string{"a", "a:b"} {
		if err := q.RegisterSource(chain); err != nil {
			t.Fatal(err)
		}
		if err := q.UpsertHeader(Header{Chain: chain, Height: 100, Trusted: true}); err != nil {
			t.Fatal(err)
		}
	}

	const perPath = 20
	var wg sync.WaitGroup
	for i := 0; i < perPath; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_, _ = q.Submit(env(fmt.Sprintf("p1-%02d", i), "a", "b", 1, 10, 0))
		}(i)
		go func(i int) {
			defer wg.Done()
			_, _ = q.Submit(env(fmt.Sprintf("p2-%02d", i), "a:b", "c", 1, 10, 0))
		}(i)
	}
	wg.Wait()
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	success := map[string]int{}
	replays := 0
	for _, r := range rep.Results {
		switch r.Status {
		case StatusSuccess:
			success[q.records[r.ID].Msg.Message.From]++
		case StatusReplay:
			replays++
		default:
			t.Fatalf("unexpected status for %s: %s", r.ID, r.Status)
		}
	}
	if len(success) != 2 || success["a"] != 1 || success["a:b"] != 1 {
		t.Fatalf("want exactly one success per distinct path, got %v", success)
	}
	if replays != 2*perPath-2 {
		t.Fatalf("want %d replays, got %d", 2*perPath-2, replays)
	}
	if len(q.consumed) != 2 {
		t.Fatalf("consumed triples: %v", q.consumed)
	}
}
