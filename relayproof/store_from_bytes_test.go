package relayproof

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Source chain names are arbitrary byte strings: the Go register/submit
// interface only requires a non-empty source, never valid UTF-8 — text,
// colons, NUL bytes, stray 0xFF/0xFE bytes, or text mixed with them. The
// source is part of the replay identity (source, destination, nonce) and keys
// registration and trusted-header coverage, so it must survive save, reopen
// and compaction byte for byte; JSON string encoding would otherwise silently
// rewrite invalid bytes to U+FFFD, merging distinct chains and mixing their
// trusted headers and consumed nonces after a restart.

const replacementCharFrom = "�"

// fromEnvelope builds an envelope from source chain from, addressed to
// destination chain-b, with caller-chosen id/nonce/proof height.
func fromEnvelope(id, from string, nonce uint64, proofAt int64) Envelope {
	return Envelope{
		Message: Message{
			ID: id, From: from, To: "chain-b", Nonce: nonce,
			Payload: "payload-" + id, ProofAt: proofAt,
		},
	}
}

// Every source chain shape must come back byte-identical from the submit
// return value, a single Query and the full Queries listing, in
// first-submission order.
func TestSourceChainArbitraryBytesPreservedInInstance(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()

	names := []string{"plain", "colon", "nul", "ff", "fe", "mixed", "replacement"}
	froms := map[string]string{
		"plain":       "chain-a",
		"colon":       "a:b",
		"nul":         "a\x00b",
		"ff":          string([]byte{0xFF}),
		"fe":          string([]byte{0xFE}),
		"mixed":       "pre\x00mid" + string([]byte{0xFF, 0xFE}) + "post",
		"replacement": replacementCharFrom,
	}
	for i, name := range names {
		if err := q.RegisterSource(froms[name]); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		if _, err := q.Submit(fromEnvelope(name, froms[name], uint64(i+1), 90)); err != nil {
			t.Fatalf("submit %s: %v", name, err)
		}
	}

	for i, name := range names {
		want := froms[name]
		echo, err := q.Submit(fromEnvelope(name, want, uint64(i+1), 90))
		if err != nil {
			t.Fatalf("identical resubmit %s: %v", name, err)
		}
		if !bytes.Equal([]byte(echo.Msg.Message.From), []byte(want)) {
			t.Fatalf("resubmit echo from for %s changed: want % x got % x", name, want, echo.Msg.Message.From)
		}
		qy, ok := q.Query(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if !bytes.Equal([]byte(qy.From), []byte(want)) {
			t.Fatalf("Query from for %s changed: want % x got % x", name, want, qy.From)
		}
	}
	all := q.Queries()
	if len(all) != len(names) {
		t.Fatalf("identical resubmits must not add records: got %d rows", len(all))
	}
	for i, qy := range all {
		if !bytes.Equal([]byte(qy.From), []byte(froms[names[i]])) {
			t.Fatalf("Queries[%d] from = % x, want % x", i, qy.From, froms[names[i]])
		}
	}
}

// 0xFF, 0xFE and the legal character U+FFFD are three different source chains:
// registered and covered each by their own trusted header, three messages to
// the same destination with the same nonce all succeed independently, each
// consuming its own triple. The chains, their headers and their consumed
// nonces must stay distinct across a plain reopen and across an automatic
// compaction plus reopen; afterwards a new id from a chain that already
// consumed the nonce replays at that chain's own winner, never borrowing
// another chain's consumption record.
func TestSourceChainInvalidBytesDistinctAcrossReopenAndCompaction(t *testing.T) {
	fromFF := string([]byte{0xFF})
	fromFE := string([]byte{0xFE})
	fromFD := replacementCharFrom
	chains := []string{fromFF, fromFE, fromFD}
	ids := map[string]string{fromFF: "won-ff", fromFE: "won-fe", fromFD: "won-fd"}

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chains {
		if err := q.RegisterSource(c); err != nil {
			t.Fatalf("register % x: %v", c, err)
		}
		if err := q.UpsertHeader(Header{Chain: c, Height: 100, Root: "root-" + c, Trusted: true}); err != nil {
			t.Fatalf("header % x: %v", c, err)
		}
	}
	// Same destination and nonce 7 for all three; only the source differs.
	for _, c := range chains {
		if _, err := q.Submit(fromEnvelope(ids[c], c, 7, 100)); err != nil {
			t.Fatalf("submit from % x: %v", c, err)
		}
	}
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 3 {
		t.Fatalf("three distinct sources must each be processed: %+v", rep.Results)
	}
	for _, r := range rep.Results {
		if r.Status != StatusSuccess {
			t.Fatalf("message %s from a distinct source must succeed, got %s (%s)", r.ID, r.Status, r.Reason)
		}
	}
	if len(q.consumed) != 3 {
		t.Fatalf("want three distinct consumed triples, got %d: %v", len(q.consumed), q.consumed)
	}

	// assertRestored verifies the three chains and their winners after every
	// reopen boundary.
	assertRestored := func(t *testing.T, q *Queue) {
		t.Helper()
		for _, c := range chains {
			qy, ok := q.Query(ids[c])
			if !ok {
				t.Fatalf("winner %s vanished", ids[c])
			}
			if !bytes.Equal([]byte(qy.From), []byte(c)) {
				t.Fatalf("source of %s changed: want % x got % x", ids[c], c, qy.From)
			}
			if qy.Status != StatusSuccess || qy.Attempts != 1 {
				t.Fatalf("winner %s not restored as success: %+v", ids[c], qy)
			}
			if winner := q.consumed[newConsumeToken(c, "chain-b", 7)]; winner != ids[c] {
				t.Fatalf("consumption of source % x misattributed to %q", c, winner)
			}
		}
	}

	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q = reopen(t, dir)
	assertRestored(t, q)

	// Force automatic compaction: superseded untrusted headers bulk the log
	// past the 4 MiB threshold, and the snapshot drops every one of them but
	// the latest, so the compacted log lands far below the threshold. The
	// invalid-byte sources, their registrations, trusted headers and consumed
	// nonces must survive byte-exactly.
	var prev int64
	compacted := false
	for i := 0; i < 6; i++ {
		root := strings.Repeat("r", 1<<20) + strconv.Itoa(i)
		h := Header{Chain: fromFF, Height: 200 + int64(i), Root: root, Trusted: false}
		if err := q.UpsertHeader(h); err != nil {
			t.Fatalf("padding header %d: %v", i, err)
		}
		if q.store.size < prev {
			compacted = true
		}
		prev = q.store.size
	}
	if !compacted {
		t.Fatal("auto-compaction never triggered")
	}
	if q.store.size > compactThreshold {
		t.Fatalf("auto-compaction did not shrink the log: %d", q.store.size)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q = reopen(t, dir)
	defer q.Close()
	assertRestored(t, q)

	// A new id from a chain that already consumed nonce 7 replays at that
	// chain's own winner; the other chains' consumption records are never
	// borrowed.
	for _, c := range chains {
		again := fromEnvelope("again-"+ids[c], c, 7, 100)
		if _, err := q.Submit(again); err != nil {
			t.Fatal(err)
		}
	}
	rep, err = q.Advance(3000)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]Result{}
	for _, r := range rep.Results {
		seen[r.ID] = r
	}
	for _, c := range chains {
		r := seen["again-"+ids[c]]
		wantReason := "nonce combination already consumed by message " + ids[c]
		if r.Status != StatusReplay || r.Reason != wantReason {
			t.Fatalf("new id from source % x must replay at its own winner %s: %+v", c, ids[c], r)
		}
	}
	if len(q.consumed) != 3 {
		t.Fatalf("replays must not consume anything: %v", q.consumed)
	}
}

// An unterminated message keeps its exact source chain across a reopen: an
// identical-byte resubmit returns the existing record with its status,
// attempts and retry schedule, while changing one source byte — or submitting
// the visually similar U+FFFD — is a content conflict that leaves the
// original record untouched.
func TestSourceChainInvalidBytesWaitingResubmitAfterReopen(t *testing.T) {
	fromRaw := "w" + string([]byte{0x00, 0xFF, 0xFE})
	env := fromEnvelope("w", fromRaw, 7, 100) // no trusted header below

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource(fromRaw)
	if _, err := q.Submit(env); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	if st, _ := q.Query("w"); st.Status != StatusWaiting || st.Attempts != 1 || st.NextRetry != 2000 {
		t.Fatalf("setup: unexpected state %+v", st)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	defer q.Close()
	echo, err := q.Submit(env)
	if err != nil {
		t.Fatalf("byte-identical resubmit after reopen must return the existing record: %v", err)
	}
	if !bytes.Equal([]byte(echo.Msg.Message.From), []byte(fromRaw)) ||
		echo.Status != StatusWaiting || echo.Attempts != 1 || echo.NextRetry != 2000 {
		t.Fatalf("resubmit must not reschedule or rewrite the source: %+v", echo)
	}
	if len(q.Queries()) != 1 {
		t.Fatal("identical resubmit must not add a record")
	}

	for name, bad := range map[string]string{
		"one byte changed":    "w" + string([]byte{0x00, 0xFF, 0x00}),
		"single invalid byte": string([]byte{0xFE}),
		"look-alike U+FFFD":   replacementCharFrom,
		"mixed but replaced":  "w" + string([]byte{0x00, 0xEF, 0xBF, 0xBD}) + string([]byte{0xFE}),
	} {
		if _, err := q.Submit(fromEnvelope("w", bad, 7, 100)); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s: source % x must conflict, got %v", name, bad, err)
		}
	}
	st, _ := q.Query("w")
	if !bytes.Equal([]byte(st.From), []byte(fromRaw)) ||
		st.Attempts != 1 || st.NextRetry != 2000 || st.Status != StatusWaiting {
		t.Fatalf("conflicting resubmits changed the original record: %+v", st)
	}
}

// Registration and trusted headers take effect for exactly the byte sequence
// they were saved with. Registering and covering only the 0xFF chain must not
// qualify the visually similar 0xFE chain: its message terminates as
// unknown-source, while a registered chain without a covering trusted header
// keeps waiting. The outcomes survive a reopen without reactivating the
// terminal message.
func TestSourceChainRegistrationAndHeadersAreByteExact(t *testing.T) {
	fromFF := string([]byte{0xFF})
	fromFE := string([]byte{0xFE})
	fromFD := replacementCharFrom

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Only the 0xFF chain is registered and covered at the proof height.
	if err := q.RegisterSource(fromFF); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: fromFF, Height: 100, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	// The U+FFFD chain is registered but its trusted header stops below the
	// proof height.
	if err := q.RegisterSource(fromFD); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: fromFD, Height: 50, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	// The 0xFE chain stays unregistered.
	if _, err := q.Submit(fromEnvelope("covered", fromFF, 1, 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(fromEnvelope("unregistered", fromFE, 2, 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(fromEnvelope("uncovered", fromFD, 3, 100)); err != nil {
		t.Fatal(err)
	}
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]Result{}
	for _, r := range rep.Results {
		seen[r.ID] = r
	}
	if r := seen["covered"]; r.Status != StatusSuccess {
		t.Fatalf("registered and covered source must deliver: %+v", r)
	}
	if r := seen["unregistered"]; r.Status != StatusUnknownSrc ||
		r.Reason != "unknown source chain "+fromFE {
		t.Fatalf("the unregistered look-alike chain must terminate unknown-source: %+v", r)
	}
	if r := seen["uncovered"]; r.Status != StatusWaiting {
		t.Fatalf("registered source without coverage must keep waiting: %+v", r)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	defer q.Close()
	if st, _ := q.Query("unregistered"); st.Status != StatusUnknownSrc ||
		!bytes.Equal([]byte(st.From), []byte(fromFE)) {
		t.Fatalf("terminal unknown-source record changed across reopen: %+v", st)
	}
	if st, _ := q.Query("uncovered"); st.Status != StatusWaiting ||
		!bytes.Equal([]byte(st.From), []byte(fromFD)) {
		t.Fatalf("waiting record changed across reopen: %+v", st)
	}
	// A later advance must not reactivate the terminal message nor deliver the
	// still-uncovered one.
	rep, err = q.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		if r.ID == "unregistered" {
			t.Fatalf("terminal message reactivated: %+v", r)
		}
	}
	if st, _ := q.Query("unregistered"); st.Status != StatusUnknownSrc || st.Attempts != 1 {
		t.Fatalf("terminal record changed: %+v", st)
	}
	if st, _ := q.Query("uncovered"); st.Status != StatusWaiting {
		t.Fatalf("still-uncovered message must keep waiting: %+v", st)
	}
}

// The compacted snapshot stores invalid source bytes base64-encoded in the
// source entry ("chainB64"), the header entry, the submit entry ("fromB64")
// and the success entry ("consumeFromB64"), never as replacement characters,
// and reads them back byte-identical after reopen.
func TestSourceChainInvalidBytesOnDiskEncoding(t *testing.T) {
	fromFF := string([]byte{0xFF})
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource(fromFF); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: fromFF, Height: 100, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(fromEnvelope("ff", fromFF, 3, 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"chainB64":"`, `"fromB64":"`, `"consumeFromB64":"`} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Fatalf("invalid source not stored byte-exactly (%s): %s", key, raw)
		}
	}
	enc := base64.StdEncoding.EncodeToString([]byte{0xFF})
	if !bytes.Contains(raw, []byte(enc)) {
		t.Fatalf("log missing base64 source bytes %q: %s", enc, raw)
	}
	if bytes.Contains(raw, []byte(replacementCharFrom)) {
		t.Fatalf("compacted log must not contain replacement characters for raw-byte sources")
	}

	q = reopen(t, dir)
	defer q.Close()
	if !q.sources[fromFF] {
		t.Fatal("invalid-byte source registration lost across compaction")
	}
	hs := q.headers[fromFF]
	if hs == nil || hs.trusted == nil || hs.trusted.Height != 100 {
		t.Fatalf("invalid-byte source trusted header lost across compaction: %+v", hs)
	}
	if st, ok := q.Query("ff"); !ok || !bytes.Equal([]byte(st.From), []byte(fromFF)) || st.Status != StatusSuccess {
		t.Fatalf("source not restored byte-exactly: ok=%v %+v", ok, st)
	}
	if winner := q.consumed[newConsumeToken(fromFF, "chain-b", 3)]; winner != "ff" {
		t.Fatalf("consumption of the invalid-byte source lost across compaction: %q", winner)
	}
}

// Existing state directories keep their meaning: source names an older build
// saved as plain JSON are read at face value. A saved U+FFFD is that
// character, not the 0xFF the old build may have lost — its registration,
// coverage and consumed nonce belong to the character chain only, the
// terminal record is never reactivated, and the genuine invalid-byte chain
// starts unregistered and unconsumed.
func TestSourceChainLegacyRecordsReadAtFaceValue(t *testing.T) {
	dir := t.TempDir()
	entries := []*logEntry{
		{T: kindSource, Chain: replacementCharFrom},
		{T: kindHeader, Chain: replacementCharFrom, Height: 100, Root: "r", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "won", From: replacementCharFrom, To: "b", Nonce: 7, Payload: "p", ProofAt: 100},
		{T: kindResult, Now: 1000, ID: "won", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeFrom: replacementCharFrom, ConsumeTo: "b", ConsumeNonce: 7, ConsumeBy: "won"},
		{T: kindAdvance, Now: 1000},
	}
	writeLegacyLog(t, dir, entries...)

	q, err := Open(dir)
	if err != nil {
		t.Fatalf("directory with a legacy replacement source must open directly: %v", err)
	}
	defer q.Close()
	if !q.sources[replacementCharFrom] {
		t.Fatal("legacy U+FFFD registration not restored at face value")
	}
	if q.sources[string([]byte{0xFF})] {
		t.Fatal("the invalid-byte chain must not be registered by a legacy U+FFFD record")
	}
	if winner := q.consumed[newConsumeToken(replacementCharFrom, "b", 7)]; winner != "won" {
		t.Fatalf("legacy consumption not restored at U+FFFD: %q", winner)
	}
	if _, taken := q.consumed[newConsumeToken(string([]byte{0xFF}), "b", 7)]; taken {
		t.Fatal("the invalid-byte chain must not be considered consumed by a legacy U+FFFD record")
	}
	// The saved U+FFFD chain still replays at its own winner; the terminal
	// record is never reactivated.
	legacy := Envelope{Message: Message{
		ID: "again", From: replacementCharFrom, To: "b", Nonce: 7, Payload: "p", ProofAt: 100,
	}}
	if _, err := q.Submit(legacy); err != nil {
		t.Fatal(err)
	}
	rep, err := q.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	var again Result
	for _, r := range rep.Results {
		if r.ID == "again" {
			again = r
		}
		if r.ID == "won" {
			t.Fatalf("terminal legacy record reactivated: %+v", r)
		}
	}
	if again.Status != StatusReplay || again.Reason != "nonce combination already consumed by message won" {
		t.Fatalf("the saved U+FFFD chain must still replay at won: %+v", again)
	}
	// The invalid bytes the old build lost are not guessed back: the 0xFF
	// chain is unknown to this directory and its message terminates as
	// unknown-source, never as a replay of the U+FFFD chain's consumption.
	if _, err := q.Submit(fromEnvelope("raw-byte-src", string([]byte{0xFF}), 7, 100)); err != nil {
		t.Fatal(err)
	}
	rep, err = q.Advance(3000)
	if err != nil {
		t.Fatal(err)
	}
	var rawSrc Result
	for _, r := range rep.Results {
		if r.ID == "raw-byte-src" {
			rawSrc = r
		}
	}
	if rawSrc.Status != StatusUnknownSrc {
		t.Fatalf("the lost 0xFF chain must not inherit the U+FFFD chain's identity: %+v", rawSrc)
	}
}

// A checksum-valid record that carries both a plain source chain and its
// base64 form, or an undecodable base64 value — in a source or header entry's
// "chain", a submit entry's "from" or a success entry's "consumeFrom" — is an
// inconsistent record no build writes: opening returns ErrCorrupt, no usable
// queue, and the file stays untouched. A success triple whose consumeFrom
// decodes to something other than the message's own source is likewise
// corrupt.
func TestSourceChainB64InconsistentRecordsRejected(t *testing.T) {
	sourceBoth := &logEntry{T: kindSource, Chain: "a", ChainB64: "YQ=="}
	sourceBad := &logEntry{T: kindSource, ChainB64: "!!!not-base64!!!"}
	headerBoth := &logEntry{T: kindHeader, Chain: "a", ChainB64: "YQ==", Height: 1, Root: "r", Trusted: true}
	submitBoth := &logEntry{
		T: kindSubmit, Seq: 0, ID: "m", From: "a", FromB64: "YQ==", To: "b",
		Nonce: 1, Payload: "p", ProofAt: 10,
	}
	submitBad := &logEntry{
		T: kindSubmit, Seq: 0, ID: "m", FromB64: "!!!not-base64!!!", To: "b",
		Nonce: 1, Payload: "p", ProofAt: 10,
	}
	successBoth := func() []*logEntry {
		return []*logEntry{
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, Payload: "p", ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok", Attempts: 1,
				ConsumeFrom: "a", ConsumeFromB64: "YQ==", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		}
	}
	successBadFrom := func() []*logEntry {
		return []*logEntry{
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, Payload: "p", ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok", Attempts: 1,
				ConsumeFromB64: "!!!not-base64!!!", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		}
	}
	// Submit comes from "a"; the success claims consumption of raw 0xFF: a
	// mismatched triple that must be rejected rather than silently accepted.
	successMismatch := func() []*logEntry {
		return []*logEntry{
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, Payload: "p", ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok", Attempts: 1,
				ConsumeFromB64: "/w==", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		}
	}
	rawCases := map[string]string{
		"empty from plus fromB64":                    `{"t":"submit","seq":0,"id":"m","from":"","to":"b","nonce":1,"proofAt":10,"fromB64":"/w=="}`,
		"empty chain plus chainB64":                  `{"t":"source","chain":"","chainB64":"/w=="}`,
		"plain and fromB64 decode to the same bytes": `{"t":"submit","seq":0,"id":"m","to":"b","nonce":1,"proofAt":10,"fromB64":"YQ==","from":"a"}`,
	}

	for name, e := range map[string]*logEntry{
		"source with both chain and chainB64": sourceBoth,
		"source with undecodable chainB64":    sourceBad,
		"header with both chain and chainB64": headerBoth,
		"submit with both from and fromB64":   submitBoth,
		"submit with undecodable fromB64":     submitBad,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var data []byte
			data = append(data, logMagic...)
			data = append(data, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
			data = append(data, encodeFrame(mustMarshal(e))...)
			writeRawLog(t, dir, data)
			assertCorruptAndUntouched(t, dir, data)
		})
	}
	for name, build := range map[string]func() []*logEntry{
		"success with both consumeFrom forms":       successBoth,
		"success with undecodable consumeFromB64":   successBadFrom,
		"success whose consumeFrom mismatches from": successMismatch,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var data []byte
			data = append(data, logMagic...)
			data = append(data, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
			for _, e := range build() {
				data = append(data, encodeFrame(mustMarshal(e))...)
			}
			writeRawLog(t, dir, data)
			assertCorruptAndUntouched(t, dir, data)
		})
	}
	for name, jsonBody := range rawCases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var data []byte
			data = append(data, logMagic...)
			data = append(data, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
			data = append(data, encodeFrame([]byte(jsonBody))...)
			writeRawLog(t, dir, data)
			assertCorruptAndUntouched(t, dir, data)
		})
	}
}

// The empty source chain stays rejected by the Go API as an invalid argument.
func TestSourceChainEmptyStillRejected(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource(""); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("empty source registration: want ErrInvalidArg, got %v", err)
	}
	_, err := q.Submit(Envelope{Message: Message{ID: "m", From: "", To: "b", Nonce: 1, ProofAt: 1}})
	if !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("empty submit source: want ErrInvalidArg, got %v", err)
	}
}
