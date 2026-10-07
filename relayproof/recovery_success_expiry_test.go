package relayproof

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Recovery must hold a recovered success — an incrementally saved plain
// result and a compacted success state alike — to the same expiry boundary a
// live advance enforces: delivery may only be stamped at a processing time
// strictly before the message's saved absolute expiry. A message expiring at
// 5000 whose success is stamped 4999 reopens normally; the same success stamped
// 5000 (the boundary itself counts as expired in normal processing) or 5001
// rejects the whole directory with ErrCorrupt, even when the record is
// complete, checksum-valid, trusted-header-covered, well scheduled and carries
// a correct nonce attribution. An expiry of zero means "never expire" and
// imposes no deadline. The judgment uses only the success's own processing
// time and the saved expiry — never the open time, a later queue checkpoint or
// the compaction time — so a success made legitimately before its deadline
// keeps reopening long afterwards, and compaction never re-expires it. The
// error names the message id, the saved success processing time and the saved
// expiry; the log keeps its exact length and bytes even when the bad record is
// the final frame.

// expirySuccessEntries builds a registered, covered source with one message
// expiring at 5000 and a success record of the given kind stamped at now.
func expirySuccessEntries(kind string, now int64) []*logEntry {
	var state *logEntry
	if kind == kindState {
		state = &logEntry{T: kindState, Now: now, ID: "m", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 3, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"}
	} else {
		state = &logEntry{T: kindResult, Now: now, ID: "m", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"}
	}
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10, ExpiresAt: 5000},
		state,
	}
	return entries
}

func TestRecoveryRejectsSuccessAtOrAfterExpiry(t *testing.T) {
	for _, kind := range []struct {
		t           string
		successNoun string
	}{
		{kindResult, "entry"},
		{kindState, "state"},
	} {
		for _, now := range []int64{5000, 5001} {
			name := kind.t + "/success at " + strconv.FormatInt(now, 10)
			t.Run(name, func(t *testing.T) {
				entries := expirySuccessEntries(kind.t, now)
				assertRecoveryCorrupt(t, entries,
					"success "+kind.successNoun, `"m"`,
					"processing time "+strconv.FormatInt(now, 10),
					"saved absolute expiry 5000")
			})
		}
	}
}

// A success stamped strictly before the saved expiry reopens for both record
// kinds, keeping the saved status, reason, attempt count and nonce attribution.
func TestRecoveryAcceptsSuccessBeforeExpiry(t *testing.T) {
	for _, kind := range []string{kindResult, kindState} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			entries := expirySuccessEntries(kind, 4999)
			entries = append(entries, &logEntry{T: kindAdvance, Now: 4999})
			writeLegacyLog(t, dir, entries...)
			q, err := Open(dir)
			if err != nil {
				t.Fatalf("success one millisecond before expiry must open: %v", err)
			}
			defer q.Close()
			r := statusOf(t, q, "m")
			if r.Status != StatusSuccess || r.Msg.ExpiresAt != 5000 ||
				!strings.Contains(r.Reason, "height 100") {
				t.Fatalf("pre-expiry success not restored as saved: %+v", r)
			}
			if kind == kindState && r.Attempts != 3 {
				t.Fatalf("compacted success state must restore attempt count 3: %+v", r)
			}
			if kind == kindResult && r.Attempts != 1 {
				t.Fatalf("plain success result must restore attempt count 1: %+v", r)
			}
			if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m" {
				t.Fatalf("nonce attribution not restored: %q", winner)
			}
		})
	}
}

// Only the success's own processing time is compared with the saved expiry: a
// success made legitimately at 4999 stays a success when the directory is
// reopened long after the deadline and the queue has even checkpointed a much
// later time. Compaction does not re-expire a completed success either.
func TestRecoveryLegalSuccessStaysSuccessLongAfterExpiry(t *testing.T) {
	t.Run("plain result with a much later checkpoint", func(t *testing.T) {
		dir := t.TempDir()
		entries := expirySuccessEntries(kindResult, 4999)
		entries = append(entries, &logEntry{T: kindAdvance, Now: 9_000_000_000_000})
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("a later checkpoint must not re-expire an old success: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "m"); r.Status != StatusSuccess || r.Attempts != 1 {
			t.Fatalf("legal success must stay terminal success: %+v", r)
		}
		// Advancing again past the expiry changes nothing terminal.
		if _, err := q.Advance(9_000_000_000_001); err != nil {
			t.Fatal(err)
		}
		if r := statusOf(t, q, "m"); r.Status != StatusSuccess || r.Attempts != 1 ||
			!strings.Contains(r.Reason, "height 100") {
			t.Fatalf("legal success altered after a post-expiry advance: %+v", r)
		}
		if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m" {
			t.Fatalf("nonce attribution lost after later advance: %q", winner)
		}
	})

	t.Run("compacted state survives compaction and a later reopen", func(t *testing.T) {
		dir := t.TempDir()
		q, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := q.RegisterSource("a"); err != nil {
			t.Fatal(err)
		}
		if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := q.Submit(env("m", "a", "b", 1, 10, 5000)); err != nil {
			t.Fatal(err)
		}
		if rep, err := q.Advance(4999); err != nil {
			t.Fatal(err)
		} else {
			res, ok := resultFor(rep, "m")
			if !ok || res.Status != StatusSuccess {
				t.Fatalf("setup delivery wrong: %+v", rep.Results)
			}
		}
		// Force compaction while the deadline is already in the past relative to
		// a later advance; the compacted success state keeps its 4999 stamp.
		if err := q.store.compact(q.snapshot()); err != nil {
			t.Fatal(err)
		}
		if _, err := q.Advance(6_000_000); err != nil {
			t.Fatal(err)
		}
		if err := q.Close(); err != nil {
			t.Fatal(err)
		}
		q2, err := Open(dir)
		if err != nil {
			t.Fatalf("a compacted pre-expiry success must reopen after the deadline: %v", err)
		}
		defer q2.Close()
		r := statusOf(t, q2, "m")
		rec := q2.records["m"]
		if rec == nil {
			t.Fatalf("m record missing after reopen")
		}
		if r.Status != StatusSuccess || r.Attempts != 1 || rec.LastProcAt != 4999 ||
			!strings.Contains(r.Reason, "height 100") {
			t.Fatalf("compacted success not restored as saved: %+v lastProcAt=%d", r, rec.LastProcAt)
		}
		if winner := q2.consumed[newConsumeToken("a", "b", 1)]; winner != "m" {
			t.Fatalf("nonce attribution not restored after compaction: %q", winner)
		}
	})
}

// An expiry of zero means "never expire", not a deadline at time zero: a
// success stamped at an arbitrary large processing time (both kinds) opens.
func TestRecoveryZeroExpiryImposesNoDeadline(t *testing.T) {
	for _, kind := range []string{kindResult, kindState} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			entries := []*logEntry{
				{T: kindSource, Chain: "a"},
				{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
				// No expiresAt field on disk: decoded as zero.
				{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			}
			attempts := 1
			if kind == kindState {
				attempts = 2
			}
			entries = append(entries, &logEntry{T: kind, Now: 9_000_000_000_000, ID: "m",
				Status:   StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: attempts, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"})
			entries = append(entries, &logEntry{T: kindAdvance, Now: 9_000_000_000_000})
			writeLegacyLog(t, dir, entries...)
			q, err := Open(dir)
			if err != nil {
				t.Fatalf("zero expiry must never act as a deadline: %v", err)
			}
			defer q.Close()
			if r := statusOf(t, q, "m"); r.Status != StatusSuccess || r.Msg.ExpiresAt != 0 {
				t.Fatalf("never-expiring success not restored: %+v", r)
			}
		})
	}
}

// The rule binds success records only: a genuine "expired" terminal result
// stamped exactly at the expiry remains legal recovery data (normal
// processing records expiry precisely when now == ExpiresAt).
func TestRecoveryExpiredTerminalAtBoundaryStillOpens(t *testing.T) {
	dir := t.TempDir()
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindSubmit, Seq: 0, ID: "x", From: "a", To: "b", Nonce: 1, ProofAt: 100, ExpiresAt: 5000},
		{T: kindResult, Now: 5000, ID: "x", Status: StatusExpired,
			Reason: "expired at 5000", Attempts: 1},
		{T: kindAdvance, Now: 5000},
	}
	writeLegacyLog(t, dir, entries...)
	q, err := Open(dir)
	if err != nil {
		t.Fatalf("an expired terminal record at the boundary must open: %v", err)
	}
	defer q.Close()
	if r := statusOf(t, q, "x"); r.Status != StatusExpired || r.Attempts != 1 ||
		!strings.Contains(r.Reason, "5000") {
		t.Fatalf("boundary expiry not restored as saved: %+v", r)
	}
}

// An old-format success carrying the legacy NUL-joined consumeKey is bound by
// the expiry rule just like a triple-field success.
func TestRecoveryLegacySuccessAtExpiryIsCorrupt(t *testing.T) {
	key := legacyNonceKey("a", "b", 1)
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10, ExpiresAt: 5000},
		{T: kindResult, Now: 5000, ID: "m", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeKey: key, ConsumeBy: "m"},
	}
	assertRecoveryCorrupt(t, entries, "success entry", `"m"`,
		"processing time 5000", "saved absolute expiry 5000")
}

// A directory whose success violates the expiry rule is never partially
// usable: even with a fully valid earlier success, opening fails with
// ErrCorrupt and no queue, the error names m1 and both times, a second open
// keeps failing, and queue.log is byte-for-byte untouched even though the bad
// record is the complete, checksum-valid final frame.
func TestRecoverySuccessExpiryFailureIsTotalAndNonDestructive(t *testing.T) {
	dir := t.TempDir()
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
		// m0 is a fully valid success earlier in the log (never-expiring).
		{T: kindSubmit, Seq: 0, ID: "m0", From: "a", To: "b", Nonce: 1, ProofAt: 10},
		{T: kindResult, Now: 1000, ID: "m0", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m0"},
		// m1 is a complete, checksum-valid success stamped exactly at its
		// expiry, as the final frame.
		{T: kindSubmit, Seq: 1, ID: "m1", From: "a", To: "b", Nonce: 2, ProofAt: 10, ExpiresAt: 5000},
		{T: kindResult, Now: 5000, ID: "m1", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 2, ConsumeBy: "m1"},
	}
	path := writeLegacyLog(t, dir, entries...)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		q, err := Open(dir)
		if !errors.Is(err, ErrCorrupt) {
			if q != nil {
				q.Close()
			}
			t.Fatalf("open %d: want ErrCorrupt naming m1, got %v", i+1, err)
		}
		if q != nil {
			q.Close()
			t.Fatalf("a corrupt directory must not return a usable queue")
		}
		for _, want := range []string{`"m1"`, "processing time 5000", "saved absolute expiry 5000"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("open %d error %q must identify %q", i+1, err.Error(), want)
			}
		}
		after, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if string(after) != string(raw) {
			t.Fatalf("open %d rewrote the log: %d -> %d bytes", i+1, len(raw), len(after))
		}
	}
}
