package relayproof

import (
	"strconv"
	"strings"
	"testing"
)

// These tests pin down the absolute-expiry boundary applied when a saved
// success — an incrementally saved plain result or a compacted state — is
// replayed. Normal advances never deliver a message at or after its absolute
// expiry (the expiry-time tie is an expired outcome), so a recovered success
// record's own processing time must be strictly before the expiry saved with
// the message's submit entry. Recovery reads only those two saved instants:
// not the wall clock at open time, not a later queue time, not when
// compaction ran. An expiry of zero means never expire and is never a
// deadline at time zero. A success at or after the saved expiry — however
// complete, checksum-valid and otherwise consistent, and even as the final
// frame — is ErrCorrupt: it names the message id, the saved processing time
// and the expiry, and the log keeps its exact length and bytes.

// expiringSuccessBase is the prefix before a success record: a registered
// source with a header covering the proof height, and one pending message
// that expires at the absolute instant 5000.
func expiringSuccessBase() []*logEntry {
	return []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10, ExpiresAt: 5000},
	}
}

// expiringSuccessRecord is a success record for the base message processed at
// now, consuming its own triple. Callers pass the kind and processing time.
func expiringSuccessRecord(kind string, now int64, attempts int) *logEntry {
	return &logEntry{
		T: kind, Now: now, ID: "m", Status: StatusSuccess,
		Reason:   "delivered; proof verified by trusted header at height 100",
		Attempts: attempts, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m",
	}
}

// A success stamped exactly at the saved expiry, or one instant later, could
// never come from a legal advance — the live queue treats now == ExpiresAt as
// expired before delivery. Both record kinds must reject it as corrupt even
// when every other recovery check passes and the record is the last frame.
func TestRecoveryRejectsSuccessAtOrAfterExpiry(t *testing.T) {
	for _, kind := range []struct {
		t    string
		noun string
	}{
		{kindResult, "entry"},
		{kindState, "state"},
	} {
		t.Run(kind.t+"/success exactly at expiry", func(t *testing.T) {
			entries := append(expiringSuccessBase(), expiringSuccessRecord(kind.t, 5000, 1))
			assertRecoveryCorrupt(t, entries,
				"success "+kind.noun+` for "m" processed at 5000 is not before its saved expiry 5000`)
		})

		t.Run(kind.t+"/success after expiry", func(t *testing.T) {
			entries := append(expiringSuccessBase(), expiringSuccessRecord(kind.t, 5001, 1))
			assertRecoveryCorrupt(t, entries,
				"processed at 5001", "saved expiry 5000", `"m"`)
		})

		t.Run(kind.t+"/multi-attempt success at expiry", func(t *testing.T) {
			// Multiple accumulated attempts change nothing about the expiry
			// boundary. A compacted state restores them directly; a plain
			// result must be incremental, so seed two prior waits (retry after
			// the second wait is 4000, so a 5000 delivery is otherwise due).
			var entries []*logEntry
			if kind.t == kindResult {
				entries = append(expiringSuccessBase(),
					&logEntry{T: kindResult, Now: 1000, ID: "m", Status: StatusWaiting,
						Reason:   "waiting for trusted header covering height 10 (current 0)",
						Attempts: 1, NextRetry: 2000},
					&logEntry{T: kindResult, Now: 2000, ID: "m", Status: StatusWaiting,
						Reason:   "waiting for trusted header covering height 10 (current 0)",
						Attempts: 2, NextRetry: 4000},
					expiringSuccessRecord(kind.t, 5000, 3),
				)
			} else {
				entries = append(expiringSuccessBase(), expiringSuccessRecord(kind.t, 5000, 4))
			}
			assertRecoveryCorrupt(t, entries,
				"processed at 5000", "saved expiry 5000", `"m"`)
		})
	}
}

// A success stamped strictly before the saved expiry is the boundary-legal
// case and must recover, for both record kinds, with its status, reason,
// attempt count and nonce attribution intact — 4999 is legal while 5000 is
// not.
func TestRecoveryAcceptsSuccessBeforeExpiry(t *testing.T) {
	for _, kind := range []string{kindResult, kindState} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			entries := append(expiringSuccessBase(), expiringSuccessRecord(kind, 4999, 1),
				&logEntry{T: kindAdvance, Now: 4999})
			writeLegacyLog(t, dir, entries...)
			q, err := Open(dir)
			if err != nil {
				t.Fatalf("success one millisecond before expiry must open: %v", err)
			}
			defer q.Close()
			r := statusOf(t, q, "m")
			if r.Status != StatusSuccess || r.Attempts != 1 || r.NextRetry != 0 ||
				!strings.Contains(r.Reason, "height 100") {
				t.Fatalf("boundary-legal success not restored: %+v", r)
			}
			if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m" {
				t.Fatalf("nonce consumption not restored: %q", winner)
			}
			// A terminal success stays delivered on a later advance past expiry.
			if _, err := q.Advance(60000); err != nil {
				t.Fatal(err)
			}
			if r := statusOf(t, q, "m"); r.Status != StatusSuccess || r.Attempts != 1 {
				t.Fatalf("delivered message changed after a later advance: %+v", r)
			}
		})
	}
}

// The decision reads only the success record's own processing time and the
// message's saved expiry: a success legitimately recorded at 4999 stays a
// success when the directory is opened long afterwards, however far the queue
// later advanced, and compaction never re-expires it (the compacted state
// still stamps the success at 4999 while the retained checkpoint is much
// later) or requires the compacted-away processing history.
func TestRecoveryExpiryIgnoresLaterOpenAndCompactionTimes(t *testing.T) {
	t.Run("plain success, checkpoint far after expiry", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(expiringSuccessBase(),
			expiringSuccessRecord(kindResult, 4999, 1),
			&logEntry{T: kindAdvance, Now: 9_000_000_000},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("an early success must survive a much later reopen: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "m"); r.Status != StatusSuccess || r.Attempts != 1 ||
			q.records["m"].LastProcAt != 4999 || !strings.Contains(r.Reason, "height 100") {
			t.Fatalf("original success not preserved: %+v lastProc=%d", r, q.records["m"].LastProcAt)
		}
		if q.Now() != 9_000_000_000 {
			t.Fatalf("checkpoint not restored: %d", q.Now())
		}
		if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m" {
			t.Fatalf("consumption attribution lost: %q", winner)
		}
	})

	t.Run("compacted success stamped 4999 with a later retained checkpoint", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(expiringSuccessBase(),
			expiringSuccessRecord(kindState, 4999, 3),
			&logEntry{T: kindAdvance, Now: 9_000_000_000},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("compaction must not re-expire an old success: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "m"); r.Status != StatusSuccess || r.Attempts != 3 ||
			q.records["m"].LastProcAt != 4999 || !strings.Contains(r.Reason, "height 100") {
			t.Fatalf("compacted success not preserved: %+v lastProc=%d", r, q.records["m"].LastProcAt)
		}
		if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m" {
			t.Fatalf("compacted consumption not restored: %q", winner)
		}
	})

	t.Run("compacted success at 5000 is corrupt despite a later checkpoint", func(t *testing.T) {
		entries := append(expiringSuccessBase(),
			expiringSuccessRecord(kindState, 5000, 3),
			&logEntry{T: kindAdvance, Now: 9_000_000_000},
		)
		assertRecoveryCorrupt(t, entries, "processed at 5000", "saved expiry 5000", `"m"`)
	})

	t.Run("a real queue compacted long after delivery keeps the success", func(t *testing.T) {
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
		if _, err := q.Submit(Envelope{
			Message:   Message{ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			ExpiresAt: 5000,
		}); err != nil {
			t.Fatal(err)
		}
		if rep, err := q.Advance(4999); err != nil {
			t.Fatal(err)
		} else if got, ok := resultFor(rep, "m"); !ok || got.Status != StatusSuccess {
			t.Fatalf("delivery at 4999 should succeed: %+v", rep.Results)
		}
		// Time advances well past the expiry; compaction runs afterwards.
		if _, err := q.Advance(9_000_000_000); err != nil {
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
			t.Fatalf("reopen after a late compaction must keep the success: %v", err)
		}
		defer q2.Close()
		if r := statusOf(t, q2, "m"); r.Status != StatusSuccess ||
			q2.records["m"].LastProcAt != 4999 {
			t.Fatalf("success lost or re-expired after compaction: %+v lastProc=%d",
				r, q2.records["m"].LastProcAt)
		}
	})
}

// An expiry of zero means never expire: it must never be read as a deadline
// at time zero, so a zero-expiry success stamped at time zero, or at any later
// instant, in either record kind, recovers normally.
func TestRecoveryZeroExpiryNeverBoundsSuccess(t *testing.T) {
	base := func() []*logEntry {
		return []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
		}
	}
	for _, kind := range []string{kindResult, kindState} {
		for _, now := range []int64{0, 1, 9_000_000_000} {
			name := kind + "/success at " + strconv.FormatInt(now, 10)
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				entries := append(base(),
					&logEntry{
						T: kind, Now: now, ID: "m", Status: StatusSuccess,
						Reason:   "delivered; proof verified by trusted header at height 100",
						Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m",
					},
					&logEntry{T: kindAdvance, Now: now},
				)
				writeLegacyLog(t, dir, entries...)
				q, err := Open(dir)
				if err != nil {
					t.Fatalf("zero-expiry success at %d must open: %v", now, err)
				}
				defer q.Close()
				if r := statusOf(t, q, "m"); r.Status != StatusSuccess {
					t.Fatalf("zero-expiry success not restored: %+v", r)
				}
			})
		}
	}
}
