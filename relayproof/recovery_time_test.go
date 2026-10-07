package relayproof

import (
	"errors"
	"strings"
	"testing"
)

// These tests pin down the processing-time validation applied when an
// existing log is opened. A plain result entry is one incremental outcome of
// a legal advance, so its time must be a non-negative Unix-millisecond
// instant and can never predate any queue-wide time the log has already
// confirmed — an advance checkpoint or any earlier result or snapshot, of any
// message, whether or not a later checkpoint was saved. A compacted snapshot
// only needs the non-negativity floor: compaction writes snapshots in
// first-submission order, each stamped with its own message's last processing
// instant, so their times are legitimately unordered. Every violation is
// ErrCorrupt naming the record category, the message id and the bad time, and
// the log keeps its exact length and bytes even when the bad record is the
// very last one.

// successResultEntry is a well-formed success result for id at now, consuming
// its own triple. Callers mutate copies.
func successResultEntry(id string, now int64) *logEntry {
	return &logEntry{
		T: kindResult, Now: now, ID: id, Status: StatusSuccess,
		Reason:   "delivered; proof verified by trusted header at height 100",
		Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: id,
	}
}

// A result stamped before the queue-wide time the log has already confirmed
// is an outcome no legal advance can have produced: normal advances never
// move processing time backwards, so such a record — however complete and
// well-checksummed — must not be recovered as a success (consuming its
// nonce), a waiting schedule or a terminal state.
func TestResultTimeMustNotPredateConfirmedTime(t *testing.T) {
	base := func() []*logEntry {
		return []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m1", From: "a", To: "b", Nonce: 1, ProofAt: 10},
		}
	}

	t.Run("first success below a saved advance checkpoint", func(t *testing.T) {
		entries := append(base(),
			&logEntry{T: kindAdvance, Now: 5000},
			&logEntry{T: kindSubmit, Seq: 1, ID: "m2", From: "a", To: "b", Nonce: 2, ProofAt: 10},
		)
		bad := successResultEntry("m2", 4000)
		bad.ConsumeNonce = 2
		entries = append(entries, bad)
		assertRecoveryCorrupt(t, entries, "result time 4000 before known time 5000", `"m2"`)
	})

	t.Run("first result below another message's result", func(t *testing.T) {
		entries := append(base(),
			&logEntry{T: kindSubmit, Seq: 1, ID: "m2", From: "a", To: "b", Nonce: 2, ProofAt: 10},
			&logEntry{T: kindResult, Now: 5000, ID: "m1", Status: StatusWaiting,
				Reason: "waiting", Attempts: 1, NextRetry: 6000},
			&logEntry{T: kindResult, Now: 4000, ID: "m2", Status: StatusWaiting,
				Reason: "waiting", Attempts: 1, NextRetry: 5000},
		)
		assertRecoveryCorrupt(t, entries, "result time 4000 before known time 5000", `"m2"`)
	})

	t.Run("first result below an uncheckpointed snapshot", func(t *testing.T) {
		// The previous message's 6000ms state was saved in full but this
		// round's advance checkpoint was not; the saved result still confirms
		// the queue had reached 6000, so a 5500ms outcome is corrupt.
		entries := append(base(),
			&logEntry{T: kindState, Now: 6000, ID: "m1", Status: StatusSuccess,
				Reason: "delivered", Attempts: 1,
				ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m1"},
			&logEntry{T: kindSubmit, Seq: 1, ID: "m2", From: "a", To: "b", Nonce: 2, ProofAt: 10},
			&logEntry{T: kindResult, Now: 5500, ID: "m2", Status: StatusWaiting,
				Reason: "waiting", Attempts: 1, NextRetry: 6500},
		)
		assertRecoveryCorrupt(t, entries, "result time 5500 before known time 6000", `"m2"`)
	})

	t.Run("terminal result is bounded too", func(t *testing.T) {
		entries := append(base(),
			successResultEntry("m1", 5000),
			&logEntry{T: kindSubmit, Seq: 1, ID: "m2", From: "a", To: "b", Nonce: 2, ProofAt: 10, ExpiresAt: 4500},
			&logEntry{T: kindResult, Now: 4000, ID: "m2", Status: StatusExpired,
				Reason: "expired at 4500", Attempts: 1},
		)
		assertRecoveryCorrupt(t, entries, "result time 4000 before known time 5000", `"m2"`)
	})

	t.Run("equal time across messages is legal", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(base(),
			&logEntry{T: kindSubmit, Seq: 1, ID: "m2", From: "a", To: "b", Nonce: 2, ProofAt: 10},
			&logEntry{T: kindResult, Now: 5000, ID: "m1", Status: StatusWaiting,
				Reason: "waiting", Attempts: 1, NextRetry: 6000},
			&logEntry{T: kindResult, Now: 5000, ID: "m2", Status: StatusWaiting,
				Reason: "waiting", Attempts: 1, NextRetry: 6000},
			&logEntry{T: kindAdvance, Now: 5000},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("equal-time results must open: %v", err)
		}
		defer q.Close()
		for _, id := range []string{"m1", "m2"} {
			if r := statusOf(t, q, id); r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != 6000 {
				t.Fatalf("equal-time result for %s not restored: %+v", id, r)
			}
		}
	})
}

// Neither kind of post-processing record may carry a negative processing
// time; zero remains a valid instant.
func TestRecoveryTimeMustBeNonNegative(t *testing.T) {
	t.Run("waiting result", func(t *testing.T) {
		r := waitingRecoveryRecord(kindResult)
		r.Now, r.NextRetry = -1000, 0
		assertRecoveryCorrupt(t, append(waitingRecoveryBase(), r), "result time -1000 is negative", `"w"`)
	})
	t.Run("success result", func(t *testing.T) {
		r := successRecoveryRecord(kindResult)
		r.Now = -1
		assertRecoveryCorrupt(t, append(successRecoveryBase(), r), "result time -1 is negative", `"m"`)
	})
	t.Run("terminal result", func(t *testing.T) {
		r := terminalRecoveryRecord(kindResult)
		r.Now = -1
		assertRecoveryCorrupt(t, append(terminalRecoveryBase(), r), "result time -1 is negative", `"t"`)
	})
	t.Run("waiting state", func(t *testing.T) {
		r := waitingRecoveryRecord(kindState)
		r.Now, r.NextRetry = -1000, 0
		assertRecoveryCorrupt(t, append(waitingRecoveryBase(), r), "state time -1000 is negative", `"w"`)
	})
	t.Run("success state", func(t *testing.T) {
		r := successRecoveryRecord(kindState)
		r.Now = -1
		assertRecoveryCorrupt(t, append(successRecoveryBase(), r), "state time -1 is negative", `"m"`)
	})

	t.Run("zero is a valid first processing time", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(waitingRecoveryBase(),
			&logEntry{T: kindResult, Now: 0, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 1, NextRetry: 1000},
			&logEntry{T: kindAdvance, Now: 0},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("zero as a first processing time must open: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "w"); r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != 1000 {
			t.Fatalf("zero-time first result not restored: %+v", r)
		}
	})

	t.Run("zero is a valid first terminal time", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(successRecoveryBase(),
			&logEntry{T: kindResult, Now: 0, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
			&logEntry{T: kindAdvance, Now: 0},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("zero-time first success must open: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "m"); r.Status != StatusSuccess || r.Attempts != 1 {
			t.Fatalf("zero-time success not restored: %+v", r)
		}
	})
}

// A compacted log stores each message's last processing instant in
// first-submission order, which is not time order: a first-submitted message
// last processed at 6000 followed by a later-submitted one last processed at
// 2000 is a legitimate state. It must open with every status, reason, attempt
// count and retry schedule intact, and the recovered queue time is the
// maximum of the saved instants and the checkpoint, so nothing appended
// afterwards may be stamped earlier.
func TestCompactedSnapshotsKeepUnorderedTimes(t *testing.T) {
	dir := t.TempDir()
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		// Snapshot retains trusted coverage at 100: m1 (proof 10) is covered,
		// m2 (proof 200) is still legitimately waiting at compaction time.
		{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "m1", From: "a", To: "b", Nonce: 1, ProofAt: 10},
		{T: kindState, Now: 6000, ID: "m1", Status: StatusSuccess,
			Reason: "delivered; proof verified by trusted header at height 100", Attempts: 3,
			ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m1"},
		{T: kindSubmit, Seq: 1, ID: "m2", From: "a", To: "b", Nonce: 2, ProofAt: 200},
		{T: kindState, Now: 2000, ID: "m2", Status: StatusWaiting,
			Reason: "waiting for trusted header covering height 200 (current 100)", Attempts: 1, NextRetry: 3000},
		{T: kindAdvance, Now: 6000},
	}
	writeLegacyLog(t, dir, entries...)

	q, err := Open(dir)
	if err != nil {
		t.Fatalf("unordered snapshot times must open: %v", err)
	}
	defer q.Close()
	if r := statusOf(t, q, "m1"); r.Status != StatusSuccess || r.Attempts != 3 ||
		!strings.Contains(r.Reason, "delivered") {
		t.Fatalf("success snapshot not restored: %+v", r)
	}
	if r := statusOf(t, q, "m2"); r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != 3000 ||
		!strings.Contains(r.Reason, "height 200") {
		t.Fatalf("waiting snapshot not restored: %+v", r)
	}
	if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m1" {
		t.Fatalf("consumption not restored: %q", winner)
	}
	// The queue time is the maximum of the saved instants and the checkpoint;
	// an earlier advance is rejected, an equal one proceeds normally.
	if q.Now() != 6000 {
		t.Fatalf("recovered queue time = %d, want 6000", q.Now())
	}
	if _, err := q.Advance(5999); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("advance below recovered time: want ErrInvalidArg, got %v", err)
	}
	if _, err := q.Advance(6000); err != nil {
		t.Fatal(err)
	}
	if r := statusOf(t, q, "m2"); r.Status != StatusWaiting || r.Attempts != 2 || r.NextRetry != 8000 {
		t.Fatalf("waiting message did not continue from its restored schedule: %+v", r)
	}
}
