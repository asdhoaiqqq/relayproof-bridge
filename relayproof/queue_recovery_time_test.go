package relayproof

import (
	"errors"
	"testing"
)

// These tests pin the queue-wide processing-time rule applied while opening an
// existing log. A complete, checksum-valid record must never be replayed as a
// success (consuming a nonce) when its processing time is impossible:
//
//   - a processing time is a non-negative Unix-millisecond instant;
//   - a plain result must never move backwards relative to anything the log
//     already confirmed queue-wide — the same message's prior result, another
//     message's saved result, or an advance checkpoint — even when the current
//     round's advance checkpoint was never saved;
//   - equal times stay legal and zero is a valid processing time;
//   - compacted snapshots store each message's last historical instant in
//     first-submission order, so descending snapshot times stay legal and the
//     restored queue time is the maximum saved instant.
//
// A violating record that is itself whole and checksum-correct is ErrCorrupt,
// not a torn tail, even when it sits at the very end: the log bytes stay
// untouched and no usable queue comes back.

// sourceSubmit builds a registered, header-covered source and one submitted
// pending message with the given id/seq/nonce.
func sourceSubmit(id string, seq int64, nonce uint64) []*logEntry {
	return []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
		{T: kindSubmit, Seq: seq, ID: id, From: "a", To: "b", Nonce: nonce, ProofAt: 10},
	}
}

func successResultAt(id string, nonce uint64, now int64) *logEntry {
	return &logEntry{
		T: kindResult, Now: now, ID: id, Status: StatusSuccess,
		Reason:      "delivered; proof verified by trusted header at height 100",
		Attempts:    1,
		ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: nonce, ConsumeBy: id,
	}
}

// An advance checkpoint already confirmed at 5000 must reject a later, whole
// record whose brand-new message first "succeeds" at 4000 — it may not be
// recovered as success and consume the nonce. The offending record is the
// final frame, so it must not be mistaken for an unwritten tail.
func TestRecoverRejectsResultBeforeAdvanceCheckpoint(t *testing.T) {
	entries := append(sourceSubmit("m", 0, 1),
		&logEntry{T: kindAdvance, Now: 5000},
		successResultAt("m", 1, 4000),
	)
	assertRecoveryCorrupt(t, entries,
		"result", "result time 4000 before confirmed queue time 5000", `"m"`)
}

// A fully saved 6000ms result for one message sets the queue floor even when
// the round's advance checkpoint was never persisted; a 5500ms result for the
// next message is still impossible and corrupt. Covers waiting, success and a
// terminal outcome as the offending second result.
func TestRecoverRejectsResultEarlierThanSavedResultOtherMessage(t *testing.T) {
	second := map[string]*logEntry{
		"waiting": {
			T: kindResult, Now: 5500, ID: "w", Status: StatusWaiting,
			Reason:   "waiting for trusted header covering height 900 (current 100)",
			Attempts: 1, NextRetry: 6500,
		},
		"success": successResultAt("s", 2, 5500),
		"terminal": {
			T: kindResult, Now: 5500, ID: "e", Status: StatusExpired,
			Reason: "expired at 5000", Attempts: 1,
		},
	}
	submitFor := map[string]*logEntry{
		"waiting":  {T: kindSubmit, Seq: 1, ID: "w", From: "a", To: "b", Nonce: 9, ProofAt: 900},
		"success":  {T: kindSubmit, Seq: 1, ID: "s", From: "a", To: "b", Nonce: 2, ProofAt: 10},
		"terminal": {T: kindSubmit, Seq: 1, ID: "e", From: "a", To: "b", Nonce: 3, ProofAt: 10, ExpiresAt: 5000},
	}
	for name, r := range second {
		t.Run(name, func(t *testing.T) {
			entries := sourceSubmit("f", 0, 1)
			entries = append(entries, successResultAt("f", 1, 6000))
			entries = append(entries, submitFor[name], r)
			assertRecoveryCorrupt(t, entries,
				"result", "result time 5500 before confirmed queue time 6000", `"`+r.ID+`"`)
		})
	}
}

// Negative processing times are corrupt in a plain result and in a compacted
// snapshot alike; a negative next-retry time is a separate, repaired legacy
// case and stays accepted (covered by the ceiling tests).
func TestRecoverRejectsNegativeProcessingTime(t *testing.T) {
	t.Run("result", func(t *testing.T) {
		r := successResultAt("m", 1, -1)
		entries := append(sourceSubmit("m", 0, 1), r)
		assertRecoveryCorrupt(t, entries, "negative processing time -1", "result", `"m"`)
	})
	t.Run("state", func(t *testing.T) {
		entries := append(sourceSubmit("m", 0, 1), &logEntry{
			T: kindState, Now: -5, ID: "m", Status: StatusSuccess,
			Reason: "delivered; proof verified by trusted header at height 100", Attempts: 1,
			ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m",
		})
		assertRecoveryCorrupt(t, entries, "negative processing time -5", "state", `"m"`)
	})
}

// Equal times remain legal and zero remains a valid processing time, both
// against a checkpoint and across messages.
func TestRecoverAcceptsEqualAndZeroProcessingTimes(t *testing.T) {
	t.Run("result equal to checkpoint", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(sourceSubmit("m", 0, 1),
			&logEntry{T: kindAdvance, Now: 5000},
			successResultAt("m", 1, 5000),
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("equal-time result must open: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "m"); r.Status != StatusSuccess || r.Attempts != 1 {
			t.Fatalf("equal-time result not recovered: %+v", r)
		}
		if q.Now() != 5000 {
			t.Fatalf("queue time: want 5000, got %d", q.Now())
		}
	})

	t.Run("zero processing time", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(sourceSubmit("a", 0, 1),
			successResultAt("a", 1, 0),
			&logEntry{T: kindSubmit, Seq: 1, ID: "b", From: "a", To: "b", Nonce: 2, ProofAt: 10},
			successResultAt("b", 2, 0),
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("zero-time results must open: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "b"); r.Status != StatusSuccess {
			t.Fatalf("zero-time result not recovered: %+v", r)
		}
		if q.Now() != 0 {
			t.Fatalf("queue time must stay zero, got %d", q.Now())
		}
	})
}

// A compacted snapshot orders full message states by first submission, not by
// their last processing instants: a message last processed at 6000 submitted
// before one last processed at 2000 is a legal snapshot. Both states (status,
// reason, attempts, retry schedule) open intact and the queue time is the
// maximum saved instant; a later ordinary result cannot precede that maximum.
func TestRecoveredSnapshotTimesNeedNotIncrease(t *testing.T) {
	dir := t.TempDir()
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "x", From: "a", To: "b", Nonce: 1, ProofAt: 10},
		{T: kindState, Now: 6000, ID: "x", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 4, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "x"},
		{T: kindSubmit, Seq: 1, ID: "w", From: "a", To: "b", Nonce: 9, ProofAt: 5000},
		{T: kindState, Now: 2000, ID: "w", Status: StatusWaiting,
			Reason:   "waiting for trusted header covering height 5000 (current 100)",
			Attempts: 2, NextRetry: 4000},
	}
	writeLegacyLog(t, dir, entries...)

	q, err := Open(dir)
	if err != nil {
		t.Fatalf("descending snapshot times must open: %v", err)
	}
	if q.Now() != 6000 {
		t.Fatalf("queue time must be the max saved instant 6000, got %d", q.Now())
	}
	if r := statusOf(t, q, "x"); r.Status != StatusSuccess || r.Attempts != 4 || r.NextRetry != 0 {
		t.Fatalf("6000ms success snapshot not preserved: %+v", r)
	}
	if r := statusOf(t, q, "w"); r.Status != StatusWaiting || r.Attempts != 2 || r.NextRetry != 4000 {
		t.Fatalf("2000ms waiting snapshot not preserved: %+v", r)
	}
	if len(q.order) != 1 || q.order[0] != "w" {
		t.Fatalf("only the waiting message stays live: %v", q.order)
	}

	// A later ordinary result before the restored maximum is impossible: the
	// live advance guard rejects 5500 and changes nothing (no nonce consumed).
	if _, err := q.Advance(5500); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("advance before restored queue time: want ErrInvalidArg, got %v", err)
	}
	if r := statusOf(t, q, "w"); r.Attempts != 2 || r.NextRetry != 4000 {
		t.Fatalf("rejected advance must not process the message: %+v", r)
	}
	// An equal-time advance is legal and reprocesses the due waiting message
	// once, scheduling the next backoff from 6000 (6000 + 4000 = 10000).
	if _, err := q.Advance(6000); err != nil {
		t.Fatalf("equal-time advance must be accepted: %v", err)
	}
	if r := statusOf(t, q, "w"); r.Status != StatusWaiting || r.Attempts != 3 || r.NextRetry != 10000 {
		t.Fatalf("equal-time advance did not process the waiting record once: %+v", r)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening the now-result-amended log must likewise accept it: its newest
	// result sits exactly on the restored floor.
	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after equal-time processing: %v", err)
	}
	defer q2.Close()
	if r := statusOf(t, q2, "w"); r.Attempts != 3 || r.NextRetry != 10000 {
		t.Fatalf("equal-time result lost on reopen: %+v", r)
	}
	if q2.Now() != 6000 {
		t.Fatalf("queue time after reopen: want 6000, got %d", q2.Now())
	}
}
