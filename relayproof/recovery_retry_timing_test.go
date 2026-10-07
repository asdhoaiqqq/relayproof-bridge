package relayproof

import (
	"strings"
	"testing"
)

// These tests pin down the retry-schedule validation applied when an existing
// log is opened. A plain result entry that requires the message to be
// processed again — waiting, success or unknown-source — is legal only once
// the retry instant the message's own earlier record scheduled has been
// reached, judged by the result's own processing time against the saved
// schedule, never against the wall clock at open time. A message first
// waiting at 1000ms with its retry saved at 2000ms cannot legitimately
// succeed or wait again at 1500ms, however complete and well-checksummed that
// record is; accepting it would recover an undeliverable message as delivered
// and consume its nonce. Replay and expired results are exempt because the
// replay/expiry re-check closes every advance regardless of backoff. A
// message with no prior processing has no schedule to obey, and a compacted
// snapshot restores the full current state — attempt count and retry instant
// included — without replaying per-attempt history; a later plain result must
// then obey the schedule the snapshot established. Every violation is
// ErrCorrupt and leaves queue.log byte-for-byte untouched.

// earlySuccessEntry is a well-formed second-attempt success result for id at
// now, consuming the (a, b, 7) triple waitingRecoveryBase submits. Callers
// mutate copies.
func earlySuccessEntry(id string, now int64, attempts int) *logEntry {
	return &logEntry{
		T: kindResult, Now: now, ID: id, Status: StatusSuccess,
		Reason:   "delivered; proof verified by trusted header at height 100",
		Attempts: attempts, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 7, ConsumeBy: id,
	}
}

// A success or a repeated waiting result recovered before the retry instant
// the previous wait scheduled is an outcome no legal advance can have
// produced: normal advances skip the message until the backoff expires. The
// whole directory is rejected even though every other field — checksums,
// attempts, consumption triple — is perfectly consistent.
func TestResultBeforeSavedRetryIsCorrupt(t *testing.T) {
	t.Run("success before the scheduled retry", func(t *testing.T) {
		entries := append(waitingRecoveryBase(),
			waitingRecoveryRecord(kindResult), // waiting at 1000, retry at 2000
			earlySuccessEntry("w", 1500, 2),
		)
		assertRecoveryCorrupt(t, entries, "not due under the saved retry schedule", `"w"`)
	})

	t.Run("waiting again before the scheduled retry", func(t *testing.T) {
		entries := append(waitingRecoveryBase(),
			waitingRecoveryRecord(kindResult),
			&logEntry{T: kindResult, Now: 1500, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 2, NextRetry: 3500},
		)
		assertRecoveryCorrupt(t, entries, "not due under the saved retry schedule", `"w"`)
	})

	t.Run("success at the very instant of the previous wait", func(t *testing.T) {
		entries := append(waitingRecoveryBase(),
			waitingRecoveryRecord(kindResult),
			earlySuccessEntry("w", 1000, 2),
		)
		assertRecoveryCorrupt(t, entries, "not due under the saved retry schedule", `"w"`)
	})

	t.Run("waiting again at the very instant of the previous wait", func(t *testing.T) {
		entries := append(waitingRecoveryBase(),
			waitingRecoveryRecord(kindResult),
			&logEntry{T: kindResult, Now: 1000, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 2, NextRetry: 3000},
		)
		assertRecoveryCorrupt(t, entries, "not due under the saved retry schedule", `"w"`)
	})

	t.Run("zero processing time obeys the same-instant rule", func(t *testing.T) {
		zeroWait := &logEntry{T: kindResult, Now: 0, ID: "w", Status: StatusWaiting,
			Reason: "waiting", Attempts: 1, NextRetry: 1000}
		entries := append(waitingRecoveryBase(), zeroWait,
			&logEntry{T: kindResult, Now: 0, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 2, NextRetry: 2000},
		)
		assertRecoveryCorrupt(t, entries, "not due under the saved retry schedule", `"w"`)

		entries = append(waitingRecoveryBase(), zeroWait,
			earlySuccessEntry("w", 0, 2),
		)
		assertRecoveryCorrupt(t, entries, "not due under the saved retry schedule", `"w"`)
	})

	t.Run("ceiling-saturated schedule rejects a second processing at the ceiling", func(t *testing.T) {
		atCeiling := &logEntry{T: kindResult, Now: ceiling, ID: "w", Status: StatusWaiting,
			Reason: "waiting", Attempts: 1, NextRetry: ceiling}
		entries := append(waitingRecoveryBase(), atCeiling,
			earlySuccessEntry("w", ceiling, 2),
		)
		assertRecoveryCorrupt(t, entries, "not due under the saved retry schedule", `"w"`)

		entries = append(waitingRecoveryBase(), atCeiling,
			&logEntry{T: kindResult, Now: ceiling, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 2, NextRetry: ceiling},
		)
		assertRecoveryCorrupt(t, entries, "not due under the saved retry schedule", `"w"`)
	})

	t.Run("result before the schedule a snapshot established", func(t *testing.T) {
		snapshot := &logEntry{T: kindState, Now: 1000, ID: "w", Status: StatusWaiting,
			Reason: "waiting", Attempts: 5, NextRetry: 17000}
		entries := append(waitingRecoveryBase(), snapshot,
			earlySuccessEntry("w", 16999, 6),
		)
		assertRecoveryCorrupt(t, entries, "not due under the saved retry schedule", `"w"`)

		entries = append(waitingRecoveryBase(), snapshot,
			&logEntry{T: kindResult, Now: 16999, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 6, NextRetry: 48999},
		)
		assertRecoveryCorrupt(t, entries, "not due under the saved retry schedule", `"w"`)
	})
}

// A result stamped exactly at the saved retry instant is the normal
// due-retry outcome and recovers with its actual status, reason and attempt
// count; a message with no prior processing gets its first result at any
// non-negative time without any backoff being imposed on it.
func TestResultAtSavedRetryRecovers(t *testing.T) {
	t.Run("success exactly at the scheduled retry", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(waitingRecoveryBase(),
			waitingRecoveryRecord(kindResult),
			earlySuccessEntry("w", 2000, 2),
			&logEntry{T: kindAdvance, Now: 2000},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("success at the scheduled retry must open: %v", err)
		}
		defer q.Close()
		r := statusOf(t, q, "w")
		if r.Status != StatusSuccess || r.Attempts != 2 || r.NextRetry != 0 ||
			!strings.Contains(r.Reason, "delivered") {
			t.Fatalf("due success not restored: %+v", r)
		}
		if winner := q.consumed[newConsumeToken("a", "b", 7)]; winner != "w" {
			t.Fatalf("due success did not consume its nonce: %q", winner)
		}
	})

	t.Run("waiting again exactly at the scheduled retry", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(waitingRecoveryBase(),
			waitingRecoveryRecord(kindResult),
			&logEntry{T: kindResult, Now: 2000, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 2, NextRetry: 4000},
			&logEntry{T: kindAdvance, Now: 2000},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("due retry must open: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "w"); r.Status != StatusWaiting || r.Attempts != 2 || r.NextRetry != 4000 {
			t.Fatalf("due waiting retry not restored: %+v", r)
		}
	})

	t.Run("first processing is accepted at any time without backoff", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(successRecoveryBase(),
			&logEntry{T: kindResult, Now: 500, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
			&logEntry{T: kindAdvance, Now: 500},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("first processing must not gain a backoff: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "m"); r.Status != StatusSuccess || r.Attempts != 1 {
			t.Fatalf("first success not restored: %+v", r)
		}
	})

	t.Run("result exactly at the schedule a snapshot established", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(waitingRecoveryBase(),
			&logEntry{T: kindState, Now: 1000, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 5, NextRetry: 17000},
			&logEntry{T: kindResult, Now: 17000, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 6, NextRetry: 49000},
			&logEntry{T: kindAdvance, Now: 17000},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("result at the snapshot's schedule must open: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "w"); r.Status != StatusWaiting || r.Attempts != 6 || r.NextRetry != 49000 {
			t.Fatalf("result after snapshot not restored: %+v", r)
		}
	})
}

// Replay and expired results come from the replay/expiry re-check that closes
// every advance regardless of backoff, so they recover even before the saved
// retry instant — including the wait-then-replay pair of a single advance.
func TestReplayAndExpiryRecoverBeforeSavedRetry(t *testing.T) {
	// replayBase submits w (proof height 500, waits under trusted height 100)
	// and z (proof height 10, succeeds), both on nonce 7.
	replayBase := func() []*logEntry {
		return []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "w", From: "a", To: "b", Nonce: 7, ProofAt: 500},
			{T: kindSubmit, Seq: 1, ID: "z", From: "a", To: "b", Nonce: 7, ProofAt: 10},
		}
	}
	waitingW := &logEntry{T: kindResult, Now: 1000, ID: "w", Status: StatusWaiting,
		Reason:   "waiting for trusted header covering height 500 (current 100)",
		Attempts: 1, NextRetry: 2000}
	successZ := func(now int64) *logEntry {
		return &logEntry{T: kindResult, Now: now, ID: "z", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 7, ConsumeBy: "z"}
	}
	replayW := func(now int64) *logEntry {
		return &logEntry{T: kindResult, Now: now, ID: "w", Status: StatusReplay,
			Reason: "nonce combination already consumed by message z", Attempts: 2}
	}

	t.Run("replay before the scheduled retry", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(replayBase(),
			waitingW, successZ(1500), replayW(1500),
			&logEntry{T: kindAdvance, Now: 1500},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("replay before the retry must open: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "w"); r.Status != StatusReplay || r.Attempts != 2 || r.NextRetry != 0 {
			t.Fatalf("early replay not restored: %+v", r)
		}
		if r := statusOf(t, q, "z"); r.Status != StatusSuccess || r.Attempts != 1 {
			t.Fatalf("consuming message not restored: %+v", r)
		}
	})

	t.Run("waiting then replay within one advance", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(replayBase(),
			waitingW, successZ(1000), replayW(1000),
			&logEntry{T: kindAdvance, Now: 1000},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("same-advance wait-then-replay must open: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "w"); r.Status != StatusReplay || r.Attempts != 2 || r.NextRetry != 0 {
			t.Fatalf("same-advance replay not restored: %+v", r)
		}
	})

	t.Run("expired before the scheduled retry", func(t *testing.T) {
		dir := t.TempDir()
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindSubmit, Seq: 0, ID: "w", From: "a", To: "b", Nonce: 7, ProofAt: 100, ExpiresAt: 1500},
			{T: kindResult, Now: 1000, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 1, NextRetry: 2000},
			{T: kindResult, Now: 1500, ID: "w", Status: StatusExpired,
				Reason: "expired at 1500", Attempts: 2},
			{T: kindAdvance, Now: 1500},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("expiry before the retry must open: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "w"); r.Status != StatusExpired || r.Attempts != 2 || r.NextRetry != 0 {
			t.Fatalf("early expiry not restored: %+v", r)
		}
	})
}

// A compacted snapshot restores the accumulated attempt count and retry
// instant directly, without any per-attempt waiting history, and the
// recovered queue then honors that schedule on later advances.
func TestSnapshotRestoresScheduleWithoutHistory(t *testing.T) {
	dir := t.TempDir()
	entries := append(waitingRecoveryBase(),
		&logEntry{T: kindState, Now: 1000, ID: "w", Status: StatusWaiting,
			Reason:   "waiting for trusted header covering height 100 (current 0)",
			Attempts: 5, NextRetry: 17000},
		&logEntry{T: kindAdvance, Now: 1000},
	)
	writeLegacyLog(t, dir, entries...)
	q, err := Open(dir)
	if err != nil {
		t.Fatalf("multi-attempt snapshot must open: %v", err)
	}
	defer q.Close()
	if r := statusOf(t, q, "w"); r.Status != StatusWaiting || r.Attempts != 5 || r.NextRetry != 17000 {
		t.Fatalf("snapshot not restored: %+v", r)
	}
	// Before the restored retry instant nothing is processed; at it, exactly
	// one more attempt runs and the backoff continues from the restored count.
	rep, err := q.Advance(16999)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("advance before the restored retry processed the message: %+v", rep.Results)
	}
	rep, err = q.Advance(17000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Status != StatusWaiting {
		t.Fatalf("restored retry did not run exactly once: %+v", rep.Results)
	}
	if r := statusOf(t, q, "w"); r.Status != StatusWaiting || r.Attempts != 6 || r.NextRetry != 49000 {
		t.Fatalf("restored schedule did not continue normally: %+v", r)
	}
}
