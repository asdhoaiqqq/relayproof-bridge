package relayproof

import (
	"strings"
	"testing"
)

// Recovery must make an incrementally saved plain result obey the retry
// schedule the message's previously saved state established: once a message
// has waited, a success or another waiting result stamped before the backoff
// elapsed — however complete, checksum-valid and otherwise consistent — is
// corruption; replay and expired phase-2 holds stay legal during the backoff,
// as does waiting-then-replay within one advance; a result exactly at the
// scheduled retry recovers normally and keeps its actual status, reason and
// attempt count. A compacted state restores the accumulated attempts directly
// (no historical waits need to be filled in), and any later plain result must
// obey the schedule recovered from it.

// waitedAt1000Base is a source with no covering header and one message that
// first waits at 1000ms, scheduling its retry for 2000ms.
func waitedAt1000Base() []*logEntry {
	return []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindSubmit, Seq: 0, ID: "w", From: "a", To: "b", Nonce: 7, ProofAt: 100},
		{T: kindResult, Now: 1000, ID: "w", Status: StatusWaiting,
			Reason:   "waiting for trusted header covering height 100 (current 0)",
			Attempts: 1, NextRetry: 2000},
		{T: kindAdvance, Now: 1000},
	}
}

// A success recorded while the backoff is still running — even at a time the
// queue had already advanced to — would consume a nonce that no normal
// advance could deliver; recovery must reject the directory rather than
// restore the success.
func TestRecoveryRejectsEarlySuccessDuringBackoff(t *testing.T) {
	t.Run("before retry after a plain wait", func(t *testing.T) {
		entries := waitedAt1000Base()
		entries = append(entries,
			&logEntry{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			&logEntry{T: kindResult, Now: 1500, ID: "w", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 2, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 7, ConsumeBy: "w"},
		)
		assertRecoveryCorrupt(t, entries, "result time 1500 precedes scheduled retry 2000", `"w"`)
	})

	t.Run("after a compacted waiting state", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "w", From: "a", To: "b", Nonce: 7, ProofAt: 100},
			// Full current state after three attempts; no waiting history.
			{T: kindState, Now: 2000, ID: "w", Status: StatusWaiting,
				Reason:   "waiting for trusted header covering height 100 (current 0)",
				Attempts: 3, NextRetry: 6000},
			{T: kindAdvance, Now: 2000},
			// Incremental success before the recovered retry.
			{T: kindResult, Now: 5000, ID: "w", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 4, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 7, ConsumeBy: "w"},
		}
		assertRecoveryCorrupt(t, entries, "result time 5000 precedes scheduled retry 6000", `"w"`)
	})
}

// A second waiting attempt recorded before the retry elapsed likewise cannot
// come from any legal advance, even with a perfectly canonical schedule.
func TestRecoveryRejectsEarlyWaitingDuringBackoff(t *testing.T) {
	t.Run("attempt added before retry", func(t *testing.T) {
		entries := append(waitedAt1000Base(),
			&logEntry{T: kindResult, Now: 1500, ID: "w", Status: StatusWaiting,
				Reason:   "waiting for trusted header covering height 100 (current 0)",
				Attempts: 2, NextRetry: 3500},
		)
		assertRecoveryCorrupt(t, entries, "result time 1500 precedes scheduled retry 2000", `"w"`)
	})

	t.Run("same instant as the prior wait", func(t *testing.T) {
		entries := append(waitedAt1000Base(),
			&logEntry{T: kindResult, Now: 1000, ID: "w", Status: StatusWaiting,
				Reason:   "waiting for trusted header covering height 100 (current 0)",
				Attempts: 2, NextRetry: 3000},
		)
		assertRecoveryCorrupt(t, entries, "same instant as its prior processing", `"w"`)
	})
}

// A message processed once at time 0 can never get another due result at the
// same instant, though 0 itself is a legal first processing time.
func TestRecoveryRejectsSecondProcessingAtTimeZero(t *testing.T) {
	t.Run("waiting again at 0", func(t *testing.T) {
		entries := append(waitingRecoveryBase(),
			&logEntry{T: kindResult, Now: 0, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 1, NextRetry: 1000},
			&logEntry{T: kindResult, Now: 0, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 2, NextRetry: 2000},
			&logEntry{T: kindAdvance, Now: 0},
		)
		assertRecoveryCorrupt(t, entries, "result time 0 re-processes", `"w"`)
	})

	t.Run("success at 0 after the wait at 0", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "w", From: "a", To: "b", Nonce: 7, ProofAt: 10},
			&logEntry{T: kindResult, Now: 0, ID: "w", Status: StatusWaiting,
				Reason:   "waiting for trusted header covering height 10 (current 0)",
				Attempts: 1, NextRetry: 1000},
			&logEntry{T: kindResult, Now: 0, ID: "w", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 2, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 7, ConsumeBy: "w"},
			{T: kindAdvance, Now: 0},
		}
		assertRecoveryCorrupt(t, entries, "result time 0 re-processes", `"w"`)
	})
}

// A due result stamped exactly at the scheduled retry recovers normally and
// keeps the actual status, reason and attempt count; a waiting result at the
// retry schedules its next backoff exactly as a live advance would.
func TestRecoveryAcceptsResultExactlyAtScheduledRetry(t *testing.T) {
	t.Run("waiting at 2000", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(waitedAt1000Base(),
			&logEntry{T: kindResult, Now: 2000, ID: "w", Status: StatusWaiting,
				Reason:   "waiting for trusted header covering height 100 (current 0)",
				Attempts: 2, NextRetry: 4000},
			&logEntry{T: kindAdvance, Now: 2000},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("result exactly at the retry must open: %v", err)
		}
		defer q.Close()
		r := statusOf(t, q, "w")
		if r.Status != StatusWaiting || r.Attempts != 2 || r.NextRetry != 4000 {
			t.Fatalf("retry-time waiting result not restored: %+v", r)
		}
	})

	t.Run("success at 2000", func(t *testing.T) {
		dir := t.TempDir()
		entries := waitedAt1000Base()
		entries = append(entries,
			&logEntry{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			&logEntry{T: kindResult, Now: 2000, ID: "w", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 2, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 7, ConsumeBy: "w"},
			&logEntry{T: kindAdvance, Now: 2000},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("success exactly at the retry must open: %v", err)
		}
		defer q.Close()
		r := statusOf(t, q, "w")
		if r.Status != StatusSuccess || r.Attempts != 2 || r.NextRetry != 0 ||
			!strings.Contains(r.Reason, "height 100") {
			t.Fatalf("retry-time success not restored: %+v", r)
		}
		if winner := q.consumed[newConsumeToken("a", "b", 7)]; winner != "w" {
			t.Fatalf("nonce not consumed by w: %q", winner)
		}
	})

	t.Run("later than the retry", func(t *testing.T) {
		dir := t.TempDir()
		entries := waitedAt1000Base()
		entries = append(entries,
			&logEntry{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			&logEntry{T: kindResult, Now: 5000, ID: "w", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 2, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 7, ConsumeBy: "w"},
			&logEntry{T: kindAdvance, Now: 5000},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("a jump over the retry still costs one attempt and must open: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "w"); r.Status != StatusSuccess || r.Attempts != 2 {
			t.Fatalf("post-retry success not restored: %+v", r)
		}
	})
}

// Replay and expired are the phase-2 holds: another message consuming the same
// (source, destination, nonce), or reaching the absolute expiry, settles a
// waiting message before its retry is due. Both must still recover while the
// backoff runs.
func TestRecoveryAcceptsReplayAndExpiredDuringBackoff(t *testing.T) {
	t.Run("replay before retry", func(t *testing.T) {
		dir := t.TempDir()
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "early", From: "a", To: "b", Nonce: 7, ProofAt: 101},
			{T: kindSubmit, Seq: 1, ID: "later", From: "a", To: "b", Nonce: 7, ProofAt: 100},
			// early waits at 1000, retry 2000; later succeeds at 1500; the
			// saved replay of early at 1500 must be accepted.
			{T: kindResult, Now: 1000, ID: "early", Status: StatusWaiting,
				Reason:   "waiting for trusted header covering height 101 (current 100)",
				Attempts: 1, NextRetry: 2000},
			{T: kindResult, Now: 1500, ID: "later", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 7, ConsumeBy: "later"},
			{T: kindResult, Now: 1500, ID: "early", Status: StatusReplay,
				Reason: "nonce combination already consumed by message later", Attempts: 2},
			{T: kindAdvance, Now: 1500},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("replay during backoff must open: %v", err)
		}
		defer q.Close()
		r := statusOf(t, q, "early")
		if r.Status != StatusReplay || r.Attempts != 2 || r.NextRetry != 0 ||
			!strings.Contains(r.Reason, "later") {
			t.Fatalf("replay during backoff not restored: %+v", r)
		}
	})

	t.Run("expired at the absolute expiry before retry", func(t *testing.T) {
		dir := t.TempDir()
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindSubmit, Seq: 0, ID: "x", From: "a", To: "b", Nonce: 1, ProofAt: 100, ExpiresAt: 1500},
			{T: kindResult, Now: 1000, ID: "x", Status: StatusWaiting,
				Reason:   "waiting for trusted header covering height 100 (current 0)",
				Attempts: 1, NextRetry: 2000},
			{T: kindResult, Now: 1500, ID: "x", Status: StatusExpired,
				Reason: "expired at 1500", Attempts: 2},
			{T: kindAdvance, Now: 1500},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("expiry during backoff must open: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "x"); r.Status != StatusExpired || r.Attempts != 2 ||
			!strings.Contains(r.Reason, "1500") {
			t.Fatalf("expired during backoff not restored: %+v", r)
		}
	})
}

// The waiting-then-replay pair within one advance is two legal results at the
// same processing instant: the first is a due wait, the second a phase-2
// replay after another message consumed the nonce. Recovery keeps both.
func TestRecoveryAcceptsWaitingThenReplaySameAdvance(t *testing.T) {
	dir := t.TempDir()
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "early", From: "a", To: "b", Nonce: 7, ProofAt: 101},
		{T: kindSubmit, Seq: 1, ID: "later", From: "a", To: "b", Nonce: 7, ProofAt: 100},
		{T: kindResult, Now: 1000, ID: "early", Status: StatusWaiting,
			Reason:   "waiting for trusted header covering height 101 (current 100)",
			Attempts: 1, NextRetry: 2000},
		{T: kindResult, Now: 1000, ID: "later", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 7, ConsumeBy: "later"},
		{T: kindResult, Now: 1000, ID: "early", Status: StatusReplay,
			Reason: "nonce combination already consumed by message later", Attempts: 2},
		{T: kindAdvance, Now: 1000},
	}
	writeLegacyLog(t, dir, entries...)
	q, err := Open(dir)
	if err != nil {
		t.Fatalf("waiting-then-replay in one advance must open: %v", err)
	}
	defer q.Close()
	if r := statusOf(t, q, "early"); r.Status != StatusReplay || r.Attempts != 2 {
		t.Fatalf("same-instant wait-then-replay not kept: %+v", r)
	}
	if r := statusOf(t, q, "later"); r.Status != StatusSuccess || r.Attempts != 1 {
		t.Fatalf("winner success not kept: %+v", r)
	}
}

// A compacted state needs no past waiting history: it restores the accumulated
// attempts and schedule directly, and subsequent advances behave exactly as if
// those attempts had happened live.
func TestRecoveryStateRestoresScheduleWithoutHistory(t *testing.T) {
	dir := t.TempDir()
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindSubmit, Seq: 0, ID: "w", From: "a", To: "b", Nonce: 7, ProofAt: 100},
		{T: kindState, Now: 2000, ID: "w", Status: StatusWaiting,
			Reason:   "waiting for trusted header covering height 100 (current 0)",
			Attempts: 3, NextRetry: 6000},
		{T: kindAdvance, Now: 2000},
	}
	writeLegacyLog(t, dir, entries...)
	q, err := Open(dir)
	if err != nil {
		t.Fatalf("compacted waiting state must open without history: %v", err)
	}
	defer q.Close()
	r := statusOf(t, q, "w")
	if r.Status != StatusWaiting || r.Attempts != 3 || r.NextRetry != 6000 {
		t.Fatalf("state schedule/attempts not restored directly: %+v", r)
	}
	// Before the recovered retry nothing happens; at the retry one attempt is
	// added with the fourth backoff interval (8s).
	if _, err := q.Advance(5999); err != nil {
		t.Fatal(err)
	}
	if r := statusOf(t, q, "w"); r.Attempts != 3 || r.NextRetry != 6000 {
		t.Fatalf("pre-retry advance changed the restored record: %+v", r)
	}
	if _, err := q.Advance(6000); err != nil {
		t.Fatal(err)
	}
	if r := statusOf(t, q, "w"); r.Status != StatusWaiting || r.Attempts != 4 || r.NextRetry != 14000 {
		t.Fatalf("restored schedule did not continue like a live one: %+v", r)
	}
}

// A plain result following a compacted state obeys the recovered schedule: an
// early due result is corrupt after a state exactly as after a result.
func TestRecoveryResultAfterStateObeysSchedule(t *testing.T) {
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindSubmit, Seq: 0, ID: "w", From: "a", To: "b", Nonce: 7, ProofAt: 100},
		{T: kindState, Now: 1000, ID: "w", Status: StatusWaiting,
			Reason:   "waiting for trusted header covering height 100 (current 0)",
			Attempts: 1, NextRetry: 2000},
		{T: kindAdvance, Now: 1000},
		&logEntry{T: kindResult, Now: 1999, ID: "w", Status: StatusWaiting,
			Reason:   "waiting for trusted header covering height 100 (current 0)",
			Attempts: 2, NextRetry: 3999},
	}
	assertRecoveryCorrupt(t, entries, "result time 1999 precedes scheduled retry 2000", `"w"`)
}
