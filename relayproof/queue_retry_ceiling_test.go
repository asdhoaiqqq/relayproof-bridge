package relayproof

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// Regression tests for retry scheduling at the int64 ceiling. Processing
// times are caller-supplied non-negative Unix milliseconds up to
// math.MaxInt64; the retry instant (processing time + backoff) must saturate
// at that ceiling rather than wrap to a negative, zero or earlier instant.
// Every observation goes through the public Advance/Query surface.

const ceiling = int64(math.MaxInt64)

// waitingAtCeilingSetup registers a source with a trusted header just short
// of the proof height and submits one never-expiring message (proof height
// 100, current trusted height 99), so every processing ends up waiting.
func waitingAtCeilingSetup(t *testing.T, q *Queue, id string) {
	t.Helper()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 99, Root: "0x99", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env(id, "a", "b", 7, 100, 0)); err != nil {
		t.Fatal(err)
	}
}

// Unit checks for the saturating scheduler.
func TestNextRetryAtSaturates(t *testing.T) {
	cases := []struct {
		name    string
		now     int64
		attempt int
		want    int64
	}{
		{"normal first", 1000, 1, 2000},
		{"normal capped interval", 500_000, 7, 560_000},
		{"exactly representable at ceiling", ceiling - 60_000, 7, ceiling},
		{"one millisecond short stays exact", ceiling - 60_001, 7, ceiling - 1},
		{"first interval overflows", ceiling - 500, 1, ceiling},
		{"processing at the ceiling", ceiling, 1, ceiling},
		{"capped interval at ceiling", ceiling, 7, ceiling},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := nextRetryAt(c.now, c.attempt)
			if got != c.want {
				t.Fatalf("nextRetryAt(%d,%d) = %d, want %d", c.now, c.attempt, got, c.want)
			}
			if got < c.now {
				t.Fatalf("retry %d must never precede processing time %d", got, c.now)
			}
		})
	}
}

// Unit checks for the due predicate at the ceiling.
func TestRetryDueAtCeiling(t *testing.T) {
	normal := &Record{Status: StatusWaiting, Attempts: 1, LastProcAt: 1000, NextRetry: 2000}
	if retryDue(normal, 1999) {
		t.Fatal("1999 is before retry 2000: not due")
	}
	if !retryDue(normal, 2000) {
		t.Fatal("2000 reaches retry 2000: due")
	}
	if retryDue(normal, 1000) {
		t.Fatal("equal-time re-advance at the processing instant must not reprocess")
	}

	// Saturated schedule, processed before the ceiling: reaching the ceiling
	// is a distinct, later instant and the retry is due.
	stuck := &Record{Status: StatusWaiting, Attempts: 1, LastProcAt: ceiling - 500, NextRetry: ceiling}
	if !retryDue(stuck, ceiling) {
		t.Fatal("retry at the ceiling must be due when last processed earlier")
	}

	// Already processed at the ceiling: the only legal later instant does not
	// exist, so equal time is never due again.
	atCeiling := &Record{Status: StatusWaiting, Attempts: 1, LastProcAt: ceiling, NextRetry: ceiling}
	if retryDue(atCeiling, ceiling) {
		t.Fatal("message already processed at the ceiling must not be due at the same time")
	}
}

// A never-expiring message first processed 500ms before the ceiling cannot
// fit its 1s backoff: the retry saturates to the ceiling, never a negative
// number. Advancing at instants before the ceiling changes nothing.
func TestWaitingRetrySaturatesAtCeiling(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	waitingAtCeilingSetup(t, q, "m1")

	first := ceiling - 500
	rep, err := q.Advance(first)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := resultFor(rep, "m1")
	if !ok || res.Status != StatusWaiting {
		t.Fatalf("first advance: want one waiting result, got %+v", rep.Results)
	}
	r := statusOf(t, q, "m1")
	if r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != ceiling || r.Msg.ExpiresAt != 0 {
		t.Fatalf("want waiting attempts=1 retry=ceiling no-expiry, got %+v", r)
	}
	if r.NextRetry <= 0 || r.NextRetry < first {
		t.Fatalf("retry %d wrapped non-positive or before processing %d", r.NextRetry, first)
	}

	// Advancing at later instants still below the ceiling changes nothing and
	// reports no result.
	for _, now := range []int64{ceiling - 400, ceiling - 1} {
		rep, err := q.Advance(now)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := resultFor(rep, "m1"); ok {
			t.Fatalf("advance at %d before the ceiling must not reprocess m1: %+v", now, rep.Results)
		}
		r = statusOf(t, q, "m1")
		if r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != ceiling {
			t.Fatalf("advance at %d changed the waiting record: %+v", now, r)
		}
	}
}

// When the retry reaches the ceiling, a covering trusted header lets the
// message succeed by the normal rules, consuming the nonce on its second
// attempt.
func TestCeilingRetryWithCoveringHeaderSucceeds(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	waitingAtCeilingSetup(t, q, "m1")

	if _, err := q.Advance(ceiling - 500); err != nil {
		t.Fatal(err)
	}
	// The header covers the proof height before the retry, but does not
	// bypass it; only the advance to the ceiling delivers.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(ceiling - 1); err != nil {
		t.Fatal(err)
	}
	r0 := statusOf(t, q, "m1")
	if r0.Status != StatusWaiting || r0.Attempts != 1 || r0.NextRetry != ceiling {
		t.Fatalf("pre-ceiling advance must not deliver: %+v", r0)
	}

	rep, err := q.Advance(ceiling)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := resultFor(rep, "m1")
	if !ok || res.Status != StatusSuccess {
		t.Fatalf("ceiling retry with coverage: want success, got %+v", rep.Results)
	}
	r := statusOf(t, q, "m1")
	if r.Status != StatusSuccess || r.Attempts != 2 || r.NextRetry != 0 {
		t.Fatalf("want success attempts=2 no retry, got %+v", r)
	}
	if got := q.consumed[newConsumeToken("a", "b", 7)]; got != "m1" {
		t.Fatalf("nonce not consumed by m1: %q", got)
	}
	// A terminal record at the ceiling survives equal-time re-advances.
	rep, err = q.Advance(ceiling)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("terminal record reprocessed at the ceiling: %+v", rep.Results)
	}
}

// Reaching the ceiling without coverage evaluates the retry exactly once and
// keeps the message waiting with its saturated schedule; every further
// equal-time advance neither retries nor re-reports the waiting result.
func TestCeilingRetryWithoutCoverageWaitsOnce(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	waitingAtCeilingSetup(t, q, "m1")

	if _, err := q.Advance(ceiling - 500); err != nil {
		t.Fatal(err)
	}
	// The scheduled retry reaches the ceiling: the message is evaluated once
	// more and, still uncovered, keeps waiting with attempts=2.
	rep, err := q.Advance(ceiling)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := resultFor(rep, "m1")
	if !ok || res.Status != StatusWaiting {
		t.Fatalf("at ceiling without coverage: want one waiting result, got %+v", rep.Results)
	}
	before := statusOf(t, q, "m1")
	if before.Status != StatusWaiting || before.Attempts != 2 || before.NextRetry != ceiling {
		t.Fatalf("want waiting attempts=2 retry=ceiling, got %+v", before)
	}

	// Repeated equal-time advances must not attempt again and must not report
	// another waiting result.
	for i := 0; i < 3; i++ {
		rep, err := q.Advance(ceiling)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 0 {
			t.Fatalf("equal-time advance %d re-reported waiting: %+v", i+1, rep.Results)
		}
		after := statusOf(t, q, "m1")
		if after.Status != before.Status || after.Reason != before.Reason ||
			after.Attempts != before.Attempts || after.NextRetry != before.NextRetry {
			t.Fatalf("equal-time advance %d changed the record: %+v vs %+v", i+1, after, before)
		}
	}

	// A covering header arriving at the ceiling does not itself process the
	// message, and an equal-time advance still cannot deliver it: the message
	// was already processed at the ceiling and waiting rules are not bypassed.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	after := statusOf(t, q, "m1")
	if after.Status != StatusWaiting || after.Attempts != 2 || after.NextRetry != ceiling {
		t.Fatalf("header update at the ceiling processed the message: %+v", after)
	}
	rep, err = q.Advance(ceiling)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("header at the ceiling bypassed the waiting rules: %+v", rep.Results)
	}
	if r := statusOf(t, q, "m1"); r.Status != StatusWaiting {
		t.Fatalf("message must keep waiting at the ceiling after the header: %+v", r)
	}
}

// A message whose first processing happens exactly at the ceiling gets its
// one first judgment there; coverage means immediate success, no coverage
// means waiting with a saturated schedule.
func TestFirstProcessingAtCeiling(t *testing.T) {
	t.Run("covered succeeds", func(t *testing.T) {
		q, _ := openTempQueue(t)
		defer q.Close()
		if err := q.RegisterSource("a"); err != nil {
			t.Fatal(err)
		}
		if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := q.Submit(env("m", "a", "b", 1, 100, 0)); err != nil {
			t.Fatal(err)
		}
		rep, err := q.Advance(ceiling)
		if err != nil {
			t.Fatal(err)
		}
		res, ok := resultFor(rep, "m")
		if !ok || res.Status != StatusSuccess {
			t.Fatalf("first judgment at the ceiling: want success, got %+v", rep.Results)
		}
		if r := statusOf(t, q, "m"); r.Attempts != 1 || r.Status != StatusSuccess {
			t.Fatalf("want success on the first attempt, got %+v", r)
		}
	})

	t.Run("uncovered waits once", func(t *testing.T) {
		q, _ := openTempQueue(t)
		defer q.Close()
		waitingAtCeilingSetup(t, q, "m")
		rep, err := q.Advance(ceiling)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 1 || rep.Results[0].Status != StatusWaiting {
			t.Fatalf("first judgment at the ceiling: want one waiting result, got %+v", rep.Results)
		}
		r := statusOf(t, q, "m")
		if r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != ceiling {
			t.Fatalf("want waiting attempts=1 retry=ceiling, got %+v", r)
		}
		// Equal time must not attempt again.
		rep, err = q.Advance(ceiling)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 0 {
			t.Fatalf("equal-time re-advance retried at the ceiling: %+v", rep.Results)
		}
		if r := statusOf(t, q, "m"); r.Attempts != 1 {
			t.Fatalf("attempts inflated at the ceiling: %+v", r)
		}
	})
}

// A brand-new message submitted after the queue has already reached the
// ceiling still gets its first judgment on the next advance.
func TestNewMessageFirstJudgmentWhenQueueAlreadyAtCeiling(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	// Move processing straight to the ceiling with no messages.
	if _, err := q.Advance(ceiling); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("late", "a", "b", 3, 100, 0)); err != nil {
		t.Fatal(err)
	}
	rep, err := q.Advance(ceiling)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := resultFor(rep, "late")
	if !ok || res.Status != StatusSuccess {
		t.Fatalf("new message must get its first judgment at the ceiling, got %+v", rep.Results)
	}
	if r := statusOf(t, q, "late"); r.Attempts != 1 || r.Status != StatusSuccess {
		t.Fatalf("new message should succeed on attempt 1, got %+v", r)
	}
}

// Stopping repeated attempts at the ceiling must not skip the replay and
// expiry checks that apply to every non-terminal message regardless of its
// backoff.
func TestReplayAndExpiryStillApplyAtCeiling(t *testing.T) {
	t.Run("stuck waiting message becomes replay", func(t *testing.T) {
		q, _ := openTempQueue(t)
		defer q.Close()
		waitingAtCeilingSetup(t, q, "m1") // nonce 7, uncovered proof 100
		// m1 first-processes at the ceiling and gets stuck waiting there.
		if _, err := q.Advance(ceiling); err != nil {
			t.Fatal(err)
		}

		// A covering header and a second message on the same nonce triple.
		if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := q.Submit(env("m2", "a", "b", 7, 100, 0)); err != nil {
			t.Fatal(err)
		}
		rep, err := q.Advance(ceiling)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, r := range rep.Results {
			got[r.ID] = r.Status
		}
		if got["m2"] != StatusSuccess {
			t.Fatalf("m2 must succeed, got %+v", rep.Results)
		}
		// Phase-2 replay check terminalizes m1 even though its retry is never
		// due again at the ceiling.
		if got["m1"] != StatusReplay {
			t.Fatalf("stuck m1 must become replay when its nonce is consumed, got %+v", rep.Results)
		}
		if r := statusOf(t, q, "m1"); r.Status != StatusReplay ||
			!strings.Contains(r.Reason, "m2") || r.NextRetry != 0 {
			t.Fatalf("m1 replay state wrong: %+v", r)
		}
	})

	t.Run("first processing at the ceiling honors exact expiry", func(t *testing.T) {
		q, _ := openTempQueue(t)
		defer q.Close()
		if err := q.RegisterSource("a"); err != nil {
			t.Fatal(err)
		}
		if _, err := q.Submit(Envelope{
			Message:   Message{ID: "ex", From: "a", To: "b", Nonce: 1, ProofAt: 100},
			ExpiresAt: ceiling,
		}); err != nil {
			t.Fatal(err)
		}
		rep, err := q.Advance(ceiling)
		if err != nil {
			t.Fatal(err)
		}
		res, ok := resultFor(rep, "ex")
		if !ok || res.Status != StatusExpired {
			t.Fatalf("now == expiry at the ceiling must expire, got %+v", rep.Results)
		}
		if r := statusOf(t, q, "ex"); r.Status != StatusExpired || r.NextRetry != 0 {
			t.Fatalf("want expired without retry, got %+v", r)
		}
	})
}

// Close/reopen restores the saturated waiting record and schedule, and the
// legal write must not look like corruption on recovery.
func TestCeilingWaitingSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	waitingAtCeilingSetup(t, q, "m1")
	if _, err := q.Advance(ceiling - 500); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(ceiling); err != nil { // uncovered: attempts=2, retry=ceiling
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen must not report corruption: %v", err)
	}
	defer q2.Close()
	if q2.Now() != ceiling {
		t.Fatalf("processing time lost: want %d got %d", ceiling, q2.Now())
	}
	r := statusOf(t, q2, "m1")
	if r.Status != StatusWaiting || r.Attempts != 2 || r.NextRetry != ceiling {
		t.Fatalf("saturated waiting record not restored: %+v", r)
	}
	// Equal-time advance after recovery still must not reprocess.
	rep, err := q2.Advance(ceiling)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("restored message retried at the ceiling: %+v", rep.Results)
	}
	if r := statusOf(t, q2, "m1"); r.Attempts != 2 || r.NextRetry != ceiling {
		t.Fatalf("restored record changed on equal-time advance: %+v", r)
	}
}

// Compaction persists the saturated schedule and the compacted snapshot
// reopens without corruption.
func TestCeilingWaitingSurvivesCompaction(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	waitingAtCeilingSetup(t, q, "m1")
	if _, err := q.Advance(ceiling - 500); err != nil {
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
		t.Fatalf("reopen compacted log at the ceiling: %v", err)
	}
	defer q2.Close()
	r := statusOf(t, q2, "m1")
	if r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != ceiling {
		t.Fatalf("saturated schedule lost in compaction: %+v", r)
	}
}

// A log written by an older build that stored the raw overflowed (negative)
// retry near the ceiling opens directly: the wrapped value is recognized as
// the old scheduler's output, repaired to the saturated ceiling in memory,
// and the message keeps waiting without reprocessing at the same time.
func TestLegacyOverflowedRetryRepairedOnReopen(t *testing.T) {
	dir := t.TempDir()
	now := ceiling
	wrapped := now + 1000 // old code wrote now+delay even when it wrapped
	if wrapped >= 0 {
		t.Fatalf("test setup: expected a negative wrapped retry, got %d", wrapped)
	}
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindHeader, Chain: "a", Height: 99, Root: "0x99", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "w", From: "a", To: "b", Nonce: 7, ProofAt: 100},
		{T: kindResult, Now: now, ID: "w", Status: StatusWaiting,
			Reason:   "waiting for trusted header covering height 100 (current 99)",
			Attempts: 1, NextRetry: wrapped},
		{T: kindAdvance, Now: now},
	}
	writeLegacyLog(t, dir, entries...)

	q, err := Open(dir)
	if err != nil {
		t.Fatalf("legacy overflowed retry must open and be repaired: %v", err)
	}
	defer q.Close()
	r := statusOf(t, q, "w")
	if r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != ceiling {
		t.Fatalf("legacy negative retry not repaired to ceiling: %+v", r)
	}
	rep, err := q.Advance(ceiling)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("repaired message must not retry at the same time: %+v", rep.Results)
	}
	if r := statusOf(t, q, "w"); r.Attempts != 1 || r.NextRetry != ceiling {
		t.Fatalf("repaired record changed on equal-time advance: %+v", r)
	}
}

// Arbitrary malformed waiting schedules near the ceiling are still rejected
// as corrupt rather than silently accepted.
func TestMalformedCeilingScheduleRejected(t *testing.T) {
	cases := map[string]int64{
		"zero retry":     0,
		"earlier retry":  ceiling - 1,
		"unrelated time": 42,
		"positive slack": ceiling - 1000, // canonical is exactly the ceiling
	}
	for name, nextRetry := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			entries := []*logEntry{
				{T: kindSource, Chain: "a"},
				{T: kindSubmit, Seq: 0, ID: "w", From: "a", To: "b", Nonce: 7, ProofAt: 100},
				{T: kindResult, Now: ceiling, ID: "w", Status: StatusWaiting,
					Reason: "waiting", Attempts: 1, NextRetry: nextRetry},
			}
			writeLegacyLog(t, dir, entries...)
			q, err := Open(dir)
			if !errors.Is(err, ErrCorrupt) {
				if q != nil {
					q.Close()
				}
				t.Fatalf("want ErrCorrupt for nextRetry=%d, got %v", nextRetry, err)
			}
		})
	}
}

// Negative processing times and backwards moves stay rejected at the ceiling
// and change nothing.
func TestCeilingRejectsNegativeAndBackwardsTime(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if _, err := q.Advance(ceiling); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(-1); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("negative time at the ceiling: want ErrInvalidArg, got %v", err)
	}
	if _, err := q.Advance(ceiling - 1); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("backwards time at the ceiling: want ErrInvalidArg, got %v", err)
	}
	if q.Now() != ceiling {
		t.Fatalf("rejected advances changed processing time: %d", q.Now())
	}
}
