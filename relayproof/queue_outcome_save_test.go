package relayproof

import (
	"errors"
	"strings"
	"testing"
)

// TestAdvanceMidSaveFailureKeepsCommittedResults pins the boundary around a
// result save failing partway through one Advance, going through the unified
// applyOutcome path:
//
//   - the failing result returns the wrapped storage error;
//   - the failed message keeps its previous status, reason, attempts,
//     processing time and retry schedule, and its nonce is not consumed;
//   - results already acknowledged earlier in the same advance stay in force;
//   - the queue instance keeps refusing further writes, while queries still
//     reflect everything that did take effect.
func TestAdvanceMidSaveFailureKeepsCommittedResults(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("m1", "a", "b", 1, 10, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("m2", "a", "b", 2, 10, 0)); err != nil {
		t.Fatal(err)
	}

	// Appends so far: source, header, submit m1, submit m2 (4). The advance
	// saves m1's success as call 5 (committed) and must fail on m2 at call 6.
	q.store.injectErr = errors.New("disk on fire")
	q.store.injectErrOnCall = 6

	_, err := q.Advance(1000)
	if !errors.Is(err, ErrStorage) {
		t.Fatalf("want ErrStorage from the failed save, got %v", err)
	}
	if !strings.Contains(err.Error(), "deliver") {
		t.Fatalf("error must keep the deliver op label, got %v", err)
	}

	// m1 was acknowledged before the failure and stays delivered, nonce
	// consumed.
	if r := statusOf(t, q, "m1"); r.Status != StatusSuccess || r.Attempts != 1 {
		t.Fatalf("committed m1 must survive the later failure: %+v", r)
	}
	if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m1" {
		t.Fatalf("m1 consumption lost: %q", winner)
	}

	// m2's save never acknowledged: it keeps its pre-advance pending state and
	// does not consume its nonce.
	if r := statusOf(t, q, "m2"); r.Status != StatusPending || r.Attempts != 0 || r.NextRetry != 0 {
		t.Fatalf("failed m2 must keep its prior state: %+v", r)
	}
	if _, taken := q.consumed[newConsumeToken("a", "b", 2)]; taken {
		t.Fatal("failed m2 must not consume its nonce")
	}
	if q.now != 0 {
		t.Fatalf("processing time must not advance past the failed save: %d", q.now)
	}

	// The instance keeps rejecting writes, and reopening later drops only the
	// unacknowledged torn tail while keeping m1.
	if err := q.RegisterSource("c"); !errors.Is(err, ErrStorage) {
		t.Fatalf("broken queue must refuse writes, got %v", err)
	}
	if r := statusOf(t, q, "m1"); r.Status != StatusSuccess {
		t.Fatalf("query must still reflect committed m1: %+v", r)
	}
	if r := statusOf(t, q, "m2"); r.Status != StatusPending {
		t.Fatalf("query must still show untouched m2: %+v", r)
	}
}

// A failed waiting save leaves the message on its previous backoff schedule
// and attempt count, while an earlier result in the same advance is kept.
func TestAdvanceWaitingSaveFailureKeepsPriorSchedule(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("m1", "a", "b", 1, 10, 0)); err != nil {
		t.Fatal(err)
	}
	// First advance: no header -> waiting, retry at 2000, one attempt.
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	if r := statusOf(t, q, "m1"); r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != 2000 {
		t.Fatalf("setup: want waiting retry=2000 attempts=1, got %+v", r)
	}

	// Appends so far: source(1), submit(2); within the first advance the
	// waiting result is appended at call 3 and the advance checkpoint at 4. On
	// the next advance the waiting re-save is call 5: make it fail.
	q.store.injectErr = errors.New("disk on fire")
	q.store.injectErrOnCall = 5
	_, err := q.Advance(2000)
	if !errors.Is(err, ErrStorage) {
		t.Fatalf("want ErrStorage, got %v", err)
	}
	if !strings.Contains(err.Error(), "schedule retry") {
		t.Fatalf("waiting failure must keep the schedule retry op label, got %v", err)
	}
	// Prior schedule and attempt count are intact; LastProcAt stays 1000.
	if r := statusOf(t, q, "m1"); r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != 2000 {
		t.Fatalf("failed waiting save must keep prior schedule: %+v", r)
	}
	if got, ok := q.Query("m1"); !ok || got.Status != StatusWaiting {
		t.Fatalf("query after failure must still show waiting: %+v ok=%v", got, ok)
	}
}
