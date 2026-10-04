package relayproof

import (
	"errors"
	"strings"
	"testing"
)

// Regression guard for "wait first, then judged replay" inside one advance:
// submitting first does not win the nonce. Two messages share
// (source, destination, nonce) but differ in proof height; only the one whose
// proof height is covered by the trusted header consumes the combination. The
// first-submitted message is processed first and goes waiting (proof height
// 101 > trusted 100), the second succeeds (proof height 100 <= trusted 100),
// and the phase-2 replay sweep then terminalizes the first message in the
// same advance — its freshly scheduled backoff must not shield it.
//
// The report therefore lists the first message twice (waiting, then replay);
// both entries are existing behavior and must be kept.
func TestWaitingThenReplaySameAdvance(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	// Same (from, to, nonce); different ids and proof heights. Neither
	// expires (ExpiresAt 0).
	if _, err := q.Submit(env("early", "a", "b", 7, 101, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("later", "a", "b", 7, 100, 0)); err != nil {
		t.Fatal(err)
	}

	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Now != 1000 {
		t.Fatalf("report time: want 1000, got %d", rep.Now)
	}
	want := []Result{
		{ID: "early", Status: StatusWaiting, Reason: "waiting for trusted header covering height 101 (current 100)"},
		{ID: "later", Status: StatusSuccess, Reason: "delivered; proof verified by trusted header at height 100"},
		{ID: "early", Status: StatusReplay, Reason: "nonce combination already consumed by message later"},
	}
	if len(rep.Results) != len(want) {
		t.Fatalf("want %d results (early appears twice: waiting then replay), got %+v", len(want), rep.Results)
	}
	for i, w := range want {
		if rep.Results[i] != w {
			t.Fatalf("result %d: want %+v, got %+v", i, w, rep.Results[i])
		}
	}

	// The waiting-then-replayed message: two attempts (the waiting processing
	// and the replay terminalization), retry schedule cleared, reason naming
	// the message that actually succeeded.
	if r := statusOf(t, q, "early"); r.Status != StatusReplay ||
		r.Attempts != 2 || r.NextRetry != 0 ||
		!strings.Contains(r.Reason, "later") {
		t.Fatalf("early must be replay with 2 attempts and no retry, got %+v", r)
	}
	// The covered message succeeded on its first attempt and owns the nonce.
	if r := statusOf(t, q, "later"); r.Status != StatusSuccess || r.Attempts != 1 || r.NextRetry != 0 {
		t.Fatalf("later must be success with 1 attempt, got %+v", r)
	}
	if winner := q.consumed[newConsumeToken("a", "b", 7)]; winner != "later" {
		t.Fatalf("nonce consumption must belong to later, got %q", winner)
	}
}

// Boundary of the same rule: when the trusted header covers neither proof
// height, both messages stay waiting with one attempt each — sharing a nonce
// alone never turns either into a replay.
func TestSharedNonceBothWaitingWhenHeaderInsufficient(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	// Trusted height 99 covers neither proof height 101 nor 100.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 99, Root: "0x99", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("early", "a", "b", 7, 101, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("later", "a", "b", 7, 100, 0)); err != nil {
		t.Fatal(err)
	}

	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("want exactly 2 waiting results, got %+v", rep.Results)
	}
	for _, res := range rep.Results {
		if res.Status != StatusWaiting {
			t.Fatalf("no message may be replayed for a shared nonce alone: %+v", rep.Results)
		}
	}
	for _, id := range []string{"early", "later"} {
		if r := statusOf(t, q, id); r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != 2000 {
			t.Fatalf("%s must stay waiting with 1 attempt and retry at 2000, got %+v", id, r)
		}
	}
	if _, taken := q.consumed[newConsumeToken("a", "b", 7)]; taken {
		t.Fatal("no delivery happened; the nonce must remain unconsumed")
	}
}

// Save failure inside the same operation: the first message's waiting result
// and the second message's success result are already saved when persisting
// the first message's replay result fails. The advance must surface the
// storage error; the unsaved replay must not leak into queries (the first
// message keeps its committed waiting state, reason, single attempt and the
// 2000ms retry instant), the committed success and its nonce consumption must
// not be rolled back, and the instance refuses further writes.
func TestWaitingThenReplaySaveFailureKeepsCommittedState(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("early", "a", "b", 7, 101, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("later", "a", "b", 7, 100, 0)); err != nil {
		t.Fatal(err)
	}

	// Appends so far: source(1), header(2), submit early(3), submit later(4).
	// Within the advance: early's waiting result is call 5 (committed),
	// later's success is call 6 (committed), early's replay is call 7: fail.
	q.store.injectErr = errors.New("disk on fire")
	q.store.injectErrOnCall = 7

	_, err := q.Advance(1000)
	if !errors.Is(err, ErrStorage) {
		t.Fatalf("want ErrStorage from the failed replay save, got %v", err)
	}
	if !strings.Contains(err.Error(), "terminalize") {
		t.Fatalf("error must keep the terminalize op label, got %v", err)
	}

	// The unsaved replay is not published: early keeps its previously
	// committed waiting result, waiting reason, one attempt and the retry
	// instant at 2000ms scheduled during that wait.
	if r := statusOf(t, q, "early"); r.Status != StatusWaiting ||
		r.Reason != "waiting for trusted header covering height 101 (current 100)" ||
		r.Attempts != 1 || r.NextRetry != 2000 {
		t.Fatalf("early must keep its committed waiting state, got %+v", r)
	}
	// The committed success is not revoked and still owns the nonce.
	if r := statusOf(t, q, "later"); r.Status != StatusSuccess || r.Attempts != 1 {
		t.Fatalf("committed later success must survive the later failure: %+v", r)
	}
	if winner := q.consumed[newConsumeToken("a", "b", 7)]; winner != "later" {
		t.Fatalf("consumption must still belong to later, got %q", winner)
	}
	if q.now != 0 {
		t.Fatalf("processing time must not advance past the failed save: %d", q.now)
	}

	// Queries remain usable on the broken instance, but every further write
	// is refused.
	if got, ok := q.Query("early"); !ok || got.Status != StatusWaiting {
		t.Fatalf("query after failure must still show committed waiting: %+v ok=%v", got, ok)
	}
	if err := q.RegisterSource("c"); !errors.Is(err, ErrStorage) {
		t.Fatalf("broken queue must refuse writes, got %v", err)
	}
	if _, err := q.Submit(env("m3", "a", "b", 8, 100, 0)); !errors.Is(err, ErrStorage) {
		t.Fatalf("broken queue must refuse submits, got %v", err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 200, Trusted: true}); !errors.Is(err, ErrStorage) {
		t.Fatalf("broken queue must refuse header writes, got %v", err)
	}
	if _, err := q.Advance(2000); !errors.Is(err, ErrStorage) {
		t.Fatalf("broken queue must refuse advances, got %v", err)
	}
}
