package relayproof

import (
	"errors"
	"strings"
	"testing"
)

// TestAdvanceFirstWaitsThenReplayWithinOneAdvance is the automated regression
// guard for the "waits first, judged replay later" rule inside a single
// advance:
//
// Two messages share (source, destination, nonce) but have different ids and
// different proof heights. Submitting first does NOT reserve the nonce — only
// a message that actually succeeds consumes the triple. With the highest
// trusted header at height 100, the first-submitted message (proof 101) waits,
// the later one (proof 100) succeeds, and the phase-2 replay/expiry sweep then
// terminalizes the waiting message as a replay despite its just-scheduled
// backoff. The report of one advance therefore carries, in order:
//
//	first  -> waiting   (entering the wait)
//	second -> success   (the real consumer)
//	first  -> replay    (settlement; the same id legitimately appears twice)
//
// The backoff arranged by the waiting result must not shield the message from
// the replay decision in the same advance.
func TestAdvanceFirstWaitsThenReplayWithinOneAdvance(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	// First-submitted: proof height 101 is beyond the trusted header at 100.
	if _, err := q.Submit(env("first", "a", "b", 7, 101, 0)); err != nil {
		t.Fatal(err)
	}
	// Later-submitted: proof height 100 is covered; same nonce triple.
	if _, err := q.Submit(env("second", "a", "b", 7, 100, 0)); err != nil {
		t.Fatal(err)
	}

	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}

	want := []Result{
		{ID: "first", Status: StatusWaiting,
			Reason: "waiting for trusted header covering height 101 (current 100)"},
		{ID: "second", Status: StatusSuccess,
			Reason: "delivered; proof verified by trusted header at height 100"},
		{ID: "first", Status: StatusReplay,
			Reason: "nonce combination already consumed by message second"},
	}
	if len(rep.Results) != len(want) {
		t.Fatalf("want %d report entries (first appears twice), got %d: %+v",
			len(want), len(rep.Results), rep.Results)
	}
	for i, w := range want {
		if rep.Results[i] != w {
			t.Fatalf("report entry %d: want %+v, got %+v (full report: %+v)",
				i, w, rep.Results[i], rep.Results)
		}
	}

	// first is terminal replay: reason names the message that actually
	// succeeded, two attempts (the wait, then the replay), retry time cleared.
	r := statusOf(t, q, "first")
	if r.Status != StatusReplay {
		t.Fatalf("first must end as replay, got %+v", r)
	}
	if !strings.Contains(r.Reason, "message second") {
		t.Fatalf("replay reason must name the actual winner second: %q", r.Reason)
	}
	if r.Attempts != 2 {
		t.Fatalf("first must have 2 attempts (wait + replay), got %d", r.Attempts)
	}
	if r.NextRetry != 0 {
		t.Fatalf("terminal replay must clear the retry time, got %d", r.NextRetry)
	}

	// second owns the success and the consumption.
	s := statusOf(t, q, "second")
	if s.Status != StatusSuccess || s.Attempts != 1 || s.NextRetry != 0 {
		t.Fatalf("second must be the single success with 1 attempt, got %+v", s)
	}
	if winner := q.consumed[newConsumeToken("a", "b", 7)]; winner != "second" {
		t.Fatalf("nonce consumption must belong to the successful second, got %q", winner)
	}
}

// TestAdvanceSharedNonceBeyondCoverageBothWait is the boundary of the rule
// above: when the trusted header covers NEITHER message, a shared nonce must
// not turn either of them into a replay. Both wait, each exactly once, and the
// advance report contains the two waiting results without a later replay
// entry — replay exists only once some message actually succeeds.
func TestAdvanceSharedNonceBeyondCoverageBothWait(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 99, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("first", "a", "b", 7, 100, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("second", "a", "b", 7, 101, 0)); err != nil {
		t.Fatal(err)
	}

	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 2 ||
		rep.Results[0] != (Result{ID: "first", Status: StatusWaiting,
			Reason: "waiting for trusted header covering height 100 (current 99)"}) ||
		rep.Results[1] != (Result{ID: "second", Status: StatusWaiting,
			Reason: "waiting for trusted header covering height 101 (current 99)"}) {
		t.Fatalf("want two waiting results and no replay, got %+v", rep.Results)
	}
	for _, id := range []string{"first", "second"} {
		if r := statusOf(t, q, id); r.Status != StatusWaiting || r.Attempts != 1 {
			t.Fatalf("%s must stay waiting with exactly one attempt, got %+v", id, r)
		}
	}
	if _, taken := q.consumed[newConsumeToken("a", "b", 7)]; taken {
		t.Fatal("nothing succeeded, so the nonce triple must remain unconsumed")
	}
}

// TestAdvanceReplaySaveFailureKeepsWaitAndSuccess pins persistence semantics
// for the wait-then-replay sequence when the FINAL save fails:
//
// In one advance, first's waiting result and second's success result are both
// durably saved; saving first's replay result then hits a write failure. The
// advance must return the recognizable storage error, queries stay available,
// first keeps its previously acknowledged waiting status/reason/one attempt
// and the retry time 2000, second keeps its success and still owns the
// consumption — the unsaved replay is never published and the saved success is
// never rolled back. The instance then refuses further writes.
func TestAdvanceReplaySaveFailureKeepsWaitAndSuccess(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("first", "a", "b", 7, 101, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("second", "a", "b", 7, 100, 0)); err != nil {
		t.Fatal(err)
	}

	// Append sequence within the single advance:
	//   call 5: first's waiting result  (committed)
	//   call 6: second's success result (committed, consumes the triple)
	//   call 7: first's replay result   (fails — no advance checkpoint follows)
	q.store.injectErr = errors.New("disk on fire")
	q.store.injectErrOnCall = 7

	_, err := q.Advance(1000)
	if !errors.Is(err, ErrStorage) {
		t.Fatalf("want the wrapped storage error from the failed replay save, got %v", err)
	}
	if !strings.Contains(err.Error(), "terminalize") {
		t.Fatalf("the replay save must keep the terminalize op label, got %v", err)
	}

	// first keeps exactly the state the acknowledged waiting save established.
	r := statusOf(t, q, "first")
	if r.Status != StatusWaiting {
		t.Fatalf("unsaved replay must not be published: first stays waiting, got %+v", r)
	}
	if r.Reason != "waiting for trusted header covering height 101 (current 100)" {
		t.Fatalf("first must keep the waiting reason, got %q", r.Reason)
	}
	if r.Attempts != 1 {
		t.Fatalf("first must keep one acknowledged attempt, got %d", r.Attempts)
	}
	if r.NextRetry != 2000 {
		t.Fatalf("first must keep the retry time 2000 arranged while waiting, got %d", r.NextRetry)
	}

	// second's acknowledged success stands and still owns the consumption.
	s := statusOf(t, q, "second")
	if s.Status != StatusSuccess || s.Attempts != 1 {
		t.Fatalf("saved success must not be rolled back: %+v", s)
	}
	if winner := q.consumed[newConsumeToken("a", "b", 7)]; winner != "second" {
		t.Fatalf("consumption must stay attributed to second, got %q", winner)
	}

	// The failed advance checkpoint means processing time did not move.
	if q.now != 0 {
		t.Fatalf("processing time must not advance past the failed save, got %d", q.now)
	}

	// Queries still work; the instance now refuses every further write.
	if err := q.RegisterSource("c"); !errors.Is(err, ErrStorage) {
		t.Fatalf("queue must reject writes after the storage failure, got %v", err)
	}
	if _, err := q.Submit(env("third", "a", "b", 8, 100, 0)); !errors.Is(err, ErrStorage) {
		t.Fatalf("submit must also be refused on the broken instance, got %v", err)
	}
	if got, ok := q.Query("first"); !ok || got.Status != StatusWaiting {
		t.Fatalf("query must remain available and show waiting first: %+v ok=%v", got, ok)
	}
}
