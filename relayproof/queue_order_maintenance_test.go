package relayproof

import (
	"fmt"
	"testing"
)

// TestAdvanceOrderMaintenanceLinearAndStable is the regression test for the
// order-maintenance refactor: one advance that terminalizes a large fraction
// of many live messages must (a) keep producing results in first-submission
// order, (b) preserve the relative order and retry schedules of the messages
// that stay live, (c) keep the two-results-per-message
// (waiting-then-replay) sequence with the replay attributed to the real
// winner, and (d) leave every terminal record visible in the full listing —
// which itself stays in first-submission order. None of the per-message
// bookkeeping after the first save may scale with the terminal history.
func TestAdvanceOrderMaintenanceLinearAndStable(t *testing.T) {
	q, dir := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	// Trusted height 100 covers the covered messages' proof heights (1) but
	// never the waiters' (999).
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}

	const n = 200 // w000..w199; even indices get a covered nonce twin later
	wid := func(i int) string { return fmt.Sprintf("w%03d", i) }
	cid := func(i int) string { return fmt.Sprintf("c%03d", i) }

	for i := 0; i < n; i++ {
		if _, err := q.Submit(env(wid(i), "a", "b", uint64(i), 999, 0)); err != nil {
			t.Fatal(err)
		}
	}
	// First advance: every waiter is due and goes waiting with its first
	// attempt; its backoff (retry at 2000) keeps it out of the next phase-1
	// pass at the same processing time.
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != n {
		t.Fatalf("want %d waiting results, got %d", n, len(rep.Results))
	}
	for i, res := range rep.Results {
		if res.ID != wid(i) || res.Status != StatusWaiting {
			t.Fatalf("first-advance result %d: want %s waiting, got %+v", i, wid(i), res)
		}
	}

	// Covered twins for even nonces (appended after every waiter), then three
	// standalone waiters with nonces no other message uses.
	for i := 0; i < n; i += 2 {
		if _, err := q.Submit(env(cid(i), "a", "b", uint64(i), 1, 0)); err != nil {
			t.Fatal(err)
		}
	}
	for k := 0; k < 3; k++ {
		if _, err := q.Submit(env(fmt.Sprintf("z%d", k), "a", "b", uint64(9000+k), 999, 0)); err != nil {
			t.Fatal(err)
		}
	}

	// Same processing time: old waiters are not due (backoff), so phase 1
	// delivers only the newly submitted covered twins and makes the z messages
	// wait; phase 2 then replays every even-nonce waiter in its own
	// first-submission position. The one unlink per terminal result must not
	// disturb either sweep.
	rep, err = q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	wantResults := n/2 + 3 + n/2 // covered successes, z waits, waiter replays
	if len(rep.Results) != wantResults {
		t.Fatalf("want %d results, got %d: %+v", wantResults, len(rep.Results), rep.Results)
	}
	pos := 0
	for i := 0; i < n; i += 2 {
		r := rep.Results[pos]
		if r.ID != cid(i) || r.Status != StatusSuccess {
			t.Fatalf("result %d: want %s success, got %+v", pos, cid(i), r)
		}
		pos++
	}
	for k := 0; k < 3; k++ {
		r := rep.Results[pos]
		if r.ID != fmt.Sprintf("z%d", k) || r.Status != StatusWaiting {
			t.Fatalf("result %d: want z%d waiting, got %+v", pos, k, r)
		}
		pos++
	}
	for i := 0; i < n; i += 2 {
		r := rep.Results[pos]
		wantReason := "nonce combination already consumed by message " + cid(i)
		if r.ID != wid(i) || r.Status != StatusReplay || r.Reason != wantReason {
			t.Fatalf("result %d: want %s replay (%q), got %+v", pos, wid(i), wantReason, r)
		}
		pos++
	}

	// Replayed waiters: two attempts (the first waiting result is not lost),
	// cancelled retry schedule, replay attributed to the message that actually
	// succeeded.
	for i := 0; i < n; i += 2 {
		r := statusOf(t, q, wid(i))
		if r.Status != StatusReplay || r.Attempts != 2 || r.NextRetry != 0 {
			t.Fatalf("%s must be replay with 2 attempts and no retry, got %+v", wid(i), r)
		}
		if winner := q.consumed[newConsumeToken("a", "b", uint64(i))]; winner != cid(i) {
			t.Fatalf("%s nonce must belong to %s, got %q", wid(i), cid(i), winner)
		}
	}
	// Surviving waiters keep their relative first-submission order — odd
	// waiters first, then the standalone z messages — and the backoff and
	// single attempt the failed sweep must never touch.
	var wantLive []string
	for i := 1; i < n; i += 2 {
		wantLive = append(wantLive, wid(i))
		if r := statusOf(t, q, wid(i)); r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != 2000 {
			t.Fatalf("%s must keep waiting/1 attempt/retry 2000, got %+v", wid(i), r)
		}
	}
	wantLive = append(wantLive, "z0", "z1", "z2")
	if got := q.order.ids(); len(got) != len(wantLive) {
		t.Fatalf("live order: want %d survivors, got %d (%v)", len(wantLive), len(got), got)
	} else {
		for i := range wantLive {
			if got[i] != wantLive[i] {
				t.Fatalf("live survivor position %d: want %s got %s (full %v)", i, wantLive[i], got[i], got)
			}
		}
	}

	// The full listing keeps first-submission order across both terminal and
	// live records: waiters, covered twins, standalone waiters — and the
	// terminal history is all still queryable with its terminal results.
	all := q.Queries()
	if len(all) != n+n/2+3 {
		t.Fatalf("full listing must keep terminal history: want %d rows, got %d", n+n/2+3, len(all))
	}
	for i := 0; i < n; i++ {
		if all[i].ID != wid(i) {
			t.Fatalf("listing position %d: want %s got %s", i, wid(i), all[i].ID)
		}
	}
	for k := 0; k < n/2; k++ {
		i := 2 * k
		if all[n+k].ID != cid(i) {
			t.Fatalf("listing position %d: want %s got %s", n+k, cid(i), all[n+k].ID)
		}
	}
	for k := 0; k < 3; k++ {
		if all[n+n/2+k].ID != fmt.Sprintf("z%d", k) {
			t.Fatalf("listing tail %d: want z%d got %s", k, k, all[n+n/2+k].ID)
		}
	}

	// The survivor order and every terminal result survive a reopen exactly.
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	if got := q2.order.ids(); len(got) != len(wantLive) {
		t.Fatalf("after reopen: want %d survivors, got %d (%v)", len(wantLive), len(got), got)
	} else {
		for i := range wantLive {
			if got[i] != wantLive[i] {
				t.Fatalf("after reopen position %d: want %s got %s", i, wantLive[i], got[i])
			}
		}
	}
	for i := 0; i < n; i += 2 {
		if r := statusOf(t, q2, wid(i)); r.Status != StatusReplay || r.Attempts != 2 || r.NextRetry != 0 {
			t.Fatalf("after reopen %s lost replay state: %+v", wid(i), r)
		}
	}

	// Terminalize the survivors once a covering header exists; afterwards the
	// live order is empty even though the terminal history is large, and an
	// advance over zero live messages still confirms the given time and emits
	// no results.
	if err := q2.UpsertHeader(Header{Chain: "a", Height: 999, Root: "r2", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	rep, err = q2.Advance(3000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != len(wantLive) {
		t.Fatalf("want %d final deliveries, got %+v", len(wantLive), rep.Results)
	}
	for i, r := range rep.Results {
		if r.ID != wantLive[i] || r.Status != StatusSuccess {
			t.Fatalf("final delivery %d: want %s success, got %+v", i, wantLive[i], r)
		}
	}
	if q2.order.len() != 0 {
		t.Fatalf("live order must be empty: %v", q2.order.ids())
	}
	rep, err = q2.Advance(4000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 || rep.Now != 4000 || q2.Now() != 4000 {
		t.Fatalf("advance with no live messages must confirm the time and emit nothing: %+v now=%d",
			rep.Results, q2.Now())
	}

	// With hundreds of terminal records behind it, a new pair of live messages
	// is processed on its own, in first-submission order.
	if _, err := q2.Submit(env("fresh1", "a", "b", 50001, 1, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q2.Submit(env("fresh2", "a", "b", 50002, 1, 0)); err != nil {
		t.Fatal(err)
	}
	rep, err = q2.Advance(5000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 2 ||
		rep.Results[0].ID != "fresh1" || rep.Results[0].Status != StatusSuccess ||
		rep.Results[1].ID != "fresh2" || rep.Results[1].Status != StatusSuccess {
		t.Fatalf("new live messages must process in order regardless of terminal history: %+v", rep.Results)
	}
}

// BenchmarkAdvanceRemovalIndependentOfHistory keeps a fixed number of live
// messages per advance (all delivered, i.e. the maximum number of unlinks)
// while the terminal history grows iteration after iteration. With linear
// slices the per-unlink scan and shift grew with the live slice length and
// every advance also rebuilt a snapshot of the whole listing; here the order
// work per advance must stay bounded by the live set, so the per-iteration
// time must not grow with the hundreds of thousands of terminal records
// accumulating behind it.
func BenchmarkAdvanceRemovalIndependentOfHistory(b *testing.B) {
	q, err := Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		b.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 1, Root: "r", Trusted: true}); err != nil {
		b.Fatal(err)
	}
	const live = 200
	for iter := 0; iter < b.N; iter++ {
		b.StopTimer()
		for j := 0; j < live; j++ {
			id := fmt.Sprintf("m-%d-%d", iter, j)
			if _, err := q.Submit(env(id, "a", "b", uint64(iter*live+j), 1, 0)); err != nil {
				b.Fatal(err)
			}
		}
		b.StartTimer()
		rep, err := q.Advance(int64(iter) + 1)
		if err != nil {
			b.Fatal(err)
		}
		if len(rep.Results) != live || q.order.len() != 0 {
			b.Fatalf("want %d deliveries and an empty live order, got %d results and %d live",
				live, len(rep.Results), q.order.len())
		}
	}
}
