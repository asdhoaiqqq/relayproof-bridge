package relayproof

import (
	"strings"
	"testing"
)

// Regression coverage for the expiry boundary during a header-induced wait.
//
// The original message is always the same id ("m") with the same content and a
// fixed, non-zero absolute expiry. A source chain is registered up front, but
// the trusted header is still short of the proof height on the first advance,
// so the message enters "waiting" with an explicit retry schedule. A later
// header update supplies coverage without bypassing that schedule. The two
// terminal scenarios below differ by exactly one millisecond in where the
// scheduled retry lands relative to the absolute expiry, and a follow-up
// message on the same (source, destination, nonce) triple shows whether the
// original terminal outcome actually consumed the nonce.

const (
	boundaryChainA = "chain-a"
	boundaryChainB = "chain-b"
	boundaryNonce  = uint64(42)
	boundaryProof  = int64(100)
)

// submitBoundaryOriginal submits the fixed original message used by every
// boundary scenario: the same id, content and absolute expiry throughout.
func submitBoundaryOriginal(t *testing.T, q *Queue, expiresAt int64) Envelope {
	t.Helper()
	e := env("m", boundaryChainA, boundaryChainB, boundaryNonce, boundaryProof, expiresAt)
	if _, err := q.Submit(e); err != nil {
		t.Fatalf("submit original: %v", err)
	}
	return e
}

// resultFor extracts the advance result for one message id.
func resultFor(t *testing.T, rep *AdvanceReport, id string) Result {
	t.Helper()
	for _, r := range rep.Results {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("advance report has no result for %s: %+v", id, rep.Results)
	return Result{}
}

// driveBoundaryWait runs the shared waiting phase: the first advance leaves
// the message waiting for a covering trusted header (one attempt, retry one
// second later); a covering trusted header then arrives, but advancing before
// the scheduled retry changes nothing and the header update by itself delivers
// nothing. This separates "the trusted header is sufficient" from "the retry
// time has not arrived", so any later success genuinely happens on a retry
// after waiting rather than on the header update. Returns the scheduled retry
// instant of the waiting message.
func driveBoundaryWait(t *testing.T, q *Queue) int64 {
	t.Helper()

	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatalf("first advance: %v", err)
	}
	r := resultFor(t, rep, "m")
	if r.Status != StatusWaiting {
		t.Fatalf("first advance: want waiting, got %s (%s)", r.Status, r.Reason)
	}
	q1 := statusOf(t, q, "m")
	if q1.Status != StatusWaiting || q1.Attempts != 1 || q1.NextRetry != 2000 {
		t.Fatalf("after first advance: want waiting attempts=1 retry=2000, got %+v", q1)
	}

	// The covering trusted header arrives while the retry is still pending.
	if err := q.UpsertHeader(Header{Chain: boundaryChainA, Height: boundaryProof, Root: "0x100", Trusted: true}); err != nil {
		t.Fatalf("upsert covering header: %v", err)
	}
	// Advancing before the scheduled retry must not reprocess the message:
	// status, attempt count and next-retry instant all stay unchanged.
	rep, err = q.Advance(1500)
	if err != nil {
		t.Fatalf("pre-retry advance: %v", err)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("header coverage before retry time must not deliver or reprocess: %+v", rep.Results)
	}
	q2 := statusOf(t, q, "m")
	if q2.Status != StatusWaiting || q2.Attempts != 1 || q2.NextRetry != 2000 {
		t.Fatalf("header sufficient but retry not due: want unchanged waiting attempts=1 retry=2000, got %+v", q2)
	}
	return q2.NextRetry
}

// TestBoundaryRetryOneMsBeforeExpirySucceeds: the scheduled retry is one
// millisecond earlier than the absolute expiry. The message, already waiting
// for a now-covered trusted header, succeeds on that retry with exactly two
// attempts; the reason cites the trusted height actually used. No further
// retry is scheduled, and the advance result matches the subsequent query.
func TestBoundaryRetryOneMsBeforeExpirySucceeds(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource(boundaryChainA); err != nil {
		t.Fatal(err)
	}
	e := submitBoundaryOriginal(t, q, 2001)
	nextRetry := driveBoundaryWait(t, q)

	rep, err := q.Advance(nextRetry) // 2000, one millisecond before expiry 2001
	if err != nil {
		t.Fatalf("retry advance: %v", err)
	}
	res := resultFor(t, rep, "m")
	if res.Status != StatusSuccess {
		t.Fatalf("retry one ms before expiry must succeed, got %s (%s)", res.Status, res.Reason)
	}
	if !strings.Contains(res.Reason, "height 100") {
		t.Fatalf("success reason must cite the trusted height actually used (100), got %q", res.Reason)
	}

	got := statusOf(t, q, "m")
	if got.Status != StatusSuccess {
		t.Fatalf("query: want success, got %s", got.Status)
	}
	if got.Attempts != 2 {
		t.Fatalf("success happens on the retry after waiting: want 2 attempts, got %d", got.Attempts)
	}
	if got.NextRetry != 0 {
		t.Fatalf("terminal success must schedule no further retry, got %d", got.NextRetry)
	}
	if got.Reason != res.Reason {
		t.Fatalf("query reason %q must match advance result reason %q", got.Reason, res.Reason)
	}
	if got.Msg.ExpiresAt != e.ExpiresAt {
		t.Fatalf("absolute expiry must stay fixed throughout: want %d got %d", e.ExpiresAt, got.Msg.ExpiresAt)
	}
	if winner := q.consumed[newConsumeToken(boundaryChainA, boundaryChainB, boundaryNonce)]; winner != "m" {
		t.Fatalf("nonce triple must be consumed by the successful original, got %q", winner)
	}

	// A later advance past the expiry must not revisit a terminal record.
	rep, err = q.Advance(5000)
	if err != nil {
		t.Fatalf("post-terminal advance: %v", err)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("terminal message must not be processed again: %+v", rep.Results)
	}
}

// TestBoundaryRetryExactlyAtExpiryExpires: the scheduled retry coincides
// exactly with the absolute expiry. Even though a trusted header covering the
// proof height is already accepted, the message expires (now == ExpiresAt
// counts as expired); the reason states its absolute expiry instant. No retry
// is scheduled and the nonce triple is left unconsumed.
func TestBoundaryRetryExactlyAtExpiryExpires(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource(boundaryChainA); err != nil {
		t.Fatal(err)
	}
	e := submitBoundaryOriginal(t, q, 2000)
	nextRetry := driveBoundaryWait(t, q)
	if nextRetry != e.ExpiresAt {
		t.Fatalf("test setup: scheduled retry %d must equal expiry %d", nextRetry, e.ExpiresAt)
	}

	rep, err := q.Advance(nextRetry) // retry instant == absolute expiry
	if err != nil {
		t.Fatalf("retry/expiry advance: %v", err)
	}
	res := resultFor(t, rep, "m")
	if res.Status != StatusExpired {
		t.Fatalf("retry exactly at expiry must expire even with a covering trusted header, got %s (%s)", res.Status, res.Reason)
	}
	if !strings.Contains(res.Reason, "2000") {
		t.Fatalf("expired reason must state the absolute expiry instant 2000, got %q", res.Reason)
	}

	got := statusOf(t, q, "m")
	if got.Status != StatusExpired {
		t.Fatalf("query: want expired, got %s", got.Status)
	}
	if got.NextRetry != 0 {
		t.Fatalf("terminal expiry must schedule no further retry, got %d", got.NextRetry)
	}
	if got.Reason != res.Reason {
		t.Fatalf("query reason %q must match advance result reason %q", got.Reason, res.Reason)
	}
	if got.Msg.ExpiresAt != e.ExpiresAt {
		t.Fatalf("absolute expiry must stay fixed throughout: want %d got %d", e.ExpiresAt, got.Msg.ExpiresAt)
	}
	if len(q.consumed) != 0 {
		t.Fatalf("an expired message must not consume its nonce triple: %v", q.consumed)
	}
}

// TestBoundaryNonceDispositionAfterTerminal observes, through a fresh message
// on the same (source, destination, nonce) triple, whether the original
// message consumed that triple.
//
//   - after a retry-success, a new id on the same triple is a replay whose
//     reason points at the genuinely successful original "m";
//   - after an expiry, the triple is still free: a new id carrying a still
//     valid absolute expiry succeeds when advanced, with trusted coverage
//     already sufficient for its proof height.
//
// Both follow-ups use a registered source and a trusted header covering their
// proof height, so the observed difference reflects only whether "m" consumed
// the nonce.
func TestBoundaryNonceDispositionAfterTerminal(t *testing.T) {
	t.Run("success consumes nonce, new id is replay", func(t *testing.T) {
		q, _ := openTempQueue(t)
		defer q.Close()
		q.RegisterSource(boundaryChainA)
		submitBoundaryOriginal(t, q, 2001)
		nextRetry := driveBoundaryWait(t, q)
		rep, err := q.Advance(nextRetry)
		if err != nil {
			t.Fatal(err)
		}
		if r := resultFor(t, rep, "m"); r.Status != StatusSuccess {
			t.Fatalf("original must succeed at retry, got %s (%s)", r.Status, r.Reason)
		}

		// A new id reusing the exact triple is judged a replay attributed to the
		// message that actually succeeded.
		if _, err := q.Submit(env("m2", boundaryChainA, boundaryChainB, boundaryNonce, boundaryProof, 0)); err != nil {
			t.Fatalf("submit replay contender: %v", err)
		}
		rep, err = q.Advance(nextRetry + 1000)
		if err != nil {
			t.Fatal(err)
		}
		res := resultFor(t, rep, "m2")
		if res.Status != StatusReplay {
			t.Fatalf("new id on a consumed triple must be replay, got %s (%s)", res.Status, res.Reason)
		}
		if !strings.Contains(res.Reason, "m") {
			t.Fatalf("replay reason must name the real winner m, got %q", res.Reason)
		}
		got := statusOf(t, q, "m2")
		if got.Status != StatusReplay || got.Reason != res.Reason {
			t.Fatalf("query must agree with advance result: %+v vs %+v", got, res)
		}
		if winner := q.consumed[newConsumeToken(boundaryChainA, boundaryChainB, boundaryNonce)]; winner != "m" {
			t.Fatalf("consumption must stay attributed to the original winner, got %q", winner)
		}
	})

	t.Run("expiry does not consume nonce, new id succeeds", func(t *testing.T) {
		q, _ := openTempQueue(t)
		defer q.Close()
		q.RegisterSource(boundaryChainA)
		submitBoundaryOriginal(t, q, 2000)
		nextRetry := driveBoundaryWait(t, q)
		rep, err := q.Advance(nextRetry)
		if err != nil {
			t.Fatal(err)
		}
		if r := resultFor(t, rep, "m"); r.Status != StatusExpired {
			t.Fatalf("original must expire at the retry/expiry instant, got %s (%s)", r.Status, r.Reason)
		}

		// The trusted header already covers the proof height; the fresh message
		// carries an expiry still in the future, so on its first processing it
		// must succeed rather than be mistaken for a replay.
		freshExpiry := nextRetry + 10_000
		if _, err := q.Submit(env("m2", boundaryChainA, boundaryChainB, boundaryNonce, boundaryProof, freshExpiry)); err != nil {
			t.Fatalf("submit fresh contender: %v", err)
		}
		rep, err = q.Advance(nextRetry + 1000)
		if err != nil {
			t.Fatal(err)
		}
		res := resultFor(t, rep, "m2")
		if res.Status != StatusSuccess {
			t.Fatalf("unconsumed triple must let the fresh message succeed, got %s (%s)", res.Status, res.Reason)
		}
		if !strings.Contains(res.Reason, "height 100") {
			t.Fatalf("success reason must cite the trusted height actually used (100), got %q", res.Reason)
		}
		got := statusOf(t, q, "m2")
		if got.Status != StatusSuccess || got.Attempts != 1 || got.Reason != res.Reason {
			t.Fatalf("query must agree with advance result: %+v vs %+v", got, res)
		}
		// The original stays expired; only m2 now owns the triple.
		if old := statusOf(t, q, "m"); old.Status != StatusExpired {
			t.Fatalf("original record must remain expired, got %s", old.Status)
		}
		if winner := q.consumed[newConsumeToken(boundaryChainA, boundaryChainB, boundaryNonce)]; winner != "m2" {
			t.Fatalf("fresh success must now consume the triple, got %q", winner)
		}
	})
}
