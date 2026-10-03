package relayproof

import (
	"strings"
	"testing"
)

// Regression tests for the retry/expiry boundary of the durable queue: a
// message that first waits for trusted-header coverage and is later resolved
// by a retry whose scheduled instant sits within one millisecond of its
// absolute expiry. All observations go through the public surface — Advance
// reports and Query — with caller-supplied Unix-millisecond times.
//
// Both scenarios share the same original message: id m1, chain a -> b,
// nonce 7, proof height 100, absolute expiry 5000. What differs is the first
// advance time, which places the scheduled retry one millisecond before the
// expiry (success) or exactly on it (expired).
const (
	boundaryID      = "m1"
	boundaryFrom    = "a"
	boundaryTo      = "b"
	boundaryNonce   = 7
	boundaryProofAt = 100
	boundaryExpiry  = 5000
)

// resultFor finds the outcome one Advance reported for a message id.
func resultFor(rep *AdvanceReport, id string) (Result, bool) {
	for _, r := range rep.Results {
		if r.ID == id {
			return r, true
		}
	}
	return Result{}, false
}

// setupBoundaryWaiting registers the source with a trusted header just short
// of the proof height, submits the boundary message and runs the first
// advance. The message must come out waiting with exactly one attempt and its
// next retry scheduled one second later (the first backoff interval).
func setupBoundaryWaiting(t *testing.T, q *Queue, firstAdvance int64) {
	t.Helper()
	if err := q.RegisterSource(boundaryFrom); err != nil {
		t.Fatal(err)
	}
	// Trusted but insufficient: the source is known, coverage is not there yet.
	if err := q.UpsertHeader(Header{Chain: boundaryFrom, Height: boundaryProofAt - 1, Root: "0x99", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env(boundaryID, boundaryFrom, boundaryTo, boundaryNonce, boundaryProofAt, boundaryExpiry)); err != nil {
		t.Fatal(err)
	}

	rep, err := q.Advance(firstAdvance)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := resultFor(rep, boundaryID)
	if !ok || res.Status != StatusWaiting {
		t.Fatalf("first advance: want one waiting result for %s, got %+v", boundaryID, rep.Results)
	}
	r := statusOf(t, q, boundaryID)
	wantRetry := firstAdvance + 1000
	if r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != wantRetry {
		t.Fatalf("first advance: want waiting attempts=1 retry=%d, got %+v", wantRetry, r)
	}
	if r.Msg.ExpiresAt != boundaryExpiry {
		t.Fatalf("expiry must stay %d, got %d", boundaryExpiry, r.Msg.ExpiresAt)
	}
	if !strings.Contains(r.Reason, "100") {
		t.Fatalf("waiting reason should name the uncovered proof height, got %q", r.Reason)
	}
}

// coverProofHeightStillWaiting installs a trusted header covering the proof
// height and proves that neither the header update itself nor an advance
// before the scheduled retry delivers the message: the two conditions
// "header sufficient" and "retry due" are independent, and only the retry
// decides when the sufficient header takes effect.
func coverProofHeightStillWaiting(t *testing.T, q *Queue, retryAt int64) {
	t.Helper()
	if err := q.UpsertHeader(Header{Chain: boundaryFrom, Height: boundaryProofAt, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	// The header update alone must not deliver, reschedule or add an attempt.
	r := statusOf(t, q, boundaryID)
	if r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != retryAt {
		t.Fatalf("header update must not process the message, got %+v", r)
	}

	// Advancing before the retry instant: header already sufficient, but the
	// message is not due, so nothing may happen to it.
	rep, err := q.Advance(retryAt - 1)
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := resultFor(rep, boundaryID); ok {
		t.Fatalf("advance before retry must not touch the message, got %+v", res)
	}
	r = statusOf(t, q, boundaryID)
	if r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != retryAt {
		t.Fatalf("pre-retry advance changed the waiting message: %+v", r)
	}
}

// assertTerminalUnchanged verifies the terminal state survives a later
// advance untouched: no further results, no rescheduled retry.
func assertTerminalUnchanged(t *testing.T, q *Queue, id, status string, at int64) {
	t.Helper()
	rep, err := q.Advance(at)
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := resultFor(rep, id); ok {
		t.Fatalf("terminal message produced a new result: %+v", res)
	}
	r := statusOf(t, q, id)
	if r.Status != status || r.NextRetry != 0 {
		t.Fatalf("terminal state changed: %+v", r)
	}
}

// The scheduled retry falls one millisecond before the absolute expiry: the
// retry wins, the message is delivered on its second attempt, and the nonce
// combination is consumed — a later message reusing it is replay.
func TestRetryOneMillisecondBeforeExpirySucceeds(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()

	// First advance at 3999: retry scheduled at 4999 = expiry 5000 - 1ms.
	setupBoundaryWaiting(t, q, 3999)
	coverProofHeightStillWaiting(t, q, 4999)

	// The retry instant itself: header sufficient, not yet expired -> success.
	rep, err := q.Advance(4999)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := resultFor(rep, boundaryID)
	if !ok || res.Status != StatusSuccess {
		t.Fatalf("retry before expiry: want success, got %+v", rep.Results)
	}
	r := statusOf(t, q, boundaryID)
	if r.Status != StatusSuccess || r.Attempts != 2 || r.NextRetry != 0 {
		t.Fatalf("want success attempts=2 no retry, got %+v", r)
	}
	if r.Reason != res.Reason {
		t.Fatalf("advance reason %q and query reason %q disagree", res.Reason, r.Reason)
	}
	if !strings.Contains(r.Reason, "height 100") {
		t.Fatalf("success reason must cite the trusted height actually used, got %q", r.Reason)
	}
	assertTerminalUnchanged(t, q, boundaryID, StatusSuccess, 6000)

	// The nonce combination was consumed by m1: a new id on the same path is
	// replay and must name the message that actually succeeded. Its own source
	// is registered and the trusted header covers its proof height, so only
	// the consumed nonce can stop it.
	if _, err := q.Submit(env("m2", boundaryFrom, boundaryTo, boundaryNonce, boundaryProofAt, 0)); err != nil {
		t.Fatal(err)
	}
	rep, err = q.Advance(7000)
	if err != nil {
		t.Fatal(err)
	}
	res, ok = resultFor(rep, "m2")
	if !ok || res.Status != StatusReplay {
		t.Fatalf("same-combination message must be replay, got %+v", rep.Results)
	}
	r = statusOf(t, q, "m2")
	if r.Status != StatusReplay || r.Reason != res.Reason ||
		!strings.Contains(r.Reason, boundaryID) {
		t.Fatalf("replay must name the consuming message %s, got %+v", boundaryID, r)
	}
}

// The scheduled retry falls exactly on the absolute expiry instant: reaching
// the expiry counts as expired even though the trusted header already covers
// the proof height, and the nonce combination is left unconsumed — a later
// message reusing it succeeds.
func TestRetryExactlyAtExpiryInstantExpires(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()

	// First advance at 4000: retry scheduled at 5000 = expiry exactly.
	setupBoundaryWaiting(t, q, 4000)
	coverProofHeightStillWaiting(t, q, 5000)

	// The retry instant equals the expiry instant: expiry wins over the now
	// sufficient header.
	rep, err := q.Advance(5000)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := resultFor(rep, boundaryID)
	if !ok || res.Status != StatusExpired {
		t.Fatalf("retry at expiry instant: want expired, got %+v", rep.Results)
	}
	r := statusOf(t, q, boundaryID)
	if r.Status != StatusExpired || r.NextRetry != 0 {
		t.Fatalf("want expired without retry, got %+v", r)
	}
	if r.Reason != res.Reason {
		t.Fatalf("advance reason %q and query reason %q disagree", res.Reason, r.Reason)
	}
	if !strings.Contains(r.Reason, "5000") {
		t.Fatalf("expiry reason must cite the absolute expiry instant, got %q", r.Reason)
	}
	assertTerminalUnchanged(t, q, boundaryID, StatusExpired, 6000)

	// The expired message never consumed the nonce combination: a new id on
	// the same path, itself still unexpired and fully covered by the trusted
	// header, succeeds — the only thing that could have stopped it was a
	// consumption by m1.
	if _, err := q.Submit(env("m2", boundaryFrom, boundaryTo, boundaryNonce, boundaryProofAt, 10000)); err != nil {
		t.Fatal(err)
	}
	rep, err = q.Advance(7000)
	if err != nil {
		t.Fatal(err)
	}
	res, ok = resultFor(rep, "m2")
	if !ok || res.Status != StatusSuccess {
		t.Fatalf("nonce must be free after expiry, got %+v", rep.Results)
	}
	r = statusOf(t, q, "m2")
	if r.Status != StatusSuccess || r.Reason != res.Reason ||
		!strings.Contains(r.Reason, "height 100") {
		t.Fatalf("new message on freed combination must succeed, got %+v", r)
	}
}
