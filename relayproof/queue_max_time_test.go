package relayproof

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// Regression tests for processing times at the int64 Unix-millisecond
// boundary. The retry schedule is computed from the actual processing time;
// when now + backoff would exceed math.MaxInt64 it must saturate at
// math.MaxInt64 instead of wrapping to a negative instant — a wrapped retry
// time reads as "due immediately" and makes every later advance re-attempt
// the message, defeating the backoff. All times here are caller-supplied
// non-negative Unix milliseconds; math.MaxInt64 is a legal processing time.

const maxTimeChain = "edge"

// setupMaxTimeWaiting registers a source with a trusted header just short of
// the proof height, submits a never-expiring message and first-processes it
// 500ms before the representable maximum. The retry must be scheduled exactly
// at the maximum: saturating, never wrapping.
func setupMaxTimeWaiting(t *testing.T, q *Queue, id string) {
	t.Helper()
	if err := q.RegisterSource(maxTimeChain); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: maxTimeChain, Height: 99, Root: "0x99", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env(id, maxTimeChain, "b", 7, 100, 0)); err != nil {
		t.Fatal(err)
	}
	rep, err := q.Advance(math.MaxInt64 - 500)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := resultFor(rep, id)
	if !ok || res.Status != StatusWaiting {
		t.Fatalf("first advance: want one waiting result, got %+v", rep.Results)
	}
	r := statusOf(t, q, id)
	if r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != math.MaxInt64 {
		t.Fatalf("retry must saturate at %d, got %+v", int64(math.MaxInt64), r)
	}
	if r.NextRetry <= 0 || r.NextRetry < math.MaxInt64-500 {
		t.Fatalf("retry time wrapped or moved backwards: %+v", r)
	}
}

// A message scheduled at the maximum stays untouched while time advances
// below it, is processed once when the maximum is reached, and is never
// re-attempted by advancing the same maximum time again — with or without a
// trusted header update in between. Closing and reopening restores the same
// waiting record and schedule without reporting corruption.
func TestRetrySaturatesAtMaxInt64(t *testing.T) {
	q, dir := openTempQueue(t)
	setupMaxTimeWaiting(t, q, "m1")

	// Advancing below the scheduled retry changes nothing.
	rep, err := q.Advance(math.MaxInt64 - 250)
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := resultFor(rep, "m1"); ok {
		t.Fatalf("advance below retry must not touch the message, got %+v", res)
	}
	r := statusOf(t, q, "m1")
	if r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != math.MaxInt64 {
		t.Fatalf("pre-retry advance changed the waiting message: %+v", r)
	}

	// Reaching the maximum processes the due message once: still no trusted
	// coverage, so it waits again with the retry pinned at the maximum.
	rep, err = q.Advance(math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := resultFor(rep, "m1")
	if !ok || res.Status != StatusWaiting {
		t.Fatalf("advance at maximum: want one waiting result, got %+v", rep.Results)
	}
	r = statusOf(t, q, "m1")
	if r.Status != StatusWaiting || r.Attempts != 2 || r.NextRetry != math.MaxInt64 {
		t.Fatalf("want waiting attempts=2 retry=%d, got %+v", int64(math.MaxInt64), r)
	}
	reason := r.Reason

	// Advancing the same maximum time again must not re-attempt the message
	// or report it again.
	rep, err = q.Advance(math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := resultFor(rep, "m1"); ok {
		t.Fatalf("same-time advance re-attempted a message processed at the maximum: %+v", res)
	}
	r = statusOf(t, q, "m1")
	if r.Status != StatusWaiting || r.Attempts != 2 || r.NextRetry != math.MaxInt64 || r.Reason != reason {
		t.Fatalf("same-time advance changed the waiting message: %+v", r)
	}

	// A trusted header update never processes messages by itself, and it must
	// not let the already-processed-at-maximum message bypass the wait rule on
	// a same-time advance.
	if err := q.UpsertHeader(Header{Chain: maxTimeChain, Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	rep, err = q.Advance(math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := resultFor(rep, "m1"); ok {
		t.Fatalf("header update plus same-time advance re-delivered the message: %+v", res)
	}
	r = statusOf(t, q, "m1")
	if r.Status != StatusWaiting || r.Attempts != 2 || r.NextRetry != math.MaxInt64 {
		t.Fatalf("header update bypassed the wait rule: %+v", r)
	}

	// Close and reopen: the same waiting record and schedule must come back
	// without a corruption report, and the same-time rule still holds.
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q, err = Open(dir)
	if err != nil {
		t.Fatalf("reopen must not report corruption: %v", err)
	}
	defer q.Close()
	r = statusOf(t, q, "m1")
	if r.Status != StatusWaiting || r.Attempts != 2 || r.NextRetry != math.MaxInt64 || r.Reason != reason {
		t.Fatalf("reopen restored a different record: %+v", r)
	}
	rep, err = q.Advance(math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := resultFor(rep, "m1"); ok {
		t.Fatalf("post-reopen same-time advance re-attempted the message: %+v", res)
	}
}

// Reaching the maximum with trusted coverage already in place lets the due
// message succeed by the ordinary rules, consuming its nonce combination.
func TestRetryAtMaxInt64SucceedsWithCoverage(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	setupMaxTimeWaiting(t, q, "m1")

	if err := q.UpsertHeader(Header{Chain: maxTimeChain, Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	rep, err := q.Advance(math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := resultFor(rep, "m1")
	if !ok || res.Status != StatusSuccess {
		t.Fatalf("covered retry at maximum: want success, got %+v", rep.Results)
	}
	r := statusOf(t, q, "m1")
	if r.Status != StatusSuccess || r.Attempts != 2 || r.NextRetry != 0 {
		t.Fatalf("want success attempts=2 no retry, got %+v", r)
	}
	if !strings.Contains(r.Reason, "height 100") {
		t.Fatalf("success reason must cite the trusted height, got %q", r.Reason)
	}
}

// The saturation guard must not shield messages that were never processed at
// the maximum: a brand-new submission is still first-processed by the next
// advance even when time is already at the maximum, and the replay/expiry
// sweep still terminalizes non-terminal messages at that time.
func TestMaxInt64StillProcessesNewAndExpiringMessages(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource(maxTimeChain); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: maxTimeChain, Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(math.MaxInt64); err != nil {
		t.Fatal(err)
	}

	// New message submitted while time sits at the maximum: first judgment
	// happens on the next advance at the same time.
	if _, err := q.Submit(env("new", maxTimeChain, "b", 1, 100, 0)); err != nil {
		t.Fatal(err)
	}
	rep, err := q.Advance(math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := resultFor(rep, "new")
	if !ok || res.Status != StatusSuccess {
		t.Fatalf("new message at maximum must be first-processed, got %+v", rep.Results)
	}

	// Expiry still applies at the maximum: a message whose absolute expiry is
	// the maximum itself expires when time reaches it, even while waiting.
	if _, err := q.Submit(env("exp", maxTimeChain, "b", 2, 100, math.MaxInt64)); err != nil {
		t.Fatal(err)
	}
	rep, err = q.Advance(math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	res, ok = resultFor(rep, "exp")
	if !ok || res.Status != StatusExpired {
		t.Fatalf("message expiring at the maximum must expire, got %+v", rep.Results)
	}
}

// Ordinary validation is unchanged by the boundary handling: negative times
// and time travelling backwards are still rejected and change nothing.
func TestMaxInt64RejectsNegativeAndBackwardsTime(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	setupMaxTimeWaiting(t, q, "m1")

	if _, err := q.Advance(-1); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("negative time must be rejected, got %v", err)
	}
	if _, err := q.Advance(math.MaxInt64 - 501); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("backwards time must be rejected, got %v", err)
	}
	r := statusOf(t, q, "m1")
	if r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != math.MaxInt64 {
		t.Fatalf("rejected advances changed the queue: %+v", r)
	}
	if now := q.Now(); now != math.MaxInt64-500 {
		t.Fatalf("rejected advances moved the clock: %d", now)
	}
}
