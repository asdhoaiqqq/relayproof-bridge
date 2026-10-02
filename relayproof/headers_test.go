package relayproof

import (
	"errors"
	"strings"
	"testing"
)

// An untrusted header written after a trusted one must not erase the
// established coverage: a message at or below the trusted height succeeds
// (and its reason names the trusted height, not the higher untrusted one),
// while a message beyond the trusted height keeps waiting.
func TestUntrustedHeaderDoesNotEraseCoverage(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "r100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 120, Root: "r120", Trusted: false}); err != nil {
		t.Fatal(err)
	}
	q.Submit(env("covered", "a", "b", 1, 90, 0))
	q.Submit(env("beyond", "a", "b", 2, 110, 0))

	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Result{}
	for _, r := range rep.Results {
		got[r.ID] = r
	}
	if got["covered"].Status != StatusSuccess {
		t.Fatalf("proof 90 under trusted 100 must succeed despite untrusted 120, got %+v", got["covered"])
	}
	if !strings.Contains(got["covered"].Reason, "100") || strings.Contains(got["covered"].Reason, "120") {
		t.Fatalf("success reason must name the trusted height 100, not untrusted 120: %q", got["covered"].Reason)
	}
	if got["beyond"].Status != StatusWaiting {
		t.Fatalf("proof 110 beyond trusted 100 must keep waiting, got %+v", got["beyond"])
	}
	if !strings.Contains(got["beyond"].Reason, "current 100") {
		t.Fatalf("waiting reason must report trusted coverage 100, got %q", got["beyond"].Reason)
	}
}

// A lower trusted header is recorded but never lowers the established
// coverage; a higher trusted header advances it.
func TestTrustedCoverageOnlyAdvances(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "r100", Trusted: true})
	if err := q.UpsertHeader(Header{Chain: "a", Height: 80, Root: "r80", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	q.Submit(env("mid", "a", "b", 1, 95, 0))
	q.Submit(env("high", "a", "b", 2, 120, 0))

	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Result{}
	for _, r := range rep.Results {
		got[r.ID] = r
	}
	if got["mid"].Status != StatusSuccess {
		t.Fatalf("lower trusted header must not lower coverage, got %+v", got["mid"])
	}
	if got["high"].Status != StatusWaiting {
		t.Fatalf("proof 120 above trusted 100 must wait, got %+v", got["high"])
	}

	// A higher trusted header advances the coverage and unblocks at retry.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 150, Root: "r150", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	rep, err = q.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		if r.ID == "high" && (r.Status != StatusSuccess || !strings.Contains(r.Reason, "150")) {
			t.Fatalf("higher trusted header must advance coverage to 150, got %+v", r)
		}
	}
	if r := statusOf(t, q, "high"); r.Status != StatusSuccess {
		t.Fatalf("high must succeed after coverage advanced, got %s", r.Status)
	}
}

// Re-submitting the same root at the coverage height is a no-op success; a
// different root at that height is a trusted-header conflict that keeps the
// original and leaves the queue fully usable.
func TestTrustedHeaderConflictAtCoverageHeight(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "root-a", Trusted: true})

	// Same height, same root: success, coverage unchanged.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "root-a", Trusted: true}); err != nil {
		t.Fatalf("identical trusted header must succeed: %v", err)
	}
	// Same height, different root: explicit conflict, original kept.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "root-b", Trusted: true}); !errors.Is(err, ErrHeaderConflict) {
		t.Fatalf("want ErrHeaderConflict, got %v", err)
	}
	// Untrusted headers never conflict, even at the coverage height.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "root-b", Trusted: false}); err != nil {
		t.Fatalf("untrusted header at coverage height must not conflict: %v", err)
	}
	// The queue remains usable and the original coverage still applies.
	q.Submit(env("m", "a", "b", 1, 100, 0))
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatalf("queue must stay usable after a conflict: %v", err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Status != StatusSuccess {
		t.Fatalf("original coverage must still deliver, got %+v", rep.Results)
	}
	// A higher trusted header still advances afterwards.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 101, Root: "root-c", Trusted: true}); err != nil {
		t.Fatalf("higher trusted header after conflict must succeed: %v", err)
	}
}

// Roots are compared as raw strings; empty roots are valid and conflict
// detection treats them like any other string.
func TestTrustedHeaderRootComparedVerbatim(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	if err := q.UpsertHeader(Header{Chain: "a", Height: 50, Trusted: true}); err != nil {
		t.Fatalf("empty root must be accepted: %v", err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 50, Trusted: true}); err != nil {
		t.Fatalf("same empty root must succeed: %v", err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 50, Root: "x", Trusted: true}); !errors.Is(err, ErrHeaderConflict) {
		t.Fatalf("empty vs non-empty root at same height must conflict, got %v", err)
	}
}

// A trusted header for an unregistered chain is recorded but must not let
// that chain's messages bypass unknown-source.
func TestTrustedHeaderDoesNotBypassUnknownSource(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.UpsertHeader(Header{Chain: "ghost", Height: 100, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	q.Submit(env("m", "ghost", "b", 1, 10, 0))
	q.Advance(1000)
	if r := statusOf(t, q, "m"); r.Status != StatusUnknownSrc {
		t.Fatalf("unregistered source with a trusted header must stay unknown-source, got %s", r.Status)
	}
}

// Header coverage is per chain: one chain's updates never affect another.
func TestHeaderCoverageIsPerChain(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.RegisterSource("b")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
	q.UpsertHeader(Header{Chain: "b", Height: 100, Trusted: false})

	q.Submit(env("ma", "a", "b", 1, 100, 0))
	q.Submit(env("mb", "b", "a", 1, 100, 0))
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Result{}
	for _, r := range rep.Results {
		got[r.ID] = r
	}
	if got["ma"].Status != StatusSuccess {
		t.Fatalf("chain a message must succeed, got %+v", got["ma"])
	}
	if got["mb"].Status != StatusWaiting {
		t.Fatalf("chain b has no trusted header and must wait, got %+v", got["mb"])
	}
	// A conflict on chain a must not disturb chain b's updates.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "other", Trusted: true}); !errors.Is(err, ErrHeaderConflict) {
		t.Fatalf("want ErrHeaderConflict on chain a, got %v", err)
	}
	if err := q.UpsertHeader(Header{Chain: "b", Height: 100, Trusted: true}); err != nil {
		t.Fatalf("chain b trusted header must succeed independently: %v", err)
	}
}

// Header updates never process messages, add attempts, or move retry times.
func TestHeaderUpdateDoesNotTouchScheduling(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.Submit(env("m", "a", "b", 1, 10, 0))
	q.Advance(1000) // waiting, retry at 2000, attempts 1
	before := statusOf(t, q, "m")

	q.UpsertHeader(Header{Chain: "a", Height: 500, Trusted: false})
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
	after := statusOf(t, q, "m")
	if after.Status != StatusWaiting || after.Attempts != before.Attempts || after.NextRetry != before.NextRetry {
		t.Fatalf("header update changed scheduling: before %+v after %+v", before, after)
	}
	// Not yet due at 1500 even though coverage now exists.
	rep, err := q.Advance(1500)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		if r.ID == "m" {
			t.Fatalf("header update must not make a waiting message due early: %+v", r)
		}
	}
	// At the scheduled retry the trusted coverage delivers, named by its
	// trusted height rather than the higher untrusted one.
	rep, err = q.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Status != StatusSuccess ||
		!strings.Contains(rep.Results[0].Reason, "100") || strings.Contains(rep.Results[0].Reason, "500") {
		t.Fatalf("retry must deliver via trusted height 100, got %+v", rep.Results)
	}
}

// The established trusted coverage survives close/reopen and log compaction;
// untrusted records never come back as coverage after either.
func TestTrustedCoverageSurvivesRestartAndCompaction(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "r100", Trusted: true})
	q.UpsertHeader(Header{Chain: "a", Height: 120, Root: "r120", Trusted: false})
	q.UpsertHeader(Header{Chain: "a", Height: 80, Root: "r80", Trusted: true})
	q.Submit(env("low", "a", "b", 1, 100, 0))
	q.Submit(env("high", "a", "b", 2, 110, 0))
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: coverage is still trusted 100 — low delivers, high waits.
	q2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := q2.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Result{}
	for _, r := range rep.Results {
		got[r.ID] = r
	}
	if got["low"].Status != StatusSuccess || !strings.Contains(got["low"].Reason, "100") {
		t.Fatalf("coverage lost across restart: %+v", got["low"])
	}
	if got["high"].Status != StatusWaiting {
		t.Fatalf("untrusted 120 must not become coverage after restart: %+v", got["high"])
	}

	// Compact, reopen, and confirm the same coverage once more.
	if err := q2.store.compact(q2.snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := q2.Close(); err != nil {
		t.Fatal(err)
	}
	q3, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q3.Close()
	if r := statusOf(t, q3, "low"); r.Status != StatusSuccess {
		t.Fatalf("low lost success after compaction: %s", r.Status)
	}
	if r := statusOf(t, q3, "high"); r.Status != StatusWaiting {
		t.Fatalf("high must still wait after compaction, got %s", r.Status)
	}
	// The conflict rule still guards the restored coverage height.
	if err := q3.UpsertHeader(Header{Chain: "a", Height: 100, Root: "other", Trusted: true}); !errors.Is(err, ErrHeaderConflict) {
		t.Fatalf("restored coverage must still reject a conflicting root, got %v", err)
	}
	if err := q3.UpsertHeader(Header{Chain: "a", Height: 100, Root: "r100", Trusted: true}); err != nil {
		t.Fatalf("restored coverage must accept the same root, got %v", err)
	}
	// And a genuinely higher trusted header advances the restored coverage.
	if err := q3.UpsertHeader(Header{Chain: "a", Height: 110, Root: "r110", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	rep, err = q3.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		if r.ID == "high" && r.Status != StatusSuccess {
			t.Fatalf("high must deliver once trusted 110 arrives, got %+v", r)
		}
	}
	if r := statusOf(t, q3, "high"); r.Status != StatusSuccess {
		t.Fatalf("high must succeed after coverage advanced to 110, got %s", r.Status)
	}
}

// Logs written by older builds recorded every header with last-write-wins
// semantics. Such directories must open directly: an untrusted overwrite
// never erases the trusted coverage, a lower trusted overwrite never lowers
// it, and a same-height trusted overwrite is kept as the first root recorded
// rather than rejected as a conflict.
func TestLegacyHeaderLogFoldsIntoCoverage(t *testing.T) {
	dir := t.TempDir()
	writeLegacyLog(t, dir,
		&logEntry{T: kindSource, Chain: "a"},
		&logEntry{T: kindHeader, Chain: "a", Height: 100, Root: "first", Trusted: true},
		&logEntry{T: kindHeader, Chain: "a", Height: 100, Root: "second", Trusted: true}, // historical same-height overwrite
		&logEntry{T: kindHeader, Chain: "a", Height: 90, Root: "lower", Trusted: true},
		&logEntry{T: kindHeader, Chain: "a", Height: 120, Root: "tip", Trusted: false},
		&logEntry{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 95},
	)

	q, err := Open(dir)
	if err != nil {
		t.Fatalf("historical same-height overwrite must not be rejected: %v", err)
	}
	defer q.Close()

	// Coverage is the first root recorded at the highest trusted height.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "first", Trusted: true}); err != nil {
		t.Fatalf("the first recorded root must be the established one, got %v", err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "second", Trusted: true}); !errors.Is(err, ErrHeaderConflict) {
		t.Fatalf("a different root at the established height must conflict, got %v", err)
	}

	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Status != StatusSuccess ||
		!strings.Contains(rep.Results[0].Reason, "100") {
		t.Fatalf("proof 95 must deliver via trusted coverage 100, got %+v", rep.Results)
	}
}
