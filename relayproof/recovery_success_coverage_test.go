package relayproof

import (
	"os"
	"strings"
	"testing"
)

// These tests pin down trusted-coverage validation of recovered successes.
// A live advance only delivers a message when the highest trusted header of
// the message's own source chain covers the proof height, so a saved success
// — a plain result or a compacted state — without that coverage in the log
// itself is corruption: opening the directory must fail with ErrCorrupt
// naming the message and its source chain, return no usable queue, and leave
// queue.log byte-for-byte untouched, even when the offending record is the
// final frame. A trusted height exactly equal to the proof height covers it;
// another chain's headers never count; a plain result's covering trusted
// header must precede it in the log, while a compacted state is judged by
// the coverage the snapshot retained. The success reason's text is not
// evidence, and lower trusted or untrusted headers saved later never
// invalidate a legal success.

// uncoveredSuccessBase is a registered source with no headers and one pending
// message proven at height 101. Callers add headers and the success record.
func uncoveredSuccessBase() []*logEntry {
	return []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 101},
	}
}

// uncoveredSuccessRecord is a complete, otherwise fully legal success record
// for the base message: correct consumption, correct retry fields, correct
// attempt count — only the trusted coverage is missing.
func uncoveredSuccessRecord(kind string) *logEntry {
	return &logEntry{
		T: kind, Now: 1000, ID: "m", Status: StatusSuccess,
		Reason:   "delivered; proof verified by trusted header at height 200",
		Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m",
	}
}

// A success with no trusted coverage of the proof height is corrupt in both
// record kinds and for every coverage shortfall: no header at all, only an
// untrusted header, or a highest trusted height below the proof height. The
// error names the message and the source chain and says trusted coverage is
// missing; the log bytes are preserved.
func TestRecoveryRejectsSuccessWithoutTrustedCoverage(t *testing.T) {
	cases := []struct {
		name    string
		headers []*logEntry
		want    []string
	}{
		{
			name:    "no header at all",
			headers: nil,
			want:    []string{"lacks trusted coverage", "no trusted header", `"m"`, `"a"`, "101"},
		},
		{
			name:    "only an untrusted header",
			headers: []*logEntry{{T: kindHeader, Chain: "a", Height: 500, Root: "0x500", Trusted: false}},
			want:    []string{"lacks trusted coverage", "no trusted header", `"m"`, `"a"`},
		},
		{
			name:    "trusted height below proof height",
			headers: []*logEntry{{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true}},
			want:    []string{"lacks trusted coverage", "highest trusted", `"m"`, `"a"`, "100", "101"},
		},
		{
			name: "another chain's trusted header does not count",
			headers: []*logEntry{
				{T: kindSource, Chain: "b"},
				{T: kindHeader, Chain: "b", Height: 500, Root: "0x500", Trusted: true},
			},
			want: []string{"lacks trusted coverage", `"m"`, `"a"`},
		},
	}
	for _, kind := range []string{kindResult, kindState} {
		for _, tc := range cases {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				entries := append(uncoveredSuccessBase(), tc.headers...)
				entries = append(entries, uncoveredSuccessRecord(kind))
				entries = append(entries, &logEntry{T: kindAdvance, Now: 1000})
				assertRecoveryCorrupt(t, entries, tc.want...)
			})
		}
	}
}

// The success reason's text is not evidence: a record whose reason claims
// verification by a trusted header at a height no saved trusted header ever
// reached is still corrupt — only a saved trusted header counts.
func TestRecoverySuccessReasonTextIsNotCoverage(t *testing.T) {
	for _, kind := range []string{kindResult, kindState} {
		t.Run(kind, func(t *testing.T) {
			r := uncoveredSuccessRecord(kind)
			r.Reason = "delivered; proof verified by trusted header at height 101"
			entries := append(uncoveredSuccessBase(), r)
			assertRecoveryCorrupt(t, entries, "lacks trusted coverage", `"m"`, `"a"`)
		})
	}
}

// A trusted header saved only after a plain success result cannot rescue it:
// the result was already illegal when it was written. (A compacted state is
// exempt from this ordering rule — it is judged by the coverage the snapshot
// retained, which compaction always writes before the states.)
func TestRecoveryRejectsSuccessBeforeItsCoveringHeader(t *testing.T) {
	entries := append(uncoveredSuccessBase(), uncoveredSuccessRecord(kindResult))
	entries = append(entries,
		&logEntry{T: kindHeader, Chain: "a", Height: 200, Root: "0x200", Trusted: true},
		&logEntry{T: kindAdvance, Now: 1000},
	)
	assertRecoveryCorrupt(t, entries, "lacks trusted coverage", `"m"`, `"a"`)
}

// A compacted success state is judged by the trusted coverage the snapshot
// retained, not by the dropped header-update history: the retained highest
// trusted header may be far above the proof height, and the height the
// success reason names need not equal it.
func TestRecoveryStateJudgedByRetainedCoverage(t *testing.T) {
	dir := t.TempDir()
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		// The snapshot retained only the highest trusted header; the success
		// reason still names the height it was originally delivered under.
		{T: kindHeader, Chain: "a", Height: 900, Root: "0x900", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 101},
		{T: kindState, Now: 1000, ID: "m", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 101",
			Attempts: 3, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		{T: kindAdvance, Now: 1000},
	}
	writeLegacyLog(t, dir, entries...)
	q, err := Open(dir)
	if err != nil {
		t.Fatalf("state with retained coverage must open: %v", err)
	}
	defer q.Close()
	r := statusOf(t, q, "m")
	if r.Status != StatusSuccess || r.Attempts != 3 ||
		!strings.Contains(r.Reason, "height 101") {
		t.Fatalf("success state not restored as saved: %+v", r)
	}
	if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m" {
		t.Fatalf("consumption not restored: %q", winner)
	}
}

// A trusted height exactly equal to the proof height covers it, for both
// record kinds.
func TestRecoveryAcceptsSuccessWithExactCoverage(t *testing.T) {
	for _, kind := range []string{kindResult, kindState} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			entries := []*logEntry{
				{T: kindSource, Chain: "a"},
				{T: kindHeader, Chain: "a", Height: 101, Root: "0x101", Trusted: true},
				{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 101},
				{T: kind, Now: 1000, ID: "m", Status: StatusSuccess,
					Reason:   "delivered; proof verified by trusted header at height 101",
					Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
				{T: kindAdvance, Now: 1000},
			}
			writeLegacyLog(t, dir, entries...)
			q, err := Open(dir)
			if err != nil {
				t.Fatalf("exactly covering success must open: %v", err)
			}
			defer q.Close()
			if r := statusOf(t, q, "m"); r.Status != StatusSuccess {
				t.Fatalf("exactly covered success not restored: %+v", r)
			}
		})
	}
}

// Coverage is judged by the highest trusted header, never the latest one:
// lower trusted headers and untrusted headers saved after a legal success
// leave it legal, and a higher trusted header saved later extends coverage
// for successes recorded after it.
func TestRecoveryCoverageNeverShiftsBackwards(t *testing.T) {
	t.Run("lower trusted and untrusted headers after the success", func(t *testing.T) {
		dir := t.TempDir()
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 100},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
			// Neither of these may invalidate the success saved before them.
			{T: kindHeader, Chain: "a", Height: 50, Root: "0x50", Trusted: true},
			{T: kindHeader, Chain: "a", Height: 5000, Root: "0x5000", Trusted: false},
			{T: kindAdvance, Now: 1000},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("later lower/untrusted headers must not corrupt a legal success: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "m"); r.Status != StatusSuccess {
			t.Fatalf("legal success misjudged: %+v", r)
		}
	})

	t.Run("higher trusted header extends coverage for later successes", func(t *testing.T) {
		dir := t.TempDir()
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m1", From: "a", To: "b", Nonce: 1, ProofAt: 100},
			{T: kindResult, Now: 1000, ID: "m1", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m1"},
			// Coverage grows; a success needing the new height is now legal.
			{T: kindHeader, Chain: "a", Height: 200, Root: "0x200", Trusted: true},
			{T: kindSubmit, Seq: 1, ID: "m2", From: "a", To: "b", Nonce: 2, ProofAt: 200},
			{T: kindResult, Now: 2000, ID: "m2", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 200",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 2, ConsumeBy: "m2"},
			{T: kindAdvance, Now: 2000},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("grown coverage must cover later successes: %v", err)
		}
		defer q.Close()
		for _, id := range []string{"m1", "m2"} {
			if r := statusOf(t, q, id); r.Status != StatusSuccess {
				t.Fatalf("success %s not restored: %+v", id, r)
			}
		}
	})
}

// Chain identity is the exact saved bytes: coverage registered for a chain
// whose name differs only in an invalid byte does not cover the message's
// source chain.
func TestRecoveryCoverageIsPerExactChainBytes(t *testing.T) {
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindSource, Chain: "a\xff"},
		// The lookalike chain is covered; the message's own chain is not.
		{T: kindHeader, Chain: "a\xff", Height: 500, Root: "r", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
		{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 500",
			Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
	}
	assertRecoveryCorrupt(t, entries, "lacks trusted coverage", `"m"`, `"a"`)
}

// A coverage violation in the very last frame of the log is corruption in
// place, never a truncatable torn tail: the open fails and the log keeps its
// exact length and bytes.
func TestRecoveryUncoveredSuccessAtEndOfLogIsNotTruncated(t *testing.T) {
	dir := t.TempDir()
	entries := append(uncoveredSuccessBase(), uncoveredSuccessRecord(kindResult))
	// No advance checkpoint: the illegal success is the final frame.
	path := writeLegacyLog(t, dir, entries...)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	q, err := Open(dir)
	if q != nil {
		q.Close()
		t.Fatalf("uncovered success at end of log must not open a queue")
	}
	if !strings.Contains(err.Error(), "lacks trusted coverage") {
		t.Fatalf("error must name the coverage violation: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("final-frame corruption was truncated or rewritten: %d -> %d bytes", len(before), len(after))
	}
}

// A legacy consumeKey success keeps its compatibility rules and is still
// accepted when its trusted coverage is saved in the log.
func TestRecoveryLegacyConsumeKeySuccessWithCoverageOpens(t *testing.T) {
	dir := t.TempDir()
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
		{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeKey: legacyNonceKey("a", "b", 1), ConsumeBy: "m"},
		{T: kindAdvance, Now: 1000},
	}
	writeLegacyLog(t, dir, entries...)
	q, err := Open(dir)
	if err != nil {
		t.Fatalf("covered legacy success must open: %v", err)
	}
	defer q.Close()
	if r := statusOf(t, q, "m"); r.Status != StatusSuccess {
		t.Fatalf("legacy success not restored: %+v", r)
	}
	if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m" {
		t.Fatalf("legacy consumption not restored: %q", winner)
	}
}
