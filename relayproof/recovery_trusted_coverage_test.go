package relayproof

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// Recovery must make every recorded success — an incrementally saved plain
// result and a compacted success state alike — satisfy the same delivery
// precondition a live advance applies: a trusted header of the message's own
// source chain, already saved (or retained by the snapshot), must cover its
// proof height. No header, only untrusted headers, or a highest trusted
// height below the proof height rejects the whole directory with ErrCorrupt,
// even when the record is complete, checksum-valid, well timed and carries a
// correct nonce attribution. A trusted height exactly equal to the proof
// height covers. The error names the message and the source chain and says
// the coverage is missing; the log keeps its exact length and bytes even when
// the bad record is the final frame.

func TestRecoveryRejectsSuccessWithoutCoverage(t *testing.T) {
	t.Run("plain result with no header saved", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			// Complete, well-timed, correctly attributed — but no header entry
			// exists anywhere in the log, and this is the final frame.
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		}
		assertRecoveryCorrupt(t, entries, "success entry", `"m"`, `source chain "a"`,
			"lacks trusted header coverage", "proof height 10", "no trusted header saved")
	})

	t.Run("plain result with only a higher untrusted header", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 500, Root: "0x500", Trusted: false},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 101},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 500",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
			{T: kindAdvance, Now: 1000},
		}
		assertRecoveryCorrupt(t, entries, `source chain "a"`, "no trusted header saved", `"m"`)
	})

	t.Run("plain result with trusted height below the proof height", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 101},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
			{T: kindAdvance, Now: 1000},
		}
		assertRecoveryCorrupt(t, entries, "highest trusted height 100 is below proof height 101",
			`source chain "a"`, `"m"`)
	})

	t.Run("a trusted header for another chain does not cover", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindSource, Chain: "c"},
			{T: kindHeader, Chain: "c", Height: 500, Root: "0x500", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 500",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
			{T: kindAdvance, Now: 1000},
		}
		assertRecoveryCorrupt(t, entries, `source chain "a"`, "no trusted header saved", `"m"`)
	})

	t.Run("chain names are raw bytes: header for \"a\" does not cover \"a\\x00b\"", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindSource, Chain: "a\x00b"},
			{T: kindHeader, Chain: "a", Height: 1000, Root: "0x1000", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a\x00b", To: "c", Nonce: 1, ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 1000",
				Attempts: 1, ConsumeFrom: "a\x00b", ConsumeTo: "c", ConsumeNonce: 1, ConsumeBy: "m"},
		}
		assertRecoveryCorrupt(t, entries, `source chain "a\x00b"`, "no trusted header saved")
	})

	t.Run("reason text cannot take the place of a saved trusted header", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 999",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		}
		assertRecoveryCorrupt(t, entries, "lacks trusted header coverage", `"m"`)
	})
}

// A trusted header written only after the success was recorded cannot
// retroactively make the illegal success legal; replay rejects at the success
// itself, even before a later advance checkpoint would have confirmed the
// higher time.
func TestRecoveryLaterTrustedHeaderDoesNotCoverEarlierSuccess(t *testing.T) {
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 101},
		{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 200",
			Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		// Saved only after the success; recovery never reaches it for the
		// coverage of m.
		{T: kindHeader, Chain: "a", Height: 200, Root: "0x200", Trusted: true},
		{T: kindAdvance, Now: 2000},
	}
	assertRecoveryCorrupt(t, entries, "success entry for \"m\"", `source chain "a"`,
		"proof height 101", "no trusted header saved")
}

// Coverage accumulates with the trusted headers replayed so far: a later
// untrusted header at a greater height must not cover a later delivery, while
// a later lower trusted header must not narrow coverage established earlier.
func TestRecoveryCoverageUsesHighestTrustedSoFar(t *testing.T) {
	t.Run("later higher untrusted header cannot cover a following success", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m1", From: "a", To: "b", Nonce: 1, ProofAt: 100},
			{T: kindResult, Now: 1000, ID: "m1", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m1"},
			{T: kindHeader, Chain: "a", Height: 500, Root: "0x500", Trusted: false},
			{T: kindSubmit, Seq: 1, ID: "m2", From: "a", To: "b", Nonce: 2, ProofAt: 150},
			{T: kindResult, Now: 2000, ID: "m2", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 2, ConsumeBy: "m2"},
			{T: kindAdvance, Now: 2000},
		}
		// The whole directory must be unusable: m1 is never partially served.
		assertRecoveryCorrupt(t, entries, "highest trusted height 100 is below proof height 150", `"m2"`)
	})

	t.Run("later lower trusted header does not narrow coverage", func(t *testing.T) {
		dir := t.TempDir()
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 200, Root: "0x200", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m1", From: "a", To: "b", Nonce: 1, ProofAt: 100},
			{T: kindResult, Now: 1000, ID: "m1", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 200",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m1"},
			// A lower trusted header afterwards is recorded but never lowers
			// coverage; m2 proving at 150 is still covered by 200.
			{T: kindHeader, Chain: "a", Height: 50, Root: "0x50", Trusted: true},
			{T: kindSubmit, Seq: 1, ID: "m2", From: "a", To: "b", Nonce: 2, ProofAt: 150},
			{T: kindResult, Now: 2000, ID: "m2", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 200",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 2, ConsumeBy: "m2"},
			{T: kindAdvance, Now: 2000},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("lower later trusted header must not narrow coverage: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "m1"); r.Status != StatusSuccess {
			t.Fatalf("m1 not restored: %+v", r)
		}
		if r := statusOf(t, q, "m2"); r.Status != StatusSuccess {
			t.Fatalf("m2 must stay covered after a lower trusted header: %+v", r)
		}
	})

	t.Run("an untrusted latest header never affects a legal success", func(t *testing.T) {
		dir := t.TempDir()
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			// A higher untrusted header becomes the latest saved header,
			// leaving the highest trusted at 200; the following success proving
			// at 150 must not be falsely reported corrupt.
			{T: kindHeader, Chain: "a", Height: 200, Root: "0x200", Trusted: true},
			{T: kindHeader, Chain: "a", Height: 900, Root: "0x900", Trusted: false},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 150},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 200",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
			{T: kindAdvance, Now: 1000},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("untrusted latest header must not corrupt a covered success: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "m"); r.Status != StatusSuccess || r.Attempts != 1 {
			t.Fatalf("covered success not restored despite untrusted latest header: %+v", r)
		}
	})
}

// A trusted height exactly equal to the proof height covers, for both a plain
// result and a compacted state; covered records reopen with content, reason,
// attempts and nonce attribution exactly as saved.
func TestRecoverySuccessWithCoverageOpens(t *testing.T) {
	t.Run("plain result covered exactly", func(t *testing.T) {
		dir := t.TempDir()
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 100},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
			{T: kindAdvance, Now: 1000},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("exact-equal coverage must open: %v", err)
		}
		defer q.Close()
		r := statusOf(t, q, "m")
		if r.Status != StatusSuccess || r.Attempts != 1 ||
			!strings.Contains(r.Reason, "height 100") {
			t.Fatalf("covered success not restored as saved: %+v", r)
		}
		if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m" {
			t.Fatalf("nonce attribution not restored: %q", winner)
		}
	})

	t.Run("compacted state covered exactly keeps content and attribution", func(t *testing.T) {
		dir := t.TempDir()
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 7, Payload: "hello", ProofAt: 100},
			{T: kindState, Now: 4000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 5, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 7, ConsumeBy: "m"},
			{T: kindAdvance, Now: 4000},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("covered success state must open: %v", err)
		}
		defer q.Close()
		r := statusOf(t, q, "m")
		if r.Msg.Message.Payload != "hello" || r.Status != StatusSuccess ||
			r.Attempts != 5 || !strings.Contains(r.Reason, "height 100") {
			t.Fatalf("covered state not restored as saved: %+v", r)
		}
		if winner := q.consumed[newConsumeToken("a", "b", 7)]; winner != "m" {
			t.Fatalf("nonce attribution not restored: %q", winner)
		}
	})
}

// Compacted success states are judged against the trusted coverage the
// snapshot retained (its headers come first in the compacted log), not
// against the compacted-away header history and not against the reason text:
// the reason may name a lower height than the retained highest trusted header
// (later trusted headers legitimately widened coverage after the reason was
// written), while a reason claiming a height with no matching saved header
// cannot establish coverage on its own.
func TestRecoveryStateCoverageComesFromSnapshot(t *testing.T) {
	t.Run("state success without retained header is corrupt", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			{T: kindState, Now: 4000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 999",
				Attempts: 5, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
			{T: kindAdvance, Now: 4000},
		}
		assertRecoveryCorrupt(t, entries, "success state", `"m"`, `source chain "a"`,
			"lacks trusted header coverage", "no trusted header saved")
	})

	t.Run("state success with only an untrusted retained header is corrupt", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 500, Root: "0x500", Trusted: false},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 101},
			{T: kindState, Now: 4000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 500",
				Attempts: 2, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		}
		assertRecoveryCorrupt(t, entries, "success state", `"m"`, "no trusted header saved")
	})

	t.Run("state success below retained trusted height is corrupt", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 101},
			{T: kindState, Now: 4000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 2, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		}
		assertRecoveryCorrupt(t, entries, "highest trusted height 100 is below proof height 101", `"m"`)
	})

	t.Run("state success covered only by another chain is corrupt", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindSource, Chain: "c"},
			{T: kindHeader, Chain: "c", Height: 500, Root: "0x500", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			{T: kindState, Now: 4000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 500",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		}
		assertRecoveryCorrupt(t, entries, `source chain "a"`, "no trusted header saved", `"m"`)
	})

	t.Run("retained wider coverage opens with the old reason verbatim", func(t *testing.T) {
		// The message proved at 90 and succeeded when 50 was the highest
		// trusted header; by compaction a trusted header at 100 has widened
		// coverage. The snapshot retains 100 and the reason still names 50;
		// the reason need not equal the retained highest trusted height.
		dir := t.TempDir()
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 90},
			{T: kindState, Now: 4000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 50",
				Attempts: 3, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
			{T: kindAdvance, Now: 4000},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("wider retained coverage must open: %v", err)
		}
		defer q.Close()
		r := statusOf(t, q, "m")
		if r.Status != StatusSuccess || r.Attempts != 3 ||
			!strings.Contains(r.Reason, "height 50") {
			t.Fatalf("success state must keep its saved reason verbatim: %+v", r)
		}
		if strings.Contains(r.Reason, "height 100") {
			t.Fatalf("saved reason must not be rewritten to the retained height: %q", r.Reason)
		}
		if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m" {
			t.Fatalf("nonce attribution not restored: %q", winner)
		}
	})
}

// An old-format success carrying the legacy NUL-joined consumeKey is still
// bound by the coverage rule: a legacy success without a covering trusted
// header is an inconsistent directory and is rejected, while a covered one
// keeps the existing compatibility acceptance.
func TestRecoveryLegacySuccessStillRequiresCoverage(t *testing.T) {
	t.Run("legacy key without a trusted header is corrupt", func(t *testing.T) {
		key := legacyNonceKey("a", "b", 1)
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeKey: key, ConsumeBy: "m"},
		}
		assertRecoveryCorrupt(t, entries, "success entry", `"m"`,
			"lacks trusted header coverage")
	})

	t.Run("legacy key with coverage keeps compatibility acceptance", func(t *testing.T) {
		dir := t.TempDir()
		key := legacyNonceKey("a", "b", 1)
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeKey: key, ConsumeBy: "m"},
			{T: kindAdvance, Now: 1000},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("covered legacy success must keep opening: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "m"); r.Status != StatusSuccess {
			t.Fatalf("covered legacy success not restored: %+v", r)
		}
		if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m" {
			t.Fatalf("legacy consumption attribution not restored: %q", winner)
		}
	})
}

// A directory that fails the coverage check is never partially usable and a
// later open keeps failing without rewriting or truncating the log; waiting
// and other records in the same directory keep their existing behavior once
// the directory is legal.
func TestRecoveryCoverageFailureIsTotalAndNonDestructive(t *testing.T) {
	dir := t.TempDir()
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
		// m0 is a fully valid, covered success earlier in the log.
		{T: kindSubmit, Seq: 0, ID: "m0", From: "a", To: "b", Nonce: 1, ProofAt: 10},
		{T: kindResult, Now: 500, ID: "m0", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m0"},
		// m1 waits legitimately.
		{T: kindSubmit, Seq: 1, ID: "m1", From: "a", To: "b", Nonce: 2, ProofAt: 101},
		{T: kindResult, Now: 1000, ID: "m1", Status: StatusWaiting,
			Reason:   "waiting for trusted header covering height 101 (current 100)",
			Attempts: 1, NextRetry: 2000},
		// m2 is a complete success with no coverage at all, final frame.
		{T: kindSubmit, Seq: 2, ID: "m2", From: "a", To: "b", Nonce: 3, ProofAt: 101},
		{T: kindResult, Now: 1000, ID: "m2", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 3, ConsumeBy: "m2"},
	}
	path := writeLegacyLog(t, dir, entries...)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		q, err := Open(dir)
		if !errors.Is(err, ErrCorrupt) {
			if q != nil {
				q.Close()
			}
			t.Fatalf("open %d: want ErrCorrupt naming m2, got %v", i+1, err)
		}
		if q != nil {
			q.Close()
			t.Fatalf("a corrupt directory must not return a usable queue")
		}
		if !strings.Contains(err.Error(), `"m2"`) ||
			!strings.Contains(err.Error(), "highest trusted height 100 is below proof height 101") {
			t.Fatalf("error must identify m2 and the missing coverage: %v", err)
		}
		after, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if string(after) != string(raw) {
			t.Fatalf("open %d rewrote the log: %d -> %d bytes", i+1, len(raw), len(after))
		}
	}
}
