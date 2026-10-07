package relayproof

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// Recovery must make every recorded success — an incrementally saved plain
// result and a compacted success state alike — satisfy the same
// source-registration precondition a live advance applies: the message's own
// source chain must be registered, or normal processing would have
// terminalized it as unknown-source however high its trusted coverage is. A
// saved trusted header never stands in for registration. An unregistered
// success rejects the whole directory with ErrCorrupt even when the record is
// complete, checksum-valid, well timed, covered and correctly attributed; the
// error names the message, the source chain and the missing registration, and
// the log keeps its exact length and bytes even when the bad record is the
// final frame.

func TestRecoveryRejectsSuccessFromUnregisteredSource(t *testing.T) {
	t.Run("plain result with a trusted header but no registration", func(t *testing.T) {
		entries := []*logEntry{
			// Trusted coverage at height 100 is saved, the message proves at 90,
			// and time, attempts and consumption are all legal — but chain "a"
			// was never registered, and this is the final frame.
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 90},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		}
		assertRecoveryCorrupt(t, entries, "success entry", `"m"`, `source chain "a"`,
			"is not registered", "no source registration saved")
	})

	t.Run("registration saved only after the success does not count", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 90},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
			// Saved only after the success; recovery never reaches it for the
			// registration of m.
			{T: kindSource, Chain: "a"},
			{T: kindAdvance, Now: 2000},
		}
		assertRecoveryCorrupt(t, entries, "success entry for \"m\"", `source chain "a"`,
			"is not registered")
	})

	t.Run("registering another chain does not cover", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "c"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 90},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		}
		assertRecoveryCorrupt(t, entries, `"m"`, `source chain "a"`, "is not registered")
	})

	t.Run("chain names are raw bytes: registering \"a\" does not cover \"a\\x00b\"", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a\x00b", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a\x00b", To: "c", Nonce: 1, ProofAt: 90},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a\x00b", ConsumeTo: "c", ConsumeNonce: 1, ConsumeBy: "m"},
		}
		assertRecoveryCorrupt(t, entries, `source chain "a\x00b"`, "is not registered")
	})

	t.Run("compacted state without a retained registration", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 90},
			{T: kindState, Now: 4000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 5, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
			{T: kindAdvance, Now: 4000},
		}
		assertRecoveryCorrupt(t, entries, "success state", `"m"`, `source chain "a"`,
			"is not registered", "no source registration saved")
	})

	t.Run("legacy consumeKey success without registration", func(t *testing.T) {
		key := legacyNonceKey("a", "b", 1)
		entries := []*logEntry{
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 90},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeKey: key, ConsumeBy: "m"},
		}
		assertRecoveryCorrupt(t, entries, "success entry", `"m"`, "is not registered")
	})
}

// A registration completed any time before the success was recorded — even
// after the message itself was submitted — satisfies the rule: the success
// reopens with its message, reason, attempts and nonce attribution exactly as
// saved. The same holds for a compacted state judged against the
// registrations the snapshot retained.
func TestRecoverySuccessFromRegisteredSourceOpens(t *testing.T) {
	t.Run("plain result registered after submit but before the success", func(t *testing.T) {
		dir := t.TempDir()
		entries := []*logEntry{
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 90},
			// Registered after the submit but before the success result.
			{T: kindSource, Chain: "a"},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
			{T: kindAdvance, Now: 1000},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("registered-before-success must open: %v", err)
		}
		defer q.Close()
		r := statusOf(t, q, "m")
		if r.Status != StatusSuccess || r.Attempts != 1 ||
			!strings.Contains(r.Reason, "height 100") {
			t.Fatalf("registered success not restored as saved: %+v", r)
		}
		if r.Msg.Message.From != "a" || r.Msg.Message.To != "b" ||
			r.Msg.Message.Nonce != 1 || r.Msg.Message.ProofAt != 90 {
			t.Fatalf("registered success lost its message content: %+v", r)
		}
		if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m" {
			t.Fatalf("nonce attribution not restored: %q", winner)
		}
	})

	t.Run("compacted state with a retained registration", func(t *testing.T) {
		dir := t.TempDir()
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 7, Payload: "hello", ProofAt: 90},
			{T: kindState, Now: 4000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 5, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 7, ConsumeBy: "m"},
			{T: kindAdvance, Now: 4000},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("registered success state must open: %v", err)
		}
		defer q.Close()
		r := statusOf(t, q, "m")
		if r.Msg.Message.Payload != "hello" || r.Status != StatusSuccess ||
			r.Attempts != 5 || !strings.Contains(r.Reason, "height 100") {
			t.Fatalf("registered success state not restored as saved: %+v", r)
		}
		if winner := q.consumed[newConsumeToken("a", "b", 7)]; winner != "m" {
			t.Fatalf("nonce attribution not restored: %q", winner)
		}
	})
}

// A directory that fails the registration check is never partially usable and
// a later open keeps failing without rewriting or truncating the log: the
// valid covered success earlier in the log is not served either, and the bad
// final frame survives byte for byte.
func TestRecoveryRegistrationFailureIsTotalAndNonDestructive(t *testing.T) {
	dir := t.TempDir()
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
		// m0 is a fully valid, registered and covered success earlier in the log.
		{T: kindSubmit, Seq: 0, ID: "m0", From: "a", To: "b", Nonce: 1, ProofAt: 10},
		{T: kindResult, Now: 500, ID: "m0", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m0"},
		// m1 waits legitimately.
		{T: kindSubmit, Seq: 1, ID: "m1", From: "a", To: "b", Nonce: 2, ProofAt: 101},
		{T: kindResult, Now: 1000, ID: "m1", Status: StatusWaiting,
			Reason:   "waiting for trusted header covering height 101 (current 100)",
			Attempts: 1, NextRetry: 2000},
		// m2 is a complete, covered success from never-registered chain "u",
		// final frame.
		{T: kindHeader, Chain: "u", Height: 300, Root: "0x300", Trusted: true},
		{T: kindSubmit, Seq: 2, ID: "m2", From: "u", To: "b", Nonce: 3, ProofAt: 90},
		{T: kindResult, Now: 1000, ID: "m2", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 300",
			Attempts: 1, ConsumeFrom: "u", ConsumeTo: "b", ConsumeNonce: 3, ConsumeBy: "m2"},
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
			!strings.Contains(err.Error(), `source chain "u"`) ||
			!strings.Contains(err.Error(), "is not registered") {
			t.Fatalf("error must identify m2, its source chain and the missing registration: %v", err)
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
