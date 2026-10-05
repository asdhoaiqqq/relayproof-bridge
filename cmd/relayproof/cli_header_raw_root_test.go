package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asdhoaiqqq/relayproof-bridge/relayproof"
)

// Roots stay the exact bytes the caller submits even when those bytes are not
// valid UTF-8. The JSON string encoding used to persist the root replaced each
// invalid byte with U+FFFD, so the byte sequence only matched within the one
// process that saved it: after the state directory reopened, resaving the same
// height with the same raw bytes failed with exit code 16 while the mangled
// replacement-character root saved successfully. Every CLI invocation opens a
// fresh process, so these scenarios necessarily cross a reopen; argv carries
// the raw bytes through unchanged.

var (
	cliRawRootFF = string([]byte{0xFF})
	cliRawRootFE = string([]byte{0xFE})
	cliRootFFFD  = "�"
)

// logSize reports the current queue.log size in the state directory.
func logSize(t *testing.T, state string) int64 {
	t.Helper()
	info, err := os.Stat(filepath.Join(state, "queue.log"))
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// A raw 0xFF root saved as trusted at height 100 resaves byte-for-byte in a
// later process, while raw 0xFE and the legal U+FFFD character each end in the
// header-conflict exit code 16 — the three never collapse into one root.
func TestCLIHeaderConflictRawBytesSurviveReopen(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")

	first := storeHeader(t, state, "chain-a", 100, cliRawRootFF, true)
	if first.code != 0 || first.stdout != wantStoredHeader("chain-a", 100, true) {
		t.Fatalf("initial invalid-UTF-8 trusted header: code=%d stdout=%q stderr=%q",
			first.code, first.stdout, first.stderr)
	}

	// A later process resaving the identical bytes must be accepted.
	again := storeHeader(t, state, "chain-a", 100, cliRawRootFF, true)
	if again.code != 0 || again.stdout != wantStoredHeader("chain-a", 100, true) || again.stderr != "" {
		t.Fatalf("identical raw root must resave after reopen: code=%d stdout=%q stderr=%q",
			again.code, again.stdout, again.stderr)
	}

	// One different byte is a conflict and names submitted and accepted root.
	assertHeaderConflict(t, storeHeader(t, state, "chain-a", 100, cliRawRootFE, true),
		"chain-a", 100, cliRawRootFE, cliRawRootFF)
	// The legal replacement character is distinct from the raw byte.
	assertHeaderConflict(t, storeHeader(t, state, "chain-a", 100, cliRootFFFD, true),
		"chain-a", 100, cliRootFFFD, cliRawRootFF)
	// And the original raw bytes still save after the rejected attempts.
	ok := storeHeader(t, state, "chain-a", 100, cliRawRootFF, true)
	if ok.code != 0 || ok.stdout != wantStoredHeader("chain-a", 100, true) {
		t.Fatalf("original raw root must still save after conflicts: code=%d stderr=%q", ok.code, ok.stderr)
	}
}

// Raw roots also survive the log being rewritten by automatic compaction, and
// the accepted root is not replaced by a higher untrusted or lower trusted
// header carrying different bytes.
func TestCLIHeaderRawRootSurvivesCompactionAndOtherSaves(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, cliRawRootFF, true); r.code != 0 {
		t.Fatalf("initial raw trusted header: code=%d stderr=%q", r.code, r.stderr)
	}

	// One large pending payload pads the log to just below the 4 MiB
	// compaction threshold. A payload that size cannot be passed as one argv
	// element (a single argument is capped at 128 KiB), so it is written
	// through the Go API in-process; equal-time CLI advance checkpoints then
	// cross the threshold in fresh processes and trigger the automatic
	// rewrite. A compaction atomically replaces the log with its snapshot,
	// observable as a sudden size drop; loop only until that drop appears.
	if err := saveFiller(state, strings.Repeat("x", (4<<20)-8192)); err != nil {
		t.Fatalf("filler setup: %v", err)
	}
	maxSize := logSize(t, state)
	compacted := false
	for i := 0; i < 400; i++ {
		if cr := queueCLI(t, state, "advance", "--now", "1000"); cr.code != 0 {
			t.Fatalf("padding advance %d: code=%d stderr=%q", i, cr.code, cr.stderr)
		}
		size := logSize(t, state)
		if size > maxSize {
			maxSize = size
		}
		if size < maxSize-1024 {
			compacted = true
			break
		}
	}
	if !compacted {
		t.Fatal("expected an automatic compaction (log size drop), never observed it")
	}

	// Higher untrusted header with different bytes saves without replacing the
	// accepted trusted root.
	if r := storeHeader(t, state, "chain-a", 120, cliRawRootFE, false); r.code != 0 {
		t.Fatalf("higher untrusted raw-root header must save: code=%d stderr=%q", r.code, r.stderr)
	}
	// Lower trusted header with the U+FFFD character also saves, no conflict.
	if r := storeHeader(t, state, "chain-a", 50, cliRootFFFD, true); r.code != 0 {
		t.Fatalf("lower trusted header must save: code=%d stderr=%q", r.code, r.stderr)
	}

	// Accepted height still carries the original raw byte: resave accepts,
	// other byte sequences conflict with exit code 16.
	if r := storeHeader(t, state, "chain-a", 100, cliRawRootFF, true); r.code != 0 {
		t.Fatalf("original raw root must resave after compaction: code=%d stderr=%q", r.code, r.stderr)
	}
	assertHeaderConflict(t, storeHeader(t, state, "chain-a", 100, cliRawRootFE, true),
		"chain-a", 100, cliRawRootFE, cliRawRootFF)
	assertHeaderConflict(t, storeHeader(t, state, "chain-a", 100, cliRootFFFD, true),
		"chain-a", 100, cliRootFFFD, cliRawRootFF)

	// Coverage and normal operation are intact: a proof-at-100 message delivers
	// citing the trusted height 100, and a proof-at-101 message keeps waiting.
	submitMsg(t, state, "m100", "chain-a", "chain-b", 1, 100)
	rep := advanceCLI(t, state, 2_000)
	got := resultFor(t, rep, "m100")
	if got.Status != "success" ||
		got.Reason != "delivered; proof verified by trusted header at height 100" {
		t.Fatalf("covered message must deliver under trusted height 100: %+v", got)
	}
}

// Surrounding whitespace and case in a root are raw content and stay distinct
// through fresh processes. (NUL bytes cannot be carried by argv at all —
// execve rejects them — so the NUL case is covered by the Go API tests in the
// relayproof package.)
func TestCLIHeaderRawRootSpacingAndCase(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	root := "r" + cliRawRootFF
	if r := storeHeader(t, state, "chain-a", 3, root, true); r.code != 0 {
		t.Fatalf("raw-byte root save: code=%d stderr=%q", r.code, r.stderr)
	}
	if r := storeHeader(t, state, "chain-a", 3, root, true); r.code != 0 {
		t.Fatalf("identical raw-byte root must resave: code=%d stderr=%q", r.code, r.stderr)
	}
	for _, other := range []string{"r" + cliRawRootFE, "R" + cliRawRootFF, root + " ", ""} {
		assertHeaderConflict(t, storeHeader(t, state, "chain-a", 3, other, true),
			"chain-a", 3, other, root)
	}
}

// saveFiller opens the state directory through the Go API and stores one large
// pending message as cheap log padding. The queue is closed before returning so
// the following CLI processes can take the directory lock.
func saveFiller(state, payload string) error {
	q, err := relayproof.Open(state)
	if err != nil {
		return err
	}
	defer q.Close()
	if _, err := q.Submit(relayproof.Envelope{
		Message: relayproof.Message{
			ID: "filler", From: "chain-a", To: "chain-b", Nonce: 42,
			Payload: payload, ProofAt: 100,
		},
		ExpiresAt: 9_000_000_000_000,
	}); err != nil {
		return err
	}
	return nil
}
