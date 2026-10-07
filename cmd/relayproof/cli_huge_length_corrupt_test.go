package main

// End-to-end behaviour when an existing state directory's queue.log declares
// a huge record length the file does not contain. The four-byte length header
// is an unsigned 32-bit value, and opening such a directory must never crash
// (on 32-bit builds the declared length used to go negative or overflow the
// frame extent, panicking with a slice out of range):
//
//   - when the FIRST record after the magic — the version record — declares a
//     body/checksum that is not fully present, `queue query` must fail with a
//     clear corruption error and the corrupt exit code 12, print no query
//     results, and leave queue.log byte-for-byte untouched (never truncated
//     to a magic-only shell, never rewritten with a fabricated version
//     record);
//   - when a complete, checksum-valid version record and good records come
//     first, a final record whose declared huge length runs past end of file
//     is the torn tail of an unacknowledged write: it is dropped, the earlier
//     messages are recovered, and `queue query` serves them normally.

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cliLogWithHugeFirstLength builds a log whose first record after the magic
// declares a payload of declared bytes while only bodyBytes of content
// actually follow.
func cliLogWithHugeFirstLength(declared uint32, bodyBytes int) []byte {
	raw := append([]byte(cliLogMagic), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(raw[len(cliLogMagic):], declared)
	return append(raw, make([]byte, bodyBytes)...)
}

// assertHugeLengthCorruptExit12 pins the corruption surface for a huge
// declared first-record length: exit code 12, no stdout query output, a
// stderr explanation naming the corruption, and an unchanged queue.log.
func assertHugeLengthCorruptExit12(t *testing.T, r cliResult, state string, wantLog []byte) {
	t.Helper()
	if r.code != 12 {
		t.Fatalf("want corrupt exit code 12, got %d (stdout=%q stderr=%q)", r.code, r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a corrupt directory must print no query results: %q", r.stdout)
	}
	if !strings.Contains(r.stderr, "corrupt") {
		t.Fatalf("stderr must name the corruption:\n%s", r.stderr)
	}
	got, err := os.ReadFile(filepath.Join(state, "queue.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wantLog) {
		t.Fatalf("queue.log changed on rejected open: want %d bytes, got %d bytes", len(wantLog), len(got))
	}
}

// A version record declaring 2147483648 or 4294967295 bytes of payload that
// the file does not hold rejects the directory: both the listing and a
// single-id lookup exit 12 without output, and a repeated open keeps failing
// with the file byte-identical.
func TestCLIQueryHugeVersionRecordLengthExit12(t *testing.T) {
	for _, declared := range []uint32{2147483647, 2147483648, 4294967295} {
		state := t.TempDir()
		raw := cliLogWithHugeFirstLength(declared, 8)
		writeCLIStateLog(t, state, raw)

		assertHugeLengthCorruptExit12(t, queueCLI(t, state, "query"), state, raw)
		assertHugeLengthCorruptExit12(t, queueCLI(t, state, "query", "--id", "anything"), state, raw)
		assertHugeLengthCorruptExit12(t, queueCLI(t, state, "query"), state, raw)
	}
}

// A final record declaring a huge length past end of file, behind a valid
// version record and good records, is dropped as the torn tail: the CLI
// recovers the acknowledged messages and the queue keeps working.
func TestCLIQueryHugeFinalRecordLengthRecovers(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0x100", true); r.code != 0 {
		t.Fatalf("store header: %v", r)
	}
	submitMsg(t, state, "m1", "chain-a", "chain-b", 1, 90)
	advanceCLI(t, state, 1_700_000_000_000)

	// Append a torn final frame: a huge declared length with only a few body
	// bytes actually written.
	path := filepath.Join(state, "queue.log")
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	torn := append(good[:len(good):len(good)], 0, 0, 0, 0)
	binary.BigEndian.PutUint32(torn[len(good):], 4294967295)
	torn = append(torn, 1, 2, 3)
	writeCLIStateLog(t, state, torn)

	// The acknowledged message is served; the torn record never existed.
	all := queryAll(t, state)
	if len(all) != 1 || all[0].ID != "m1" || all[0].Status != "success" {
		t.Fatalf("recovered listing wrong: %+v", all)
	}

	// Only the torn frame was removed; the prefix is byte-identical.
	repaired, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(repaired) != string(good) {
		t.Fatalf("recovery must drop only the torn frame: want %d bytes, got %d", len(good), len(repaired))
	}

	// The recovered queue accepts new work through the CLI.
	submitMsg(t, state, "m2", "chain-a", "chain-b", 2, 90)
	rep := advanceCLI(t, state, 1_700_000_001_000)
	if got := resultFor(t, rep, "m2"); got.Status != "success" {
		t.Fatalf("new message should deliver on recovered queue: %+v", got)
	}
}
