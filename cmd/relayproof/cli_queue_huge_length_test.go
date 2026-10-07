package main

// End-to-end behaviour when an existing state directory's queue.log declares
// an absurd record length right after the magic: the leading version record's
// body and checksum are not all present, so the directory is corrupt
// (ErrCorrupt), whatever the declared length is. `queue query` must fail with
// the corrupt exit code 12, explain the incomplete version record on stderr,
// print no query results, and leave queue.log byte-for-byte untouched — the
// huge declared length must never be wrapped into a crash, a truncated log,
// or a fabricated version record.

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cliLogWithHugeVersionLength builds a log whose first record declares a
// 2^32-1 byte body but carries almost nothing after the length header.
func cliLogWithHugeVersionLength() []byte {
	var raw []byte
	raw = append(raw, cliLogMagic...)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 0xFFFFFFFF)
	raw = append(raw, hdr[:]...)
	raw = append(raw, '{')
	return raw
}

func TestCLIQueryHugeVersionLengthCorruptExit12(t *testing.T) {
	state := t.TempDir()
	raw := cliLogWithHugeVersionLength()
	writeCLIStateLog(t, state, raw)

	for _, args := range [][]string{
		{"query"},
		{"query", "--id", "anything"},
	} {
		r := queueCLI(t, state, args[0], args[1:]...)
		if r.code != 12 {
			t.Fatalf("query %v: want corrupt exit code 12, got %d (stdout=%q stderr=%q)",
				args, r.code, r.stdout, r.stderr)
		}
		if r.stdout != "" {
			t.Fatalf("query %v: a corrupt directory must print no query results: %q", args, r.stdout)
		}
		for _, want := range []string{"corrupt", "incomplete version record"} {
			if !strings.Contains(r.stderr, want) {
				t.Fatalf("query %v: stderr missing %q:\n%s", args, want, r.stderr)
			}
		}
	}

	// The rejected opens left the log byte-for-byte in place for diagnosis.
	got, err := os.ReadFile(filepath.Join(state, "queue.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("queue.log changed on rejected open: want %d bytes, got %d bytes", len(raw), len(got))
	}
}
