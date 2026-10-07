package main

// End-to-end behaviour when a state directory's queue.log records a complete,
// checksum-valid success whose source chain was never registered: trusted
// coverage, retry timing and nonce attribution are all legal, but no normal
// advance could have delivered the message — and consumed its nonce — without
// a registration; normal processing would have terminalized it as
// unknown-source. Reopening the directory must fail with the corrupt exit
// code 12, print no query records (including none for an unrelated, fully
// legal success earlier in the log), name the message, its source chain and
// the missing registration on stderr, and leave queue.log byte-for-byte
// untouched even though the bad record is the very last frame.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cliUnregisteredSuccessLog is a valid version record followed by: a
// registered source "a" with a trusted header at 100 and the fully legal
// success m0 (proof 10), then message m1 from never-registered chain "u" —
// covered by a trusted header at 300, proving at 90 — whose success is the
// final frame.
func cliUnregisteredSuccessLog() []byte {
	var raw []byte
	raw = append(raw, cliLogMagic...)
	raw = append(raw, cliFrame([]byte(`{"t":"version","v":1}`))...)
	raw = append(raw, cliFrame([]byte(`{"t":"source","chain":"a"}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"header","chain":"a","height":100,"root":"0x100","trusted":true}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"submit","seq":0,"id":"m0","from":"a","to":"b","nonce":1,"proofAt":10}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"result","now":500,"id":"m0","status":"success",`+
			`"reason":"delivered; proof verified by trusted header at height 100","attempts":1,`+
			`"consumeFrom":"a","consumeTo":"b","consumeNonce":1,"consumeBy":"m0"}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"header","chain":"u","height":300,"root":"0x300","trusted":true}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"submit","seq":1,"id":"m1","from":"u","to":"b","nonce":7,"proofAt":90}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"result","now":1000,"id":"m1","status":"success",`+
			`"reason":"delivered; proof verified by trusted header at height 300","attempts":1,`+
			`"consumeFrom":"u","consumeTo":"b","consumeNonce":7,"consumeBy":"m1"}`))...)
	return raw
}

// A success from a source chain that was never registered rejects the whole
// directory on open: exit code 12, no query output at all — the valid m0
// record must not be partially served — stderr names the message, its source
// chain and the missing registration, and a repeated open keeps failing
// without rewriting the log, bad final frame included.
func TestCLIQueryUnregisteredSuccessCorruptExit12(t *testing.T) {
	state := t.TempDir()
	raw := cliUnregisteredSuccessLog()
	writeCLIStateLog(t, state, raw)

	check := func(r cliResult) {
		t.Helper()
		if r.code != 12 {
			t.Fatalf("want corrupt exit code 12, got %d (stdout=%q stderr=%q)", r.code, r.stdout, r.stderr)
		}
		if r.stdout != "" {
			t.Fatalf("a corrupt directory must print no query records: %q", r.stdout)
		}
		for _, want := range []string{
			"corrupt",
			"is not registered",
			`"m1"`,
			`source chain "u"`,
		} {
			if !strings.Contains(r.stderr, want) {
				t.Fatalf("stderr missing %q:\n%s", want, r.stderr)
			}
		}
		got, err := os.ReadFile(filepath.Join(state, "queue.log"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(raw) {
			t.Fatalf("queue.log changed on rejected open: want %d bytes, got %d bytes", len(raw), len(got))
		}
	}

	check(queueCLI(t, state, "query"))
	check(queueCLI(t, state, "query", "--id", "m0"))
	check(queueCLI(t, state, "advance", "--now", "3000"))

	// The bytes survive a second rejected open as well.
	check(queueCLI(t, state, "query"))
}
