package main

// End-to-end behaviour when a state directory's queue.log records a waiting
// result and then a success stamped before that message's scheduled retry.
// The record is complete and checksum-valid, and every other recovery rule
// passes, but no normal advance could have delivered the message — and
// consumed its nonce — while the backoff was still running. Opening the
// directory must fail with the corrupt exit code 12, print no query records
// (including none for an unrelated, fully valid message earlier in the log),
// explain the retry-timing violation on stderr, and leave queue.log
// byte-for-byte untouched.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cliEarlySuccessLog is a valid version record followed by: a registered
// source with a covering trusted header, a fully delivered message m0, and
// message w which waits at 1000ms (retry scheduled for 2000ms) but is then
// recorded successful at 1500ms — before its backoff elapsed.
func cliEarlySuccessLog() []byte {
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
		`{"t":"submit","seq":1,"id":"w","from":"a","to":"b","nonce":7,"proofAt":10}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"result","now":1000,"id":"w","status":"waiting",`+
			`"reason":"waiting for trusted header covering height 10 (current 100)","attempts":1,"nextRetry":2000}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"result","now":1500,"id":"w","status":"success",`+
			`"reason":"delivered; proof verified by trusted header at height 100","attempts":2,`+
			`"consumeFrom":"a","consumeTo":"b","consumeNonce":7,"consumeBy":"w"}`))...)
	raw = append(raw, cliFrame([]byte(`{"t":"advance","now":1500}`))...)
	return raw
}

// A pre-retry success rejects the whole directory on open: exit code 12, no
// query output at all — the valid m0 record must not be partially served —
// the error names the scheduling violation, and a repeated open keeps failing
// without rewriting the log.
func TestCLIQueryEarlySuccessDuringBackoffCorruptExit12(t *testing.T) {
	state := t.TempDir()
	raw := cliEarlySuccessLog()
	writeCLIStateLog(t, state, raw)

	check := func(r cliResult) {
		t.Helper()
		if r.code != 12 {
			t.Fatalf("want corrupt exit code 12, got %d (stdout=%q stderr=%q)", r.code, r.stdout, r.stderr)
		}
		if r.stdout != "" {
			t.Fatalf("a corrupt directory must print no query records: %q", r.stdout)
		}
		for _, want := range []string{"corrupt", "precedes scheduled retry 2000", `"w"`} {
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
