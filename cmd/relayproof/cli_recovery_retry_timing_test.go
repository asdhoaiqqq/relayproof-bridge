package main

// End-to-end behaviour when an existing state directory's queue.log records,
// after a complete and well-checksummed waiting result (processed at 1000ms,
// retry scheduled for 2000ms), an equally complete success result stamped
// 1500ms — an outcome no legal advance can have produced, because the message
// is not processed again before its backoff expires. Opening the directory
// must fail with the corrupt exit code 12, print no query results, and leave
// queue.log byte-for-byte untouched: the offending record is complete and
// checksummed, so it is never dropped as a torn tail, and the good records
// before it are never served partially.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// earlyRetryLog is a log whose second result for message m predates the retry
// its first result scheduled: waiting at 1000 (retry at 2000), then a fully
// consistent success at 1500.
func earlyRetryLog() []byte {
	var raw []byte
	raw = append(raw, cliLogMagic...)
	raw = append(raw, cliFrame([]byte(`{"t":"version","v":1}`))...)
	raw = append(raw, cliFrame([]byte(`{"t":"source","chain":"a"}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":7,"proofAt":100}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"result","id":"m","now":1000,"status":"waiting","reason":"waiting for trusted header covering height 100 (current 0)","attempts":1,"nextRetry":2000}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"result","id":"m","now":1500,"status":"success","reason":"delivered; proof verified by trusted header at height 100","attempts":2,"consumeFrom":"a","consumeTo":"b","consumeNonce":7,"consumeBy":"m"}`))...)
	return raw
}

func assertEarlyRetryCorruptExit12(t *testing.T, r cliResult, state string, wantLog []byte) {
	t.Helper()
	if r.code != 12 {
		t.Fatalf("want corrupt exit code 12, got %d (stdout=%q stderr=%q)", r.code, r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a corrupt directory must print no query results: %q", r.stdout)
	}
	for _, want := range []string{"corrupt", `"m"`, "retry"} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("stderr missing %q:\n%s", want, r.stderr)
		}
	}
	got, err := os.ReadFile(filepath.Join(state, "queue.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wantLog) {
		t.Fatalf("queue.log changed on rejected open: want %d bytes, got %d bytes", len(wantLog), len(got))
	}
}

// The premature success rejects the whole directory on open: the query
// listing and a single-id lookup exit 12 without output, no command can open
// or append to the directory, and a repeated open keeps failing with the log
// byte-identical.
func TestCLIQueryEarlyRetrySuccessCorruptExit12(t *testing.T) {
	state := t.TempDir()
	raw := earlyRetryLog()
	writeCLIStateLog(t, state, raw)

	assertEarlyRetryCorruptExit12(t, queueCLI(t, state, "query"), state, raw)
	assertEarlyRetryCorruptExit12(t, queueCLI(t, state, "query", "--id", "m"), state, raw)

	// No other command can open the directory either, so nothing is appended
	// and the premature success never delivers or consumes the nonce.
	assertEarlyRetryCorruptExit12(t, queueCLI(t, state, "advance", "--now", "2000"), state, raw)
	assertEarlyRetryCorruptExit12(t, queueCLI(t, state, "submit",
		"--id", "n", "--from", "a", "--to", "b",
		"--nonce", "8", "--proof-at", "10", "--payload", "fresh"), state, raw)

	// The directory stays unopenable and byte-identical on a further attempt.
	assertEarlyRetryCorruptExit12(t, queueCLI(t, state, "query"), state, raw)
}

// A directory whose retry schedule is respected opens and queries normally:
// the same waiting result followed by the success at exactly the scheduled
// 2000ms recovers the delivered message with its two attempts.
func TestCLIQueryRetryAtScheduledInstantRecovers(t *testing.T) {
	state := t.TempDir()
	var raw []byte
	raw = append(raw, cliLogMagic...)
	raw = append(raw, cliFrame([]byte(`{"t":"version","v":1}`))...)
	raw = append(raw, cliFrame([]byte(`{"t":"source","chain":"a"}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":7,"proofAt":100}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"result","id":"m","now":1000,"status":"waiting","reason":"waiting for trusted header covering height 100 (current 0)","attempts":1,"nextRetry":2000}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"result","id":"m","now":2000,"status":"success","reason":"delivered; proof verified by trusted header at height 100","attempts":2,"consumeFrom":"a","consumeTo":"b","consumeNonce":7,"consumeBy":"m"}`))...)
	raw = append(raw, cliFrame([]byte(`{"t":"advance","now":2000}`))...)
	writeCLIStateLog(t, state, raw)

	r := queueCLI(t, state, "query", "--id", "m")
	if r.code != 0 {
		t.Fatalf("due retry must open: code=%d stderr=%q", r.code, r.stderr)
	}
	for _, want := range []string{`"status":"success"`, `"attempts":2`, `"reason":"delivered`} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("query output missing %s: %q", want, r.stdout)
		}
	}
}
