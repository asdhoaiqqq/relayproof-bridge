package relayproof

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// Regression coverage for the shutdown boundary where the reader delivers
// log bytes and the terminal status of the stream in the SAME Read call.
// A clean EOF arriving together with the final bytes is normal completion
// (including a final line that has no trailing newline), while a non-EOF
// read fault arriving with identical bytes must keep every newline-ended
// line but must never turn the trailing fragment into an event or a line
// failure: whether the fragment parses as a complete, field-valid JSON
// object is irrelevant, because it belongs to the failed read.
//
// Every scenario is scripted through scriptReader/failWriter from
// normalize_io_test.go, so the boundary reproduces deterministically
// offline without real pipes, networks, or device failures.

// mixedCompleteLines holds every kind of complete physical line:
//
//	line 1: a valid log
//	line 2: a blank line (no output, but it keeps its physical line number)
//	line 3: a field-invalid log (failure result with a reason)
//
// trailingFragment is a complete, field-valid JSON object WITHOUT a trailing
// newline: at a clean EOF it is the final complete log; under a read fault it
// is a fragment of the failed read.
func mixedCompleteLinesAndFragment() (complete, fragment string) {
	complete = validLog("a") + "\n" +
		"\n" +
		`{"timestamp":"not-a-time","action":"b"}` + "\n"
	fragment = `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-fragment"}`
	return complete, fragment
}

// The same bytes delivered in one Read, terminated by a clean EOF, are
// normal completion: every newline-ended line is processed in physical line
// order, the blank line only reserves its number, and the trailing
// newline-less JSON log still produces a result rather than being dropped.
func TestNormalizeIOEOFWithBytesInSameRead(t *testing.T) {
	complete, fragment := mixedCompleteLinesAndFragment()
	src := &scriptReader{steps: []scriptStep{
		// One step: all bytes and io.EOF become available together.
		{data: []byte(complete + fragment), err: io.EOF},
	}}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	if err != nil {
		t.Fatalf("bytes delivered with a clean EOF are normal completion, got %v", err)
	}
	if failures != 1 {
		t.Fatalf("only the one invalid complete line counts, got %d", failures)
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 3 {
		t.Fatalf("blank line emits nothing but the two valid logs and the invalid line do: %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must be the first valid log: %#v", results[0])
	}
	if eventOf(t, results[0])["action"] != "a" {
		t.Fatalf("line 1 content/order mismatch: %#v", results[0])
	}
	if results[1]["line"] != float64(3) || results[1]["ok"] != false {
		t.Fatalf("blank line 2 must reserve a number so the invalid log is line 3: %#v", results[1])
	}
	if msg, _ := results[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("invalid line must carry its reason, got %q", msg)
	}
	// The trailing newline-less log is a complete line at EOF and must not
	// be lost merely because EOF arrived in the same Read.
	if results[2]["line"] != float64(4) || results[2]["ok"] != true {
		t.Fatalf("trailing newline-less log must be processed as physical line 4: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "tail-fragment" {
		t.Fatalf("trailing log content mismatch: %#v", results[2])
	}
}

// Identical bytes delivered with a non-EOF read fault must end differently
// from a clean EOF: the newline-ended lines survive untouched and stay
// byte-for-byte identical to a healthy read of those same lines, while the
// trailing fragment is neither an event nor a failure even though it is a
// valid JSON object with every required field.
func TestNormalizeIOReadFaultWithBytesInSameRead(t *testing.T) {
	complete, fragment := mixedCompleteLinesAndFragment()
	src := &scriptReader{steps: []scriptStep{
		// One step: complete lines, a valid-JSON fragment, and the fault
		// all become available in the same Read.
		{data: []byte(complete + fragment), err: errSimulatedRead},
	}}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	if err == nil {
		t.Fatalf("a read fault must not be reported as normal completion")
	}
	if !errors.Is(err, ErrLogRead) {
		t.Fatalf("caller must recognize ErrLogRead, got %v", err)
	}
	if !errors.Is(err, errSimulatedRead) {
		t.Fatalf("the reader's original cause must stay reachable, got %v", err)
	}
	if errors.Is(err, ErrLogWrite) {
		t.Fatalf("a healthy writer must not tag the result as a write failure: %v", err)
	}
	if !strings.Contains(err.Error(), errSimulatedRead.Error()) {
		t.Fatalf("error text must retain the original read cause, got %q", err.Error())
	}
	if failures != 1 {
		t.Fatalf("the valid-JSON fragment must not add a failure; only the invalid complete line counts, got %d", failures)
	}

	// The fault must neither swallow already-delivered complete lines nor
	// turn them into failures: output must match a healthy read of the very
	// same complete lines exactly, including order and physical numbers.
	var healthy bytes.Buffer
	healthyFailures, healthyErr := NormalizeReader(strings.NewReader(complete), &healthy)
	if healthyErr != nil || healthyFailures != 1 {
		t.Fatalf("test setup: healthy reference read failed: failures=%d err=%v", healthyFailures, healthyErr)
	}
	if !bytes.Equal(out.Bytes(), healthy.Bytes()) {
		t.Fatalf("fault run output must equal a healthy read of the complete lines:\nfault:   %q\nhealthy: %q", out.String(), healthy.String())
	}

	results := decodeResults(t, out.Bytes())
	if len(results) != 2 {
		t.Fatalf("only the two non-blank complete lines may be emitted, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true ||
		results[1]["line"] != float64(3) || results[1]["ok"] != false {
		t.Fatalf("delivered lines keep their healthy-read order, numbers and outcomes: %#v", results)
	}
	if bytes.Contains(out.Bytes(), []byte("tail-fragment")) {
		t.Fatalf("the trailing valid-JSON fragment belongs to the failed read and must not become an event or failure record: %q", out.String())
	}
}

// A newline-less, fully valid JSON object alone with a read fault proves the
// admission rule is line completeness at the stream boundary, not whether
// the text parses: there must be no per-line output and no failure count,
// while the stream fault still reaches the caller.
func TestNormalizeIOValidJSONFragmentOnlyUnderFault(t *testing.T) {
	fragment := `{"timestamp":"2026-01-02T00:00:00Z","action":"lonely-fragment"}`
	src := &scriptReader{steps: []scriptStep{
		{data: []byte(fragment), err: errSimulatedRead},
	}}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
		t.Fatalf("want ErrLogRead wrapping the read cause, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("a parseable failed-read fragment must not count as a line failure, got %d", failures)
	}
	if out.Len() != 0 {
		t.Fatalf("no complete line means no output at all, got %q", out.String())
	}

	// The same fragment at a clean EOF is accepted: the differing outcome
	// comes solely from how the stream ended.
	var healthy bytes.Buffer
	healthyFailures, healthyErr := NormalizeReader(strings.NewReader(fragment), &healthy)
	if healthyErr != nil || healthyFailures != 0 {
		t.Fatalf("same bytes at clean EOF must be a healthy read, got failures=%d err=%v", healthyFailures, healthyErr)
	}
	results := decodeResults(t, healthy.Bytes())
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("clean-EOF fragment must be one successful result: %#v", results)
	}
}

// When the read fault and a shutdown write fault both happen, the read cause
// stays the primary error (ErrLogRead plus the original cause are reachable
// via errors.Is); the later write cause appears only in the message text and
// must not replace the read cause. The processed failure count is frozen at
// whatever the complete lines already produced. Unlike the two-step variant
// elsewhere, the fault and its complete-line bytes arrive in a single Read.
func TestNormalizeIOReadFaultWithBytesWinsOverFlushFault(t *testing.T) {
	complete, fragment := mixedCompleteLinesAndFragment()
	src := &scriptReader{steps: []scriptStep{
		{data: []byte(complete + fragment), err: errSimulatedRead},
	}}
	// Small records stay buffered in the 4096-byte writer, so the rejecting
	// writer is first touched by the shutdown flush after the read fault.
	w := &failWriter{err: errSimulatedWrite}
	failures, err := NormalizeReader(src, w)
	if err == nil {
		t.Fatalf("expected the read failure, got nil")
	}
	if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
		t.Fatalf("read failure and its cause must remain primary, got %v", err)
	}
	if errors.Is(err, ErrLogWrite) || errors.Is(err, errSimulatedWrite) {
		t.Fatalf("the later flush fault must not replace or shadow the read cause: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, errSimulatedRead.Error()) {
		t.Fatalf("message must name the read cause, got %q", msg)
	}
	if !strings.Contains(msg, errSimulatedWrite.Error()) {
		t.Fatalf("the shutdown write fault must remain visible in the message text, got %q", msg)
	}
	if failures != 1 {
		t.Fatalf("processed failure count must freeze at the one invalid complete line, got %d", failures)
	}
}
