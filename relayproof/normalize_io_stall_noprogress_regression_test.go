package relayproof

// Regression coverage for an input source that makes no progress the way a
// stuck reader does: Read keeps returning (0, nil) — no bytes, no EOF, no
// error. A short run of such answers is tolerated (a source may briefly
// have nothing ready), but it must not be waited on forever: the 101st
// consecutive zero-byte, nil-error Read ends the run as an input-stream
// fault. The fixed contract asserted here:
//
//   - the returned error is non-nil and errors.Is matches BOTH ErrLogRead
//     and io.ErrNoProgress, while never matching ErrLogWrite, so the stall
//     can never look like normal completion, a single bad log line, or an
//     output fault;
//   - reading stops at the Read call that reaches the limit: a log the
//     source could deliver afterwards is never read or emitted, and a stall
//     never fabricates a failure record of its own — with no complete line
//     processed the failure count is zero despite the non-nil error;
//   - complete lines already processed survive untouched (valid logs keep
//     their events, invalid logs keep physical line number and reason,
//     blank lines only occupy a number), the failure count covers only
//     lines that failed normalization, and results are neither lost nor
//     duplicated;
//   - bytes received without a terminating newline stay an unfinished read
//     even when they are already a complete, field-valid JSON object: the
//     stall neither emits them as a final line nor counts them;
//   - the streak is CONSECUTIVE: 100 empty reads followed by bytes resume
//     normally, and ANY non-empty delivery — even a single byte that does
//     not complete a line — restarts the count, so several sub-limit empty
//     stretches interleaved with log fragments never accumulate into an
//     early failure; at a later clean EOF the newline-less final line is
//     still emitted under the existing rule.
//
// Every scenario is scripted in-process with scriptReader from
// normalize_io_test.go, so the boundary reproduces deterministically
// offline without real pipes, networks, timers, or device failures.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

// emptyReadSteps returns n scripted Read calls that deliver no bytes and
// report no error: the exact answer a wedged source gives while it neither
// produces data nor admits failure.
func emptyReadSteps(n int) []scriptStep {
	return make([]scriptStep, n)
}

// stalledTail is a valid log the source only becomes able to deliver
// AFTER the stall limit. A run that stops on time must leave this step
// unread; if it is consumed or emitted the run read past the fault.
func stalledTail() scriptStep {
	return scriptStep{data: []byte(validLog("delivered-after-stall") + "\n")}
}

// assertStallFault checks the public shape of a stalled-read return: a
// non-nil error recognizable as both ErrLogRead and io.ErrNoProgress, never
// as ErrLogWrite, carrying the progress-failure wording.
func assertStallFault(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("101 consecutive (0, nil) Reads must be a stream fault, got normal completion")
	}
	if !errors.Is(err, ErrLogRead) {
		t.Fatalf("stall must be reported as an input-stream fault (ErrLogRead), got %v", err)
	}
	if !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("caller must recognize the stall via io.ErrNoProgress, got %v", err)
	}
	if errors.Is(err, ErrLogWrite) {
		t.Fatalf("a stall with a healthy writer must not be classified as a write fault: %v", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte(io.ErrNoProgress.Error())) {
		t.Fatalf("error text must explain the lack of progress, got %q", err.Error())
	}
}

// With no complete line ever delivered, 101 consecutive empty reads are a
// fault that reports zero failed logs and writes nothing: the stall must
// not masquerade as a successful empty stream nor as one bad log line.
func TestNormalizeIOStallBeforeAnyLine(t *testing.T) {
	steps := append(emptyReadSteps(101), stalledTail())
	src := &scriptReader{steps: steps}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	assertStallFault(t, err)
	if failures != 0 {
		t.Fatalf("no complete log was processed, so the failure count must be 0, got %d", failures)
	}
	if out.Len() != 0 {
		t.Fatalf("a stall with no complete line must emit no record, got %q", out.String())
	}
	if src.i != 101 {
		t.Fatalf("reading must stop at the 101st empty Read, consumed %d of %d scripted steps", src.i, len(steps))
	}
	if bytes.Contains(out.Bytes(), []byte("delivered-after-stall")) {
		t.Fatalf("logs appearing only after the stall must never be emitted: %q", out.String())
	}
}

// A complete, field-valid JSON object already received WITHOUT a trailing
// newline is still an unfinished read when the source stalls: it must
// neither become the final result nor count as a failure, even though at a
// clean EOF the same bytes would be accepted as the last line.
func TestNormalizeIOStallKeepsPendingFragmentUnfinished(t *testing.T) {
	fragment := `{"timestamp":"2026-01-02T00:00:00Z","action":"stalled-pending-fragment"}`
	steps := append([]scriptStep{{data: []byte(fragment)}}, emptyReadSteps(101)...)
	steps = append(steps, stalledTail())
	src := &scriptReader{steps: steps}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	assertStallFault(t, err)
	if failures != 0 {
		t.Fatalf("the newline-less pending object is not a processed log, failures must be 0, got %d", failures)
	}
	if out.Len() != 0 {
		t.Fatalf("the pending object must not be finalized as a last line on a stall, got %q", out.String())
	}
	if src.i != 102 {
		t.Fatalf("run must stop on the 101st empty Read after the fragment, consumed %d of %d steps", src.i, len(steps))
	}
}

// Complete lines already in hand when the source stalls must survive
// exactly as a healthy read of the same prefix would leave them: a valid
// log keeps its event, a blank line only reserves its physical number, an
// invalid log keeps that number and its reason and is the only counted
// failure, and nothing is lost, repeated, or reordered. The pending
// newline-less object (valid JSON) stays out, and the source is not read
// again after the limit is reached.
func TestNormalizeIOStallPreservesProcessedResults(t *testing.T) {
	complete, fragment := mixedCompleteLinesAndFragment()
	steps := []scriptStep{
		{data: []byte(complete)},
		{data: []byte(fragment)}, // newline-less valid object, left unfinished
	}
	steps = append(steps, emptyReadSteps(101)...)
	steps = append(steps, stalledTail())
	src := &scriptReader{steps: steps}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	assertStallFault(t, err)
	if failures != 1 {
		t.Fatalf("only the one invalid complete line counts, got %d failures", failures)
	}
	if src.i != 103 {
		t.Fatalf("processing must stop at the 101st empty Read (2 data Reads + 101), consumed %d of %d steps", src.i, len(steps))
	}

	// Output must be byte-for-byte the healthy prefix: two whole records in
	// physical order with no fabricated stall record and no duplication.
	var healthy bytes.Buffer
	healthyFailures, healthyErr := NormalizeReader(bytes.NewReader([]byte(complete)), &healthy)
	if healthyErr != nil || healthyFailures != 1 {
		t.Fatalf("test setup: healthy reference read failed: failures=%d err=%v", healthyFailures, healthyErr)
	}
	if !bytes.Equal(out.Bytes(), healthy.Bytes()) {
		t.Fatalf("stall output must equal a healthy read of the complete prefix:\nstall:   %q\nhealthy: %q", out.String(), healthy.String())
	}

	results := decodeResults(t, out.Bytes())
	if len(results) != 2 {
		t.Fatalf("the valid log and the invalid log each appear exactly once, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must survive as a valid event: %#v", results[0])
	}
	if eventOf(t, results[0])["action"] != "a" {
		t.Fatalf("line 1 content/order mismatch: %#v", results[0])
	}
	if results[1]["line"] != float64(3) || results[1]["ok"] != false {
		t.Fatalf("blank line 2 only reserves a number, so the invalid log stays line 3: %#v", results[1])
	}
	if msg, _ := results[1]["error"].(string); msg == "" || !bytes.Contains([]byte(msg), []byte(FieldTimestamp)) {
		t.Fatalf("invalid line must keep its concrete reason, got %q", msg)
	}
	if bytes.Contains(out.Bytes(), []byte("tail-fragment")) {
		t.Fatalf("the pending newline-less object must not be finalized on a stall: %q", out.String())
	}
	if bytes.Contains(out.Bytes(), []byte("delivered-after-stall")) {
		t.Fatalf("input appearing only after the stall must never be read or emitted: %q", out.String())
	}
}

// Exactly 100 consecutive empty reads sit at the tolerated boundary: bytes
// arriving on the next call resume normal processing, whether the empty
// stretch comes before the first log or between two logs. The final
// newline-less line is still finalized normally at EOF.
func TestNormalizeIOStallHundredEmptyReadsStillRecover(t *testing.T) {
	steps := emptyReadSteps(100)
	steps = append(steps,
		scriptStep{data: []byte(validLog("a") + "\n")},
	)
	steps = append(steps, emptyReadSteps(100)...)
	steps = append(steps,
		scriptStep{data: []byte(validLog("b"))}, // no trailing newline
		scriptStep{err: io.EOF},
	)
	src := &scriptReader{steps: steps}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	if err != nil {
		t.Fatalf("two runs of exactly 100 tolerated empty reads must end normally, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("all logs valid, got %d failures", failures)
	}
	if src.i != len(steps) {
		t.Fatalf("recovery must consume the whole scripted stream, read %d of %d steps", src.i, len(steps))
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 2 {
		t.Fatalf("both logs around the empty stretches must be emitted, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[1]["line"] != float64(2) {
		t.Fatalf("physical line numbers must be unaffected by empty reads: %#v", results)
	}
	if eventOf(t, results[1])["action"] != "b" {
		t.Fatalf("the newline-less final line must finalize normally after recovery: %#v", results[1])
	}
}

// ANY non-empty delivery ends the consecutive-empty streak, even a single
// byte that does not complete a log line: 100 empties, then one '{', then
// 101 more empties must trip only the SECOND streak, and the lone byte must
// never become output. The scripted step after the trip stays unread.
func TestNormalizeIOStallSingleByteRestartsCounting(t *testing.T) {
	steps := []scriptStep{{data: []byte(validLog("a") + "\n")}}
	steps = append(steps, emptyReadSteps(100)...)
	steps = append(steps, scriptStep{data: []byte("{")}) // one byte, no newline
	steps = append(steps, emptyReadSteps(101)...)
	steps = append(steps, stalledTail())
	src := &scriptReader{steps: steps}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	assertStallFault(t, err)
	if failures != 0 {
		t.Fatalf("the lone byte never completed a log; failures must be 0, got %d", failures)
	}
	// 1 data Read + 100 + 1 byte + 101 empties = 203; the post-stall step
	// must remain unread. Stopping earlier (on the first streak) or later
	// (reading past the trip) fails this position check.
	wantReads := 1 + 100 + 1 + 101
	if src.i != wantReads {
		t.Fatalf("the second 101-empty streak must trip at Read %d, consumed %d of %d steps", wantReads, src.i, len(steps))
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("only the complete log before the streaks may be emitted, got %#v", results)
	}
	if eventOf(t, results[0])["action"] != "a" {
		t.Fatalf("surviving record content mismatch: %#v", results[0])
	}
	if bytes.Contains(out.Bytes(), []byte("delivered-after-stall")) {
		t.Fatalf("input delivered after the trip must not be read: %q", out.String())
	}
}

// Several empty stretches, each below the limit and separated by fragments
// of one log line, must not accumulate into a failure: counting is per
// consecutive streak, not cumulative. The line fragments only reunite at a
// clean EOF, where the newline-less final log is emitted under the existing
// final-line rule.
func TestNormalizeIOStallSubLimitStretchesDoNotAccumulate(t *testing.T) {
	line := validLog("seg-tail")
	if len(line) < 30 {
		t.Fatalf("test setup: fragment split point out of range")
	}
	first, rest := line[:25], line[25:]
	steps := []scriptStep{{data: []byte(validLog("a") + "\n")}}
	steps = append(steps, emptyReadSteps(99)...)
	steps = append(steps, scriptStep{data: []byte(first)}) // no newline yet
	steps = append(steps, emptyReadSteps(99)...)
	steps = append(steps, scriptStep{data: []byte(rest)}) // completes the object, still no newline
	steps = append(steps, emptyReadSteps(99)...)
	steps = append(steps, scriptStep{err: io.EOF})
	src := &scriptReader{steps: steps}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	if err != nil {
		t.Fatalf("three sub-limit empty stretches (297 empty reads in total) must not fail, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("all logs valid, got %d failures", failures)
	}
	if src.i != len(steps) {
		t.Fatalf("a healthy stream must be read to its EOF step, read %d of %d", src.i, len(steps))
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 2 {
		t.Fatalf("the fragmented final log must reassemble into one record, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[1]["line"] != float64(2) || results[1]["ok"] != true {
		t.Fatalf("both logs must appear once with correct physical numbers: %#v", results)
	}
	if eventOf(t, results[1])["action"] != "seg-tail" {
		t.Fatalf("fragments reunited at EOF must produce the intended final event, got %#v", results[1])
	}
}

// Sanity guard for the scripting itself: the threshold the contract names is
// 101 consecutive empty reads, so 101 is the smallest number that faults.
// This keeps the other tests' counts honest if the bound is ever adjusted.
func TestNormalizeIOStallThresholdIsDocumentedBoundary(t *testing.T) {
	for _, n := range []int{101, 102} {
		t.Run(fmt.Sprintf("%d empty reads", n), func(t *testing.T) {
			src := &scriptReader{steps: emptyReadSteps(n)}
			failures, err := NormalizeReader(src, &bytes.Buffer{})
			if err == nil || !errors.Is(err, ErrLogRead) || !errors.Is(err, io.ErrNoProgress) {
				t.Fatalf("%d consecutive empty reads must be a stall fault, got failures=%d err=%v", n, failures, err)
			}
			if src.i != 101 {
				t.Fatalf("must stop exactly on the 101st empty Read regardless of script length, consumed %d", src.i)
			}
		})
	}
}
