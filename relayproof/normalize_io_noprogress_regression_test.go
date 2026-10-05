package relayproof

// Regression coverage for input streams that stall: a Reader that keeps
// returning (0, nil) — no bytes, no error, no EOF — reports no progress, and
// NormalizeReader must not wait for it forever. The contract asserted here:
//
//   - After 101 CONSECUTIVE empty reads the run stops and the caller receives
//     an input-stream failure recognizable via errors.Is as BOTH ErrLogRead
//     and io.ErrNoProgress. It is not normal completion, not a per-line log
//     failure, and not an output failure, and nothing is read afterwards —
//     logs that appear only after the stall are never consumed.
//   - Already-processed complete lines keep exactly their healthy results:
//     valid logs keep their normalized events, invalid logs keep their
//     physical line numbers and reasons, blank lines only consume a number,
//     and the failure count covers only normalization failures. A newline-less
//     tail buffered when the stall hits belongs to the unfinished read: even
//     a field-complete valid JSON object is neither emitted nor counted.
//   - "Consecutive" is taken literally: 100 empty reads followed by bytes
//     recovers normally, and ANY non-empty delivery — even a single byte that
//     does not complete a log line — resets the streak, so several sub-limit
//     empty stretches interleaved with log fragments must not fail on their
//     cumulative count. A clean EOF afterwards still processes a newline-less
//     final line by the ordinary rules.
//
// A zero-value scriptStep{} is exactly one (0, nil) read, so every stall is
// scripted through scriptReader from normalize_io_test.go and reproduces
// deterministically offline.

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// readCounter wraps a Reader and counts every Read call, so tests can prove
// the run stopped reading at the stall instead of consuming later input.
type readCounter struct {
	r     io.Reader
	reads int
}

func (c *readCounter) Read(p []byte) (int, error) {
	c.reads++
	return c.r.Read(p)
}

// emptySteps returns n script steps that each read as (0, nil): no bytes, no
// error, no EOF — one progress-less read apiece.
func emptySteps(n int) []scriptStep {
	return make([]scriptStep, n)
}

// expectNoProgressFailure is the shared error-classification contract for a
// stalled input: an input-stream failure that is both ErrLogRead and
// io.ErrNoProgress, never a write failure, and never nil.
func expectNoProgressFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("a stalled input must not be reported as normal completion, got nil error")
	}
	if !errors.Is(err, ErrLogRead) {
		t.Fatalf("stalled input must classify as the read failure, got %v", err)
	}
	if !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("stalled input must be recognizable as io.ErrNoProgress, got %v", err)
	}
	if errors.Is(err, ErrLogWrite) {
		t.Fatalf("a healthy writer must not tag the stall as a write failure: %v", err)
	}
}

// The input answers (0, nil) forever from the very first Read. The run must
// stop after the 101st consecutive empty read with the no-progress failure:
// zero failures (no complete line was ever processed, so nothing failed
// normalization), empty output (no fabricated failure record), and no further
// Read — the valid log scripted right after the stall is never consumed.
func TestNormalizeIOStalledInputFromStartStops(t *testing.T) {
	steps := append(emptySteps(101),
		scriptStep{data: []byte(validLog("after-stall") + "\n")})
	src := &readCounter{r: &scriptReader{steps: steps}}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	expectNoProgressFailure(t, err)
	if failures != 0 {
		t.Fatalf("no complete line was processed, so no log can have failed, got %d failures", failures)
	}
	if out.Len() != 0 {
		t.Fatalf("a stall before any complete line must not fabricate a failure record, got %q", out.String())
	}
	if src.reads != 101 {
		t.Fatalf("must stop at the 101st consecutive empty read without reading on, got %d reads", src.reads)
	}
	if bytes.Contains(out.Bytes(), []byte("after-stall")) {
		t.Fatalf("input offered only after the stall must never be read: %q", out.String())
	}
}

// Complete lines processed before the stall keep exactly their healthy
// results — the valid logs their events, the invalid log its physical line
// number and reason, the blank line only its number — and the newline-less
// tail buffered when the streak begins is part of the unfinished read: even
// though it is a field-complete valid JSON object, it is neither emitted as a
// final line nor counted as a failure. Logs scripted after the stall are
// never read.
func TestNormalizeIOStallPreservesEarlierResults(t *testing.T) {
	complete := validLog("a") + "\n" +
		`{"timestamp":"not-a-time","action":"b"}` + "\n" +
		"\n" + // blank: consumes physical line 3 only
		validLog("d") + "\n"
	fragment := `{"timestamp":"2026-01-02T00:00:00Z","action":"stall-tail"}`

	var healthy bytes.Buffer
	healthyFailures, healthyErr := NormalizeReader(strings.NewReader(complete), &healthy)
	if healthyErr != nil || healthyFailures != 1 {
		t.Fatalf("test setup: healthy reference read failed: failures=%d err=%v", healthyFailures, healthyErr)
	}

	steps := []scriptStep{{data: []byte(complete + fragment)}}
	steps = append(steps, emptySteps(101)...)
	steps = append(steps, scriptStep{data: []byte(validLog("after-stall") + "\n")})
	src := &readCounter{r: &scriptReader{steps: steps}}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	expectNoProgressFailure(t, err)
	if failures != 1 {
		t.Fatalf("only the invalid complete line 2 counts; the stall tail adds nothing, got %d failures", failures)
	}
	if src.reads != 102 {
		t.Fatalf("one data read plus 101 empty reads, then stop: got %d reads", src.reads)
	}

	// The pre-stall results are whole, line-readable JSON records identical
	// to a healthy read of the complete lines: nothing lost, nothing
	// duplicated, nothing renumbered by the blank line.
	if !bytes.Equal(out.Bytes(), healthy.Bytes()) {
		t.Fatalf("pre-stall results must equal a healthy read of the complete lines:\nstall:   %q\nhealthy: %q", out.String(), healthy.String())
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 3 {
		t.Fatalf("expected the 3 non-blank complete lines only, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must keep its success: %#v", results[0])
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != false {
		t.Fatalf("invalid line must keep physical number 2: %#v", results[1])
	}
	if msg, _ := results[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("line 2 must keep its timestamp-specific reason, got %q", msg)
	}
	if results[2]["line"] != float64(4) || results[2]["ok"] != true {
		t.Fatalf("the blank line 3 must only consume a number; line 4 keeps its success: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "d" {
		t.Fatalf("line 4 event mismatch: %#v", results[2])
	}
	if bytes.Contains(out.Bytes(), []byte("stall-tail")) {
		t.Fatalf("the newline-less tail is part of the unfinished read and must leave no record: %q", out.String())
	}
	if bytes.Contains(out.Bytes(), []byte("after-stall")) {
		t.Fatalf("input offered only after the stall must never be read: %q", out.String())
	}
}

// A streak of exactly 100 consecutive empty reads stays under the limit:
// when bytes arrive again the run recovers and processes them normally.
func TestNormalizeIOHundredEmptyReadsThenRecovery(t *testing.T) {
	steps := append(emptySteps(100),
		scriptStep{data: []byte(validLog("recovered") + "\n")})
	src := &readCounter{r: &scriptReader{steps: steps}}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	if err != nil {
		t.Fatalf("100 consecutive empty reads must not trip the limit, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("a valid log after recovery must report zero failures, got %d", failures)
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("the recovered log must be processed normally: %#v", results)
	}
	if eventOf(t, results[0])["action"] != "recovered" {
		t.Fatalf("recovered log content mismatch: %#v", results[0])
	}
}

// Any non-empty delivery ends an empty streak, even a single byte that does
// not complete a log line: sub-limit empty stretches interleaved with log
// fragments must not fail on their cumulative count (far beyond 101 here),
// and the newline-less final line at the clean EOF is still emitted by the
// ordinary rules.
func TestNormalizeIOAnyBytesResetTheEmptyStreak(t *testing.T) {
	line1 := validLog("piecewise") + "\n"
	line2 := validLog("tail-complete") // no trailing newline

	var steps []scriptStep
	// Deliver line 1 in fragments — the first a single byte — with 100 empty
	// reads before every fragment after the first. Each stretch stays under
	// the limit, but their sum exceeds it many times over.
	first := true
	for i := 0; i < len(line1); i += 7 {
		end := i + 7
		if end > len(line1) {
			end = len(line1)
		}
		if !first {
			steps = append(steps, emptySteps(100)...)
		}
		first = false
		steps = append(steps, scriptStep{data: []byte(line1[i:end])})
	}
	// The newline-less final line also arrives in pieces separated by
	// sub-limit empty stretches; script exhaustion then reports a clean EOF.
	steps = append(steps, emptySteps(100)...)
	half := len(line2) / 2
	steps = append(steps,
		scriptStep{data: []byte(line2[:half])},
	)
	steps = append(steps, emptySteps(100)...)
	steps = append(steps, scriptStep{data: []byte(line2[half:])})

	src := &readCounter{r: &scriptReader{steps: steps}}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	if err != nil {
		t.Fatalf("sub-limit empty stretches must not fail on cumulative count, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("two valid logs must report zero failures, got %d", failures)
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 2 {
		t.Fatalf("expected the piecewise line and the newline-less final line, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must be assembled from its fragments: %#v", results[0])
	}
	if eventOf(t, results[0])["action"] != "piecewise" {
		t.Fatalf("line 1 content mismatch: %#v", results[0])
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != true {
		t.Fatalf("the newline-less final line must be emitted at clean EOF: %#v", results[1])
	}
	if eventOf(t, results[1])["action"] != "tail-complete" {
		t.Fatalf("final line content mismatch: %#v", results[1])
	}
}
