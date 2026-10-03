package relayproof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// These regressions pin down how NormalizeReader reports input/output
// interruptions separately from per-line validation failures:
//
//   - a line that fails normalization is data, not an I/O fault: it stays in
//     the output with its physical line number, later lines keep processing,
//     and the returned error is nil;
//   - a read fault after complete lines surfaces as the returned error,
//     already read lines are still emitted in order, and the fault is never
//     counted as a failed log or rendered as an extra event/line error;
//   - a write fault (mid-stream or while flushing the final batch) surfaces
//     as the returned error without changing the accumulated failure count;
//   - when both a read fault and a close-time write fault happen, the earlier
//     read fault is what the caller receives;
//   - clean EOF, including a final line without a newline, stays error-free.
//
// All faults are produced by in-memory test doubles, so the behavior is
// reproduced offline and deterministically with no network or device reliance.

var (
	errBoomRead  = errors.New("synthetic read interruption")
	errBoomWrite = errors.New("synthetic write interruption")
)

// failingReader serves prefix verbatim on the first Read, then returns
// (0, readFault) on every later Read.
type failingReader struct {
	prefix    string
	readFault error
	read      bool
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.read {
		return 0, f.readFault
	}
	f.read = true
	return copy(p, f.prefix), nil
}

// repeatReader hands out one chunk per Read call. When faultWithLast is true
// the final chunk is delivered together with fault (bufio keeps those bytes
// while remembering the pending error); otherwise fault is reported on the
// Read after the chunks run out.
type repeatReader struct {
	chunks        []string
	pos           int
	fault         error
	faultWithLast bool
	faulted       bool
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.faulted {
		return 0, r.fault
	}
	if r.pos >= len(r.chunks) {
		r.faulted = true
		return 0, r.fault
	}
	n := copy(p, r.chunks[r.pos])
	r.pos++
	if r.faultWithLast && r.pos >= len(r.chunks) {
		r.faulted = true
		return n, r.fault
	}
	return n, nil
}

// failingWriter records every byte it accepts until failAfter writes; the
// next Write fails with fault and every Write afterwards fails too.
type failingWriter struct {
	sink      bytes.Buffer
	failAfter int // number of successful Write calls before failing
	write     int
	fault     error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.write >= w.failAfter {
		return 0, w.fault
	}
	w.write++
	return w.sink.Write(p)
}

// decodeResultsLenient parses as many complete JSON result objects as the
// output contains. After a write interruption the residue may be a partial
// JSON line, so a trailing decode error is expected and ignored here; tests
// that need a guaranteed-complete output decode the prefix explicitly.
func decodeResultsLenient(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var results []map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			break
		}
		results = append(results, m)
	}
	return results
}

// assertResultsComplete decodes exactly want results and fails if the output
// is truncated or contains anything after the last object.
func assertResultsComplete(t *testing.T, raw []byte, want int) []map[string]any {
	t.Helper()
	var results []map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("output must be %d complete JSON lines, decode failed: %v; output=%q", want, err, raw)
			}
			break
		}
		results = append(results, m)
	}
	if len(results) != want {
		t.Fatalf("expected %d complete result lines, got %d: %q", want, len(results), raw)
	}
	return results
}

func validLog(action string) string {
	return `{"timestamp":"2026-01-02T00:00:00Z","action":"` + action + `"}`
}

// TestNormalizeInvalidLineIsDataNotIOError reproduces the baseline contract:
// an invalid log line amid legal ones is a numbered per-line failure, later
// legal logs still come out, and — with healthy I/O — the run error is nil
// while the failure count reflects only the bad logs themselves.
func TestNormalizeInvalidLineIsDataNotIOError(t *testing.T) {
	input := validLog("a") + "\n" +
		"not json at all\n" +
		`{"timestamp":"bad","action":"c"}` + "\n" +
		validLog("d") + "\n"
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("per-line validation failures must not surface as an I/O error, got %v", err)
	}
	if failures != 2 {
		t.Fatalf("failures must count exactly the two invalid logs, got %d", failures)
	}
	results := assertResultsComplete(t, out.Bytes(), 4)
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1: %#v", results[0])
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != false {
		t.Fatalf("invalid line must keep its original line number: %#v", results[1])
	}
	if results[2]["line"] != float64(3) || results[2]["ok"] != false {
		t.Fatalf("invalid line must keep its original line number: %#v", results[2])
	}
	if results[3]["line"] != float64(4) || results[3]["ok"] != true {
		t.Fatalf("later legal line must still be output: %#v", results[3])
	}
	if eventOf(t, results[3])["action"] != "d" || eventOf(t, results[0])["action"] != "a" {
		t.Fatalf("output order must match input order: %#v", results)
	}
	if msg, _ := results[2]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("line error must stay recognizable as a field error, got %q", msg)
	}
}

// TestNormalizeReadErrorAfterCompleteLines: when the input stream breaks
// after several complete log lines, everything already read is processed in
// order and flushed out (both success events and per-line error records), the
// returned error is the read fault, and it is not counted as a log failure.
func TestNormalizeReadErrorAfterCompleteLines(t *testing.T) {
	// Delivered in separate chunks so bufio cannot see the fault as part of
	// any later Read: three complete lines, the middle one invalid.
	r := &repeatReader{
		chunks: []string{
			validLog("a") + "\n",
			"not json\n",
			validLog("c") + "\n",
		},
		fault: errBoomRead,
	}
	var out bytes.Buffer
	failures, err := NormalizeReader(r, &out)
	if !errors.Is(err, errBoomRead) {
		t.Fatalf("caller must receive the read error, got %v", err)
	}
	if failures != 1 {
		t.Fatalf("read fault must not be counted as a failed log; expected 1 (the invalid line), got %d", failures)
	}
	results := assertResultsComplete(t, out.Bytes(), 3)
	if results[0]["line"] != float64(1) || results[0]["ok"] != true || eventOf(t, results[0])["action"] != "a" {
		t.Fatalf("line 1 success must be written: %#v", results[0])
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != false {
		t.Fatalf("line 2 per-line error must be written with its line number: %#v", results[1])
	}
	if results[2]["line"] != float64(3) || results[2]["ok"] != true || eventOf(t, results[2])["action"] != "c" {
		t.Fatalf("line 3 success must be written: %#v", results[2])
	}
}

// TestNormalizeReadErrorOnTrailingFragment: bytes past the last newline that
// arrive together with a non-EOF read fault are an unresolved fragment, not a
// final log. The fault must produce no event and no fabricated line-level
// failure, must not advance the line counter, and the complete lines already
// read are still emitted.
func TestNormalizeReadErrorOnTrailingFragment(t *testing.T) {
	for _, fragment := range []string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":`,     // would-be legal, cut off
		`{"timestamp":"2026-01-02T00:00:00Z","action":"x"}`, // complete-looking object, but no newline
		"not json either", // outright garbage
	} {
		t.Run(fmt.Sprintf("fragment=%q", fragment), func(t *testing.T) {
			r := &repeatReader{
				chunks: []string{
					validLog("a") + "\n",
					fragment,
				},
				fault:         errBoomRead,
				faultWithLast: true,
			}
			var out bytes.Buffer
			failures, err := NormalizeReader(r, &out)
			if !errors.Is(err, errBoomRead) {
				t.Fatalf("caller must receive the read error, got %v", err)
			}
			if failures != 0 {
				t.Fatalf("fault fragment must not create a per-line failure, got failures=%d", failures)
			}
			results := assertResultsComplete(t, out.Bytes(), 1)
			if results[0]["line"] != float64(1) || results[0]["ok"] != true {
				t.Fatalf("only the completed line 1 must be emitted, got %#v", results)
			}
		})
	}
}

// TestNormalizeReadErrorAfterInvalidLinesCountPreserved: with multiple invalid
// lines already accumulated, a read fault leaves the failure count exactly at
// the number of invalid logs and is still returned as the error.
func TestNormalizeReadErrorAfterInvalidLinesCountPreserved(t *testing.T) {
	r := &failingReader{
		prefix: "garbage1\n" + "garbage2\n" + validLog("ok") + "\n",
	}
	r.readFault = errBoomRead
	var out bytes.Buffer
	failures, err := NormalizeReader(r, &out)
	if !errors.Is(err, errBoomRead) {
		t.Fatalf("caller must receive the read error, got %v", err)
	}
	if failures != 2 {
		t.Fatalf("failures must stay at the 2 invalid logs, fault adds none, got %d", failures)
	}
	results := assertResultsComplete(t, out.Bytes(), 3)
	if results[0]["ok"] != false || results[0]["line"] != float64(1) ||
		results[1]["ok"] != false || results[1]["line"] != float64(2) ||
		results[2]["ok"] != true || results[2]["line"] != float64(3) {
		t.Fatalf("all three complete lines must be emitted in order: %#v", results)
	}
}

// TestNormalizeWriteFailureMidStream forces the underlying writer to fail on
// its first Write call while the stream is still being processed (the
// buffered writer must flush to reach it). The write fault is returned, no
// residue reaches the failing device, and no ordinary log failure record is
// synthesized for it.
func TestNormalizeWriteFailureMidStream(t *testing.T) {
	// Each result line is about 95 bytes; 100 lines (~9.5 KiB) guarantee the
	// 4 KiB buffered writer flushes at least twice mid-stream, and
	// failAfter=0 makes the first flush fail before input is exhausted.
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString(validLog(fmt.Sprintf("action-%02d", i)))
		sb.WriteByte('\n')
	}
	w := &failingWriter{failAfter: 0, fault: errBoomWrite}
	failures, err := NormalizeReader(strings.NewReader(sb.String()), w)
	if !errors.Is(err, errBoomWrite) {
		t.Fatalf("caller must receive the write error, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("write fault must not add failures when all logs are legal, got %d", failures)
	}
	if w.sink.Len() != 0 {
		t.Fatalf("failing writer must leave no residue on the failed Write, got %q", w.sink.Bytes())
	}
}

// TestNormalizeWriteFailureKeepsAccumulatedFailures: when invalid logs have
// already accumulated and the output then breaks mid-stream, the write fault
// is returned and the failure count is neither bumped (fault is not a bad log)
// nor reset.
func TestNormalizeWriteFailureKeepsAccumulatedFailures(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("bad line one\n") // invalid -> failure
	for i := 0; i < 100; i++ {
		sb.WriteString(validLog(fmt.Sprintf("action-%02d", i)))
		sb.WriteByte('\n')
	}
	sb.WriteString("bad line two\n") // invalid -> failure
	for i := 0; i < 100; i++ {
		sb.WriteString(validLog(fmt.Sprintf("more-%02d", i)))
		sb.WriteByte('\n')
	}
	// Fail the first underlying Write that carries the result record for
	// line 101 or later. Normalization counts a line before encoding its
	// result, so by the time that batch is written both invalid lines have
	// already been counted; the trigger is independent of flush boundaries.
	w := &recordGateWriter{failFromRecord: 101, fault: errBoomWrite}
	failures, err := NormalizeReader(strings.NewReader(sb.String()), w)
	if !errors.Is(err, errBoomWrite) {
		t.Fatalf("caller must receive the write error, got %v", err)
	}
	if failures != 2 {
		t.Fatalf("accumulated per-line failures must survive (expected 2), write fault adds none, got %d", failures)
	}
}

// recordGateWriter stays healthy until the running number of result records
// (newline-terminated objects) handed to Write reaches failFromRecord; the
// Write that crosses that threshold fails, and every later Write fails too.
type recordGateWriter struct {
	seen           int
	failFromRecord int
	fault          error
	failed         bool
}

func (w *recordGateWriter) Write(p []byte) (int, error) {
	if w.failed {
		return 0, w.fault
	}
	w.seen += bytes.Count(p, []byte{'\n'})
	if w.seen >= w.failFromRecord {
		w.failed = true
		return 0, w.fault
	}
	return len(p), nil
}

// TestNormalizeWriteFailureAtFinalFlush: healthy input of all-legal logs that
// only fails when the last buffered batch is written at the end must still
// hand the caller the write error; a write fault cannot turn into success.
func TestNormalizeWriteFailureAtFinalFlush(t *testing.T) {
	// Small input that fits inside the 4 KiB buffer, so nothing is written
	// until the deferred flush at input EOF.
	input := validLog("only") + "\n"
	w := &failingWriter{failAfter: 0, fault: errBoomWrite}
	failures, err := NormalizeReader(strings.NewReader(input), w)
	if !errors.Is(err, errBoomWrite) {
		t.Fatalf("write failure while flushing the final batch must reach the caller, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("all-legal input plus write fault must report 0 failures, got %d", failures)
	}
}

// TestNormalizeWriteFailureAtFinalFlushAfterInvalidLine is the same final-flush
// failure with an invalid line already accumulated: the count must survive.
func TestNormalizeWriteFailureAtFinalFlushAfterInvalidLine(t *testing.T) {
	input := "not json\n" + validLog("ok") + "\n"
	w := &failingWriter{failAfter: 0, fault: errBoomWrite}
	failures, err := NormalizeReader(strings.NewReader(input), w)
	if !errors.Is(err, errBoomWrite) {
		t.Fatalf("write failure at final flush must reach the caller, got %v", err)
	}
	if failures != 1 {
		t.Fatalf("the invalid line must still count as 1 after the write fault, got %d", failures)
	}
}

// TestNormalizeWriteFailureLeavesNoFabricatedFailureRecord checks the partial
// residue after a mid-stream write fault: it may contain truncated JSON, but
// every complete result line still parses to a real normalization result and
// there is no extra failure attributable to the output fault.
func TestNormalizeWriteFailureLeavesNoFabricatedFailureRecord(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("first bad\n")
	for i := 0; i < 150; i++ {
		sb.WriteString(validLog(fmt.Sprintf("action-%02d", i)))
		sb.WriteByte('\n')
	}
	// The second flush happens around 8 KiB, well before the ~14 KiB input
	// ends, so it fails genuinely mid-stream and leaves partial JSON behind.
	w := &partialWriter{failAfter: 2, fault: errBoomWrite}
	failures, err := NormalizeReader(strings.NewReader(sb.String()), w)
	if !errors.Is(err, errBoomWrite) {
		t.Fatalf("caller must receive the write error, got %v", err)
	}
	if failures != 1 {
		t.Fatalf("only the one invalid log counts; the write fault adds none, got %d", failures)
	}
	results := decodeResultsLenient(t, w.sink.Bytes())
	for i, r := range results {
		line, _ := r["line"].(float64)
		if line < 1 {
			t.Fatalf("result %d has no real line number: %#v", i, r)
		}
		if r["ok"] == false {
			// The only line-level failure permitted is the first input line.
			if line != 1 {
				t.Fatalf("write fault must not synthesize a line failure; failure found on line %v: %#v", line, r)
			}
		}
	}
}

// partialWriter accepts failAfter full Writes, then performs a partial write
// on the next call and reports the fault; afterwards every Write fails. It
// models a device that accepts some bytes of a batch and then breaks, which
// leaves genuinely partial JSON in the output.
type partialWriter struct {
	sink      bytes.Buffer
	failAfter int
	fault     error
	write     int
}

func (w *partialWriter) Write(p []byte) (int, error) {
	if w.write < w.failAfter {
		w.write++
		return w.sink.Write(p)
	}
	if w.write == w.failAfter {
		w.write++
		k := len(p) / 2
		if k == 0 {
			k = 1
		}
		w.sink.Write(p[:k])
		return k, w.fault
	}
	return 0, w.fault
}

// TestNormalizeReadErrorWinsOverCloseTimeWriteError: when reading has already
// failed and the final flush of successfully produced results also fails, the
// caller still receives the original read error — the later write fault must
// not mask the root cause.
func TestNormalizeReadErrorWinsOverCloseTimeWriteError(t *testing.T) {
	r := &repeatReader{
		chunks: []string{
			validLog("a") + "\n",
			validLog("b") + "\n",
		},
		fault: errBoomRead,
	}
	// Two short result lines stay inside the 4 KiB buffer, so the only
	// underlying Write is the deferred flush after the read fault is seen.
	w := &failingWriter{failAfter: 0, fault: errBoomWrite}
	failures, err := NormalizeReader(r, w)
	if !errors.Is(err, errBoomRead) {
		t.Fatalf("earlier read error must be returned even when the final flush also fails, got %v", err)
	}
	if errors.Is(err, errBoomWrite) {
		t.Fatalf("write error must not replace the read error, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("neither fault counts as a failed log, got %d", failures)
	}
}

// TestNormalizeReadAndWriteErrorsWithInvalidLines combines every element:
// invalid logs already counted, a read fault ending the stream, and a flush
// that also fails. The caller gets the read error and the accumulated
// validation failures remain exactly as they were.
func TestNormalizeReadAndWriteErrorsWithInvalidLines(t *testing.T) {
	r := &failingReader{
		prefix:    "garbage1\n" + validLog("ok") + "\n",
		readFault: errBoomRead,
	}
	w := &failingWriter{failAfter: 0, fault: errBoomWrite}
	failures, err := NormalizeReader(r, w)
	if !errors.Is(err, errBoomRead) {
		t.Fatalf("read error must remain the reported cause, got %v", err)
	}
	if failures != 1 {
		t.Fatalf("the one invalid log must still count after both faults, got %d", failures)
	}
}

// TestNormalizeCleanEOFWithoutNewline is the non-fault path that must stay
// distinct: a complete final log with no trailing newline is processed and
// written normally, with nil error.
func TestNormalizeCleanEOFWithoutNewline(t *testing.T) {
	input := validLog("last")
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("clean EOF must not be reported as an interruption, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("legal final line must not count as failure, got %d", failures)
	}
	results := assertResultsComplete(t, out.Bytes(), 1)
	if results[0]["ok"] != true || eventOf(t, results[0])["action"] != "last" {
		t.Fatalf("unterminated final line must be processed normally: %#v", results[0])
	}
}

// TestNormalizeCleanEOFMixedLinesWithoutNewline: the unterminated last line is
// an invalid log; it is still a numbered per-line failure and the run error
// stays nil — validation failure is never confused with an I/O fault.
func TestNormalizeCleanEOFMixedLinesWithoutNewline(t *testing.T) {
	input := validLog("a") + "\n" + "bad without newline"
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("invalid final line at clean EOF is a validation failure, not I/O error: %v", err)
	}
	if failures != 1 {
		t.Fatalf("expected 1 validation failure, got %d", failures)
	}
	results := assertResultsComplete(t, out.Bytes(), 2)
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1: %#v", results[0])
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != false {
		t.Fatalf("unterminated invalid line 2 must be a numbered failure: %#v", results[1])
	}
}

// TestNormalizeErrorsStayIdentifiable guarantees read faults, write faults,
// and per-line validation errors are not collapsed into one unclassifiable
// failure message.
func TestNormalizeErrorsStayIdentifiable(t *testing.T) {
	// Read fault: returned directly.
	r := &failingReader{prefix: validLog("a") + "\n", readFault: errBoomRead}
	if _, err := NormalizeReader(r, io.Discard); !errors.Is(err, errBoomRead) {
		t.Fatalf("read fault must stay identifiable via errors.Is, got %v", err)
	}

	// Write fault: returned directly.
	w := &failingWriter{failAfter: 0, fault: errBoomWrite}
	if _, err := NormalizeReader(strings.NewReader(validLog("a")+"\n"), w); !errors.Is(err, errBoomWrite) {
		t.Fatalf("write fault must stay identifiable via errors.Is, got %v", err)
	}

	// Per-line validation error: nil run error, identifiable field message
	// inside the result record.
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(`{"timestamp":"bad","action":"a"}`+"\n"), &out)
	if err != nil || failures != 1 {
		t.Fatalf("validation failure must keep run error nil, got failures=%d err=%v", failures, err)
	}
	results := assertResultsComplete(t, out.Bytes(), 1)
	msg, _ := results[0]["error"].(string)
	if !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("line error must remain recognizable as %q, got %q", FieldTimestamp, msg)
	}
}

// TestNormalizeEmptyReadErrorIsNotEOF guards the distinction between a stream
// that fails immediately (before any bytes) and an empty stream at clean EOF.
func TestNormalizeEmptyReadErrorIsNotEOF(t *testing.T) {
	r := &failingReader{prefix: "", readFault: errBoomRead}
	var out bytes.Buffer
	failures, err := NormalizeReader(r, &out)
	if !errors.Is(err, errBoomRead) {
		t.Fatalf("immediate read fault must be reported, got %v", err)
	}
	if failures != 0 || out.Len() != 0 {
		t.Fatalf("fault before any data must produce no results and no failures, got failures=%d out=%q", failures, out.String())
	}
}
