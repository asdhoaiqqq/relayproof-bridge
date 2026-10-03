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

// Regression coverage for stream-level interruptions: the error a caller
// receives must stay distinguishable from a single invalid log line, the
// failure count must cover only lines that failed normalization, and read
// failures must not be masked by later write failures. All fault injection
// is in-process and scripted, so the behavior reproduces deterministically
// without real pipes, networks, or device failures.

var (
	errSimulatedRead  = errors.New("simulated input device read failure")
	errSimulatedWrite = errors.New("simulated output device write failure")
)

// scriptReader replays fixed (data, err) Read results in order. A step may
// return data together with an error, mirroring a reader that loses its
// underlying device after delivering a truncated final fragment. After the
// script is exhausted every further Read returns io.EOF.
type scriptReader struct {
	steps []scriptStep
	i     int
}

type scriptStep struct {
	data []byte
	err  error
}

func (s *scriptReader) Read(p []byte) (int, error) {
	if s.i >= len(s.steps) {
		return 0, io.EOF
	}
	step := s.steps[s.i]
	s.i++
	n := copy(p, step.data)
	if n < len(step.data) {
		panic("scriptReader step larger than the caller's buffer; shrink the script data")
	}
	return n, step.err
}

// failWriter accepts exactly allowBytes bytes in total, then fails. From the
// failing Write up to partial bytes are still recorded, so tests can model
// output cut off mid-record. Everything accepted is kept for inspection.
type failWriter struct {
	buf        bytes.Buffer
	allowBytes int
	partial    int
	err        error
	failed     bool
}

func (w *failWriter) Write(p []byte) (int, error) {
	accepted := 0
	if w.allowBytes > 0 {
		n := len(p)
		if n > w.allowBytes {
			n = w.allowBytes
		}
		w.buf.Write(p[:n])
		w.allowBytes -= n
		accepted, p = n, p[n:]
		if len(p) == 0 {
			return accepted, nil
		}
	}
	m := w.partial
	if m > len(p) {
		m = len(p)
	}
	w.buf.Write(p[:m])
	w.failed = true
	return accepted + m, w.err
}

// decodeResults parses complete JSON-object-per-line output. A non-EOF
// decode error fails the test: healthy output must always be whole records.
func decodeResults(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var results []map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				return results
			}
			t.Fatalf("output must consist of whole result records, got decode error %v after %d records: %q", err, len(results), string(data))
		}
		results = append(results, m)
	}
}

// decodePrefix parses as many whole records as a possibly-truncated output
// contains; a write interruption is allowed to leave a non-record tail, so
// a trailing syntax error is expected rather than fatal.
func decodePrefix(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var results []map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				t.Fatalf("expected truncated trailing output, got a clean record boundary")
			}
			return results
		}
		results = append(results, m)
	}
}

func validLog(action string) string {
	return `{"timestamp":"2026-01-02T00:00:00Z","action":"` + action + `"}`
}

func bigValidLog(action string) string {
	return fmt.Sprintf(`{"timestamp":"2026-01-02T00:00:00Z","action":%q,"pad":%q}`,
		action, strings.Repeat("p", 5000))
}

// encodedRecord is the exact byte form NormalizeReader writes for one line
// (json.Encoder appends a newline), used to script writer byte budgets.
func encodedRecord(t *testing.T, lineNo int, raw string) []byte {
	t.Helper()
	b, err := json.Marshal(NormalizeLine(lineNo, []byte(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// A field-invalid line embedded in a healthy stream produces a failure
// result carrying its original line number, later valid lines keep coming,
// and the returned error is nil: per-line failures are not I/O failures.
func TestNormalizeIOInvalidLineIsNotStreamError(t *testing.T) {
	input := validLog("a") + "\n" +
		`{"timestamp":"not-a-time","action":"b"}` + "\n" +
		validLog("c") + "\n"
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("healthy stream must return nil error, got %v", err)
	}
	if errors.Is(err, ErrLogRead) || errors.Is(err, ErrLogWrite) {
		t.Fatalf("nil error cannot match an I/O sentinel: %v", err)
	}
	if failures != 1 {
		t.Fatalf("only the invalid log must count as a failure, got %d", failures)
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 mismatch: %#v", results[0])
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != false {
		t.Fatalf("invalid line must keep line number 2: %#v", results[1])
	}
	if msg, _ := results[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("per-line error explanation must survive in output, got %q", msg)
	}
	if _, exists := results[1]["event"]; exists {
		t.Fatalf("failed line must not carry an event: %#v", results[1])
	}
	if results[2]["line"] != float64(3) || results[2]["ok"] != true {
		t.Fatalf("valid line 3 must still be emitted: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "c" {
		t.Fatalf("line 3 must preserve order and content")
	}
}

// When the input stream fails after whole lines, everything already read is
// processed in order and flushed; the read error is reported wrapped with
// ErrLogRead, the failure count covers only genuinely invalid complete
// lines, and an unterminated fragment delivered with the failure is neither
// normalized, counted, nor emitted.
func TestNormalizeIOReadErrorAfterCompleteLines(t *testing.T) {
	complete := validLog("a") + "\n" +
		`{"timestamp":"not-a-time","action":"b"}` + "\n" +
		validLog("c") + "\n"
	cases := []struct {
		name     string
		fragment []byte
	}{
		{"error carries an unterminated fragment", []byte(`{"timestamp":"FRAGMENT-MARKER","action":`)},
		{"error stands alone after a newline", nil},
		{"error carries only blank bytes", []byte("   ")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &scriptReader{steps: []scriptStep{
				{data: []byte(complete)},
				{data: tc.fragment, err: errSimulatedRead},
			}}
			var out bytes.Buffer
			failures, err := NormalizeReader(src, &out)
			if err == nil {
				t.Fatalf("read failure must be returned, not treated as success")
			}
			if !errors.Is(err, ErrLogRead) {
				t.Fatalf("error must match ErrLogRead, got %v", err)
			}
			if !errors.Is(err, errSimulatedRead) {
				t.Fatalf("underlying read cause must stay reachable, got %v", err)
			}
			if errors.Is(err, ErrLogWrite) {
				t.Fatalf("a healthy writer must not tag the error as a write failure: %v", err)
			}
			if !strings.Contains(err.Error(), errSimulatedRead.Error()) {
				t.Fatalf("error text must stay recognizable as the read cause, got %q", err.Error())
			}
			if failures != 1 {
				t.Fatalf("read fault must not count as a log; only the one bad line counts, got %d", failures)
			}
			results := decodeResults(t, out.Bytes())
			if len(results) != 3 {
				t.Fatalf("only the 3 complete lines may be emitted, got %#v", results)
			}
			if results[0]["line"] != float64(1) || results[0]["ok"] != true ||
				results[1]["line"] != float64(2) || results[1]["ok"] != false ||
				results[2]["line"] != float64(3) || results[2]["ok"] != true {
				t.Fatalf("processed lines must keep order, numbers and outcomes: %#v", results)
			}
			if msg, _ := results[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
				t.Fatalf("per-line error explanation must be preserved, got %q", msg)
			}
			if bytes.Contains(out.Bytes(), []byte("FRAGMENT-MARKER")) {
				t.Fatalf("unterminated fragment must not produce an event or line error: %q", out.String())
			}
		})
	}
}

// A read failure before any complete line yields no results and no failure
// count, but the stream error still reaches the caller.
func TestNormalizeIOReadErrorBeforeAnyLine(t *testing.T) {
	src := &scriptReader{steps: []scriptStep{
		{data: []byte(`{"timestamp":"cut off`), err: errSimulatedRead},
	}}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
		t.Fatalf("want ErrLogRead wrapping the cause, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("an unread stream has no failed logs, got %d", failures)
	}
	if out.Len() != 0 {
		t.Fatalf("no complete line means no output, got %q", out.String())
	}
}

// The writer fails only when the final buffered batch is flushed at input
// end: the caller must still receive ErrLogWrite. When every log was valid
// the failure count stays zero; when invalid logs were already counted,
// that count must not be reset.
func TestNormalizeIOWriteErrorOnFinalFlush(t *testing.T) {
	cases := []struct {
		name         string
		input        string
		wantFailures int
	}{
		{
			name:         "all logs valid",
			input:        validLog("a") + "\n" + validLog("b") + "\n",
			wantFailures: 0,
		},
		{
			name: "invalid log already counted",
			input: validLog("a") + "\n" +
				`{"timestamp":"not-a-time","action":"b"}` + "\n" +
				validLog("c") + "\n",
			wantFailures: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &failWriter{err: errSimulatedWrite} // reject every Write
			failures, err := NormalizeReader(strings.NewReader(tc.input), w)
			if !errors.Is(err, ErrLogWrite) || !errors.Is(err, errSimulatedWrite) {
				t.Fatalf("want ErrLogWrite wrapping the cause, got %v", err)
			}
			if errors.Is(err, ErrLogRead) {
				t.Fatalf("a healthy reader must not tag the error as a read failure: %v", err)
			}
			if !w.failed {
				t.Fatalf("the final flush must actually have reached the failing writer")
			}
			if failures != tc.wantFailures {
				t.Fatalf("write fault must not alter the failure count: got %d, want %d", failures, tc.wantFailures)
			}
		})
	}
}

// A write failure in the middle of processing (records larger than the
// internal buffer go straight to the underlying writer) stops the run with
// ErrLogWrite; whatever reached the writer may end mid-record, and the write
// fault never fabricates an ordinary log failure or moves the count.
func TestNormalizeIOWriteErrorMidStream(t *testing.T) {
	t.Run("all valid logs", func(t *testing.T) {
		line1 := bigValidLog("a")
		line2 := bigValidLog("b")
		encoded1 := encodedRecord(t, 1, line1)
		if len(encoded1) <= 4096 {
			t.Fatalf("test setup: encoded line must exceed the 4096-byte buffer, got %d", len(encoded1))
		}
		// Line 1 is accepted whole; the write for line 2 takes 120 bytes
		// and then fails, leaving a truncated non-record tail.
		w := &failWriter{allowBytes: len(encoded1), partial: 120, err: errSimulatedWrite}
		failures, err := NormalizeReader(strings.NewReader(line1+"\n"+line2+"\n"), w)
		if !errors.Is(err, ErrLogWrite) || !errors.Is(err, errSimulatedWrite) {
			t.Fatalf("want ErrLogWrite wrapping the cause, got %v", err)
		}
		if failures != 0 {
			t.Fatalf("write fault must not add a log failure, got %d", failures)
		}
		results := decodePrefix(t, w.buf.Bytes())
		if len(results) != 1 || results[0]["ok"] != true {
			t.Fatalf("only the fully written line 1 may decode whole: %#v", results)
		}
		if eventOf(t, results[0])["action"] != "a" {
			t.Fatalf("written record must be the genuine first log")
		}
		if w.buf.Len() != len(encoded1)+120 {
			t.Fatalf("the interrupted write must leave exactly 120 partial bytes beyond line 1, got total %d", w.buf.Len())
		}
	})

	t.Run("invalid log counted before the write fault", func(t *testing.T) {
		line1 := bigValidLog("a")
		encoded1 := encodedRecord(t, 1, line1)
		invalid := `{"timestamp":"not-a-time","action":"b"}` // small failure result stays buffered
		line3 := bigValidLog("c")
		// Line 1 goes out whole; the next physical write (the buffered
		// failure result, flushed while line 3 is encoded) accepts a few
		// bytes and then fails.
		w := &failWriter{allowBytes: len(encoded1) + 5, err: errSimulatedWrite}
		failures, err := NormalizeReader(strings.NewReader(line1+"\n"+invalid+"\n"+line3+"\n"), w)
		if !errors.Is(err, ErrLogWrite) {
			t.Fatalf("want ErrLogWrite, got %v", err)
		}
		if failures != 1 {
			t.Fatalf("the invalid log must still count exactly once after the write fault, got %d", failures)
		}
		results := decodePrefix(t, w.buf.Bytes())
		if len(results) != 1 || results[0]["ok"] != true {
			t.Fatalf("only line 1 should have left a whole record: %#v", results)
		}
	})
}

// If the reader has already failed and flushing the buffered results fails
// too, the caller must still receive the original read cause: the later
// write error must not mask it.
func TestNormalizeIOReadErrorWinsOverFlushError(t *testing.T) {
	complete := validLog("a") + "\n" +
		`{"timestamp":"not-a-time","action":"b"}` + "\n" +
		validLog("c") + "\n"
	src := &scriptReader{steps: []scriptStep{
		{data: []byte(complete)},
		{data: []byte(`{"truncated":`), err: errSimulatedRead},
	}}
	// Small records stay in the internal buffer, so the first physical
	// write is the shutdown flush, which fails with a distinct error.
	w := &failWriter{err: errSimulatedWrite}
	failures, err := NormalizeReader(src, w)
	if err == nil {
		t.Fatalf("expected the read failure, got nil")
	}
	if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
		t.Fatalf("the original read error must reach the caller, got %v", err)
	}
	if errors.Is(err, ErrLogWrite) || errors.Is(err, errSimulatedWrite) {
		t.Fatalf("the later flush error must not replace the read cause: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, errSimulatedRead.Error()) {
		t.Fatalf("error text must name the read cause first, got %q", msg)
	}
	if !strings.Contains(msg, errSimulatedWrite.Error()) {
		t.Fatalf("the shutdown write failure should still be visible in the message, got %q", msg)
	}
	if failures != 1 {
		t.Fatalf("only the one invalid complete line counts, got %d", failures)
	}
}

// A clean EOF after a final newline-less complete line is normal completion:
// the line is processed, results flush, and no error is reported.
func TestNormalizeIOCleanEOFWithoutFinalNewline(t *testing.T) {
	input := validLog("a") + "\n" + validLog("b") // last line has no "\n"
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("clean EOF must not be an error, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("valid logs must report zero failures, got %d", failures)
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 2 || results[1]["ok"] != true {
		t.Fatalf("final line without newline must be processed normally: %#v", results)
	}
	if eventOf(t, results[1])["action"] != "b" {
		t.Fatalf("final line content mismatch: %#v", results[1])
	}
}
