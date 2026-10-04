package relayproof

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// Regression coverage for an output that acknowledges only part of the
// final result batch while reporting NO error. A nil error from the writer
// is not proof of delivery: a short Write (n < len(p), err == nil) is an
// interrupted write, and io.WriterTo/bufio contract turns it into
// io.ErrShortWrite. NormalizeReader must surface that as ErrLogWrite with
// io.ErrShortWrite kept in the error chain, never as normal completion and
// never as ErrLogRead. The two signals exposed to callers stay independent:
// the invalid-log count says how many processed lines failed field rules
// (regardless of whether their results were delivered), and the stream
// error says whether input/output ended cleanly (regardless of line
// validity). Zero invalid logs does not make a short write healthy, and a
// short write does not make a valid log invalid.
//
// Faults are scripted in-process with failWriter (nil error, short count),
// so the interruption reproduces deterministically without real pipes,
// networks, or device failures.

// healthyRun processes the same input with an output that receives every
// result byte; it is the reference for normal completion and for the
// byte-for-byte prefix a short-write run is allowed to retain.
func healthyRun(t *testing.T, input string) (output []byte, results []map[string]any, failures int) {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("test setup: healthy reference run failed: %v", err)
	}
	return out.Bytes(), decodeResults(t, out.Bytes()), failures
}

// TestNormalizeIOShortWriteOnFinalFlush covers an output that, while the
// final batch of results is flushed at a clean EOF, accepts only a prefix
// (or nothing at all) and returns a nil error.
func TestNormalizeIOShortWriteOnFinalFlush(t *testing.T) {
	// A few short logs keep the whole result batch inside the internal
	// 4096-byte buffer, so the first physical Write is the shutdown flush:
	// one call decides whether the final batch was delivered in full.
	const lineCount = 3
	input := validLog("a") + "\n" +
		validLog("b") + "\n" +
		validLog("c") + "\n"

	fullOutput, healthyResults, healthyFailures := healthyRun(t, input)
	if healthyFailures != 0 || len(healthyResults) != lineCount {
		t.Fatalf("test setup: reference input must be all valid, got failures=%d results=%d", healthyFailures, len(healthyResults))
	}
	lastRecord := encodedRecord(t, lineCount, validLog("c"))
	fullLen := len(fullOutput)

	cases := []struct {
		name       string
		allowBytes int // bytes the output accepts before the short, nil-error Write
	}{
		{
			name:       "output accepts an opening prefix of the final batch",
			allowBytes: fullLen / 2, // mid-record: the last JSON is left incomplete
		},
		{
			name:       "output accepts zero bytes",
			allowBytes: 0,
		},
		{
			name:       "output accepts complete records but cuts the last one mid-JSON",
			allowBytes: fullLen - len(lastRecord)/2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.allowBytes >= fullLen {
				t.Fatalf("test setup: budget %d must be shorter than the %d-byte batch", tc.allowBytes, fullLen)
			}
			// err left nil: the writer returns a short count WITH an empty
			// error, exactly the undelivered-but-acknowledged case.
			w := &failWriter{allowBytes: tc.allowBytes}
			failures, err := NormalizeReader(strings.NewReader(input), w)

			if err == nil {
				t.Fatalf("a short write with an empty error must not be reported as normal completion")
			}
			if !errors.Is(err, ErrLogWrite) {
				t.Fatalf("caller must recognize the interruption via errors.Is(err, ErrLogWrite), got %v", err)
			}
			if !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("error chain must retain io.ErrShortWrite, got %v", err)
			}
			if errors.Is(err, ErrLogRead) {
				t.Fatalf("a write interruption must not be classified as ErrLogRead: %v", err)
			}
			if failures != 0 {
				t.Fatalf("all logs were valid; a write interruption must not invent a log failure, got %d", failures)
			}

			// Whatever the output acknowledged is retained and is exactly a
			// prefix of the healthy output; the final JSON may be incomplete.
			got := w.buf.Bytes()
			if w.buf.Len() != tc.allowBytes {
				t.Fatalf("accepted prefix must be retained: got %d bytes, want %d", w.buf.Len(), tc.allowBytes)
			}
			if !bytes.Equal(got, fullOutput[:tc.allowBytes]) {
				t.Fatalf("retained bytes must be the opening prefix of a complete write:\ngot:  %q\nwant: %q", got, fullOutput[:tc.allowBytes])
			}
			if bytes.Equal(got, fullOutput) {
				t.Fatalf("the interrupted run must not retain the complete batch")
			}
			var whole []map[string]any
			if len(got) > 0 {
				whole = decodePrefix(t, got) // accepted prefix ends in a truncated tail
			}
			if tc.allowBytes == 0 {
				if len(whole) != 0 {
					t.Fatalf("zero accepted bytes means zero delivered records, got %#v", whole)
				}
			} else {
				if len(whole) >= lineCount {
					t.Fatalf("the final record must be incomplete or absent, got %d whole records", len(whole))
				}
				if whole[0]["line"] != float64(1) || whole[0]["ok"] != true {
					t.Fatalf("delivered prefix records must be genuine results in input order: %#v", whole[0])
				}
			}
		})
	}
}

// TestNormalizeIOShortWriteKeepsInvalidCount freezes the meaning of the
// invalid-log count under a short final write: it counts processed lines
// that failed normalization, not failure records that happened to be
// written, and an undelivered success is never counted.
func TestNormalizeIOShortWriteKeepsInvalidCount(t *testing.T) {
	invalid := `{"timestamp":"not-a-time","action":"b"}`
	input := validLog("a") + "\n" +
		invalid + "\n" +
		validLog("c") + "\n"

	fullOutput, healthyResults, healthyFailures := healthyRun(t, input)
	if healthyFailures != 1 || len(healthyResults) != 3 {
		t.Fatalf("test setup: want exactly one invalid line and 3 results, got failures=%d results=%d", healthyFailures, len(healthyResults))
	}
	failureRecord := encodedRecord(t, 2, invalid)
	cRecord := encodedRecord(t, 3, validLog("c"))
	firstRecord := encodedRecord(t, 1, validLog("a"))

	cases := []struct {
		name        string
		allowBytes  int
		wantRecords int // whole records the prefix must contain
	}{
		{
			// Cut inside the invalid line's own failure result: that line
			// was already processed and must still count, even though its
			// failure result is never fully delivered.
			name:        "invalid line failure result is itself truncated",
			allowBytes:  len(firstRecord) + len(failureRecord)/2,
			wantRecords: 1,
		},
		{
			// Cut inside the later valid line: the failure result happened
			// to be delivered whole, but the count must not be defined by
			// how many failure records reached the output either.
			name:        "failure result delivered, later success truncated",
			allowBytes:  len(firstRecord) + len(failureRecord) + len(cRecord)/2,
			wantRecords: 2,
		},
		{
			name:        "nothing delivered at all",
			allowBytes:  0,
			wantRecords: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &failWriter{allowBytes: tc.allowBytes} // short Write, nil error
			failures, err := NormalizeReader(strings.NewReader(input), w)
			if !errors.Is(err, ErrLogWrite) || !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short write must surface as ErrLogWrite retaining io.ErrShortWrite, got %v", err)
			}
			if errors.Is(err, ErrLogRead) {
				t.Fatalf("a short write must not be classified as a read failure: %v", err)
			}
			if failures != 1 {
				t.Fatalf("the one processed invalid line must count exactly once even though delivery was cut, got %d", failures)
			}
			got := w.buf.Bytes()
			if !bytes.Equal(got, fullOutput[:tc.allowBytes]) {
				t.Fatalf("retained bytes must be the healthy output prefix:\ngot:  %q\nwant: %q", got, fullOutput[:tc.allowBytes])
			}
			var whole []map[string]any
			if len(got) > 0 {
				whole = decodePrefix(t, got) // truncated tail expected when bytes were accepted
			}
			if len(whole) != tc.wantRecords {
				t.Fatalf("delivered prefix must hold %d whole record(s), got %#v", tc.wantRecords, whole)
			}
			// The interruption adds no synthetic log-failure record: every
			// whole record in the retained prefix is a genuine input result
			// in its original order with its original validity verdict.
			for i, r := range whole {
				if line, _ := r["line"].(float64); line != float64(i+1) {
					t.Fatalf("delivered record %d must be genuine input line %d: %#v", i+1, i+1, r)
				}
				if i == 1 && r["ok"] != false {
					t.Fatalf("the delivered invalid-line record must be line 2's genuine failure result: %#v", r)
				}
			}
		})
	}
}

// TestNormalizeIOCompleteDeliveryIsNormal contrasts the short-write cases
// with an output that accepts the whole final batch: the same inputs end
// cleanly with a nil error, results appear in input order keyed by original
// physical line numbers, valid logs carry normalized events, the invalid
// log carries only its own failure reason, and later valid logs still
// succeed. Delivery completeness changes only the stream-level error and
// which bytes actually arrived — never the validity verdict of the batch.
func TestNormalizeIOCompleteDeliveryIsNormal(t *testing.T) {
	input := validLog("a") + "\n" +
		`{"timestamp":"not-a-time","action":"b"}` + "\n" +
		validLog("c") + "\n"

	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("an output that receives everything must end normally, got %v", err)
	}
	if failures != 1 {
		t.Fatalf("exactly the one field-invalid line counts, got %d", failures)
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 3 {
		t.Fatalf("expected 3 results in input order, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must be a valid result: %#v", results[0])
	}
	if eventOf(t, results[0])["action"] != "a" {
		t.Fatalf("line 1 must carry its normalized event: %#v", results[0])
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != false {
		t.Fatalf("line 2 must be the invalid log: %#v", results[1])
	}
	if _, hasEvent := results[1]["event"]; hasEvent {
		t.Fatalf("invalid log must not carry an event: %#v", results[1])
	}
	if msg, _ := results[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("invalid log must carry only its own failure reason, got %q", msg)
	}
	if results[2]["line"] != float64(3) || results[2]["ok"] != true {
		t.Fatalf("a valid log after the invalid one must still succeed: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "c" {
		t.Fatalf("line 3 must carry its normalized event: %#v", results[2])
	}

	// Result shape/format stays the published one: one JSON object per line,
	// directly unmarshallable into NormalizeResult, for every non-blank line.
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for wantLine := 1; wantLine <= 3; wantLine++ {
		var r NormalizeResult
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("result %d must decode as NormalizeResult: %v", wantLine, err)
		}
		if r.Line != wantLine {
			t.Fatalf("result %d must echo physical line %d, got %d", wantLine, wantLine, r.Line)
		}
		switch wantLine {
		case 2:
			if r.OK || r.Event != nil || r.Error == "" {
				t.Fatalf("line 2 must be a failure with reason and no event: %+v", r)
			}
		default:
			if !r.OK || r.Event == nil || r.Error != "" {
				t.Fatalf("line %d must be a success with an event and no error: %+v", wantLine, r)
			}
		}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("healthy output must end exactly after the 3 result records, got %v", err)
	}
}
