package relayproof

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// Regression coverage for the output end that acknowledges only a prefix of
// the final result batch and then returns a nil error. A Writer that reports
// (n < len(p), nil) breaks the io.Writer contract, but the shutdown flush is
// the only write for a short-log stream (records stay buffered), so the
// interruption must be surfaced as a stream write failure rather than normal
// completion. The two channels NormalizeReader offers its caller stay
// independent: a nil output error does not prove the batch arrived whole,
// and the invalid-log count is a property of processed input, never a count
// of the failure records that made it to the output.
//
// Everything is scripted in-process (scriptReader/failWriter family plus the
// nilErrorPrefixWriter below), so the boundary reproduces deterministically
// without real pipes, networks, or device failures.

// nilErrorPrefixWriter accepts at most allowBytes bytes across all Write
// calls, records everything accepted, and always returns a nil error — even
// when it accepts nothing or only a prefix of the offered bytes. This models
// an output end that goes away mid-batch without setting the error value
// (an io.Writer contract violation that callers must still survive): a
// well-behaved sink must turn the short acknowledgement into io.ErrShortWrite
// instead of taking the nil error as proof that delivery completed.
type nilErrorPrefixWriter struct {
	buf        bytes.Buffer
	allowBytes int
	writes     int
}

func (w *nilErrorPrefixWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.allowBytes <= 0 {
		return 0, nil
	}
	n := len(p)
	if n > w.allowBytes {
		n = w.allowBytes
	}
	w.buf.Write(p[:n])
	w.allowBytes -= n
	return n, nil
}

// shortWriteBatchInput builds a small batch of short logs: valid logs around
// a single field-invalid complete line. The blank line keeps a physical line
// number but emits nothing.
func shortWriteBatchInput() string {
	return validLog("a") + "\n" +
		"\n" +
		`{"timestamp":"not-a-time","action":"b"}` + "\n" +
		validLog("c") + "\n"
}

// expectShortWriteInterruption checks the common contract for any output that
// only partially acknowledges the final flush: ErrLogWrite with
// io.ErrShortWrite in its chain, never normal completion and never a read
// failure, no fabricated extra log failure, and no retry storm against the
// broken writer.
func expectShortWriteInterruption(t *testing.T, w *nilErrorPrefixWriter, failures, wantFailures int, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("a partially acknowledged final flush must not return as normal completion, got nil (failures=%d)", failures)
	}
	if !errors.Is(err, ErrLogWrite) {
		t.Fatalf("caller must recognize the interruption via errors.Is(err, ErrLogWrite), got %v", err)
	}
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("error chain must retain io.ErrShortWrite so the cause is a silent short write, got %v", err)
	}
	if errors.Is(err, ErrLogRead) {
		t.Fatalf("a healthy reader must not classify a write interruption as ErrLogRead: %v", err)
	}
	if failures != wantFailures {
		t.Fatalf("invalid-log count must describe processed input regardless of delivery, got %d, want %d", failures, wantFailures)
	}
	if w.writes != 1 {
		t.Fatalf("the sticky flush failure must stop after one write attempt, got %d calls", w.writes)
	}
}

// When the final batch is flushed at clean input EOF and the output accepts
// only a leading run of the offered bytes with a nil error, the caller must
// still receive ErrLogWrite carrying io.ErrShortWrite. Accepted bytes may
// remain, including an incomplete final JSON record; the interruption must
// not fabricate an additional per-log failure, and all-valid input still
// reports zero invalid logs even though none of the results is guaranteed to
// have arrived.
func TestNormalizeIOShortWriteNilErrorOnFinalFlush(t *testing.T) {
	allValid := validLog("a") + "\n" + validLog("b") + "\n"

	t.Run("accepts no bytes at all", func(t *testing.T) {
		w := &nilErrorPrefixWriter{allowBytes: 0}
		failures, err := NormalizeReader(strings.NewReader(allValid), w)
		expectShortWriteInterruption(t, w, failures, 0, err)
		if w.buf.Len() != 0 {
			t.Fatalf("zero acknowledged bytes must leave zero output, got %q", w.buf.String())
		}
	})

	t.Run("accepts a prefix of the batch", func(t *testing.T) {
		firstRecord := encodedRecord(t, 1, validLog("a"))
		var healthy bytes.Buffer
		if _, err := NormalizeReader(strings.NewReader(allValid), &healthy); err != nil {
			t.Fatalf("test setup: healthy reference run failed: %v", err)
		}
		total := healthy.Len()
		cuts := []struct {
			name string
			cut  int
		}{
			{"mid first record", 5},
			{"whole first record plus fragment", len(firstRecord) + 5},
			{"last JSON of the batch cut open", total - 3},
		}
		for _, tc := range cuts {
			t.Run(tc.name, func(t *testing.T) {
				cut := tc.cut
				w := &nilErrorPrefixWriter{allowBytes: cut}
				failures, err := NormalizeReader(strings.NewReader(allValid), w)
				expectShortWriteInterruption(t, w, failures, 0, err)
				if w.buf.Len() != cut {
					t.Fatalf("exactly the acknowledged prefix must remain, got %d bytes, want %d", w.buf.Len(), cut)
				}
				// The retained bytes are an unmodified prefix of a healthy
				// run's output, ending wherever the output stopped accepting.
				if !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
					t.Fatalf("accepted bytes must be the unmodified prefix of complete output:\nkept:    %q\nhealthy: %q", w.buf.String(), healthy.String())
				}
				// The tail is allowed to be an incomplete final JSON record;
				// the interruption must not have added a failure record.
				results := decodePrefix(t, w.buf.Bytes())
				for _, r := range results {
					if r["ok"] == false {
						t.Fatalf("write interruption must not add a log failure record, got %#v", r)
					}
				}
			})
		}
	})
}

// The invalid-log count belongs to processed input, not to what the output
// managed to receive: with one field-invalid complete line already processed,
// a partially acknowledged final flush still reports exactly one invalid log
// even when its failure result never fully reaches the output — and reports
// zero when every processed log was valid. The count is neither "failure
// records written" nor inflated by undelivered success results.
func TestNormalizeIOShortWriteKeepsInvalidLogCountIndependent(t *testing.T) {
	cases := []struct {
		name         string
		input        string
		wantFailures int
	}{
		{"all logs valid", validLog("a") + "\n" + validLog("b") + "\n", 0},
		{"one field-invalid log processed", shortWriteBatchInput(), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("no bytes accepted", func(t *testing.T) {
				w := &nilErrorPrefixWriter{allowBytes: 0}
				failures, err := NormalizeReader(strings.NewReader(tc.input), w)
				expectShortWriteInterruption(t, w, failures, tc.wantFailures, err)
				if w.buf.Len() != 0 {
					t.Fatalf("nothing should be retained, got %q", w.buf.String())
				}
			})

			t.Run("prefix accepted", func(t *testing.T) {
				// Accept a small opening fragment only, so with the invalid
				// line present its failure result is certainly not among the
				// whole records that arrived.
				w := &nilErrorPrefixWriter{allowBytes: 5}
				failures, err := NormalizeReader(strings.NewReader(tc.input), w)
				expectShortWriteInterruption(t, w, failures, tc.wantFailures, err)
				if w.buf.Len() != 5 {
					t.Fatalf("the acknowledged 5-byte fragment must remain, got %d", w.buf.Len())
				}
				whole := decodePrefix(t, w.buf.Bytes())
				if len(whole) != 0 {
					t.Fatalf("a 5-byte prefix cannot contain a whole record, got %#v", whole)
				}
			})
		})
	}
}

// The same inputs handed to an output that receives the whole batch end
// normally: nil error, results in input order keyed by original physical line
// numbers (the blank line reserves a number), valid logs carry normalized
// events, the invalid log carries only its own reason, and later valid logs
// still succeed. Complete vs. incomplete delivery changes only the stream
// error and what physically arrived — never the legality verdict for the same
// processed batch.
func TestNormalizeIOFullDeliverySameBatchCompletesNormally(t *testing.T) {
	cases := []struct {
		name         string
		input        string
		wantFailures int
	}{
		{"all valid", validLog("a") + "\n" + validLog("b") + "\n", 0},
		{"one invalid among valid", shortWriteBatchInput(), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			failures, err := NormalizeReader(strings.NewReader(tc.input), &out)
			if err != nil {
				t.Fatalf("fully acknowledged output must complete with nil error, got %v", err)
			}
			if failures != tc.wantFailures {
				t.Fatalf("invalid-log count on healthy delivery = %d, want %d", failures, tc.wantFailures)
			}
			results := decodeResults(t, out.Bytes())

			if tc.name == "all valid" {
				if len(results) != 2 {
					t.Fatalf("expected 2 results, got %#v", results)
				}
				if results[0]["line"] != float64(1) || results[0]["ok"] != true ||
					results[1]["line"] != float64(2) || results[1]["ok"] != true {
					t.Fatalf("results must keep physical line order: %#v", results)
				}
				if eventOf(t, results[0])["action"] != "a" || eventOf(t, results[1])["action"] != "b" {
					t.Fatalf("valid logs must carry normalized events in order: %#v", results)
				}
				return
			}

			// Blank physical line 2 emits nothing; line numbers stay physical.
			if len(results) != 3 {
				t.Fatalf("blank line emits nothing but the other three lines do, got %#v", results)
			}
			if results[0]["line"] != float64(1) || results[0]["ok"] != true {
				t.Fatalf("line 1 must be the first valid log: %#v", results[0])
			}
			if eventOf(t, results[0])["action"] != "a" {
				t.Fatalf("line 1 event mismatch: %#v", results[0])
			}
			if results[1]["line"] != float64(3) || results[1]["ok"] != false {
				t.Fatalf("field-invalid line must be a failure, got %#v", results[1])
			}
			if msg, _ := results[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
				t.Fatalf("invalid log must carry only its own failure reason, got %q", msg)
			}
			if _, exists := results[1]["event"]; exists {
				t.Fatalf("invalid log must not carry an event: %#v", results[1])
			}
			if results[2]["line"] != float64(4) || results[2]["ok"] != true {
				t.Fatalf("later valid log must still succeed as physical line 4: %#v", results[2])
			}
			if eventOf(t, results[2])["action"] != "c" {
				t.Fatalf("later valid log must carry its normalized event: %#v", results[2])
			}
		})
	}
}

// The interrupted run and the healthy run judge the exact same processed
// batch identically: per-line legality, physical line numbers, order, and
// result bytes agree up to the point the broken output stopped accepting.
func TestNormalizeIOShortAndFullDeliveryShareLegality(t *testing.T) {
	input := shortWriteBatchInput()

	var healthy bytes.Buffer
	healthyFailures, healthyErr := NormalizeReader(strings.NewReader(input), &healthy)
	if healthyErr != nil || healthyFailures != 1 {
		t.Fatalf("test setup: healthy reference run: failures=%d err=%v", healthyFailures, healthyErr)
	}

	for _, cut := range []int{0, 5, len(encodedRecord(t, 1, validLog("a"))) + 5} {
		t.Run(fmt.Sprintf("cut_%d", cut), func(t *testing.T) {
			w := &nilErrorPrefixWriter{allowBytes: cut}
			failures, err := NormalizeReader(strings.NewReader(input), w)
			expectShortWriteInterruption(t, w, failures, 1, err)
			if w.buf.Len() != cut {
				t.Fatalf("acknowledged prefix length = %d, want %d", w.buf.Len(), cut)
			}
			if !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
				t.Fatalf("interrupted output must be a prefix of healthy output:\nkept:    %q\nhealthy: %q", w.buf.String(), healthy.String())
			}
		})
	}
}
