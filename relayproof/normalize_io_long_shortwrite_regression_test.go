package relayproof

// Regression coverage for nil-error short acknowledgements while writing a
// result larger than the 4096-byte buffering writer. Such a result bypasses
// the buffer and is handed to the underlying io.Writer in one call; bufio
// retries a (n < len(p), nil) answer forever, so an output end that accepts
// nothing (or only a prefix) without setting an error previously made
// NormalizeReader spin without returning. The fix turns the broken
// acknowledgement into io.ErrShortWrite at the boundary, ending the run with
// ErrLogWrite on the first short answer.
//
// The assertions pin the contract from the task:
//   - zero-byte and non-empty-prefix nil acknowledgements both stop the run
//     immediately, with an error matching ErrLogWrite AND io.ErrShortWrite;
//   - an output that could accept again after the broken answer is neither
//     retried nor allowed to turn the anomaly into success;
//   - a concrete output error stays the cause and is never replaced by
//     io.ErrShortWrite;
//   - accepted bytes remain the unmodified prefix of normal output, complete
//     records keep physical line order, and an incomplete final JSON may
//     remain without an extra fabricated log-failure record;
//   - the failure count describes processed input: an invalid log already
//     normalized counts even when its failure result did not fully arrive,
//     later unprocessed invalid logs do not count, and a legal long log does
//     not become illegal because of the write fault;
//   - under the source-CIDR filter a long out-of-network event is never
//     written (so it cannot trigger the fault), while a long admitted event
//     obeys the same short-write rules and fully arrives on healthy output.
//
// Everything is scripted in-process with the helpers from
// normalize_io_test.go / normalize_io_shortwrite_regression_test.go.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// bigSourcedLog builds a legal log whose normalized result exceeds the 4096
// byte buffer: a 5000-character extra field is the extension evidence. With
// ip != "" the log also carries a source_ip for filter scenarios.
func bigSourcedLog(action, ip string) string {
	source := ""
	if ip != "" {
		source = fmt.Sprintf(`,"source_ip":%q`, ip)
	}
	return fmt.Sprintf(`{"timestamp":"2026-01-02T00:00:00Z","action":%q%s,"pad":%q}`,
		action, source, strings.Repeat("p", 5000))
}

// expectLongShortWriteFailure is the mid-stream analogue of
// expectShortWriteInterruption: the error must classify as a write failure
// carrying io.ErrShortWrite, never a read failure, and processing must stop
// after exactly wantWrites physical attempts (no retry loop).
func expectLongShortWriteFailure(t *testing.T, w *nilErrorPrefixWriter, failures, wantFailures, wantWrites int, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("a nil-error short write on a long result must not end as normal completion, got nil (failures=%d)", failures)
	}
	if !errors.Is(err, ErrLogWrite) {
		t.Fatalf("caller must recognize the interruption via errors.Is(err, ErrLogWrite), got %v", err)
	}
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("error chain must retain io.ErrShortWrite for a nil-error short acknowledgement, got %v", err)
	}
	if errors.Is(err, ErrLogRead) {
		t.Fatalf("a healthy reader must not classify a write interruption as ErrLogRead: %v", err)
	}
	if failures != wantFailures {
		t.Fatalf("invalid-log count must describe processed input regardless of delivery, got %d, want %d", failures, wantFailures)
	}
	if w.writes != wantWrites {
		t.Fatalf("processing must stop on the first nil-error short acknowledgement, got %d write calls, want %d", w.writes, wantWrites)
	}
}

// decodeAvailable decodes every whole record a possibly truncated output
// contains, accepting either a trailing syntax error (cut mid-record), a
// clean record boundary, or empty output. The interruption guarantees never
// add a failure record regardless of where the cut lands.
func decodeAvailable(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var results []map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			return results
		}
		results = append(results, m)
	}
}

// A single legal log longer than the buffer, offered to an output that
// accepts ZERO bytes with a nil error, must end with ErrLogWrite carrying
// io.ErrShortWrite after exactly one physical write: no busy retry, and the
// legal log does not become a failure.
func TestNormalizeIOLongResultZeroByteNilErrorStops(t *testing.T) {
	line := bigSourcedLog("long-a", "")
	rec := encodedRecord(t, 1, line)
	if len(rec) <= 4096 {
		t.Fatalf("test setup: encoded result must exceed the 4096-byte buffer, got %d", len(rec))
	}
	w := &nilErrorPrefixWriter{allowBytes: 0}
	failures, err := NormalizeReader(strings.NewReader(line+"\n"), w)
	expectLongShortWriteFailure(t, w, failures, 0, 1, err)
	if w.buf.Len() != 0 {
		t.Fatalf("zero acknowledged bytes must leave zero output, got %q", w.buf.String())
	}
}

// Non-empty-prefix nil acknowledgements on a long result follow the same rule
// at every cut: stop on the first answer, keep exactly the acknowledged
// prefix of a healthy run's output, allow an incomplete final JSON, and never
// add a failure record. Both a lone long line and a small complete record
// preceding the interrupted long line are covered.
func TestNormalizeIOLongResultPrefixNilErrorKeepsPrefix(t *testing.T) {
	t.Run("single long line", func(t *testing.T) {
		line := bigSourcedLog("long-a", "")
		rec := encodedRecord(t, 1, line)
		var healthy bytes.Buffer
		if _, err := NormalizeReader(strings.NewReader(line+"\n"), &healthy); err != nil {
			t.Fatalf("test setup: healthy reference run failed: %v", err)
		}
		for _, cut := range []int{5, 120, len(rec) - 3} {
			t.Run(fmt.Sprintf("cut_%d", cut), func(t *testing.T) {
				w := &nilErrorPrefixWriter{allowBytes: cut}
				failures, err := NormalizeReader(strings.NewReader(line+"\n"), w)
				expectLongShortWriteFailure(t, w, failures, 0, 1, err)
				if w.buf.Len() != cut {
					t.Fatalf("exactly the acknowledged prefix must remain, got %d bytes, want %d", w.buf.Len(), cut)
				}
				if !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
					t.Fatalf("accepted bytes must be the unmodified prefix of healthy output:\nkept:    %q\nhealthy: %q", w.buf.String(), healthy.String())
				}
				for _, r := range decodeAvailable(t, w.buf.Bytes()) {
					if r["ok"] == false {
						t.Fatalf("write interruption must not add a log failure record, got %#v", r)
					}
				}
			})
		}
	})

	t.Run("small record delivered before the interrupted long line", func(t *testing.T) {
		small := validLog("a")
		line := bigSourcedLog("long-b", "")
		input := small + "\n" + line + "\n"

		var healthy bytes.Buffer
		firstRecord := encodedRecord(t, 1, small)
		if _, err := NormalizeReader(strings.NewReader(input), &healthy); err != nil {
			t.Fatalf("test setup: healthy reference run failed: %v", err)
		}
		// Encoding the long line flushes the buffered small record together
		// with the first buffer-fill of the long line in ONE physical write
		// of 4096 bytes; every cut below lands inside that single offer.
		for _, cut := range []int{0, 5, len(firstRecord) + 10, 4096 - 1} {
			t.Run(fmt.Sprintf("cut_%d", cut), func(t *testing.T) {
				w := &nilErrorPrefixWriter{allowBytes: cut}
				failures, err := NormalizeReader(strings.NewReader(input), w)
				expectLongShortWriteFailure(t, w, failures, 0, 1, err)
				if w.buf.Len() != cut {
					t.Fatalf("exactly the acknowledged prefix must remain, got %d, want %d", w.buf.Len(), cut)
				}
				if !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
					t.Fatalf("accepted bytes must be the unmodified prefix of healthy output:\nkept:    %q\nhealthy: %q", w.buf.String(), healthy.String())
				}
				whole := decodeAvailable(t, w.buf.Bytes())
				for _, r := range whole {
					if r["ok"] == false {
						t.Fatalf("write interruption must not add a log failure record, got %#v", r)
					}
				}
				if cut >= len(firstRecord) {
					if len(whole) != 1 || whole[0]["line"] != float64(1) || whole[0]["ok"] != true {
						t.Fatalf("the complete small record must survive in physical line order, got %#v", whole)
					}
					if eventOf(t, whole[0])["action"] != "a" {
						t.Fatalf("surviving record must be the genuine first log, got %#v", whole[0])
					}
				}
			})
		}
	})
}

// The invalid-log count belongs to processed input around the long-write
// fault:
//  1. an invalid log normalized before the fault counts even when its failure
//     result is cut off mid-record;
//  2. the same invalid log counts when its failure result happened to arrive
//     whole just before the cut;
//  3. invalid logs never reached because the long write failed first do not
//     count, and the legal long log does not become a failure itself.
func TestNormalizeIOLongResultShortWriteFailureCountSemantics(t *testing.T) {
	invalid := `{"timestamp":"not-a-time","action":"bad"}`
	failureRecord := encodedRecord(t, 2, invalid)

	t.Run("invalid already processed, failure result cut off", func(t *testing.T) {
		line1 := bigSourcedLog("long-a", "")
		encoded1 := encodedRecord(t, 1, line1)
		line3 := bigSourcedLog("long-c", "")
		// Line 1 is one full physical write; while line 3 is encoded the
		// buffered line-2 failure record is flushed with line 3's prefix, and
		// only 5 of those bytes are accepted before the nil-error stop.
		w := &nilErrorPrefixWriter{allowBytes: len(encoded1) + 5}
		failures, err := NormalizeReader(strings.NewReader(line1+"\n"+invalid+"\n"+line3+"\n"), w)
		expectLongShortWriteFailure(t, w, failures, 1, 2, err)
		whole := decodeAvailable(t, w.buf.Bytes())
		if len(whole) != 1 || whole[0]["ok"] != true {
			t.Fatalf("only the fully delivered line 1 may decode whole: %#v", whole)
		}
		if eventOf(t, whole[0])["action"] != "long-a" {
			t.Fatalf("surviving record must be the genuine first log, got %#v", whole[0])
		}
	})

	t.Run("invalid already processed, failure result delivered whole", func(t *testing.T) {
		line1 := bigSourcedLog("long-a", "")
		encoded1 := encodedRecord(t, 1, line1)
		line3 := bigSourcedLog("long-c", "")
		w := &nilErrorPrefixWriter{allowBytes: len(encoded1) + len(failureRecord)}
		failures, err := NormalizeReader(strings.NewReader(line1+"\n"+invalid+"\n"+line3+"\n"), w)
		expectLongShortWriteFailure(t, w, failures, 1, 2, err)
		whole := decodeAvailable(t, w.buf.Bytes())
		if len(whole) != 2 {
			t.Fatalf("line 1 and the complete failure record must decode, got %#v", whole)
		}
		if whole[0]["line"] != float64(1) || whole[0]["ok"] != true {
			t.Fatalf("line 1 mismatch: %#v", whole[0])
		}
		if whole[1]["line"] != float64(2) || whole[1]["ok"] != false {
			t.Fatalf("the invalid log must keep physical line number 2: %#v", whole[1])
		}
		if _, exists := whole[1]["event"]; exists {
			t.Fatalf("failure record must not carry an event: %#v", whole[1])
		}
		if msg, _ := whole[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
			t.Fatalf("failure record must keep its own reason, got %q", msg)
		}
	})

	t.Run("later invalid logs are never processed", func(t *testing.T) {
		line1 := bigSourcedLog("long-a", "")
		// The very first physical write is already cut off, so neither later
		// invalid line is ever normalized.
		w := &nilErrorPrefixWriter{allowBytes: 0}
		failures, err := NormalizeReader(strings.NewReader(line1+"\n"+invalid+"\n"+invalid+"\n"), w)
		expectLongShortWriteFailure(t, w, failures, 0, 1, err)
		if w.buf.Len() != 0 {
			t.Fatalf("nothing should have been retained, got %q", w.buf.String())
		}
	})
}

// nilShortThenRecoverWriter returns a nil-error short acknowledgement on its
// first Write and would fully accept every later offer. A correct run must
// never take the later offers: the anomaly is a deterministic failure, not a
// reason to wait for the output end to recover.
type nilShortThenRecoverWriter struct {
	buf         bytes.Buffer
	firstAccept int // bytes acknowledged on the first (short, nil) Write
	writes      int
}

func (w *nilShortThenRecoverWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		n := w.firstAccept
		if n >= len(p) {
			n = len(p) - 1
		}
		w.buf.Write(p[:n])
		return n, nil
	}
	w.buf.Write(p)
	return len(p), nil
}

// Even an output end that could keep receiving afterwards must not make the
// run succeed: the first nil-error short answer ends it with both write
// markers, the acknowledged prefix alone remains, and no second write occurs.
func TestNormalizeIOLongResultNilErrorShortNotRetriedEvenIfOutputRecovers(t *testing.T) {
	line := bigSourcedLog("long-a", "")
	rec := encodedRecord(t, 1, line)

	var healthy bytes.Buffer
	if _, err := NormalizeReader(strings.NewReader(line+"\n"), &healthy); err != nil {
		t.Fatalf("test setup: healthy reference run failed: %v", err)
	}

	for _, firstAccept := range []int{0, 120, len(rec) - 3} {
		t.Run(fmt.Sprintf("first_accept_%d", firstAccept), func(t *testing.T) {
			w := &nilShortThenRecoverWriter{firstAccept: firstAccept}
			failures, err := NormalizeReader(strings.NewReader(line+"\n"), w)
			if err == nil || !errors.Is(err, ErrLogWrite) || !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("the first nil short acknowledgement must end the run as a short write, got %v", err)
			}
			if failures != 0 {
				t.Fatalf("a legal long log must not become a failure, got %d", failures)
			}
			if w.writes != 1 {
				t.Fatalf("the run must not retry an output that later could receive, got %d writes", w.writes)
			}
			if w.buf.Len() != firstAccept {
				t.Fatalf("only the initially acknowledged prefix may remain, got %d bytes, want %d", w.buf.Len(), firstAccept)
			}
			if !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
				t.Fatalf("retained bytes must be the healthy output prefix:\nkept:    %q\nhealthy: %q", w.buf.String(), healthy.String())
			}
		})
	}
}

// An output end that reports a concrete error on a long write keeps that
// error as the write failure's original cause: it must not be replaced by
// io.ErrShortWrite, whether it accepted nothing or a non-empty prefix first.
func TestNormalizeIOLongResultConcreteWriteErrorStaysCause(t *testing.T) {
	line := bigSourcedLog("long-a", "")

	t.Run("nothing accepted, concrete error", func(t *testing.T) {
		w := &failWriter{err: errSimulatedWrite}
		failures, err := NormalizeReader(strings.NewReader(line+"\n"), w)
		if !errors.Is(err, ErrLogWrite) || !errors.Is(err, errSimulatedWrite) {
			t.Fatalf("want ErrLogWrite wrapping the concrete cause, got %v", err)
		}
		if errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("a concrete write error must not be replaced by io.ErrShortWrite: %v", err)
		}
		if failures != 0 {
			t.Fatalf("the legal long log must not become a failure, got %d", failures)
		}
	})

	t.Run("prefix accepted, then concrete error", func(t *testing.T) {
		w := &failWriter{partial: 120, err: errSimulatedWrite}
		failures, err := NormalizeReader(strings.NewReader(line+"\n"), w)
		if !errors.Is(err, ErrLogWrite) || !errors.Is(err, errSimulatedWrite) {
			t.Fatalf("want ErrLogWrite wrapping the concrete cause, got %v", err)
		}
		if errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("a concrete error after a prefix must not become io.ErrShortWrite: %v", err)
		}
		if failures != 0 {
			t.Fatalf("the legal long log must not become a failure, got %d", failures)
		}
		if w.buf.Len() != 120 {
			t.Fatalf("the 120 bytes accepted before the error must remain, got %d", w.buf.Len())
		}
	})
}

// On healthy output the long event completes normally, including its long
// extension evidence: processing runs to clean EOF with nil error, the event
// is valid, and event.extra carries the input's pad field verbatim.
func TestNormalizeIOLongResultFullDeliveryCompletes(t *testing.T) {
	line := bigSourcedLog("long-a", "")
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(line+"\n"), &out)
	if err != nil {
		t.Fatalf("fully acknowledged long output must complete with nil error, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("legal long logs must report zero failures, got %d", failures)
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 1 || results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("the long log must be one successful result in physical line order: %#v", results)
	}
	event := eventOf(t, results[0])
	if event["action"] != "long-a" {
		t.Fatalf("long event must keep its action, got %#v", event)
	}
	extra, ok := event["extra"].(map[string]any)
	if !ok {
		t.Fatalf("long extension field must survive as event.extra, got %#v", event)
	}
	pad, _ := extra["pad"].(string)
	if pad != strings.Repeat("p", 5000) {
		t.Fatalf("extension evidence must be preserved verbatim, got pad length %d", len(pad))
	}
}

// Under the source-CIDR filter the same rules hold: a long out-of-network
// event is not written at all and cannot trip the output fault, a long
// admitted event obeys the nil-error short-write stop, and full delivery
// preserves its normalized content and extension evidence.
func TestNormalizeIOFilteredLongResultShortWrite(t *testing.T) {
	f, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	filter := &f
	inNet := bigSourcedLog("in-big", "192.0.2.10")
	outNet := bigSourcedLog("out-big", "198.51.100.20")

	t.Run("long out-of-network event never touches a broken output", func(t *testing.T) {
		w := &nilErrorPrefixWriter{allowBytes: 0}
		failures, err := NormalizeReaderFiltered(strings.NewReader(outNet+"\n"), w, filter)
		if err != nil {
			t.Fatalf("a filtered-out event must not be written, so its length cannot cause a write fault, got %v", err)
		}
		if failures != 0 || w.writes != 0 || w.buf.Len() != 0 {
			t.Fatalf("filtered-out long event must leave no output, no failures and no write attempts, got failures=%d writes=%d bytes=%d",
				failures, w.writes, w.buf.Len())
		}
	})

	t.Run("long admitted event, zero bytes accepted", func(t *testing.T) {
		w := &nilErrorPrefixWriter{allowBytes: 0}
		failures, err := NormalizeReaderFiltered(strings.NewReader(inNet+"\n"), w, filter)
		expectLongShortWriteFailure(t, w, failures, 0, 1, err)
		if w.buf.Len() != 0 {
			t.Fatalf("zero acknowledged bytes must leave zero output, got %q", w.buf.String())
		}
	})

	t.Run("long admitted event, prefix accepted", func(t *testing.T) {
		var healthy bytes.Buffer
		if _, err := NormalizeReaderFiltered(strings.NewReader(inNet+"\n"), &healthy, filter); err != nil {
			t.Fatalf("test setup: healthy filtered reference run failed: %v", err)
		}
		w := &nilErrorPrefixWriter{allowBytes: 120}
		failures, err := NormalizeReaderFiltered(strings.NewReader(inNet+"\n"), w, filter)
		expectLongShortWriteFailure(t, w, failures, 0, 1, err)
		if w.buf.Len() != 120 {
			t.Fatalf("exactly the acknowledged prefix must remain, got %d", w.buf.Len())
		}
		if !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
			t.Fatalf("accepted bytes must be the unmodified prefix of healthy filtered output:\nkept:    %q\nhealthy: %q", w.buf.String(), healthy.String())
		}
	})

	t.Run("long admitted event fully delivered with evidence, out-of-network one silent", func(t *testing.T) {
		var out bytes.Buffer
		failures, err := NormalizeReaderFiltered(strings.NewReader(outNet+"\n"+inNet+"\n"), &out, filter)
		if err != nil {
			t.Fatalf("healthy delivery must complete with nil error, got %v", err)
		}
		if failures != 0 {
			t.Fatalf("both logs are legal; filtering does not count failures, got %d", failures)
		}
		results := decodeResults(t, out.Bytes())
		if len(results) != 1 || results[0]["line"] != float64(2) || results[0]["ok"] != true {
			t.Fatalf("only the admitted physical line 2 must be emitted, got %#v", results)
		}
		event := eventOf(t, results[0])
		if event["action"] != "in-big" || event["source_ip"] != "192.0.2.10" {
			t.Fatalf("admitted long event mismatch: %#v", event)
		}
		extra, ok := event["extra"].(map[string]any)
		if !ok {
			t.Fatalf("extension evidence must survive under the filter, got %#v", event)
		}
		pad, _ := extra["pad"].(string)
		if pad != strings.Repeat("p", 5000) {
			t.Fatalf("extension evidence must be preserved verbatim, got pad length %d", len(pad))
		}
		if bytes.Contains(out.Bytes(), []byte("out-big")) {
			t.Fatalf("the out-of-network long event must leave no trace: %q", out.String())
		}
	})
}
