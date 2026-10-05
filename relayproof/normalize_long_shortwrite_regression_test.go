package relayproof

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// Regression coverage for a nil-error short write on a result LARGER than
// the internal 4096-byte output buffer. Short results stay buffered and are
// only delivered by the shutdown Flush, whose short-write handling already
// exists; but a single result bigger than the buffer is handed straight to
// the underlying writer (bufio's empty-buffer fast path), and a writer that
// acknowledges fewer bytes than offered with a nil error is then either
// retried forever (the (0, nil) case leaves the offer unchanged and the
// buffer sticky-error slot unset) or treated as a complete delivery (a
// non-empty prefix acknowledgement). Both violate the stream contract: the
// run must end deterministically with ErrLogWrite wrapping io.ErrShortWrite,
// after one acknowledgement, regardless of whether the output later becomes
// willing to receive again.
//
// Everything is scripted in-process (nilErrorPrefixWriter and failWriter
// from the other I/O regression tests, plus a recovering writer below), so
// the hang reproduces deterministically without real pipes, networks, or
// device failures.

// runNormalizeBounded calls NormalizeReader (or the filtered entry) and fails
// the test if a broken writer can make the call hang instead of return. The
// pre-fix code loops forever on a (0, nil) acknowledgement of a direct large
// write; the 2s bound turns that hang into a deterministic failure instead
// of waiting out the whole test binary timeout.
func runNormalizeBounded(t *testing.T, r io.Reader, w io.Writer, filter *SourceCIDRFilter) (int, error) {
	t.Helper()
	type outcome struct {
		failures int
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		if filter != nil {
			f, e := NormalizeReaderFiltered(r, w, filter)
			done <- outcome{f, e}
			return
		}
		f, e := NormalizeReader(r, w)
		done <- outcome{f, e}
	}()
	select {
	case o := <-done:
		return o.failures, o.err
	case <-time.After(2 * time.Second):
		t.Fatalf("NormalizeReader did not return after a nil-error short write on a long result (processing hung)")
		return 0, nil
	}
}

// recoversAfterShortWriter returns a short acknowledgement with a nil error
// on the first Write, then accepts every byte offered on every later Write.
// It models an output end whose self-inflicted (n < len(p), nil) hiccup heals
// immediately: a correct sink must still end the run at the first hiccup
// rather than waiting for or noticing the recovery.
type recoversAfterShortWriter struct {
	buf      bytes.Buffer
	firstN   int
	calls    int
	recovery bool // set once the first Write has returned
}

func (w *recoversAfterShortWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		n := w.firstN
		if n > len(p) {
			n = len(p)
		}
		w.buf.Write(p[:n])
		w.recovery = true
		return n, nil
	}
	if !w.recovery {
		panic("recovering writer: subsequent write before the first short acknowledgement")
	}
	w.buf.Write(p)
	return len(p), nil
}

// invalidSmallLog is a complete, field-invalid line whose failure result is
// small enough to stay buffered ahead of a later oversized result.
const invalidSmallLog = `{"timestamp":"not-a-time","action":"bad"}`

// bigSourcedLog builds a valid log whose encoded result exceeds the 4096-byte
// output buffer thanks to a long extra field, carrying the given source_ip.
func bigSourcedLog(t *testing.T, action, sourceIP string) string {
	t.Helper()
	line := fmt.Sprintf(
		`{"timestamp":"2026-01-02T00:00:00Z","action":%q,"source_ip":%q,"pad":%q}`,
		action, sourceIP, strings.Repeat("p", 5000))
	if rec := encodedRecord(t, 1, line); len(rec) <= 4096 {
		t.Fatalf("test setup: encoded long result must exceed the 4096-byte buffer, got %d bytes", len(rec))
	}
	return line
}

// A single oversized valid result delivered straight to the underlying
// writer must stop the run on ANY nil-error short acknowledgement: zero
// bytes, a non-empty prefix, or a prefix cut only bytes before the end. The
// error must satisfy both errors.Is(err, ErrLogWrite) and
// errors.Is(err, io.ErrShortWrite), exactly one physical write must be
// attempted, and the retained bytes must be the unmodified prefix of a
// healthy run's output (an incomplete trailing JSON is allowed; no extra log
// failure record may be synthesized).
func TestNormalizeIOLongResultNilErrorShortWriteStops(t *testing.T) {
	long := bigValidLog("long")

	var healthy bytes.Buffer
	healthyFailures, healthyErr := NormalizeReader(strings.NewReader(long+"\n"), &healthy)
	if healthyErr != nil || healthyFailures != 0 {
		t.Fatalf("test setup: healthy reference run: failures=%d err=%v", healthyFailures, healthyErr)
	}

	cases := []struct {
		name       string
		allowBytes int
	}{
		{"accepts zero bytes then nil forever", 0},
		{"accepts a 120-byte prefix", 120},
		{"accepts all but the final three bytes", healthy.Len() - 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &nilErrorPrefixWriter{allowBytes: tc.allowBytes}
			failures, err := runNormalizeBounded(t, strings.NewReader(long+"\n"), w, nil)
			expectShortWriteInterruption(t, w, failures, 0, err)
			if w.buf.Len() != tc.allowBytes {
				t.Fatalf("exactly the acknowledged prefix must remain, got %d bytes, want %d", w.buf.Len(), tc.allowBytes)
			}
			if !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
				t.Fatalf("retained bytes must be the unmodified prefix of healthy output:\nkept:    %q\nhealthy: %q",
					w.buf.String(), healthy.String())
			}
			// The interruption must not fabricate a log failure record; the
			// tail may be an incomplete JSON record of the one valid log.
			if tc.allowBytes > 0 {
				for _, r := range decodePrefix(t, w.buf.Bytes()) {
					if r["ok"] == false {
						t.Fatalf("write interruption must not add a log failure record, got %#v", r)
					}
				}
			}
		})
	}
}

// When the output heals immediately after its first nil-error short
// acknowledgement, the run must STILL end at that first acknowledgement: the
// later, fully accepting Write calls must never be reached, so the anomaly
// cannot be silently completed into a success or awaited until recovery.
func TestNormalizeIOLongResultShortWriteStopsEvenWhenWriterRecovers(t *testing.T) {
	long := bigValidLog("long")

	t.Run("first acknowledgement is zero bytes", func(t *testing.T) {
		w := &recoversAfterShortWriter{firstN: 0}
		failures, err := runNormalizeBounded(t, strings.NewReader(long+"\n"), w, nil)
		if err == nil || !errors.Is(err, ErrLogWrite) || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short nil acknowledgement must end the run as ErrLogWrite/ErrShortWrite, got %v", err)
		}
		if failures != 0 {
			t.Fatalf("the valid long log must not become a failure, got %d", failures)
		}
		if w.calls != 1 {
			t.Fatalf("processing must not retry waiting for recovery, got %d write calls", w.calls)
		}
		if w.buf.Len() != 0 {
			t.Fatalf("nothing was acknowledged, got %q", w.buf.String())
		}
	})

	t.Run("first acknowledgement is a non-empty prefix", func(t *testing.T) {
		w := &recoversAfterShortWriter{firstN: 300}
		failures, err := runNormalizeBounded(t, strings.NewReader(long+"\n"), w, nil)
		if err == nil || !errors.Is(err, ErrLogWrite) || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short nil acknowledgement must end the run as ErrLogWrite/ErrShortWrite, got %v", err)
		}
		if failures != 0 {
			t.Fatalf("the valid long log must not become a failure, got %d", failures)
		}
		if w.calls != 1 {
			t.Fatalf("processing must not resume after the writer recovers, got %d write calls", w.calls)
		}
		if w.buf.Len() != 300 {
			t.Fatalf("only the first acknowledged prefix may remain, got %d bytes", w.buf.Len())
		}
	})
}

// The returned failure count describes processed input only, independent of
// how many results the broken output received:
//
//   - An invalid log whose normalization already finished counts even when
//     its (small, buffered) failure record is swept into the same physical
//     write that the long result triggers and never reaches the output whole.
//   - An invalid log BEHIND the interrupted long result was never processed
//     and must not count.
//   - The legal long log itself never turns into an invalid log because of
//     the write fault.
func TestNormalizeIOLongResultShortWriteFailureCount(t *testing.T) {
	long := bigValidLog("long")
	invalidRec := encodedRecord(t, 1, invalidSmallLog)

	t.Run("processed invalid counts though its record never ships", func(t *testing.T) {
		input := invalidSmallLog + "\n" + long + "\n"

		t.Run("no bytes accepted", func(t *testing.T) {
			w := &nilErrorPrefixWriter{allowBytes: 0}
			failures, err := runNormalizeBounded(t, strings.NewReader(input), w, nil)
			expectShortWriteInterruption(t, w, failures, 1, err)
			if w.buf.Len() != 0 {
				t.Fatalf("nothing should be retained, got %q", w.buf.String())
			}
		})

		t.Run("failure record ships whole but the flush still cuts early", func(t *testing.T) {
			// The first physical write holds the buffered failure record and
			// a prefix of the oversized result; accept the failure record
			// plus a 7-byte fragment, so exactly one whole record -- the
			// failure itself -- reaches the output before the interruption.
			cut := len(invalidRec) + 7
			w := &nilErrorPrefixWriter{allowBytes: cut}
			failures, err := runNormalizeBounded(t, strings.NewReader(input), w, nil)
			expectShortWriteInterruption(t, w, failures, 1, err)
			if w.buf.Len() != cut {
				t.Fatalf("acknowledged prefix length = %d, want %d", w.buf.Len(), cut)
			}
			whole := decodePrefix(t, w.buf.Bytes())
			if len(whole) != 1 || whole[0]["ok"] != false || whole[0]["line"] != float64(1) {
				t.Fatalf("only the processed line-1 failure may be a whole record: %#v", whole)
			}
		})
	})

	t.Run("later invalid log is never processed or counted", func(t *testing.T) {
		input := long + "\n" + invalidSmallLog + "\n"

		t.Run("no bytes accepted", func(t *testing.T) {
			w := &nilErrorPrefixWriter{allowBytes: 0}
			failures, err := runNormalizeBounded(t, strings.NewReader(input), w, nil)
			expectShortWriteInterruption(t, w, failures, 0, err)
			if w.buf.Len() != 0 {
				t.Fatalf("nothing should be retained, got %q", w.buf.String())
			}
			if bytes.Contains(w.buf.Bytes(), []byte("bad")) {
				t.Fatalf("the unprocessed later line must leave no trace: %q", w.buf.String())
			}
		})

		t.Run("prefix of the long result accepted", func(t *testing.T) {
			w := &nilErrorPrefixWriter{allowBytes: 120}
			failures, err := runNormalizeBounded(t, strings.NewReader(input), w, nil)
			expectShortWriteInterruption(t, w, failures, 0, err)
			if w.buf.Len() != 120 {
				t.Fatalf("only the 120 acknowledged bytes may remain, got %d", w.buf.Len())
			}
			if len(decodePrefix(t, w.buf.Bytes())) != 0 {
				t.Fatalf("a 120-byte prefix cannot contain a whole record")
			}
		})
	})
}

// When the output returns a concrete error together with a partial
// acknowledgement of a direct large write, that concrete cause must survive
// as the write failure's original reason: it must neither be replaced by
// io.ErrShortWrite nor retried. The nil-error conversion applies only to the
// nil-error contract violation.
func TestNormalizeIOLongResultConcreteWriteErrorIsKept(t *testing.T) {
	line1 := bigValidLog("a")
	line2 := bigValidLog("b")
	encoded1 := encodedRecord(t, 1, line1)

	w := &failWriter{allowBytes: len(encoded1), partial: 120, err: errSimulatedWrite}
	failures, err := runNormalizeBounded(t, strings.NewReader(line1+"\n"+line2+"\n"), w, nil)
	if err == nil {
		t.Fatalf("the concrete write failure must be returned")
	}
	if !errors.Is(err, ErrLogWrite) || !errors.Is(err, errSimulatedWrite) {
		t.Fatalf("want ErrLogWrite wrapping the concrete cause, got %v", err)
	}
	if errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("a concrete cause must not be replaced by io.ErrShortWrite: %v", err)
	}
	if errors.Is(err, ErrLogRead) {
		t.Fatalf("a healthy reader must not tag the error as a read failure: %v", err)
	}
	if failures != 0 {
		t.Fatalf("a write fault must not add a log failure, got %d", failures)
	}
	if w.buf.Len() != len(encoded1)+120 {
		t.Fatalf("the interrupted write must leave line 1 plus 120 partial bytes, got %d", w.buf.Len())
	}
}

// The same rules hold on the filtered public entry: a valid oversized event
// OUTSIDE the selected network is never offered to the output at all (its
// long extra field cannot provoke a write fault, it is not a failure, and the
// run completes normally), while an oversized event that actually has to be
// written obeys the same nil-error short-write rule; on full delivery the
// long event and its extra evidence emit normally and processing ends clean.
func TestNormalizeReaderFilteredLongResultShortWrite(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	inside := bigSourcedLog(t, "in-long", "192.0.2.10")
	outside := bigSourcedLog(t, "out-long", "198.51.100.20")

	t.Run("filtered-out long event never touches the output", func(t *testing.T) {
		// Two out-of-network oversized lines: the broken writer must never
		// be called, so its nil-error rejection cannot turn into a fault.
		w := &nilErrorPrefixWriter{allowBytes: 0}
		failures, err := runNormalizeBounded(t,
			strings.NewReader(outside+"\n"+outside+"\n"), w, &filter)
		if err != nil {
			t.Fatalf("unwritten filtered events must complete without a stream error, got %v", err)
		}
		if failures != 0 {
			t.Fatalf("filtered-out valid events are not failures, got %d", failures)
		}
		if w.writes != 0 || w.buf.Len() != 0 {
			t.Fatalf("the output must never be contacted for a filtered event: calls=%d bytes=%q",
				w.writes, w.buf.String())
		}
	})

	t.Run("admitted long event stops on a nil-error short write", func(t *testing.T) {
		// The admitted oversized result is the very first output: the write
		// buffer is empty, so bufio hands it straight to the underlying
		// writer rather than flushing buffered bytes first.
		t.Run("direct write with an empty buffer", func(t *testing.T) {
			for _, tc := range []struct {
				name       string
				allowBytes int
			}{
				{"zero bytes", 0},
				{"120-byte prefix", 120},
			} {
				t.Run(tc.name, func(t *testing.T) {
					w := &nilErrorPrefixWriter{allowBytes: tc.allowBytes}
					failures, err := runNormalizeBounded(t, strings.NewReader(inside+"\n"), w, &filter)
					expectShortWriteInterruption(t, w, failures, 0, err)
					if w.buf.Len() != tc.allowBytes {
						t.Fatalf("acknowledged prefix length = %d, want %d", w.buf.Len(), tc.allowBytes)
					}
				})
			}
		})

		// An invalid small line processed ahead of the long event still
		// counts: the filter never hides a normalization failure, and a write
		// fault neither adds nor removes such counts.
		t.Run("after a processed invalid small line", func(t *testing.T) {
			input := invalidSmallLog + "\n" + inside + "\n"
			for _, tc := range []struct {
				name       string
				allowBytes int
			}{
				{"zero bytes", 0},
				{"120-byte prefix", 120},
			} {
				t.Run(tc.name, func(t *testing.T) {
					w := &nilErrorPrefixWriter{allowBytes: tc.allowBytes}
					failures, err := runNormalizeBounded(t, strings.NewReader(input), w, &filter)
					expectShortWriteInterruption(t, w, failures, 1, err)
				})
			}
		})
	})

	t.Run("admitted long event delivers fully with its extra evidence", func(t *testing.T) {
		// Out-of-network line 1 emits nothing but keeps physical numbering;
		// in-network line 2 is the oversized result that goes out whole.
		input := outside + "\n" + inside + "\n"
		var out bytes.Buffer
		failures, err := runNormalizeBounded(t, strings.NewReader(input), &out, &filter)
		if err != nil {
			t.Fatalf("fully acknowledged output must complete normally, got %v", err)
		}
		if failures != 0 {
			t.Fatalf("valid events must report zero failures, got %d", failures)
		}
		results := decodeResults(t, out.Bytes())
		if len(results) != 1 {
			t.Fatalf("only the admitted event must be present, got %#v", results)
		}
		if results[0]["line"] != float64(2) || results[0]["ok"] != true {
			t.Fatalf("admitted event must keep physical line 2: %#v", results[0])
		}
		event := eventOf(t, results[0])
		if event["action"] != "in-long" || event["source_ip"] != "192.0.2.10" {
			t.Fatalf("admitted event mismatch: %#v", event)
		}
		if pad := extraOf(t, results[0])["pad"]; pad != strings.Repeat("p", 5000) {
			got, _ := pad.(string)
			t.Fatalf("long extra field must be preserved verbatim, got %d chars, want 5000", len(got))
		}
		if bytes.Contains(out.Bytes(), []byte("out-long")) {
			t.Fatalf("the filtered-out event must leave no record: %q", out.String())
		}
	})
}
