package relayproof

// Regression coverage for the end-of-stream boundary when one Read delivers
// bytes together with an error that carries BOTH io.EOF and an independent
// read cause. Go permits a Reader to return a combined error — errors.Join,
// a custom error with an Unwrap() []error, or either behind ordinary
// single-cause wrapping — and a plain errors.Is(err, io.EOF) matches it even
// though a genuine failure rode along. Classifying such a delivery as a clean
// EOF dropped the read cause entirely and, worse, normalized the newline-less
// tail as a complete final log.
//
// The fixed contract asserted here:
//   - io.EOF joined with another cause (in any order), behind wrapping or via
//     a custom multi-cause error, is a read interruption: errors.Is matches
//     ErrLogRead and the reader's actual cause; complete newline-ended lines
//     delivered in the same call are still processed in order; the trailing
//     newline-less fragment produces neither an event nor a failure and does
//     not move the failure count, even when it is a complete valid JSON object;
//   - processing stops without a second Read;
//   - a bare io.EOF and an error that wraps ONLY the EOF marker stay normal
//     completion, including the final newline-less log;
//   - the same distinction holds under the source-CIDR filter, which may
//     suppress successes but never hide the interruption;
//   - when an output fault fires after such a combined read fault, the read
//     fault stays the only errors.Is chain; the write cause is text only.
//
// Everything is scripted in-process, so the boundary reproduces
// deterministically offline.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// multiCauseError is a hand-written multi-cause error satisfying the same
// errors.Is/Unwrap() []error contract as errors.Join. It proves the classifier
// works against the contract rather than matching errors.Join's concrete type.
type multiCauseError struct {
	causes []error
}

func (e *multiCauseError) Error() string {
	parts := make([]string, len(e.causes))
	for i, c := range e.causes {
		parts[i] = c.Error()
	}
	return strings.Join(parts, "\n")
}

func (e *multiCauseError) Unwrap() []error { return e.causes }

// singleWrapError is an ordinary one-cause wrapper with the same semantics as
// fmt.Errorf("...: %w", cause), written explicitly so the test does not depend
// on the standard library's wrapper type.
type singleWrapError struct {
	msg   string
	cause error
}

func (e *singleWrapError) Error() string { return e.msg + ": " + e.cause.Error() }
func (e *singleWrapError) Unwrap() error { return e.cause }

// cyclicWrapError points back into a graph that may contain itself, exercising
// the classifier's cycle guard.
type cyclicWrapError struct {
	note  string
	inner error
}

func (e *cyclicWrapError) Error() string { return e.note }
func (e *cyclicWrapError) Unwrap() error { return e.inner }

// countReader counts Read calls so tests can prove processing never reads
// again merely to confirm how the stream ended.
type countReader struct {
	r     io.Reader
	reads int
}

func (c *countReader) Read(p []byte) (int, error) {
	c.reads++
	return c.r.Read(p)
}

// The classifier itself: only an error whose whole Unwrap tree is the EOF
// marker is a clean end. Any independent leaf is a fault; this includes a
// cause sitting beside EOF in a join and the same behind ordinary wrapping.
func TestIsCleanEOF(t *testing.T) {
	joinEOFCause := errors.Join(io.EOF, errSimulatedRead)
	joinCauseEOF := errors.Join(errSimulatedRead, io.EOF)

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not an end at all", nil, false},
		{"bare io.EOF is clean", io.EOF, true},
		{"ordinary wrapping of io.EOF is clean", fmt.Errorf("closed: %w", io.EOF), true},
		{"custom wrapper of io.EOF only is clean", &singleWrapError{msg: "closed", cause: io.EOF}, true},
		{"a join of only EOF markers carries no other cause", errors.Join(io.EOF, io.EOF), true},
		{"a plain non-EOF fault is not clean", errSimulatedRead, false},
		{"wrapped non-EOF fault is not clean", fmt.Errorf("device: %w", errSimulatedRead), false},
		{"errors.Join(EOF, cause) is not clean", joinEOFCause, false},
		{"errors.Join(cause, EOF) is not clean", joinCauseEOF, false},
		{"custom multi-cause EOF+cause is not clean", &multiCauseError{causes: []error{io.EOF, errSimulatedRead}}, false},
		{"a join EOF+cause behind ordinary wrapping is not clean",
			fmt.Errorf("device closed: %w", joinEOFCause), false},
		{"a custom multi-cause EOF+cause behind custom wrapping is not clean",
			&singleWrapError{msg: "device closed", cause: &multiCauseError{causes: []error{io.EOF, errSimulatedRead}}}, false},
		{"wrapping an EOF-only join is still clean",
			fmt.Errorf("closed: %w", errors.Join(io.EOF, io.EOF)), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCleanEOF(tc.err); got != tc.want {
				t.Fatalf("isCleanEOF(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}

	// A self-referential Unwrap graph must terminate rather than loop. Since
	// it never reaches the EOF marker it is not a clean end (fail-safe: an
	// error that is not demonstrably io.EOF must not be treated as normal
	// completion); a cycle that also reaches a real cause is a fault as well.
	pureCycle := &cyclicWrapError{note: "cyclic"}
	pureCycle.inner = pureCycle
	if isCleanEOF(pureCycle) {
		t.Fatalf("a cycle with no EOF leaf must not be treated as clean EOF")
	}
	withCause := &cyclicWrapError{note: "cyclic"}
	withCause.inner = &multiCauseError{causes: []error{withCause, errSimulatedRead}}
	if isCleanEOF(withCause) {
		t.Fatalf("a cycle that also reaches a real cause must not be clean EOF")
	}

	// An unwrapper exposing no leaf at all is not the EOF marker: fail safe.
	emptyMulti := &multiCauseError{causes: nil}
	if isCleanEOF(emptyMulti) {
		t.Fatalf("an empty multi-cause error must not be treated as clean EOF")
	}
	nilWrap := &singleWrapError{msg: "nothing underneath", cause: nil}
	if isCleanEOF(nilWrap) {
		t.Fatalf("a nil-cause wrapper must not be treated as clean EOF")
	}
}

// The core boundary: complete lines, a valid-JSON newline-less tail, and an
// EOF+cause combined error all arrive in ONE Read. The complete lines survive
// exactly as a healthy read of them would; the tail is part of the failed
// read (no record, no failure count); the call returns the interruption with
// both sentinels reachable; and no second Read happens.
func TestNormalizeIOEOFJoinedWithFaultInSameRead(t *testing.T) {
	complete, fragment := mixedCompleteLinesAndFragment()
	cases := []struct {
		name string
		err  error
	}{
		{"errors.Join(io.EOF, cause)", errors.Join(io.EOF, errSimulatedRead)},
		{"errors.Join(cause, io.EOF)", errors.Join(errSimulatedRead, io.EOF)},
		{"custom multi-cause EOF+cause", &multiCauseError{causes: []error{io.EOF, errSimulatedRead}}},
		{"join EOF+cause behind ordinary wrapping",
			fmt.Errorf("device gone: %w", errors.Join(io.EOF, errSimulatedRead))},
		{"custom multi-cause EOF+cause behind custom wrapping",
			&singleWrapError{msg: "device gone", cause: &multiCauseError{causes: []error{io.EOF, errSimulatedRead}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := &scriptReader{steps: []scriptStep{
				{data: []byte(complete + fragment), err: tc.err},
			}}
			src := &countReader{r: inner}
			var out bytes.Buffer
			failures, err := NormalizeReader(src, &out)
			if err == nil {
				t.Fatalf("EOF combined with a read cause must not be normal completion")
			}
			if !errors.Is(err, ErrLogRead) {
				t.Fatalf("caller must recognize ErrLogRead, got %v", err)
			}
			if !errors.Is(err, errSimulatedRead) {
				t.Fatalf("the reader's actual cause must stay reachable via errors.Is, got %v", err)
			}
			if errors.Is(err, ErrLogWrite) {
				t.Fatalf("a healthy writer must not tag the result as a write failure: %v", err)
			}
			if !strings.Contains(err.Error(), errSimulatedRead.Error()) {
				t.Fatalf("diagnostic text must retain the read cause, got %q", err.Error())
			}
			if failures != 1 {
				t.Fatalf("only the invalid complete line counts; the valid-JSON tail adds nothing, got %d", failures)
			}
			if src.reads != 1 {
				t.Fatalf("processing must stop after the fault delivery without reading again, got %d reads", src.reads)
			}

			results := decodeResults(t, out.Bytes())
			if len(results) != 2 {
				t.Fatalf("only the two non-blank complete lines may be emitted, got %#v", results)
			}
			if results[0]["line"] != float64(1) || results[0]["ok"] != true ||
				results[1]["line"] != float64(3) || results[1]["ok"] != false {
				t.Fatalf("delivered complete lines keep healthy order, numbers, outcomes: %#v", results)
			}
			if bytes.Contains(out.Bytes(), []byte("tail-fragment")) {
				t.Fatalf("the newline-less tail belongs to the failed read and must leave no record: %q", out.String())
			}

			var healthy bytes.Buffer
			healthyFailures, healthyErr := NormalizeReader(strings.NewReader(complete), &healthy)
			if healthyErr != nil || healthyFailures != 1 {
				t.Fatalf("test setup: healthy reference read failed: failures=%d err=%v", healthyFailures, healthyErr)
			}
			if !bytes.Equal(out.Bytes(), healthy.Bytes()) {
				t.Fatalf("fault run output must equal a healthy read of the complete lines:\nfault:   %q\nhealthy: %q",
					out.String(), healthy.String())
			}
		})
	}
}

// A lone newline-less valid JSON object — or no bytes at all — delivered with
// an EOF+cause combination yields empty output and zero failures, yet still
// returns the read interruption. Empty output with zero failures must never
// read as normal completion.
func TestNormalizeIOEOFJoinedWithFaultNoCompleteLines(t *testing.T) {
	fragment := `{"timestamp":"2026-01-02T00:00:00Z","action":"lonely-fragment"}`
	cases := []struct {
		name string
		data string
	}{
		{"a parseable fragment rides the failed read", fragment},
		{"the fault carries no bytes", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := &scriptReader{steps: []scriptStep{
				{data: []byte(tc.data), err: errors.Join(io.EOF, errSimulatedRead)},
			}}
			src := &countReader{r: inner}
			var out bytes.Buffer
			failures, err := NormalizeReader(src, &out)
			if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
				t.Fatalf("want ErrLogRead wrapping the actual read cause, got %v", err)
			}
			if failures != 0 {
				t.Fatalf("a failed-read fragment must never count as a line failure, got %d", failures)
			}
			if out.Len() != 0 {
				t.Fatalf("no complete line means no output at all, got %q", out.String())
			}
			if src.reads != 1 {
				t.Fatalf("must not read again to confirm the end, got %d reads", src.reads)
			}
		})
	}
}

// Control: a bare io.EOF and an error wrapping ONLY the EOF marker remain
// ordinary completion, so the final newline-less log is normalized just like
// at a plain EOF.
func TestNormalizeIOBareAndWrappedEOFStillNormalCompletion(t *testing.T) {
	complete, fragment := mixedCompleteLinesAndFragment()
	cases := []struct {
		name string
		err  error
	}{
		{"bare io.EOF", io.EOF},
		{"ordinary wrapping of io.EOF only", fmt.Errorf("stream closed: %w", io.EOF)},
		{"custom wrapping of io.EOF only", &singleWrapError{msg: "stream closed", cause: io.EOF}},
		{"a join containing only EOF markers", errors.Join(io.EOF, io.EOF)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &scriptReader{steps: []scriptStep{
				{data: []byte(complete + fragment), err: tc.err},
			}}
			var out bytes.Buffer
			failures, err := NormalizeReader(src, &out)
			if err != nil {
				t.Fatalf("an end marker with no other cause is normal completion, got %v", err)
			}
			if failures != 1 {
				t.Fatalf("only the one invalid complete line counts, got %d", failures)
			}
			results := decodeResults(t, out.Bytes())
			if len(results) != 3 {
				t.Fatalf("the final newline-less log must still be processed: %#v", results)
			}
			if results[2]["line"] != float64(4) || results[2]["ok"] != true {
				t.Fatalf("trailing newline-less log must be physical line 4: %#v", results[2])
			}
			if eventOf(t, results[2])["action"] != "tail-fragment" {
				t.Fatalf("trailing log content mismatch: %#v", results[2])
			}
		})
	}
}

// Under the source-CIDR filter the same joined-EOF boundary holds: filtering
// may suppress out-of-network successes, but it cannot hide an EOF+cause read
// interruption, and the admittable newline-less tail still rides the failed
// read and leaves no record.
func TestNormalizeReaderFilteredEOFJoinedWithFault(t *testing.T) {
	filter, complete := filteredInterruptFixture(t)
	tail := `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-in-allowed","source_ip":"192.0.2.77"}`

	t.Run("joined EOF+cause interrupts despite the filter", func(t *testing.T) {
		inner := &scriptReader{steps: []scriptStep{
			{data: []byte(complete + tail), err: errors.Join(io.EOF, errSimulatedRead)},
		}}
		src := &countReader{r: inner}
		var out bytes.Buffer
		failures, err := NormalizeReaderFiltered(src, &out, filter)
		if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
			t.Fatalf("want ErrLogRead wrapping the actual cause, got %v", err)
		}
		if failures != 1 {
			t.Fatalf("only the complete invalid line 4 counts; the tail adds nothing, got %d", failures)
		}
		if src.reads != 1 {
			t.Fatalf("must stop without reading again, got %d reads", src.reads)
		}
		results := decodeResults(t, out.Bytes())
		if len(results) != 2 {
			t.Fatalf("expected line 1 success and line 4 failure only, got %#v", results)
		}
		if results[0]["line"] != float64(1) || results[0]["ok"] != true {
			t.Fatalf("in-network line 1 must be emitted with its physical number: %#v", results[0])
		}
		if eventOf(t, results[0])["action"] != "in-allowed" {
			t.Fatalf("line 1 event mismatch: %#v", results[0])
		}
		if results[1]["line"] != float64(4) || results[1]["ok"] != false {
			t.Fatalf("outside-source invalid-time line must keep physical number 4: %#v", results[1])
		}
		if bytes.Contains(out.Bytes(), []byte("tail-in-allowed")) {
			t.Fatalf("the newline-less tail belongs to the failed read and must leave no record: %q", out.String())
		}
	})

	t.Run("wrapped EOF only still completes and processes the tail", func(t *testing.T) {
		src := &scriptReader{steps: []scriptStep{
			{data: []byte(complete + tail), err: fmt.Errorf("closed: %w", io.EOF)},
		}}
		var out bytes.Buffer
		failures, err := NormalizeReaderFiltered(src, &out, filter)
		if err != nil {
			t.Fatalf("wrapped EOF with no other cause is normal completion, got %v", err)
		}
		if failures != 1 {
			t.Fatalf("only line 4 fails; the tail is a valid fifth line, got %d", failures)
		}
		results := decodeResults(t, out.Bytes())
		if len(results) != 3 {
			t.Fatalf("clean wrapped EOF must process the newline-less tail as line 5: %#v", results)
		}
		if results[2]["line"] != float64(5) || results[2]["ok"] != true {
			t.Fatalf("tail must be physical line 5 success: %#v", results[2])
		}
		if eventOf(t, results[2])["action"] != "tail-in-allowed" {
			t.Fatalf("line 5 event mismatch: %#v", results[2])
		}
	})
}

// When an output fault fires while emitting results that arrived in the same
// delivery as an EOF+cause combined read fault, the read fault stays the
// primary error: ErrLogRead and the reader's cause are reachable via
// errors.Is, the write cause is text only, and the newline-less tail still
// leaves no record. The combined marker must not let the run look like a
// clean EOF that merely then failed to write.
func TestNormalizeIOEOFJoinedWithFaultWinsOverWriteFault(t *testing.T) {
	invalid := `{"timestamp":"not-a-time","action":"bad"}`
	big := bigValidLog("big")
	if len(encodedRecord(t, 2, big)) <= 4096 {
		t.Fatalf("test setup: encoded long line must exceed the 4096-byte write buffer")
	}
	prefix := invalid + "\n"
	fragment := `{"timestamp":"2026-01-02T00:00:00Z","action":"fault-tail"}`

	src := newFaultWithBatchReader(prefix, big, fragment)
	// The persistent reader fault is an EOF combined with a real cause.
	src.faultErr = errors.Join(io.EOF, errSimulatedRead)
	w := &failWriter{allowBytes: len(encodedRecord(t, 1, invalid)), partial: 120, err: errSimulatedWrite}
	failures, err := NormalizeReader(src, w)
	expectReadPrimaryOverWrite(t, err)
	if failures != 1 {
		t.Fatalf("only the invalid complete line counts; the long line and fault tail add nothing, got %d", failures)
	}
	if src.postFaultReads != 0 {
		t.Fatalf("processing must stop without another Read after the combined fault, got %d", src.postFaultReads)
	}
	if bytes.Contains(w.buf.Bytes(), []byte("fault-tail")) {
		t.Fatalf("the fault's newline-less tail must leave no record: %q", w.buf.String())
	}
}
