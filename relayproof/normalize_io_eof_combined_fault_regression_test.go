package relayproof

// Regression coverage for the end-of-input decision when a single Read
// delivers bytes together with a COMBINED error: one that carries io.EOF
// joined with another independent cause (errors.Join), possibly behind
// ordinary %w wrapping. errors.Is(err, io.EOF) matches such a combination,
// so it used to be mistaken for a clean end of input: the real read cause
// vanished and the newline-less tail fragment was normalized as if it were
// a complete final line.
//
// The fixed contract asserted here:
//   - only an error that is io.EOF and nothing else (plain, %w-wrapped, or
//     joined with nothing but io.EOF) is normal completion; a combination
//     that pairs io.EOF with any other independent cause is a read fault;
//   - the caller recognizes the interruption via errors.Is against both
//     ErrLogRead and the reader's own cause, and the diagnostic text keeps
//     that cause; processing stops without another Read;
//   - complete newline-ended lines delivered with the fault are still
//     processed in order (valid lines succeed, invalid lines keep their
//     original failure reason, blank lines occupy a number without output),
//     while the newline-less tail belongs to the failed read: no event, no
//     failure record, no count — even when it is itself a fully legal JSON
//     object. With no complete line at all the output is empty and the
//     failure count zero, yet the return still reports the interruption;
//   - the source-CIDR filter only hides success records; it never hides the
//     interruption, and a later output fault supplements the diagnostic
//     text without replacing or joining the read error chain.
//
// Everything is scripted in-process, so the boundary reproduces
// deterministically offline without real pipes, networks, or devices.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// oneShotFaultReader delivers all of data together with err on the first
// Read, mirroring a reader whose underlying device fails in the same read
// that hands over the final bytes. Any later Read is counted: processing
// must stop at the fault instead of reading on to confirm the end.
type oneShotFaultReader struct {
	data           []byte
	err            error
	delivered      bool
	postFaultReads int
}

func (r *oneShotFaultReader) Read(p []byte) (int, error) {
	if r.delivered {
		r.postFaultReads++
		return 0, r.err
	}
	r.delivered = true
	n := copy(p, r.data)
	if n < len(r.data) {
		panic("oneShotFaultReader data larger than the caller's buffer; shrink the data")
	}
	return n, r.err
}

// combinedFaultFixture is the shared batch for the combined-error runs:
//
//	line 1: valid log                                -> success
//	line 2: invalid timestamp                        -> failure with reason
//	line 3: blank line                               -> no output, keeps number
//	line 4: valid log                                -> success
//	tail:   valid JSON object WITHOUT a newline      -> part of the failed read
//
// The tail is a fully legal log on its own, so mistaking the combined error
// for a clean EOF is directly observable as a fifth record.
func combinedFaultFixture() (complete, tail string) {
	complete = strings.Join([]string{
		validLog("a"),
		`{"timestamp":"not-a-time","action":"b"}`,
		``,
		validLog("d"),
	}, "\n") + "\n"
	tail = `{"timestamp":"2026-01-02T00:00:00Z","action":"combined-tail"}`
	return complete, tail
}

// A combined io.EOF+fault error delivered with the final batch is a read
// interruption: the complete lines are processed exactly as in a healthy
// run, the legal newline-less tail leaves no trace, the failure count
// covers only the invalid complete line, and the returned error keeps both
// ErrLogRead and the reader's own cause recognizable — whether the
// combination is bare or hidden behind ordinary %w wrapping.
func TestNormalizeIOCombinedEOFFaultIsReadInterruption(t *testing.T) {
	complete, tail := combinedFaultFixture()

	var healthy bytes.Buffer
	healthyFailures, healthyErr := NormalizeReader(strings.NewReader(complete), &healthy)
	if healthyErr != nil || healthyFailures != 1 {
		t.Fatalf("test setup: healthy reference read failed: failures=%d err=%v", healthyFailures, healthyErr)
	}

	cases := []struct {
		name string
		err  error
	}{
		{"joined EOF and fault", errors.Join(io.EOF, errSimulatedRead)},
		{"joined fault and EOF (order swapped)", errors.Join(errSimulatedRead, io.EOF)},
		{"wrapped joined combination", fmt.Errorf("upstream device lost: %w", errors.Join(io.EOF, errSimulatedRead))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &oneShotFaultReader{data: []byte(complete + tail), err: tc.err}
			var out bytes.Buffer
			failures, err := NormalizeReader(src, &out)
			if err == nil {
				t.Fatalf("a combined EOF+fault error must not be normal completion")
			}
			if !errors.Is(err, ErrLogRead) {
				t.Fatalf("caller must recognize ErrLogRead, got %v", err)
			}
			if !errors.Is(err, errSimulatedRead) {
				t.Fatalf("the reader's own cause must stay reachable through the combination, got %v", err)
			}
			if errors.Is(err, ErrLogWrite) {
				t.Fatalf("a healthy writer must not tag the error as a write failure: %v", err)
			}
			if !strings.Contains(err.Error(), errSimulatedRead.Error()) {
				t.Fatalf("diagnostic text must keep the read cause, got %q", err.Error())
			}
			if failures != 1 {
				t.Fatalf("only the invalid complete line counts; the failed-read tail adds nothing, got %d", failures)
			}
			if src.postFaultReads != 0 {
				t.Fatalf("processing must stop at the fault without reading on, got %d post-fault reads", src.postFaultReads)
			}
			if !bytes.Equal(out.Bytes(), healthy.Bytes()) {
				t.Fatalf("complete lines must be processed exactly as in a healthy run:\nfault:   %q\nhealthy: %q", out.String(), healthy.String())
			}
			if bytes.Contains(out.Bytes(), []byte("combined-tail")) {
				t.Fatalf("the newline-less tail belongs to the failed read and must leave no record: %q", out.String())
			}
			results := decodeResults(t, out.Bytes())
			if len(results) != 3 {
				t.Fatalf("expected the 3 non-blank complete lines only, got %#v", results)
			}
			if results[0]["line"] != float64(1) || results[0]["ok"] != true {
				t.Fatalf("line 1 must succeed with its physical number: %#v", results[0])
			}
			if results[1]["line"] != float64(2) || results[1]["ok"] != false {
				t.Fatalf("line 2 must keep its physical number past the blank line: %#v", results[1])
			}
			if msg, _ := results[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
				t.Fatalf("line 2 must keep its original failure reason, got %q", msg)
			}
			if results[2]["line"] != float64(4) || results[2]["ok"] != true {
				t.Fatalf("line 4 must succeed with its physical number: %#v", results[2])
			}
		})
	}
}

// The combined fault arrives with only a newline-less fragment and no
// complete line at all: the output is empty and the failure count zero, yet
// the return value still reports the read interruption.
func TestNormalizeIOCombinedEOFFaultWithoutAnyCompleteLine(t *testing.T) {
	_, tail := combinedFaultFixture()
	src := &oneShotFaultReader{data: []byte(tail), err: errors.Join(io.EOF, errSimulatedRead)}
	var out bytes.Buffer
	failures, err := NormalizeReader(src, &out)
	if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
		t.Fatalf("want ErrLogRead wrapping the reader's cause, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("no complete line means no failed logs, got %d", failures)
	}
	if out.Len() != 0 {
		t.Fatalf("no complete line means no output, got %q", out.String())
	}
	if src.postFaultReads != 0 {
		t.Fatalf("processing must stop at the fault without reading on, got %d post-fault reads", src.postFaultReads)
	}
}

// Errors that carry io.EOF and NOTHING else stay normal completion: the
// plain marker, an ordinary %w chain around it, and a join of only EOF
// markers all process the newline-less final line and return no error.
func TestNormalizeIOOnlyEOFWrappingsStayCleanCompletion(t *testing.T) {
	complete, tail := combinedFaultFixture()
	cases := []struct {
		name string
		err  error
	}{
		{"plain io.EOF", io.EOF},
		{"wrapped io.EOF", fmt.Errorf("connection closed: %w", io.EOF)},
		{"join of only EOF markers", errors.Join(io.EOF, io.EOF)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &scriptReader{steps: []scriptStep{
				{data: []byte(complete + tail), err: tc.err},
			}}
			var out bytes.Buffer
			failures, err := NormalizeReader(src, &out)
			if err != nil {
				t.Fatalf("an error that is only io.EOF must be normal completion, got %v", err)
			}
			if failures != 1 {
				t.Fatalf("only the invalid complete line counts, got %d", failures)
			}
			results := decodeResults(t, out.Bytes())
			if len(results) != 4 {
				t.Fatalf("the newline-less final line must be processed at a clean EOF: %#v", results)
			}
			if results[3]["line"] != float64(5) || results[3]["ok"] != true {
				t.Fatalf("the tail must become physical line 5: %#v", results[3])
			}
			if eventOf(t, results[3])["action"] != "combined-tail" {
				t.Fatalf("final line content mismatch: %#v", results[3])
			}
		})
	}
}

// Under the source-CIDR filter the same end decision holds: the filter
// hides the out-of-network success but never the read interruption, and the
// in-network newline-less tail riding the combined fault leaves no record.
func TestNormalizeReaderFilteredCombinedEOFFaultIsReadInterruption(t *testing.T) {
	f, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	filter := &f
	complete := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"in-allowed","source_ip":"192.0.2.10"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"out-dropped","source_ip":"198.51.100.20"}`,
		`{"timestamp":"not-a-time","action":"bad-time-outside","source_ip":"198.51.100.30"}`,
	}, "\n") + "\n"
	tail := `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-in-allowed","source_ip":"192.0.2.77"}`

	src := &oneShotFaultReader{
		data: []byte(complete + tail),
		err:  fmt.Errorf("upstream device lost: %w", errors.Join(io.EOF, errSimulatedRead)),
	}
	var out bytes.Buffer
	failures, err := NormalizeReaderFiltered(src, &out, filter)
	if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
		t.Fatalf("the filter must not hide the read interruption, got %v", err)
	}
	if failures != 1 {
		t.Fatalf("only the invalid complete line counts, got %d", failures)
	}
	if src.postFaultReads != 0 {
		t.Fatalf("processing must stop at the fault without reading on, got %d post-fault reads", src.postFaultReads)
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 2 {
		t.Fatalf("expected the admitted success and the failure record only, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("in-network line 1 must be emitted: %#v", results[0])
	}
	if results[1]["line"] != float64(3) || results[1]["ok"] != false {
		t.Fatalf("the invalid line must keep physical number 3: %#v", results[1])
	}
	if bytes.Contains(out.Bytes(), []byte("out-dropped")) {
		t.Fatalf("the out-of-network valid line must produce no record: %q", out.String())
	}
	if bytes.Contains(out.Bytes(), []byte("tail-in-allowed")) {
		t.Fatalf("the failed-read tail must leave no record: %q", out.String())
	}
}

// When the combined read fault is already in hand and the shutdown flush of
// the buffered results also fails, the read failure stays primary: both
// ErrLogRead and the reader's cause remain errors.Is-reachable, the write
// fault contributes only its message text, and neither ErrLogWrite nor the
// write cause joins the error chain.
func TestNormalizeIOCombinedEOFFaultWinsOverFlushFault(t *testing.T) {
	complete, tail := combinedFaultFixture()
	src := &oneShotFaultReader{
		data: []byte(complete + tail),
		err:  errors.Join(io.EOF, errSimulatedRead),
	}
	// Small records stay buffered, so the first physical write is the
	// shutdown flush, which fails with a distinct error.
	w := &failWriter{err: errSimulatedWrite}
	failures, err := NormalizeReader(src, w)
	if err == nil {
		t.Fatalf("expected the read failure, got nil")
	}
	if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
		t.Fatalf("the combined read cause must reach the caller, got %v", err)
	}
	if errors.Is(err, ErrLogWrite) || errors.Is(err, errSimulatedWrite) {
		t.Fatalf("the later flush fault must not replace or join the read error chain: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, errSimulatedRead.Error()) {
		t.Fatalf("error text must name the read cause, got %q", msg)
	}
	if !strings.Contains(msg, errSimulatedWrite.Error()) {
		t.Fatalf("the shutdown write failure should stay visible in the message, got %q", msg)
	}
	if failures != 1 {
		t.Fatalf("only the invalid complete line counts, got %d", failures)
	}
}
