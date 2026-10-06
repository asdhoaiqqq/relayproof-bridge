package relayproof

// Regression coverage for assembling one physical log line from many short
// deliveries. A log larger than the 64 KiB read buffer must arrive over many
// Read calls; while its terminating newline is still missing the reader must
// not re-examine bytes an earlier delivery already proved newline-free. The
// old accumulator loop restarted its newline search at byte zero after every
// Read, so a long line fed one byte at a time paid for a full rescan of the
// whole pending prefix per byte — quadratic work that made a multi-MiB line
// take seconds (and a slightly larger one, tens of seconds) without a single
// byte of output. The fixed contract asserted here:
//
//   - Every delivered byte participates in at most one newline search, so a
//     roughly 1 MiB line delivered one byte per Read completes in linear
//     time; the wall-clock bound below is tens of multiples above the fixed
//     runtime and a small fraction of the old quadratic runtime, which is why
//     it is reliable rather than a racy micro-benchmark.
//   - Output is byte-for-byte identical to reading the whole input at once,
//     in both content and failure count, under the one-byte-at-a-time shape
//     (so every boundary lands inside a multi-byte UTF-8 sequence and, for
//     ASCII surroundings, between every other pair of bytes) and under a
//     shape where one final Read carries the long line's newline together
//     with every following log: those later logs are neither lost, merged
//     into the long line, nor emitted twice.
//   - Physical line numbering is untouched: the long line is line 1, a short
//     line after it still uses its own number 2, a blank line only occupies
//     number 3, an invalid complete line keeps number 4 and its original
//     reason, and later valid lines keep processing. The long unknown text
//     reaches extra whole, with no length cap, no truncation, and no
//     replacement characters.
//   - With --source-cidr semantics (NormalizeReaderFiltered) the same scale
//     holds: only non-admitted successes disappear, the out-of-network
//     invalid line is still the failure with its number and reason, and
//     dropped lines never renumber later records.
//
// All inputs are built and replayed in-process, so the cases reproduce
// deterministically offline.

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

// longScaledInput builds one stream around a single very long valid log.
// The blob is longPattern repeated, a sequence full of multi-byte UTF-8, so
// one-byte delivery splits inside Chinese characters and the emoji on every
// line. Physical layout:
//
//	line 1: oversized valid log carrying blob verbatim in extra
//	line 2: ordinary short valid log (source outside the test filter)
//	line 3: blank
//	line 4: invalid-timestamp complete log (source outside the test filter)
//	line 5: CRLF-terminated valid log with an emoji extra
//	line 6: final valid log without a trailing newline
//
// Every line carries source_ip so the same input drives the filtered entry
// point as well; the addresses only matter there.
func longScaledInput(blob string) string {
	long := `{"timestamp":"2026-01-02T00:00:00Z","action":"big","source_ip":"192.0.2.7","blob":` + jsonString(blob) + `}`
	return long + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"after","source_ip":"198.51.100.9"}` + "\n" +
		"\n" +
		`{"timestamp":"not-a-time","action":"bad","source_ip":"198.51.100.9"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"尾","source_ip":"192.0.2.7","note":"结束🚀"}` + "\r\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"tail","source_ip":"192.0.2.7"}`
}

// oneByteAtATimeReader hands over exactly one byte per Read, mirroring an
// upstream that dribbles a long log out; after the bytes it answers EOF. It
// never returns (0, nil).
type oneByteAtATimeReader struct {
	data []byte
	pos  int
}

func (r *oneByteAtATimeReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

// longLineThenBatchReader dribbles the oversized first line one byte per
// Read, then delivers its terminating newline AND every following log in a
// single final Read. That batch is the boundary the accumulator must not
// fumble: the newline completes the long line, while the remaining bytes are
// separate lines that must each be processed exactly once.
type longLineThenBatchReader struct {
	data      []byte
	boundary  int // bytes delivered one at a time; the rest goes in one batch
	pos       int
	batchSent bool
}

func (r *longLineThenBatchReader) Read(p []byte) (int, error) {
	switch {
	case r.pos < r.boundary:
		if len(p) == 0 {
			return 0, nil
		}
		p[0] = r.data[r.pos]
		r.pos++
		return 1, nil
	case !r.batchSent:
		n := copy(p, r.data[r.pos:])
		r.pos += n
		r.batchSent = true
		return n, nil
	default:
		return 0, io.EOF
	}
}

// scaledLongLineCostBound is the linearity guard: an about-1 MiB pending line
// delivered one byte per Read must normalize in well under a second on a
// contended machine. The fixed implementation spends roughly tens of
// milliseconds here (search work proportional to the byte count), while the
// old rescan-from-zero loop spent several seconds on this exact shape, so the
// bound is simultaneously far above fixed-machine noise and far below the
// quadratic regression it guards against.
const scaledLongLineCostBound = 2 * time.Second

// assertScaledBusinessResults checks the results shared by the whole-input
// and reassembled runs: exact line numbers, outcomes, order, the one failure
// with its timestamp reason, and the blob preserved whole in extra.
func assertScaledBusinessResults(t *testing.T, results []map[string]any, blob string) {
	t.Helper()
	if len(results) != 5 {
		t.Fatalf("five non-blank logs must yield five results, got %d: %#v", len(results), results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("oversized line 1 must succeed: %#v", results[0])
	}
	if got := extraOf(t, results[0])["blob"]; got != blob {
		t.Fatalf("long unknown text must enter extra verbatim (got %d chars, want %d)",
			len(got.(string)), len(blob))
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != true {
		t.Fatalf("short line after the oversized one must keep line number 2: %#v", results[1])
	}
	if eventOf(t, results[1])["action"] != "after" {
		t.Fatalf("line 2 must keep its own content: %#v", results[1])
	}
	// Blank physical line 3 only advances the counter.
	if results[2]["line"] != float64(4) || results[2]["ok"] != false {
		t.Fatalf("invalid log must fail on physical line 4: %#v", results[2])
	}
	if _, exists := results[2]["event"]; exists {
		t.Fatalf("failed log must not carry an event: %#v", results[2])
	}
	if msg, _ := results[2]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("line 4 must keep its timestamp-specific reason, got %q", msg)
	}
	if results[3]["line"] != float64(5) || results[3]["ok"] != true {
		t.Fatalf("CRLF-terminated line 5 must succeed: %#v", results[3])
	}
	if eventOf(t, results[3])["action"] != "尾" {
		t.Fatalf("line 5 action mismatch: %#v", results[3])
	}
	if extraOf(t, results[3])["note"] != "结束🚀" {
		t.Fatalf("line 5 emoji extra must survive split delivery: %#v", results[3])
	}
	if results[4]["line"] != float64(6) || results[4]["ok"] != true {
		t.Fatalf("final newline-less log must succeed on line 6: %#v", results[4])
	}
	if eventOf(t, results[4])["action"] != "tail" {
		t.Fatalf("line 6 content mismatch: %#v", results[4])
	}
}

// The unfiltered entry point: a roughly 1 MiB line dribbled one byte per Read
// produces exactly the whole-input output and failure count, in linear time,
// and the same holds when one final Read carries the long line's newline
// together with all following logs.
func TestNormalizeLongLineAssembledFromShortDeliveries(t *testing.T) {
	blob := strings.Repeat("长x🚀", 140000) // 8 bytes each, about 1.12 MiB
	input := longScaledInput(blob)
	if len(input) < 1024*1024 {
		t.Fatalf("test setup: oversized log must be around 1 MiB, got %d bytes", len(input))
	}

	var baseline bytes.Buffer
	baseFailures, err := NormalizeReader(strings.NewReader(input), &baseline)
	if err != nil {
		t.Fatalf("whole-input baseline must not fail, got %v", err)
	}
	if baseFailures != 1 {
		t.Fatalf("test setup: only line 4 may fail, got %d failures", baseFailures)
	}

	t.Run("one byte per read", func(t *testing.T) {
		var out bytes.Buffer
		start := time.Now()
		failures, err := NormalizeReader(&oneByteAtATimeReader{data: []byte(input)}, &out)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("dribbled delivery must not become a stream error, got %v", err)
		}
		if failures != baseFailures || out.String() != baseline.String() {
			t.Fatalf("dribbled delivery changed results: failures got %d want %d", failures, baseFailures)
		}
		if elapsed > scaledLongLineCostBound {
			t.Fatalf("rescanning already-received bytes is quadratic: %d-byte line one byte per Read took %v, want under %v",
				len(input), elapsed, scaledLongLineCostBound)
		}
		assertScaledBusinessResults(t, decodeResults(t, out.Bytes()), blob)
	})

	// Dribble every byte up to (but not including) the long first line's
	// newline; that newline and all following logs arrive in one final Read.
	boundary := strings.IndexByte(input, '\n')
	if boundary < 0 {
		t.Fatalf("test setup: first line must be newline-terminated")
	}

	t.Run("newline and following logs in one batch", func(t *testing.T) {
		var out bytes.Buffer
		failures, err := NormalizeReader(&longLineThenBatchReader{
			data:     []byte(input),
			boundary: boundary,
		}, &out)
		if err != nil {
			t.Fatalf("batched delivery must not become a stream error, got %v", err)
		}
		if failures != baseFailures {
			t.Fatalf("batched delivery changed the failure count: got %d, want %d", failures, baseFailures)
		}
		if out.String() != baseline.String() {
			t.Fatalf("the batch carrying the long line's newline and later logs changed the output")
		}
		assertScaledBusinessResults(t, decodeResults(t, out.Bytes()), blob)
	})
}

// The filtered entry point at the same scale: admitted hits and the one
// failure survive exactly as in a whole-input filtered read, the
// out-of-network invalid line is still emitted with number 4 and its reason,
// the dropped line 2 renumbers nothing, and the long text stays whole.
func TestNormalizeLongLineAssembledFromShortDeliveriesFiltered(t *testing.T) {
	blob := strings.Repeat("长x🚀", 140000)
	input := longScaledInput(blob)
	filter := mustSourceFilter(t, "192.0.2.0/24")

	var baseline bytes.Buffer
	baseFailures, err := NormalizeReaderFiltered(strings.NewReader(input), &baseline, filter)
	if err != nil {
		t.Fatalf("whole-input filtered baseline must not fail, got %v", err)
	}

	var out bytes.Buffer
	start := time.Now()
	failures, err := NormalizeReaderFiltered(&oneByteAtATimeReader{data: []byte(input)}, &out, filter)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("dribbled filtered delivery must not become a stream error, got %v", err)
	}
	if elapsed > scaledLongLineCostBound {
		t.Fatalf("filtered rescanning is quadratic: took %v, want under %v", elapsed, scaledLongLineCostBound)
	}
	if failures != baseFailures {
		t.Fatalf("filtering changed the failure count: got %d, want %d", failures, baseFailures)
	}
	if out.String() != baseline.String() {
		t.Fatalf("dribbled filtered delivery changed the output")
	}
	if baseFailures != 1 {
		t.Fatalf("only the invalid complete line counts, got %d failures", baseFailures)
	}

	// Line 2 was a valid but out-of-network success and is absent; line 3 was
	// blank. Remaining records: hit on 1, failure on 4, hits on 5 and 6.
	results := decodeResults(t, out.Bytes())
	if len(results) != 4 {
		t.Fatalf("expected 4 records (three hits plus the failure), got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("oversized admitted line 1 must succeed: %#v", results[0])
	}
	if got := extraOf(t, results[0])["blob"]; got != blob {
		t.Fatalf("long unknown text must enter extra verbatim (got %d chars, want %d)",
			len(got.(string)), len(blob))
	}
	if results[1]["line"] != float64(4) || results[1]["ok"] != false {
		t.Fatalf("out-of-network invalid line must still fail on line 4: %#v", results[1])
	}
	if msg, _ := results[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("line 4 must keep its timestamp-specific reason, got %q", msg)
	}
	if results[2]["line"] != float64(5) || results[3]["line"] != float64(6) {
		t.Fatalf("later hits must keep physical numbers 5 and 6: %#v", results)
	}
}
