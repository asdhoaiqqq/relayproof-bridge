package relayproof

// Regression coverage for read interruptions while the 192.0.2.0/24 source
// filter is active. The filter must not blur the line between a stream that
// simply had no admitted events and one that was cut off before it was fully
// read:
//
//   - Complete lines already delivered by a failed read keep their results,
//     in physical line order: admitted successes are emitted, out-of-network
//     successes and blank lines stay invisible without renumbering anything,
//     and a failed line is still emitted with its physical number and reason
//     even though its source is outside the network.
//   - A newline-less tail delivered together with a non-EOF read fault is part
//     of the failed read: whether it is a complete, admittable JSON object or
//     carries an invalid timestamp, it produces no success or failure record
//     and does not move the failure count.
//   - The caller still receives the interruption as ErrLogRead wrapping the
//     underlying cause, even when output is empty and the failure count is
//     zero. The same bytes at a clean EOF are ordinary completion instead.
//
// Every scenario is scripted through scriptReader from normalize_io_test.go,
// so the boundary reproduces deterministically offline without real pipes,
// networks, or device failures.

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// filteredInterruptFixture builds the shared batch:
//
//	line 1: valid log from inside 192.0.2.0/24      -> admitted success
//	line 2: valid log from outside the network      -> silently filtered
//	line 3: blank line                              -> no output, keeps number
//	line 4: outside source, invalid timestamp       -> failure with reason
//
// All four end with "\n". The returned tail fragments have NO trailing
// newline: at a clean EOF they are a fifth physical line, under a read fault
// they are a fragment of the failed read.
func filteredInterruptFixture(t *testing.T) (filter *SourceCIDRFilter, complete string) {
	t.Helper()
	f, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	complete = strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"in-allowed","source_ip":"192.0.2.10"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"out-dropped","source_ip":"198.51.100.20"}`,
		``,
		`{"timestamp":"not-a-time","action":"bad-time-outside","source_ip":"198.51.100.30"}`,
	}, "\n") + "\n"
	return &f, complete
}

// A read fault that delivers the complete lines and an unterminated tail in
// the SAME Read must preserve exactly the newline-ended processing: the
// in-network success on physical line 1 and the timestamp failure on
// physical line 4 (not renumbered for the filtered line 2 or blank line 3).
// The tail is swallowed with the read whether it is already a complete,
// admittable JSON object or itself has an invalid timestamp.
func TestNormalizeReaderFilteredReadFaultWithBytesInSameRead(t *testing.T) {
	filter, complete := filteredInterruptFixture(t)
	cases := []struct {
		name     string
		fragment string
		marker   string // text unique to the fragment, must never appear in output
	}{
		{
			name:     "tail is a complete admittable JSON object",
			fragment: `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-in-allowed","source_ip":"192.0.2.77"}`,
			marker:   "tail-in-allowed",
		},
		{
			name:     "tail carries an invalid timestamp",
			fragment: `{"timestamp":"not-a-time","action":"tail-bad-time","source_ip":"192.0.2.77"}`,
			marker:   "tail-bad-time",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &scriptReader{steps: []scriptStep{
				// Complete lines, the newline-less tail, and the fault all
				// become available in a single Read.
				{data: []byte(complete + tc.fragment), err: errSimulatedRead},
			}}
			var out bytes.Buffer
			failures, err := NormalizeReaderFiltered(src, &out, filter)
			if err == nil {
				t.Fatalf("a read fault must not be reported as normal completion, even with %d failures", failures)
			}
			if !errors.Is(err, ErrLogRead) {
				t.Fatalf("caller must recognize ErrLogRead, got %v", err)
			}
			if !errors.Is(err, errSimulatedRead) {
				t.Fatalf("the reader's original cause must stay reachable, got %v", err)
			}
			if errors.Is(err, ErrLogWrite) {
				t.Fatalf("a healthy writer must not tag the result as a write failure: %v", err)
			}
			if !strings.Contains(err.Error(), errSimulatedRead.Error()) {
				t.Fatalf("error text must retain the original read cause, got %q", err.Error())
			}
			if failures != 1 {
				t.Fatalf("only the complete invalid line 4 counts; the failed-read tail adds nothing, got %d", failures)
			}

			results := decodeResults(t, out.Bytes())
			if len(results) != 2 {
				t.Fatalf("expected line 1 success and line 4 failure only, got %#v", results)
			}
			if results[0]["line"] != float64(1) || results[0]["ok"] != true {
				t.Fatalf("in-network line 1 must be emitted with its physical number: %#v", results[0])
			}
			event := eventOf(t, results[0])
			if event["action"] != "in-allowed" || event["source_ip"] != "192.0.2.10" {
				t.Fatalf("line 1 event mismatch: %#v", event)
			}
			if results[1]["line"] != float64(4) || results[1]["ok"] != false {
				t.Fatalf("outside-source invalid-time line must keep physical number 4: %#v", results[1])
			}
			if _, exists := results[1]["event"]; exists {
				t.Fatalf("failed record must not carry an event: %#v", results[1])
			}
			if msg, _ := results[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
				t.Fatalf("failed record must keep the timestamp-specific reason, got %q", msg)
			}

			if bytes.Contains(out.Bytes(), []byte("out-dropped")) {
				t.Fatalf("the out-of-network valid line must produce no record: %q", out.String())
			}
			if bytes.Contains(out.Bytes(), []byte(tc.marker)) {
				t.Fatalf("the newline-less tail belongs to the failed read and must leave no record: %q", out.String())
			}

			// The fault run must equal a healthy read of exactly the complete
			// lines under the same filter: filtering, blank-line skipping,
			// ordering, and numbering are all byte-for-byte unchanged.
			var healthy bytes.Buffer
			healthyFailures, healthyErr := NormalizeReaderFiltered(strings.NewReader(complete), &healthy, filter)
			if healthyErr != nil || healthyFailures != 1 {
				t.Fatalf("test setup: healthy reference read failed: failures=%d err=%v", healthyFailures, healthyErr)
			}
			if !bytes.Equal(out.Bytes(), healthy.Bytes()) {
				t.Fatalf("fault run output must equal a healthy read of the complete lines:\nfault:   %q\nhealthy: %q", out.String(), healthy.String())
			}
		})
	}
}

// When the only complete line before the interruption is a valid but
// out-of-network log, the run has no output and zero failures -- the same
// observable shape as "nothing matched" -- yet the read error must still be
// visible so callers do not mistake a cut-off stream for an empty result.
func TestNormalizeReaderFilteredReadFaultAfterOnlyDroppedLines(t *testing.T) {
	filter, _ := filteredInterruptFixture(t)
	outsideOnly := `{"timestamp":"2026-01-02T00:00:00Z","action":"out-dropped","source_ip":"198.51.100.20"}` + "\n"
	tail := `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-in-allowed","source_ip":"192.0.2.77"}`

	cases := []struct {
		name string
		step scriptStep
	}{
		{
			name: "fault stands alone after the newline",
			step: scriptStep{data: []byte(outsideOnly), err: errSimulatedRead},
		},
		{
			name: "fault delivers an admittable newline-less fragment too",
			step: scriptStep{data: []byte(outsideOnly + tail), err: errSimulatedRead},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &scriptReader{steps: []scriptStep{tc.step}}
			var out bytes.Buffer
			failures, err := NormalizeReaderFiltered(src, &out, filter)
			if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
				t.Fatalf("want ErrLogRead wrapping the read cause, got %v", err)
			}
			if failures != 0 {
				t.Fatalf("no complete line failed normalization, got %d failures", failures)
			}
			if out.Len() != 0 {
				t.Fatalf("dropped lines and a failed-read fragment must leave empty output, got %q", out.String())
			}
		})
	}

	// Control: the same out-of-network-only bytes ending in a clean EOF are
	// genuinely "no events hit" -- empty output, zero failures, and NO error.
	// That nil-vs-ErrLogRead distinction is what lets callers tell the two
	// empty-result cases apart.
	var clean bytes.Buffer
	failures, err := NormalizeReaderFiltered(strings.NewReader(outsideOnly), &clean, filter)
	if err != nil {
		t.Fatalf("clean EOF with no admitted events must not be an error, got %v", err)
	}
	if failures != 0 || clean.Len() != 0 {
		t.Fatalf("clean EOF with only dropped lines must be an empty, failure-free result, got failures=%d out=%q", failures, clean.String())
	}
}

// The same batch terminated by a clean EOF treats the newline-less tail as
// the fifth physical line per the existing rules: an admittable tail appends
// a line-5 success, an invalid-time tail appends a line-5 failure (raising
// the count to 2), the pre-existing line-4 failure is never lost, and no
// stream-level error is returned.
func TestNormalizeReaderFilteredCleanEOFProcessesNewlineLessTail(t *testing.T) {
	filter, complete := filteredInterruptFixture(t)
	cases := []struct {
		name         string
		fragment     string
		tailOK       bool
		wantFailures int
	}{
		{
			name:         "tail is a complete admittable JSON object",
			fragment:     `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-in-allowed","source_ip":"192.0.2.77"}`,
			tailOK:       true,
			wantFailures: 1,
		},
		{
			name:         "tail carries an invalid timestamp",
			fragment:     `{"timestamp":"not-a-time","action":"tail-bad-time","source_ip":"192.0.2.77"}`,
			tailOK:       false,
			wantFailures: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &scriptReader{steps: []scriptStep{
				// All bytes and clean EOF become available together.
				{data: []byte(complete + tc.fragment), err: io.EOF},
			}}
			var out bytes.Buffer
			failures, err := NormalizeReaderFiltered(src, &out, filter)
			if err != nil {
				t.Fatalf("clean EOF is ordinary completion, including a final line without newline, got %v", err)
			}
			if failures != tc.wantFailures {
				t.Fatalf("want %d failures (line 4 plus any tail failure), got %d", tc.wantFailures, failures)
			}
			results := decodeResults(t, out.Bytes())
			if len(results) != 3 {
				t.Fatalf("expected line 1 success, line 4 failure, line 5 tail result, got %#v", results)
			}
			if results[0]["line"] != float64(1) || results[0]["ok"] != true {
				t.Fatalf("line 1 must keep its physical number and success: %#v", results[0])
			}
			if eventOf(t, results[0])["action"] != "in-allowed" {
				t.Fatalf("line 1 event mismatch: %#v", results[0])
			}
			// The earlier complete-line failure must not be ignored just
			// because the stream ended on an additional line.
			if results[1]["line"] != float64(4) || results[1]["ok"] != false {
				t.Fatalf("line 4 failure must survive ahead of the tail: %#v", results[1])
			}
			if _, exists := results[1]["event"]; exists {
				t.Fatalf("line 4 failure must not carry an event: %#v", results[1])
			}
			if msg, _ := results[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
				t.Fatalf("line 4 must keep the timestamp-specific reason, got %q", msg)
			}
			if results[2]["line"] != float64(5) || results[2]["ok"] != tc.tailOK {
				t.Fatalf("tail must be processed as physical line 5 (ok=%v): %#v", tc.tailOK, results[2])
			}
			if tc.tailOK {
				if eventOf(t, results[2])["action"] != "tail-in-allowed" {
					t.Fatalf("line 5 event mismatch: %#v", results[2])
				}
			} else {
				if _, exists := results[2]["event"]; exists {
					t.Fatalf("line 5 failure must not carry an event: %#v", results[2])
				}
				if msg, _ := results[2]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
					t.Fatalf("line 5 must keep the timestamp-specific reason, got %q", msg)
				}
			}
		})
	}
}
