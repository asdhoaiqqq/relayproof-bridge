package relayproof

// Regression coverage for read interruptions while the IPv4 source network
// filter is enabled. The caller must be able to tell "no event matched the
// filter" apart from "the stream broke before all logs were read": a non-EOF
// read fault surfaces as ErrLogRead wrapping the original cause no matter
// what the complete lines before it produced — admitted events, silently
// filtered events, failures, or nothing at all. Complete newline-ended lines
// delivered in the same Read as the fault keep their results; the trailing
// newline-less fragment belongs to the failed read and yields neither a
// record nor a failure count, whether or not it parses as a valid log.
//
// All fault injection is scripted in-process through scriptReader from
// normalize_io_test.go, so every scenario reproduces deterministically
// offline without real pipes, networks, or device failures.

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// filteredMixedCompleteLines holds every kind of complete physical line a
// filtered run can meet, each terminated by a newline:
//
//	line 1: a valid log whose source is inside 192.0.2.0/24 (admitted)
//	line 2: a valid log whose source is outside the network (silently dropped)
//	line 3: a blank line (no output, but it keeps its physical line number)
//	line 4: a log with an out-of-network source AND an invalid timestamp
//	        (a failure record: the filter never hides bad logs)
//
// The fragment variants are newline-less tails whose source is inside the
// network: one a complete, field-valid JSON log, one with an invalid
// timestamp. At a clean EOF either is the final complete log (physical
// line 5); under a read fault either is a fragment of the failed read.
func filteredMixedCompleteLinesAndFragments() (complete, validFragment, badTimeFragment string) {
	complete = `{"timestamp":"2026-01-02T00:00:00Z","action":"in-net","source_ip":"192.0.2.10"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"out-net","source_ip":"198.51.100.9"}` + "\n" +
		"\n" +
		`{"timestamp":"not-a-time","action":"bad-time","source_ip":"198.51.100.9"}` + "\n"
	validFragment = `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-in-net","source_ip":"192.0.2.99"}`
	badTimeFragment = `{"timestamp":"not-a-time","action":"tail-bad-time","source_ip":"192.0.2.99"}`
	return complete, validFragment, badTimeFragment
}

func mustFilter192_0_2_0_24(t *testing.T) *SourceCIDRFilter {
	t.Helper()
	filter, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	return &filter
}

// A non-EOF read fault arriving in the SAME Read as the complete lines and
// the trailing fragment must preserve the complete lines' results — the
// admitted line 1 event and the line 4 failure record with their original
// physical line numbers — while the fragment, valid JSON or not, produces
// nothing. The caller still receives ErrLogRead wrapping the read cause.
func TestSourceCIDRFilterReadFaultWithBytesInSameRead(t *testing.T) {
	complete, validFragment, badTimeFragment := filteredMixedCompleteLinesAndFragments()
	cases := []struct {
		name     string
		fragment string
		marker   string
	}{
		{"fragment is a valid in-network log", validFragment, "tail-in-net"},
		{"fragment has an invalid timestamp", badTimeFragment, "tail-bad-time"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filter := mustFilter192_0_2_0_24(t)
			src := &scriptReader{steps: []scriptStep{
				// One step: complete lines, the fragment, and the fault
				// all become available in the same Read.
				{data: []byte(complete + tc.fragment), err: errSimulatedRead},
			}}
			var out bytes.Buffer
			failures, err := NormalizeReaderFiltered(src, &out, filter)

			// The interruption must reach the caller as a stream-level read
			// failure, never as normal completion — the admitted success and
			// the counted failure already in hand change nothing about that.
			if err == nil {
				t.Fatalf("a read fault must not be reported as normal completion")
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

			// Only the invalid complete line (line 4) counts: the filtered-out
			// line 2, the blank line 3, and the failed-read fragment add
			// nothing.
			if failures != 1 {
				t.Fatalf("only the invalid complete line counts as a failure, got %d", failures)
			}

			// Output must equal a healthy filtered read of the very same
			// complete lines, byte for byte: the fault neither swallows
			// delivered lines nor renumbers them.
			var healthy bytes.Buffer
			healthyFailures, healthyErr := NormalizeReaderFiltered(strings.NewReader(complete), &healthy, filter)
			if healthyErr != nil || healthyFailures != 1 {
				t.Fatalf("test setup: healthy reference read failed: failures=%d err=%v", healthyFailures, healthyErr)
			}
			if !bytes.Equal(out.Bytes(), healthy.Bytes()) {
				t.Fatalf("fault run output must equal a healthy filtered read of the complete lines:\nfault:   %q\nhealthy: %q", out.String(), healthy.String())
			}

			results := decodeResults(t, out.Bytes())
			if len(results) != 2 {
				t.Fatalf("only the admitted success and the failure record may be emitted, got %#v", results)
			}
			if results[0]["line"] != float64(1) || results[0]["ok"] != true {
				t.Fatalf("the in-network log must stay physical line 1: %#v", results[0])
			}
			if eventOf(t, results[0])["action"] != "in-net" {
				t.Fatalf("line 1 content mismatch: %#v", results[0])
			}
			// Filtering line 2 and skipping blank line 3 must not renumber
			// the failure record.
			if results[1]["line"] != float64(4) || results[1]["ok"] != false {
				t.Fatalf("the invalid log must stay physical line 4 despite filtering and blank lines: %#v", results[1])
			}
			if _, exists := results[1]["event"]; exists {
				t.Fatalf("the failure record must not carry an event: %#v", results[1])
			}
			if msg, _ := results[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
				t.Fatalf("the failure record must keep its timestamp reason, got %q", msg)
			}
			if bytes.Contains(out.Bytes(), []byte(tc.marker)) {
				t.Fatalf("the trailing fragment belongs to the failed read and must not become an event or failure record: %q", out.String())
			}
		})
	}
}

// When every complete line before the fault is a valid but out-of-network
// log, the filter drops them all: the output is empty and the failure count
// is zero. That must not read as a healthy "nothing matched" run — the read
// interruption is still reported as ErrLogRead with its original cause.
func TestSourceCIDRFilterReadFaultAfterOnlyFilteredOutLines(t *testing.T) {
	filter := mustFilter192_0_2_0_24(t)
	complete := `{"timestamp":"2026-01-02T00:00:00Z","action":"out-a","source_ip":"198.51.100.1"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"out-b","source_ip":"203.0.113.7"}` + "\n"
	src := &scriptReader{steps: []scriptStep{
		{data: []byte(complete), err: errSimulatedRead},
	}}
	var out bytes.Buffer
	failures, err := NormalizeReaderFiltered(src, &out, filter)
	if err == nil {
		t.Fatalf("zero emitted events and zero failures must not mask the read interruption")
	}
	if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
		t.Fatalf("want ErrLogRead wrapping the read cause, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("filtered-out valid logs are not failures, got %d", failures)
	}
	if out.Len() != 0 {
		t.Fatalf("out-of-network logs produce no output, got %q", out.String())
	}

	// The same complete lines at a clean EOF are the genuinely quiet run the
	// fault run must remain distinguishable from.
	var healthy bytes.Buffer
	healthyFailures, healthyErr := NormalizeReaderFiltered(strings.NewReader(complete), &healthy, filter)
	if healthyErr != nil || healthyFailures != 0 || healthy.Len() != 0 {
		t.Fatalf("test setup: clean-EOF run of filtered-out lines must be quiet: failures=%d err=%v out=%q",
			healthyFailures, healthyErr, healthy.String())
	}
}

// The same log content terminated by a clean EOF instead of a fault is
// normal completion: the newline-less final line is a complete log and is
// processed by the usual rules — admitted as line 5 when valid and in the
// network, a line 5 failure record when its timestamp is invalid — and no
// stream-level error is returned. The failure already counted among the
// complete lines is preserved either way.
func TestSourceCIDRFilterCleanEOFProcessesNewlineLessFinalLine(t *testing.T) {
	complete, validFragment, badTimeFragment := filteredMixedCompleteLinesAndFragments()
	filter := mustFilter192_0_2_0_24(t)

	t.Run("valid in-network final line is admitted", func(t *testing.T) {
		var out bytes.Buffer
		failures, err := NormalizeReaderFiltered(strings.NewReader(complete+validFragment), &out, filter)
		if err != nil {
			t.Fatalf("clean EOF must not be a stream error, got %v", err)
		}
		if failures != 1 {
			t.Fatalf("only the invalid complete line counts, got %d", failures)
		}
		results := decodeResults(t, out.Bytes())
		if len(results) != 3 {
			t.Fatalf("expected the line 1 event, the line 4 failure, and the line 5 event: %#v", results)
		}
		if results[2]["line"] != float64(5) || results[2]["ok"] != true {
			t.Fatalf("the newline-less final log must be processed as physical line 5: %#v", results[2])
		}
		if eventOf(t, results[2])["action"] != "tail-in-net" {
			t.Fatalf("final line content mismatch: %#v", results[2])
		}
	})

	t.Run("invalid-timestamp final line fails as line 5", func(t *testing.T) {
		var out bytes.Buffer
		failures, err := NormalizeReaderFiltered(strings.NewReader(complete+badTimeFragment), &out, filter)
		if err != nil {
			t.Fatalf("clean EOF must not be a stream error, got %v", err)
		}
		if failures != 2 {
			t.Fatalf("the invalid final line joins the earlier invalid complete line, got %d", failures)
		}
		results := decodeResults(t, out.Bytes())
		if len(results) != 3 {
			t.Fatalf("expected the line 1 event and two failure records: %#v", results)
		}
		// The pre-existing failure among the complete lines must not be
		// forgotten because the final line also failed.
		if results[1]["line"] != float64(4) || results[1]["ok"] != false {
			t.Fatalf("the earlier failure must stay physical line 4: %#v", results[1])
		}
		if results[2]["line"] != float64(5) || results[2]["ok"] != false {
			t.Fatalf("the invalid final log must fail as physical line 5: %#v", results[2])
		}
		if _, exists := results[2]["event"]; exists {
			t.Fatalf("the final failure record must not carry an event: %#v", results[2])
		}
		if msg, _ := results[2]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
			t.Fatalf("the final failure record must keep its timestamp reason, got %q", msg)
		}
	})
}
