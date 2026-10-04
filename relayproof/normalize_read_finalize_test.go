package relayproof

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

// Regression coverage for input finalization: a reader is allowed to deliver
// its last bytes in the SAME Read call that reports the terminating status
// (EOF or a failure). Those bytes must be handled exactly as if the status
// had arrived in a later Read — complete newline-terminated logs are
// processed in order, a clean EOF admits a final unterminated log, and a
// read failure discards the trailing fragment no matter how parseable its
// text happens to be. All fault injection is scripted in-process, so the
// behavior reproduces deterministically offline, without real networks,
// damaged devices, or timing accidents.

// mixedStream is a complete-line prefix shared by several scenarios: one
// valid log, one blank physical line, one field-invalid log, one valid log.
const mixedStream = `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}` + "\n" +
	"\n" + // blank physical line: no output, still advances numbering
	`{"timestamp":"not-a-time","action":"b"}` + "\n" +
	`{"timestamp":"2026-01-02T00:00:03Z","action":"c"}` + "\n"

// runFaulty normalizes a scripted source and decodes its whole-record output.
func runFaulty(t *testing.T, src *scriptReader, w *bytes.Buffer) (failures int, err error, results []map[string]any) {
	t.Helper()
	failures, err = NormalizeReader(src, w)
	return failures, err, decodeResults(t, w.Bytes())
}

// referenceRun normalizes the same complete lines through an ordinary
// reader (bytes first, EOF later) to pin the expected per-line outcomes.
func referenceRun(t *testing.T, complete string) (failures int, results []map[string]any) {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(complete), &out)
	if err != nil {
		t.Fatalf("reference run of complete lines must succeed, got %v", err)
	}
	return failures, decodeResults(t, out.Bytes())
}

// Complete lines delivered in the same Read as EOF are normal completion:
// every log is processed in input order, blank lines keep their physical
// line numbers without emitting anything, the failure count reflects only
// genuinely invalid lines, and the returned error is nil. The per-line
// results must be identical to a run where EOF arrives after the bytes.
func TestNormalizeFinalizeCompleteLinesArriveWithEOF(t *testing.T) {
	wantFailures, wantResults := referenceRun(t, mixedStream)
	if wantFailures != 1 || len(wantResults) != 3 {
		t.Fatalf("test setup: reference stream has 1 failure and 3 results, got %d and %#v", wantFailures, wantResults)
	}

	src := &scriptReader{steps: []scriptStep{
		{data: []byte(mixedStream), err: io.EOF}, // bytes and EOF in one Read
	}}
	var out bytes.Buffer
	failures, err, results := runFaulty(t, src, &out)
	if err != nil {
		t.Fatalf("bytes delivered with a clean EOF are normal completion, got %v", err)
	}
	if failures != wantFailures {
		t.Fatalf("failure count must match a clean read of the same lines: got %d, want %d", failures, wantFailures)
	}
	if !reflect.DeepEqual(results, wantResults) {
		t.Fatalf("results must match a clean read of the same lines:\ngot  %#v\nwant %#v", results, wantResults)
	}
	// Pin the shape explicitly so the comparison above cannot hide a
	// silently renumbered or reordered stream.
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must be a valid event: %#v", results[0])
	}
	if results[1]["line"] != float64(3) || results[1]["ok"] != false {
		t.Fatalf("the blank line must still advance numbering; failure belongs to line 3: %#v", results[1])
	}
	if msg, _ := results[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("invalid line must carry its reason, got %q", msg)
	}
	if results[2]["line"] != float64(4) || results[2]["ok"] != true {
		t.Fatalf("line 4 must be a valid event: %#v", results[2])
	}
}

// A final complete log without a trailing newline, delivered in the same
// Read as EOF, still produces its event: clean EOF must not drop it.
func TestNormalizeFinalizeUnterminatedTailArrivesWithEOF(t *testing.T) {
	tail := `{"timestamp":"2026-01-02T00:00:09Z","action":"tail"}` // no "\n"
	src := &scriptReader{steps: []scriptStep{
		{data: []byte(validLog("a") + "\n" + tail), err: io.EOF},
	}}
	var out bytes.Buffer
	failures, err, results := runFaulty(t, src, &out)
	if err != nil {
		t.Fatalf("clean EOF must not be an error, got %v", err)
	}
	if failures != 0 {
		t.Fatalf("valid logs must report zero failures, got %d", failures)
	}
	if len(results) != 2 {
		t.Fatalf("the unterminated final log must not be lost at EOF: %#v", results)
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != true {
		t.Fatalf("final line must be processed normally: %#v", results[1])
	}
	if eventOf(t, results[1])["action"] != "tail" {
		t.Fatalf("final line content mismatch: %#v", results[1])
	}
}

// The same byte layout delivered with a non-EOF read failure changes only
// the tail's fate: complete lines are still processed exactly as in a clean
// run, but the trailing unterminated text is a fragment of the failed read.
// It must not become an event or a failure record even when its text is a
// perfectly valid, fully populated JSON object — admissibility is decided
// by the read status, not by whether the fragment parses.
func TestNormalizeFinalizeValidJSONFragmentArrivesWithReadError(t *testing.T) {
	// A fragment that WOULD normalize cleanly if it were a complete line.
	fragment := `{"timestamp":"2026-01-02T00:00:09Z","action":"FRAGMENT-TAIL"}`
	wantFailures, wantResults := referenceRun(t, mixedStream)

	src := &scriptReader{steps: []scriptStep{
		{data: []byte(mixedStream + fragment), err: errSimulatedRead},
	}}
	var out bytes.Buffer
	failures, err, results := runFaulty(t, src, &out)
	if err == nil {
		t.Fatalf("read failure must be returned, not treated as normal completion")
	}
	if !errors.Is(err, ErrLogRead) {
		t.Fatalf("error must match ErrLogRead, got %v", err)
	}
	if !errors.Is(err, errSimulatedRead) {
		t.Fatalf("the reader's original cause must stay reachable, got %v", err)
	}
	if failures != wantFailures {
		t.Fatalf("failure count must reflect only complete-line failures: got %d, want %d", failures, wantFailures)
	}
	if !reflect.DeepEqual(results, wantResults) {
		t.Fatalf("complete lines must keep the order, numbers and outcomes of a clean read:\ngot  %#v\nwant %#v", results, wantResults)
	}
	if bytes.Contains(out.Bytes(), []byte("FRAGMENT-TAIL")) {
		t.Fatalf("parseable fragment must not become an event or failure record: %q", out.String())
	}
}

// A stream that fails before delivering any complete line produces no
// per-line output and a zero failure count, yet still reports the read
// failure — even when the fragment's text is a valid complete JSON object.
func TestNormalizeFinalizeOnlyFragmentWithReadError(t *testing.T) {
	cases := []struct {
		name     string
		fragment []byte
	}{
		{"fragment is valid complete JSON", []byte(validLog("lonely"))},
		{"fragment is truncated JSON", []byte(`{"timestamp":"cut off`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &scriptReader{steps: []scriptStep{
				{data: tc.fragment, err: errSimulatedRead},
			}}
			var out bytes.Buffer
			failures, err := NormalizeReader(src, &out)
			if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
				t.Fatalf("want ErrLogRead wrapping the cause, got %v", err)
			}
			if failures != 0 {
				t.Fatalf("a failed read contributes no log failures, got %d", failures)
			}
			if out.Len() != 0 {
				t.Fatalf("no complete line means no per-line output, got %q", out.String())
			}
		})
	}
}

// When the final bytes and the read failure arrive together AND flushing the
// remaining results also fails, the read cause stays the primary error: the
// caller can still match ErrLogRead and the original read cause, the write
// cause is visible only in the error text, and the failure count already
// recorded for complete lines is unchanged.
func TestNormalizeFinalizeReadErrorWinsOverWriteError(t *testing.T) {
	src := &scriptReader{steps: []scriptStep{
		{data: []byte(mixedStream + `{"truncated":`), err: errSimulatedRead},
	}}
	// Small records stay buffered, so the first physical write is the
	// shutdown flush, which fails with a distinct error.
	w := &failWriter{err: errSimulatedWrite}
	failures, err := NormalizeReader(src, w)
	if err == nil {
		t.Fatalf("expected the read failure, got nil")
	}
	if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
		t.Fatalf("the original read error must reach the caller, got %v", err)
	}
	if errors.Is(err, ErrLogWrite) || errors.Is(err, errSimulatedWrite) {
		t.Fatalf("the later write failure must not replace the read cause: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, errSimulatedRead.Error()) {
		t.Fatalf("error text must name the read cause, got %q", msg)
	}
	if !strings.Contains(msg, errSimulatedWrite.Error()) {
		t.Fatalf("the shutdown write failure should still be visible in the message, got %q", msg)
	}
	if failures != 1 {
		t.Fatalf("only the one invalid complete line counts, got %d", failures)
	}
}
