package relayproof

import (
	"strings"
	"testing"
)

// Failure-reason precedence coverage: when one log line carries several
// problems at once, the reason the user sees must follow the pipeline order —
// raw-byte UTF-8 integrity first, then \uXXXX surrogate pairing, then JSON
// decoding (including the duplicate top-level key rule), then field
// validation — never the position or the combination of the defects. Each
// failing line produces exactly one result with one error, ok:false, and no
// event; the character checks must neither hide the later problems nor
// repair corrupted input into something the field stage would accept.

// expectSingleFailure asserts the one input line fails with ok:false, no
// event, and exactly one error member in its serialized result, and returns
// the error message for category assertions.
func expectSingleFailure(t *testing.T, input string) string {
	t.Helper()
	results := runNormalize(t, input)
	if len(results) != 1 {
		t.Fatalf("one input line must produce exactly one result, got %#v", results)
	}
	r := results[0]
	if r["ok"] != false {
		t.Fatalf("the multi-problem line must fail: %#v", r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("a failed line must not carry an event: %#v", r)
	}
	msg, _ := r["error"].(string)
	if msg == "" {
		t.Fatalf("a failed line must explain itself: %#v", r)
	}
	// The serialized record carries a single error member — the failure
	// reason is decided once, not stacked.
	raw := runNormalizeRaw(t, input)
	if got := strings.Count(raw, `"error"`); got != 1 {
		t.Fatalf("the failed line must carry exactly one error member, got %d in %s", got, raw)
	}
	return msg
}

// assertErrorCategory pins that msg belongs to exactly one failure category:
// it must contain every wanted marker and none of the markers of the other
// categories that compete for the same line.
func assertErrorCategory(t *testing.T, msg string, want []string, notWant []string) {
	t.Helper()
	for _, marker := range want {
		if !strings.Contains(msg, marker) {
			t.Fatalf("error %q must contain %q", msg, marker)
		}
	}
	for _, marker := range notWant {
		if strings.Contains(msg, marker) {
			t.Fatalf("error %q must not contain %q: the wrong problem decided the failure", msg, marker)
		}
	}
}

// Invalid UTF-8 bytes anywhere in the raw line decide the failure, no matter
// what else is wrong with the line — an unpaired surrogate escape, an invalid
// timestamp, or a duplicate top-level key on the same line must not pre-empt
// the byte-encoding report, and the relative position of the two character
// problems must not matter either.
func TestNormalizeInvalidUTF8BeatsEveryOtherProblem(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "unpaired escape before the invalid byte",
			input: `{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800","note":"bad` + "\xff" + `"}`,
		},
		{
			name:  "invalid byte before the unpaired escape",
			input: `{"timestamp":"2026-01-02T00:00:00Z","action":"bad` + "\xff" + `","note":"\uD800"}`,
		},
		{
			name:  "invalid byte with an invalid timestamp",
			input: `{"timestamp":"not-a-time","action":"bad` + "\xff" + `"}`,
		},
		{
			name:  "invalid byte with a duplicate top-level key",
			input: `{"timestamp":"2026-01-02T00:00:00Z","action":"a","action":"b` + "\xff" + `"}`,
		},
		{
			name:  "invalid byte, unpaired escape, invalid timestamp, and duplicate key together",
			input: `{"timestamp":"not-a-time","action":"\uD800","action":"b` + "\xff" + `"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := expectSingleFailure(t, tc.input)
			assertErrorCategory(t, msg,
				[]string{"UTF-8"},
				[]string{"surrogate", "duplicate", "RFC3339"})
		})
	}
}

// Once the raw bytes are legal UTF-8, an unpaired surrogate escape decides
// the failure next — ahead of timestamp validation and ahead of the duplicate
// top-level key rule — wherever the escape lives: a mapped value, a field
// name, or an unknown field's nested object or array.
func TestNormalizeUnpairedSurrogateBeatsFieldAndDuplicateProblems(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "lone high surrogate in action with invalid timestamp",
			input: `{"timestamp":"not-a-time","action":"\uD800"}`,
		},
		{
			name:  "lone low surrogate in action with invalid timestamp",
			input: `{"timestamp":"not-a-time","action":"act\uDC00ion"}`,
		},
		{
			name:  "reversed pair in action with invalid timestamp",
			input: `{"timestamp":"not-a-time","action":"\uDC00\uD800"}`,
		},
		{
			name:  "lone high surrogate in a field name with a duplicate key",
			input: `{"timestamp":"2026-01-02T00:00:00Z","action":"a","no\uD800te":"x","action":"b"}`,
		},
		{
			name:  "lone low surrogate in a field name with an invalid timestamp",
			input: `{"time\uDFFFstamp":"not-a-time","action":"a"}`,
		},
		{
			name:  "reversed pair nested in an unknown field array with invalid timestamp",
			input: `{"timestamp":"not-a-time","action":"a","extra":{"list":["ok","\uDC00\uD800"]}}`,
		},
		{
			name:  "lone high surrogate in a nested unknown key with a duplicate top-level key",
			input: `{"timestamp":"2026-01-02T00:00:00Z","action":"a","action":"b","payload":{"k\uD800":1}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := expectSingleFailure(t, tc.input)
			assertErrorCategory(t, msg,
				[]string{"unpaired", "surrogate"},
				[]string{"UTF-8", "duplicate", "RFC3339"})
		})
	}
}

// The reported reason must track the input as the character problems are
// removed one step at a time from the same log: fixing the bytes surfaces the
// escape problem, fixing the escape surfaces the timestamp problem, and
// fixing the timestamp lets the line succeed. The character checks never
// make a later problem disappear, and a corrupted line is never repaired
// into one the field stage would accept.
func TestNormalizeFailureReasonFollowsProgressiveRepair(t *testing.T) {
	steps := []struct {
		name    string
		input   string
		want    []string
		notWant []string
	}{
		{
			name:    "invalid byte, unpaired escape, and invalid timestamp",
			input:   `{"timestamp":"not-a-time","action":"\uD800","note":"x` + "\xff" + `"}`,
			want:    []string{"UTF-8"},
			notWant: []string{"surrogate", "RFC3339"},
		},
		{
			name:    "byte fixed: unpaired escape and invalid timestamp remain",
			input:   `{"timestamp":"not-a-time","action":"\uD800","note":"x"}`,
			want:    []string{"unpaired", "surrogate"},
			notWant: []string{"UTF-8", "RFC3339"},
		},
		{
			name:    "escape fixed: only the invalid timestamp remains",
			input:   `{"timestamp":"not-a-time","action":"ok","note":"x"}`,
			want:    []string{FieldTimestamp, "RFC3339"},
			notWant: []string{"UTF-8", "surrogate"},
		},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			msg := expectSingleFailure(t, step.input)
			assertErrorCategory(t, msg, step.want, step.notWant)
		})
	}

	t.Run("timestamp fixed: the line succeeds", func(t *testing.T) {
		results := runNormalize(t, `{"timestamp":"2026-01-02T00:00:00Z","action":"ok","note":"x"}`)
		if len(results) != 1 || results[0]["ok"] != true {
			t.Fatalf("the fully repaired line must succeed, got %#v", results)
		}
		if eventOf(t, results[0])["action"] != "ok" {
			t.Fatalf("the repaired line must normalize normally: %#v", results[0])
		}
	})
}

// A duplicate top-level key whose characters are entirely legal still fails
// by the duplicate rule — the character checks pass it through untouched,
// and the duplicate is reported before any field-level problem on the same
// line, exactly as for a line with no other defect.
func TestNormalizeCharLegalDuplicateKeyStillFailsAsDuplicate(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "duplicate key alone",
			input: `{"timestamp":"2026-01-02T00:00:00Z","action":"a","action":"b"}`,
		},
		{
			name:  "duplicate key with equal values",
			input: `{"timestamp":"2026-01-02T00:00:00Z","action":"a","action":"a"}`,
		},
		{
			name:  "duplicate key with an invalid timestamp",
			input: `{"timestamp":"not-a-time","action":"a","action":"b"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := expectSingleFailure(t, tc.input)
			assertErrorCategory(t, msg,
				[]string{"duplicate", FieldAction},
				[]string{"UTF-8", "surrogate", "RFC3339", "conflict"})
		})
	}
}

// Legal character content must not be caught by the precedence net: a
// correctly paired surrogate escape, a literal U+FFFD the user actually
// wrote, and uD800 appearing as ordinary text behind an escaped backslash
// all pass the character checks, and the rest of the line normalizes as
// usual with unknown text and nested structures kept in extra.
func TestNormalizeLegalCharacterContentNotFlaggedByPrecedence(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"` + escGrinning + `",` +
		`"note":"\\uD800","replacement":"�","escaped_replacement":"` + escReplacement + `",` +
		`"payload":{"pair":"` + escGrinning + `","list":["�",1]}}`
	results := runNormalize(t, input)
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("legal character content must succeed, got %#v", results)
	}
	if eventOf(t, results[0])["action"] != "😀" {
		t.Fatalf("the paired escape in action must decode to the emoji, got %#v", results[0])
	}
	extra := extraOf(t, results[0])
	if extra["note"] != `\uD800` {
		t.Fatalf(`escaped-backslash text must stay the plain text \uD800, got %v`, extra["note"])
	}
	if extra["replacement"] != "�" || extra["escaped_replacement"] != "�" {
		t.Fatalf("a literal U+FFFD is valid input, got %#v", extra)
	}
	payload, ok := extra["payload"].(map[string]any)
	if !ok {
		t.Fatalf("the nested unknown structure must be kept in extra, got %#v", extra)
	}
	if payload["pair"] != "😀" {
		t.Fatalf("the nested paired escape must decode, got %v", payload["pair"])
	}
	list, ok := payload["list"].([]any)
	if !ok || len(list) != 2 || list[0] != "�" {
		t.Fatalf("the nested array with a literal U+FFFD must survive, got %#v", payload["list"])
	}
}

// In a healthy mixed stream, lines carrying several problems at once behave
// like any other per-line failure: one result each with the original
// physical line number and the highest-precedence reason, valid lines around
// them still processed in input order, and exactly the failing lines
// counted.
func TestNormalizeMultiProblemLinesInMixedStream(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"first"}` + "\n" +
		`{"timestamp":"not-a-time","action":"\uD800","note":"x` + "\xff" + `"}` + "\n" +
		"\n" +
		`{"timestamp":"not-a-time","action":"\uD800"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:02Z","action":"last"}` + "\n"

	var out strings.Builder
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("per-line failures are not a stream error, got %v", err)
	}
	if failures != 2 {
		t.Fatalf("exactly the two multi-problem lines must count, got %d", failures)
	}
	results := decodeResults(t, []byte(out.String()))
	if len(results) != 4 {
		t.Fatalf("expected 4 results for 5 physical lines, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("the leading valid log must succeed on line 1: %#v", results[0])
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != false {
		t.Fatalf("the byte+escape+timestamp line must fail on physical line 2: %#v", results[1])
	}
	assertErrorCategory(t, results[1]["error"].(string),
		[]string{"UTF-8"},
		[]string{"surrogate", "RFC3339"})
	if results[2]["line"] != float64(4) || results[2]["ok"] != false {
		t.Fatalf("the escape+timestamp line must fail on physical line 4: %#v", results[2])
	}
	assertErrorCategory(t, results[2]["error"].(string),
		[]string{"unpaired", "surrogate"},
		[]string{"UTF-8", "RFC3339"})
	if results[3]["line"] != float64(5) || results[3]["ok"] != true {
		t.Fatalf("the trailing valid log must still succeed on line 5: %#v", results[3])
	}
	if eventOf(t, results[3])["action"] != "last" {
		t.Fatalf("input order must be preserved past multi-problem lines: %#v", results[3])
	}
}
