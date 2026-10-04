package relayproof

// Regression coverage for comparing the canonical "timestamp" field with its
// alias "time" when both carry fractional seconds.
//
// The two spellings must be compared as instants, not as text: equal
// instants written with different precisions, different offsets, or a
// different number of trailing zeros merge into one canonical UTC timestamp
// that keeps the real (nonzero) precision and drops only trailing zeros.
// Genuinely different instants — even a single nanosecond apart, or the same
// clock reading under different offsets — fail the whole line as a value
// conflict. Validity is judged before any comparison: a fraction longer
// than nine digits is a format error even when the excess digits are zeros
// whose truncation would make the two values equal.
//
// These tests go through the public NormalizeReader output only and use
// fixed offline input; nothing depends on the current time.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// timePairLine builds one log object carrying tsA and tsB under the
// canonical name and the alias in the requested assignment and member order.
func timePairLine(firstKey, firstTS, secondKey, secondTS, action string) string {
	return `{"` + firstKey + `":"` + firstTS + `","` + secondKey + `":"` + secondTS + `","action":"` + action + `"}`
}

// timePairVariants spells the same two timestamp values in every assignment
// and member-order combination: which value sits under "timestamp" versus
// "time", and which member is written first, must not change the outcome.
func timePairVariants(tsA, tsB, action string) []string {
	return []string{
		timePairLine(FieldTimestamp, tsA, "time", tsB, action),
		timePairLine("time", tsB, FieldTimestamp, tsA, action),
		timePairLine(FieldTimestamp, tsB, "time", tsA, action),
		timePairLine("time", tsA, FieldTimestamp, tsB, action),
	}
}

// TestNormalizeTimeAliasFractionSameInstantMerges pins the merge rule: both
// values are legal and denote one instant, so the line succeeds and the
// event carries only the canonical "timestamp" field with the instant in
// UTC, trailing fraction zeros removed, real precision preserved.
func TestNormalizeTimeAliasFractionSameInstantMerges(t *testing.T) {
	cases := []struct {
		name string
		tsA  string
		tsB  string
		want string
	}{
		{
			name: "nine-digit fraction with offset equals one-digit UTC fraction",
			tsA:  "2026-01-02T08:04:05.100000000+08:00",
			tsB:  "2026-01-02T00:04:05.1Z",
			want: "2026-01-02T00:04:05.1Z",
		},
		{
			name: "all-zero fraction equals no fraction",
			tsA:  "2026-01-02T00:04:05.000000000Z",
			tsB:  "2026-01-02T00:04:05Z",
			want: "2026-01-02T00:04:05Z",
		},
		{
			name: "trailing zeros beyond real precision are dropped",
			tsA:  "2026-01-02T00:04:05.120000000Z",
			tsB:  "2026-01-02T00:04:05.12Z",
			want: "2026-01-02T00:04:05.12Z",
		},
		{
			name: "minute offset shifting the date still matches the UTC instant",
			tsA:  "2026-01-02T23:30:00.5-00:30", // -> 2026-01-03T00:00:00.5Z
			tsB:  "2026-01-03T00:00:00.5Z",
			want: "2026-01-03T00:00:00.5Z",
		},
		{
			name: "hour-and-minute offset keeps real nanosecond precision",
			tsA:  "2026-01-03T01:30:00.123456789+05:30", // -> 2026-01-02T20:00:00.123456789Z
			tsB:  "2026-01-02T20:00:00.123456789Z",
			want: "2026-01-02T20:00:00.123456789Z",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, input := range timePairVariants(tc.tsA, tc.tsB, "a") {
				results := runNormalize(t, input)
				if len(results) != 1 || results[0]["ok"] != true {
					t.Fatalf("same instant under both names must succeed: %s -> %#v", input, results)
				}
				event := eventOf(t, results[0])
				if got := event[FieldTimestamp]; got != tc.want {
					t.Fatalf("%s merged to %v, want %q", input, got, tc.want)
				}
				if _, exists := event["time"]; exists {
					t.Fatalf("merged event must keep only the canonical field, not the alias: %#v", event)
				}
			}
		})
	}
}

// TestNormalizeTimeAliasFractionDifferentInstantsConflict pins the failure
// rule: two legal timestamps denoting different instants fail the whole
// line. Precision must never be sacrificed to reach equality — a one
// nanosecond difference, a difference beyond millisecond resolution, and the
// same clock reading under different offsets are all conflicts.
func TestNormalizeTimeAliasFractionDifferentInstantsConflict(t *testing.T) {
	cases := []struct {
		name string
		tsA  string
		tsB  string
	}{
		{
			name: "one nanosecond apart",
			tsA:  "2026-01-02T00:04:05.100000000Z",
			tsB:  "2026-01-02T00:04:05.100000001Z",
		},
		{
			name: "difference beyond millisecond resolution must not truncate to equal",
			tsA:  "2026-01-02T00:04:05.123456789Z",
			tsB:  "2026-01-02T00:04:05.123999999Z",
		},
		{
			name: "fraction versus no fraction within the same second",
			tsA:  "2026-01-02T00:04:05.000000001Z",
			tsB:  "2026-01-02T00:04:05Z",
		},
		{
			name: "identical clock reading under different offsets",
			tsA:  "2026-01-02T08:04:05.1+08:00",
			tsB:  "2026-01-02T08:04:05.1+07:00",
		},
		{
			name: "same local date and time, offset differs by one minute",
			tsA:  "2026-01-02T08:04:05.1+08:00",
			tsB:  "2026-01-02T08:04:05.1+08:01",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, input := range timePairVariants(tc.tsA, tc.tsB, "a") {
				results := runNormalize(t, input)
				if len(results) != 1 || results[0]["ok"] != false {
					t.Fatalf("different instants must fail the whole line: %s -> %#v", input, results)
				}
				if results[0]["line"] != float64(1) {
					t.Fatalf("failure must keep its original line number: %#v", results[0])
				}
				if _, exists := results[0]["event"]; exists {
					t.Fatalf("conflicting timestamps must not emit an event: %#v", results[0])
				}
				msg, _ := results[0]["error"].(string)
				if !strings.Contains(msg, FieldTimestamp) {
					t.Fatalf("conflict error must name %q, got %q (%s)", FieldTimestamp, msg, input)
				}
				if !strings.Contains(strings.ToLower(msg), "conflict") {
					t.Fatalf("different instants must be reported as a value conflict, got %q (%s)", msg, input)
				}
			}
		})
	}
}

// TestNormalizeTimeAliasFractionTooLongRejected pins validity-before-
// equality: a fraction longer than nine digits is a format error even when
// the excess digits are zeros and truncating them would make the two values
// equal. The legal value on the other key cannot mask the error, and the
// failure must not be reported as a conflict between two legal values.
func TestNormalizeTimeAliasFractionTooLongRejected(t *testing.T) {
	cases := []struct {
		name string
		bad  string
		good string
	}{
		{
			name: "ten digits, excess zero, truncation would match",
			bad:  "2026-01-02T00:04:05.1000000000Z",
			good: "2026-01-02T00:04:05.1Z",
		},
		{
			name: "twelve zero digits versus no fraction",
			bad:  "2026-01-02T00:04:05.000000000000Z",
			good: "2026-01-02T00:04:05Z",
		},
		{
			name: "ten digits with a nonzero tenth digit",
			bad:  "2026-01-02T08:04:05.1000000001+08:00",
			good: "2026-01-02T00:04:05.1Z",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, input := range timePairVariants(tc.bad, tc.good, "a") {
				results := runNormalize(t, input)
				if len(results) != 1 || results[0]["ok"] != false {
					t.Fatalf("over-long fraction must fail the line: %s -> %#v", input, results)
				}
				if _, exists := results[0]["event"]; exists {
					t.Fatalf("invalid fraction must not merge into an event: %#v", results[0])
				}
				msg, _ := results[0]["error"].(string)
				if !strings.Contains(msg, FieldTimestamp) {
					t.Fatalf("format error must name %q, got %q (%s)", FieldTimestamp, msg, input)
				}
				if !strings.Contains(msg, "invalid RFC3339 timestamp") {
					t.Fatalf("over-long fraction must be a timestamp format error, got %q (%s)", msg, input)
				}
				if strings.Contains(strings.ToLower(msg), "conflict") {
					t.Fatalf("an invalid value must never be reported as a conflict of legal values: %q (%s)", msg, input)
				}
			}
		})
	}
}

// TestNormalizeTimeAliasFractionMixedStream puts merges, conflicts, and
// format errors into one normally terminating stream: each failure fails
// only its own line with its physical line number, later legal logs still
// produce results in input order, the failure count covers exactly the
// failed log lines, and a clean EOF reports no stream-level error.
func TestNormalizeTimeAliasFractionMixedStream(t *testing.T) {
	input := `{"timestamp":"2026-01-02T08:04:05.100000000+08:00","time":"2026-01-02T00:04:05.1Z","action":"a"}` + "\n" + // line 1: merge
		"\n" + // line 2: blank, only advances the counter
		`{"time":"2026-01-02T00:04:05.100000001Z","timestamp":"2026-01-02T00:04:05.100000000Z","action":"b"}` + "\n" + // line 3: 1ns conflict
		`{"time":"2026-01-02T00:04:06Z","action":"c"}` + "\n" + // line 4: legal
		`{"timestamp":"2026-01-02T00:04:05.1000000000Z","time":"2026-01-02T00:04:05.1Z","action":"d"}` + "\n" + // line 5: over-long fraction
		`{"timestamp":"2026-01-02T00:04:07Z","action":"e"}` // line 6: legal, no trailing newline (clean EOF)

	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("per-line timestamp failures must not surface as a stream error: %v", err)
	}
	if errors.Is(err, ErrLogRead) || errors.Is(err, ErrLogWrite) {
		t.Fatalf("conflicts and format errors are per-line failures, got stream error: %v", err)
	}
	if failures != 2 {
		t.Fatalf("exactly the conflict and format-error lines must count as failures, got %d", failures)
	}

	results := []map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for {
		var m map[string]any
		if derr := dec.Decode(&m); derr != nil {
			if errors.Is(derr, io.EOF) {
				break
			}
			t.Fatalf("decoding result: %v", derr)
		}
		results = append(results, m)
	}
	if len(results) != 5 {
		t.Fatalf("each of the 5 non-blank lines must yield exactly one result, got %d: %#v", len(results), results)
	}
	if got := countFailures(results); got != failures {
		t.Fatalf("output shows %d failures but NormalizeReader returned %d", got, failures)
	}

	wantLines := []int{1, 3, 4, 5, 6}
	wantOK := []bool{true, false, true, false, true}
	for i, r := range results {
		if r["line"] != float64(wantLines[i]) {
			t.Fatalf("result %d must keep physical line %d, got %v: %#v", i, wantLines[i], r["line"], r)
		}
		if r["ok"] != wantOK[i] {
			t.Fatalf("line %d ok = %v, want %v: %#v", wantLines[i], r["ok"], wantOK[i], r)
		}
	}

	// The merge line keeps the shared instant in UTC with real precision.
	if got := eventOf(t, results[0])[FieldTimestamp]; got != "2026-01-02T00:04:05.1Z" {
		t.Fatalf("line 1 merged timestamp %v", got)
	}
	// Later legal lines are unaffected by the failures between them.
	if got := eventOf(t, results[2])[FieldTimestamp]; got != "2026-01-02T00:04:06Z" {
		t.Fatalf("line 4 timestamp %v", got)
	}
	if got := eventOf(t, results[4])[FieldTimestamp]; got != "2026-01-02T00:04:07Z" {
		t.Fatalf("line 6 timestamp %v", got)
	}

	// Each failure is error-only, keeps its line number, and names timestamp.
	for _, idx := range []int{1, 3} {
		r := results[idx]
		if _, exists := r["event"]; exists {
			t.Fatalf("line %v failure must carry no event: %#v", r["line"], r)
		}
		msg, _ := r["error"].(string)
		if !strings.Contains(msg, FieldTimestamp) {
			t.Fatalf("line %v error must name %q, got %q", r["line"], FieldTimestamp, msg)
		}
	}
	if msg, _ := results[1]["error"].(string); !strings.Contains(strings.ToLower(msg), "conflict") {
		t.Fatalf("line 3 must report a value conflict, got %q", msg)
	}
	if msg, _ := results[3]["error"].(string); !strings.Contains(msg, "invalid RFC3339 timestamp") {
		t.Fatalf("line 5 must report a timestamp format error, got %q", msg)
	}
}
