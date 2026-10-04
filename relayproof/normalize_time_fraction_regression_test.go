package relayproof

// Regression coverage for comparing the timestamp canonical field with its
// "time" alias when both carry fractional seconds.
//
// The two values must be compared as instants, not as text: different
// spellings of one moment (different offsets, different fraction widths,
// trailing zeros, an all-zero fraction versus no fraction) merge into the
// single canonical UTC timestamp, while values whose real instants differ —
// even by one nanosecond, or only through their timezone offset — fail the
// whole line as a value conflict. Validity still comes first: a fraction
// longer than nine digits is a format error even when the extra digits are
// zeros that a truncating comparison would have equated.
//
// All inputs are fixed strings; nothing here depends on the current time or
// any external service.

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// timePairLines spells one timestamp pair under every combination that must
// not change the outcome: the canonical name holding either value, and the
// two members appearing in either order within the object.
func timePairLines(a, b string) []string {
	return []string{
		`{"timestamp":"` + a + `","time":"` + b + `","action":"a"}`,
		`{"timestamp":"` + b + `","time":"` + a + `","action":"a"}`,
		`{"time":"` + a + `","timestamp":"` + b + `","action":"a"}`,
		`{"action":"a","time":"` + b + `","timestamp":"` + a + `"}`,
	}
}

// TestNormalizeTimeAliasFractionSameInstantMerges pins the merge rule: two
// legal values denoting one instant produce one success result whose event
// carries only the canonical "timestamp" field (never a "time" member),
// rendered in UTC with trailing fraction zeros stripped but real non-zero
// precision kept.
func TestNormalizeTimeAliasFractionSameInstantMerges(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want string
	}{
		{
			name: "offset spelling versus Z spelling of one instant",
			a:    "2026-01-02T08:04:05.100000000+08:00",
			b:    "2026-01-02T00:04:05.1Z",
			want: "2026-01-02T00:04:05.1Z",
		},
		{
			name: "all-zero fraction equals no fraction",
			a:    "2026-01-02T00:04:05.000000000Z",
			b:    "2026-01-02T00:04:05Z",
			want: "2026-01-02T00:04:05Z",
		},
		{
			name: "all-zero fraction equals shorter zero fraction",
			a:    "2026-01-02T00:04:05.000Z",
			b:    "2026-01-02T00:04:05.000000000Z",
			want: "2026-01-02T00:04:05Z",
		},
		{
			name: "minute offset crossing midnight keeps nanosecond precision",
			a:    "2026-01-02T00:04:05.123456789+00:30",
			b:    "2026-01-01T23:34:05.123456789Z",
			want: "2026-01-01T23:34:05.123456789Z",
		},
		{
			name: "minute offset crossing midnight forward",
			a:    "2026-01-01T23:34:05.5-00:30",
			b:    "2026-01-02T00:04:05.5Z",
			want: "2026-01-02T00:04:05.5Z",
		},
		{
			name: "trailing zeros stripped, non-zero precision kept",
			a:    "2026-01-02T08:04:05.120000000+08:00",
			b:    "2026-01-02T00:04:05.12Z",
			want: "2026-01-02T00:04:05.12Z",
		},
		{
			name: "wide and narrow spellings of the same fraction",
			a:    "2026-01-02T00:04:05.000000001Z",
			b:    "2026-01-02T08:04:05.000000001+08:00",
			want: "2026-01-02T00:04:05.000000001Z",
		},
	}
	for _, tc := range cases {
		for i, input := range timePairLines(tc.a, tc.b) {
			t.Run(fmt.Sprintf("%s/variant-%d", tc.name, i), func(t *testing.T) {
				results := runNormalize(t, input)
				if len(results) != 1 || results[0]["ok"] != true {
					t.Fatalf("same instant spelled two ways must merge (variant %d): %s -> %#v", i, input, results)
				}
				event := eventOf(t, results[0])
				if got := event[FieldTimestamp]; got != tc.want {
					t.Fatalf("merged timestamp = %v, want %q (variant %d: %s)", got, tc.want, i, input)
				}
				if _, exists := event["time"]; exists {
					t.Fatalf("merged event must keep only the canonical timestamp field, got %#v", event)
				}
			})
		}
	}
}

// TestNormalizeTimeAliasFractionDifferentInstantsConflict pins the failure
// rule: two legal values whose real instants differ fail the whole line.
// The comparison must not truncate to milliseconds or whole seconds (a one
// nanosecond gap is a conflict), and must not compare clock-face text while
// ignoring the offset. The failure carries the original line number, ok
// false, a timestamp conflict explanation, and no event.
func TestNormalizeTimeAliasFractionDifferentInstantsConflict(t *testing.T) {
	cases := []struct {
		name string
		a, b string
	}{
		{
			name: "one nanosecond apart at full precision",
			a:    "2026-01-02T00:04:05.100000000Z",
			b:    "2026-01-02T00:04:05.100000001Z",
		},
		{
			name: "one nanosecond apart across an offset spelling",
			a:    "2026-01-02T08:04:05.999999999+08:00", // 00:04:05.999999999Z
			b:    "2026-01-02T00:04:06Z",
		},
		{
			name: "same clock face and fraction, different offsets",
			a:    "2026-01-02T08:04:05.1+08:00",
			b:    "2026-01-02T08:04:05.1+07:00",
		},
		{
			name: "same local time, offset minutes differ",
			a:    "2026-01-02T00:04:05.123456789+00:30",
			b:    "2026-01-02T00:04:05.123456789+00:31",
		},
		{
			name: "difference below millisecond precision must not truncate away",
			a:    "2026-01-02T00:04:05.123000000Z",
			b:    "2026-01-02T00:04:05.123456789Z", // equal to the millisecond, 456789ns later
		},
	}
	for _, tc := range cases {
		for i, input := range timePairLines(tc.a, tc.b) {
			t.Run(fmt.Sprintf("%s/variant-%d", tc.name, i), func(t *testing.T) {
				results := runNormalize(t, input)
				if len(results) != 1 || results[0]["ok"] != false {
					t.Fatalf("different instants must fail the whole line (variant %d): %s -> %#v", i, input, results)
				}
				if results[0]["line"] != float64(1) {
					t.Fatalf("failure must carry the original line number: %#v", results[0])
				}
				if _, exists := results[0]["event"]; exists {
					t.Fatalf("conflict failure must not carry an event: %#v", results[0])
				}
				msg, _ := results[0]["error"].(string)
				if !strings.Contains(msg, FieldTimestamp) {
					t.Fatalf("conflict error must name %q, got %q", FieldTimestamp, msg)
				}
				if !strings.Contains(strings.ToLower(msg), "conflict") {
					t.Fatalf("different instants must be reported as a value conflict, got %q", msg)
				}
				if strings.Contains(strings.ToLower(msg), "invalid") {
					t.Fatalf("two legal values must not be reported as a format error, got %q", msg)
				}
			})
		}
	}
}

// TestNormalizeTimeAliasFractionTooManyDigits pins that validity is judged
// before equality: a fraction longer than nine digits is a format error even
// when every extra digit is a zero and a truncating comparison would have
// found the two values equal. The legal value on the other side cannot mask
// the error, and the failure is a format error, never a successful merge and
// never a conflict between two legal values.
func TestNormalizeTimeAliasFractionTooManyDigits(t *testing.T) {
	cases := []struct {
		name string
		a, b string
	}{
		{
			name: "ten digits, extra zero would truncate to equality",
			a:    "2026-01-02T00:04:05.1000000000Z",
			b:    "2026-01-02T00:04:05.1Z",
		},
		{
			name: "ten digits across an offset spelling",
			a:    "2026-01-02T08:04:05.1000000000+08:00",
			b:    "2026-01-02T00:04:05.1Z",
		},
		{
			name: "twelve all-zero digits versus no fraction",
			a:    "2026-01-02T00:04:05.000000000000Z",
			b:    "2026-01-02T00:04:05Z",
		},
		{
			name: "non-zero digit beyond nine places",
			a:    "2026-01-02T00:04:05.1000000001Z",
			b:    "2026-01-02T00:04:05.1Z",
		},
	}
	for _, tc := range cases {
		for i, input := range timePairLines(tc.a, tc.b) {
			t.Run(fmt.Sprintf("%s/variant-%d", tc.name, i), func(t *testing.T) {
				results := runNormalize(t, input)
				if len(results) != 1 || results[0]["ok"] != false {
					t.Fatalf("over-long fraction must fail even when truncation would match (variant %d): %s -> %#v", i, input, results)
				}
				if _, exists := results[0]["event"]; exists {
					t.Fatalf("format error must not emit an event: %#v", results[0])
				}
				msg, _ := results[0]["error"].(string)
				if !strings.Contains(msg, FieldTimestamp) {
					t.Fatalf("format error must name %q, got %q", FieldTimestamp, msg)
				}
				if !strings.Contains(strings.ToLower(msg), "invalid") {
					t.Fatalf("over-long fraction must be reported as a format error, got %q", msg)
				}
				if strings.Contains(strings.ToLower(msg), "conflict") {
					t.Fatalf("an illegal value must be rejected as invalid, not compared: %q", msg)
				}
			})
		}
	}
}

// TestNormalizeTimeAliasFractionMixedStream places fraction-carrying
// timestamp pairs in a normally terminating stream: a conflict line and a
// format-error line fail alone, the surrounding legal lines still produce
// results in input order with their physical line numbers, the failure count
// covers exactly the two failed log lines, and a clean EOF reports no
// stream-level error.
func TestNormalizeTimeAliasFractionMixedStream(t *testing.T) {
	input := `{"timestamp":"2026-01-02T08:04:05.100000000+08:00","time":"2026-01-02T00:04:05.1Z","action":"merge"}` + "\n" + // line 1: same instant, merges
		"\n" + // line 2: blank, only advances the counter
		`{"timestamp":"2026-01-02T00:04:05.100000000Z","time":"2026-01-02T00:04:05.100000001Z","action":"x"}` + "\n" + // line 3: 1ns conflict
		`{"timestamp":"2026-01-02T00:04:06Z","action":"after-conflict"}` + "\n" + // line 4: legal
		`{"time":"2026-01-02T00:04:07.1000000000Z","timestamp":"2026-01-02T00:04:07.1Z","action":"y"}` + "\n" + // line 5: 10-digit fraction
		`{"timestamp":"2026-01-02T00:04:08Z","action":"last"}` // line 6: legal, clean EOF without trailing newline

	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("per-line time failures at a clean EOF must not surface as a stream error: %v", err)
	}
	if errors.Is(err, ErrLogRead) || errors.Is(err, ErrLogWrite) {
		t.Fatalf("time conflicts and format errors are per-line failures, got stream error: %v", err)
	}
	if failures != 2 {
		t.Fatalf("exactly the conflict line and the format-error line must count, got %d", failures)
	}

	results := runNormalize(t, input)
	if len(results) != 5 {
		t.Fatalf("each of the 5 non-blank lines must yield one result, got %d: %#v", len(results), results)
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

	// The merging line keeps only the canonical UTC timestamp.
	event1 := eventOf(t, results[0])
	if got := event1[FieldTimestamp]; got != "2026-01-02T00:04:05.1Z" {
		t.Fatalf("line 1 merged timestamp = %v", got)
	}
	if _, exists := event1["time"]; exists {
		t.Fatalf("line 1 event must not keep the alias member: %#v", event1)
	}

	// Later legal lines come out in input order, undisturbed by the failures.
	if got := eventOf(t, results[2])[FieldAction]; got != "after-conflict" {
		t.Fatalf("line 4 must survive the earlier conflict: %#v", results[2])
	}
	if got := eventOf(t, results[4])[FieldAction]; got != "last" {
		t.Fatalf("line 6 must survive the earlier format error: %#v", results[4])
	}

	// The conflict failure explains the timestamp value clash; the format
	// failure reports the invalid timestamp; neither carries an event.
	conflictMsg, _ := results[1]["error"].(string)
	if _, exists := results[1]["event"]; exists {
		t.Fatalf("conflict line must carry no event: %#v", results[1])
	}
	if !strings.Contains(conflictMsg, FieldTimestamp) || !strings.Contains(strings.ToLower(conflictMsg), "conflict") {
		t.Fatalf("line 3 must report a timestamp value conflict, got %q", conflictMsg)
	}
	formatMsg, _ := results[3]["error"].(string)
	if _, exists := results[3]["event"]; exists {
		t.Fatalf("format-error line must carry no event: %#v", results[3])
	}
	if !strings.Contains(formatMsg, FieldTimestamp) || !strings.Contains(strings.ToLower(formatMsg), "invalid") {
		t.Fatalf("line 5 must report an invalid timestamp, got %q", formatMsg)
	}
	if strings.Contains(strings.ToLower(formatMsg), "conflict") {
		t.Fatalf("line 5 is a format error, not a conflict: %q", formatMsg)
	}
}
