package relayproof

// Regression coverage for calendar validity in timestamp normalization.
//
// A timestamp's date must really exist in the year/month/day as written,
// before any timezone conversion is applied: 2000 is a leap year, 1900 is
// not, ordinary common years have no February 29, and a 30-day month has
// no 31st (the day must never roll over into the next month). Only once
// the written date is accepted is the instant converted to UTC, where a
// conversion may legitimately move it across midnight — including onto a
// leap day or off the end of a month — without dropping the event.
//
// These tests go through the same public NormalizeReader/NormalizeLine
// output as every other caller and introduce no new timestamp shapes.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// calendarLine wraps one RFC3339 value in a log object carrying the
// timestamp under either its canonical name or its alias, plus an action
// so the success path has an event to preserve across midnight.
func calendarLine(key, ts, action string) string {
	return `{"` + key + `":"` + ts + `","action":"` + action + `"}`
}

// bothTimestampKeys runs one check with the value under "timestamp" and
// under "time"; both spellings must behave identically.
func bothTimestampKeys(ts, action string) []string {
	return []string{
		calendarLine(FieldTimestamp, ts, action),
		calendarLine("time", ts, action),
	}
}

// TestNormalizeCalendarExistingDatesAccepted pins real month-end and leap
// dates, including the centuries and 31/30-day month boundaries that tell
// a real calendar check apart from a day<=31 shortcut.
func TestNormalizeCalendarExistingDatesAccepted(t *testing.T) {
	ok := map[string]string{
		"2000-02-29T00:00:00Z":      "2000-02-29T00:00:00Z", // divisible by 400: leap
		"2000-02-29T23:59:59.5Z":    "2000-02-29T23:59:59.5Z",
		"2024-02-29T12:00:00Z":      "2024-02-29T12:00:00Z", // ordinary leap year
		"1900-02-28T12:00:00Z":      "1900-02-28T12:00:00Z", // 1900 is common; the 28th is its last February day
		"2000-02-28T12:00:00Z":      "2000-02-28T12:00:00Z",
		"2000-04-30T12:00:00Z":      "2000-04-30T12:00:00Z", // last day of a 30-day month
		"2000-06-30T23:59:59Z":      "2000-06-30T23:59:59Z",
		"2000-11-30T00:00:00Z":      "2000-11-30T00:00:00Z",
		"2000-01-31T12:00:00Z":      "2000-01-31T12:00:00Z", // last day of a 31-day month
		"2000-12-31T23:59:59Z":      "2000-12-31T23:59:59Z",
		"2001-03-01T00:00:00Z":      "2001-03-01T00:00:00Z", // day after common-year Feb 28 exists
		"2000-02-29T00:00:00+01:00": "2000-02-28T23:00:00Z", // leap day accepted before conversion
	}
	for in, want := range ok {
		for _, wrapper := range bothTimestampKeys(in, "a") {
			results := runNormalize(t, wrapper)
			if results[0]["ok"] != true {
				t.Fatalf("real calendar date %q must be accepted, got %#v", in, results[0])
			}
			if got := eventOf(t, results[0])[FieldTimestamp]; got != want {
				t.Fatalf("date %q -> %v, want %q", in, got, want)
			}
		}
	}
}

// TestNormalizeCalendarNonexistentDatesRejected pins the core rule: the
// written year/month/day combination must exist. Failures name the
// timestamp field, carry a date ("day out of range") complaint, and emit
// no event — a 31st in a 30-day month must never be carried to day 1.
func TestNormalizeCalendarNonexistentDatesRejected(t *testing.T) {
	bad := []string{
		"1900-02-29T00:00:00Z", // century not divisible by 400: not a leap year
		"2001-02-29T12:00:00Z", // ordinary common year
		"1999-02-29T23:59:59Z",
		"2000-02-30T00:00:00Z", // leap February still ends on the 29th
		"2024-02-30T00:00:00Z",
		"2000-04-31T00:00:00Z", // must not become 2000-05-01
		"2001-04-31T12:00:00Z",
		"2000-06-31T00:00:00Z",
		"2000-09-31T00:00:00Z",
		"2000-11-31T00:00:00Z",
		// The written local fields are judged first: even though the zone
		// conversion would land both on a real February 28/March 1 date,
		// the date as spelled does not exist and must fail.
		"2001-02-29T00:30:00+01:00", // converts to 2001-02-28T23:30Z
		"1900-02-29T23:30:00-01:00", // converts to 1900-03-01T00:30Z
	}
	for _, in := range bad {
		for _, wrapper := range bothTimestampKeys(in, "a") {
			results := runNormalize(t, wrapper)
			if results[0]["ok"] != false {
				t.Fatalf("nonexistent date %q must fail, got %#v", in, results[0])
			}
			if _, exists := results[0]["event"]; exists {
				t.Fatalf("nonexistent date %q must not roll over into an event: %#v", in, results[0])
			}
			msg, _ := results[0]["error"].(string)
			if !strings.Contains(msg, FieldTimestamp) {
				t.Fatalf("error for %q must name %q, got %q", in, FieldTimestamp, msg)
			}
			if !strings.Contains(msg, "day out of range") {
				t.Fatalf("error for %q must report the calendar-date problem, got %q", in, msg)
			}
		}
	}
}

// TestNormalizeCalendarCrossMidnightConversionOutput checks legal dates
// whose zone conversion crosses midnight: the moved date (including onto a
// leap day and off a month end) is visible directly in the canonical
// timestamp, and the action survives instead of the event being lost.
func TestNormalizeCalendarCrossMidnightConversionOutput(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"leap day minus offset rolls back to Feb 28", "2000-02-29T00:30:00+01:00", "2000-02-28T23:30:00Z"},
		{"Feb 28 minus offset rolls onto the leap day", "2000-02-28T23:30:00-01:00", "2000-02-29T00:30:00Z"},
		{"leap day evening rolls into March", "2000-02-29T23:30:00-01:00", "2000-03-01T00:30:00Z"},
		{"March 1 early rolls back onto the leap day", "2000-03-01T00:30:00+01:00", "2000-02-29T23:30:00Z"},
		{"common-year Feb 28 rolls onto March 1", "2001-02-28T23:30:00-01:00", "2001-03-01T00:30:00Z"},
		{"April 30 evening rolls onto May 1", "2000-04-30T23:30:00-01:00", "2000-05-01T00:30:00Z"},
		{"May 1 early rolls back to April 30", "2000-05-01T00:30:00+01:00", "2000-04-30T23:30:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, wrapper := range bothTimestampKeys(tc.in, "login") {
				results := runNormalize(t, wrapper)
				if results[0]["ok"] != true {
					t.Fatalf("legal date crossing midnight must succeed, got %#v", results[0])
				}
				event := eventOf(t, results[0])
				if got := event[FieldTimestamp]; got != tc.want {
					t.Fatalf("%q -> %v, want %q", tc.in, got, tc.want)
				}
				// Crossing a date boundary must not drop the record or
				// disturb the independently normalized action.
				if event[FieldAction] != "login" {
					t.Fatalf("action lost across midnight: %#v", event)
				}
			}
		})
	}
}

// TestNormalizeCalendarCanonicalAndAliasMergeAcrossDateBoundary: the
// canonical name and its alias may spell one instant with different
// written dates and different offsets (one side on each side of midnight).
// Both values validating and converting to the same UTC instant must merge
// into that one timestamp, in either key assignment.
func TestNormalizeCalendarCanonicalAndAliasMergeAcrossDateBoundary(t *testing.T) {
	cases := []struct {
		name      string
		canonical string
		alias     string
		want      string
	}{
		{
			name:      "leap day early and Feb 28 evening are one instant",
			canonical: "2000-02-29T00:30:00+01:00", // -> 28th 23:30Z
			alias:     "2000-02-28T18:30:00-05:00", // -> 28th 23:30Z
			want:      "2000-02-28T23:30:00Z",
		},
		{
			name:      "Feb 28 evening and leap day early morning are one instant",
			canonical: "2000-02-28T23:30:00-01:00", // -> 29th 00:30Z
			alias:     "2000-02-29T05:30:00+05:00", // -> 29th 00:30Z
			want:      "2000-02-29T00:30:00Z",
		},
		{
			name:      "leap day evening and March 1 early morning are one instant",
			canonical: "2000-02-29T23:30:00-01:00", // -> Mar 1 00:30Z
			alias:     "2000-03-01T01:30:00+01:00", // -> Mar 1 00:30Z
			want:      "2000-03-01T00:30:00Z",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wrappers := []string{
				`{"timestamp":"` + tc.canonical + `","time":"` + tc.alias + `","action":"a"}`,
				`{"timestamp":"` + tc.alias + `","time":"` + tc.canonical + `","action":"a"}`,
			}
			for _, wrapper := range wrappers {
				results := runNormalize(t, wrapper)
				if results[0]["ok"] != true {
					t.Fatalf("same instant spelled across a date boundary must merge, got %#v", results[0])
				}
				if got := eventOf(t, results[0])[FieldTimestamp]; got != tc.want {
					t.Fatalf("merged timestamp %v, want %q", got, tc.want)
				}
			}
		})
	}
}

// TestNormalizeCalendarInvalidDateFailsWholeLine: when canonical name and
// alias coexist, every written date must be valid on its own. A nonexistent
// date on one side fails the entire line even when the other side is legal,
// and even when a lenient "roll the date over, then compare" parser would
// find the two equal. The error is always attributed to "timestamp",
// regardless of which key carried the bad value, and is an invalid-value
// error rather than a value conflict.
func TestNormalizeCalendarInvalidDateFailsWholeLine(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "legal canonical, nonexistent alias",
			input: `{"timestamp":"2000-02-28T00:00:00Z","time":"1900-02-29T00:00:00Z","action":"a"}`,
		},
		{
			name:  "nonexistent canonical, legal alias",
			input: `{"timestamp":"2001-02-29T00:00:00Z","time":"2000-02-28T00:00:00Z","action":"a"}`,
		},
		{
			// A forgiving parser would roll Feb 29 (common year) forward to
			// March 1, making 01:30+01:00 the same instant as the legal
			// canonical value; validation must happen before that comparison.
			name:  "legal canonical, alias invalid but rollover would match",
			input: `{"timestamp":"2001-03-01T00:30:00Z","time":"2001-02-29T01:30:00+01:00","action":"a"}`,
		},
		{
			name:  "same trap with the invalid date under the canonical name",
			input: `{"timestamp":"2001-02-29T01:30:00+01:00","time":"2001-03-01T00:30:00Z","action":"a"}`,
		},
		{
			name:  "alias only: bad date still attributed to canonical field",
			input: `{"time":"2026-04-31T00:00:00Z","action":"a"}`,
		},
		{
			name:  "canonical only: same failure",
			input: `{"timestamp":"2026-04-31T00:00:00Z","action":"a"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := runNormalize(t, tc.input)
			if results[0]["ok"] != false {
				t.Fatalf("line with one nonexistent date must fail: %#v", results[0])
			}
			if _, exists := results[0]["event"]; exists {
				t.Fatalf("invalid date must not emit a partial event: %#v", results[0])
			}
			msg, _ := results[0]["error"].(string)
			if !strings.Contains(msg, FieldTimestamp) {
				t.Fatalf("error must be attributed to %q even when only the alias is bad, got %q", FieldTimestamp, msg)
			}
			if !strings.Contains(msg, "day out of range") {
				t.Fatalf("error must identify the calendar-date problem, got %q", msg)
			}
			if strings.Contains(msg, "conflicting values") {
				t.Fatalf("an invalid date must be rejected as invalid, not compared: %q", msg)
			}
		})
	}
}

// TestNormalizeCalendarMixedStream interleaves legal leap days,
// nonexistent dates, and ordinary legal dates in one stream, with blank
// physical lines between them. Every non-blank line must produce exactly
// one result carrying its original physical line number; date errors count
// only against their own line, later legal records still come out in order,
// and a normal EOF reports the date failures as per-line failures rather
// than a stream read/write error.
func TestNormalizeCalendarMixedStream(t *testing.T) {
	input := "{\"timestamp\":\"2000-02-29T12:00:00Z\",\"action\":\"a\"}\n" + // line 1: legal leap day
		"\n" + // line 2: blank, only advances the counter
		"{\"timestamp\":\"1900-02-29T12:00:00Z\",\"action\":\"b\"}\n" + // line 3: bad date
		"{\"timestamp\":\"2026-04-15T12:00:00Z\",\"action\":\"c\"}\n" + // line 4: legal ordinary date
		"  \t  \n" + // line 5: blank
		"{\"time\":\"2026-04-31T12:00:00Z\",\"action\":\"d\"}\n" + // line 6: bad date under alias
		"{\"timestamp\":\"2000-02-28T23:30:00-01:00\",\"action\":\"e\"}\n" + // line 7: legal, crosses onto leap day
		"{\"timestamp\":\"2001-02-29T00:30:00+01:00\",\"action\":\"f\"}\n" + // line 8: bad written date despite UTC landing on Feb 28
		"{\"timestamp\":\"2000-04-30T23:30:00-01:00\",\"action\":\"g\"}" // line 9: legal, no trailing newline (clean EOF)

	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("normal EOF with bad-date lines must not be a stream failure: %v", err)
	}
	if errors.Is(err, ErrLogRead) || errors.Is(err, ErrLogWrite) {
		t.Fatalf("invalid dates are per-line normalization failures, got stream error: %v", err)
	}
	if failures != 3 {
		t.Fatalf("exactly the 3 nonexistent-date lines must count as failures, got %d", failures)
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
	if len(results) != 7 {
		t.Fatalf("each of the 7 non-blank lines must yield exactly one result, got %d: %#v", len(results), results)
	}
	if got := countFailures(results); got != failures {
		t.Fatalf("output shows %d failures but NormalizeReader returned %d", got, failures)
	}

	wantLines := []int{1, 3, 4, 6, 7, 8, 9}
	wantOK := []bool{true, false, true, false, true, false, true}
	for i, r := range results {
		if r["line"] != float64(wantLines[i]) {
			t.Fatalf("result %d must keep physical line %d, got %v: %#v", i, wantLines[i], r["line"], r)
		}
		if r["ok"] != wantOK[i] {
			t.Fatalf("line %d ok = %v, want %v: %#v", wantLines[i], r["ok"], wantOK[i], r)
		}
	}

	// Successful records keep input order and show the cross-midnight UTC dates.
	if got := eventOf(t, results[0])[FieldTimestamp]; got != "2000-02-29T12:00:00Z" {
		t.Fatalf("line 1 timestamp %v", got)
	}
	if got := eventOf(t, results[2])[FieldTimestamp]; got != "2026-04-15T12:00:00Z" {
		t.Fatalf("line 4 timestamp %v", got)
	}
	event6 := eventOf(t, results[4])
	if got := event6[FieldTimestamp]; got != "2000-02-29T00:30:00Z" || event6[FieldAction] != "e" {
		t.Fatalf("line 7 must cross onto the leap day with its action intact: %#v", event6)
	}
	event9 := eventOf(t, results[6])
	if got := event9[FieldTimestamp]; got != "2000-05-01T00:30:00Z" || event9[FieldAction] != "g" {
		t.Fatalf("final line must cross from April 30 to May 1: %#v", event9)
	}

	// Each date failure is error-only and names the timestamp calendar problem.
	for _, idx := range []int{1, 3, 5} {
		r := results[idx]
		if _, exists := r["event"]; exists {
			t.Fatalf("line %v failure must carry no event: %#v", r["line"], r)
		}
		msg, _ := r["error"].(string)
		if !strings.Contains(msg, FieldTimestamp) || !strings.Contains(msg, "day out of range") {
			t.Fatalf("line %v error must name %q's date problem, got %q", r["line"], FieldTimestamp, msg)
		}
	}
}
