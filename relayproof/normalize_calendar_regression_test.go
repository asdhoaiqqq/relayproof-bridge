package relayproof

// Regression coverage for calendar validity in timestamp normalization.
//
// The rule guarded here is older than this file: the date written in the
// input must really exist in its own year/month before any timezone math
// runs. In particular 2000 is a leap year and 1900 is not, a common-year
// February has no 29th, and a 31st in a 30-day month (e.g. April 31) must
// fail outright instead of being carried into the next month. Only after
// the written date is accepted is the instant converted to UTC, where a
// legitimate offset may move it across midnight — backwards off a leap day
// or forwards onto one. The tests pin both the accepted UTC outputs and
// the per-line failures through the public NormalizeReader/NormalizeLine
// surface, for the canonical "timestamp" name and its "time" alias alike.

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// normalizeOne is the single-line convenience used by the calendar cases:
// it runs the same streaming pipeline the rest of the suite uses so the
// assertions always reflect public output, never an internal helper.
func normalizeOne(t *testing.T, line string) map[string]any {
	t.Helper()
	results := runNormalize(t, line)
	if len(results) != 1 {
		t.Fatalf("expected exactly one result for one line, got %d: %#v", len(results), results)
	}
	return results[0]
}

// forEachTimestampKey runs fn once for a log object carrying the timestamp
// under the canonical key and once under the alias, so every calendar rule
// is proven for both spellings.
func forEachTimestampKey(t *testing.T, tsValue string, fn func(t *testing.T, input string)) {
	t.Helper()
	for _, input := range []string{
		`{"timestamp":"` + tsValue + `","action":"a"}`,
		`{"time":"` + tsValue + `","action":"a"}`,
	} {
		fn(t, input)
	}
}

// TestNormalizeCalendarLeapDayCrossMidnight pins the two headline
// conversions: a legal Feb 29 instant can move to Feb 28 in UTC, and a
// legal Feb 28 instant can move onto Feb 29 in UTC. The normalized event
// survives the date change intact — the action field is still present, so
// crossing midnight never costs the line its event.
func TestNormalizeCalendarLeapDayCrossMidnight(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		wantTS string
	}{
		{
			name:   "leap day early morning behind UTC rolls back to Feb 28",
			input:  "2000-02-29T00:30:00+01:00",
			wantTS: "2000-02-28T23:30:00Z",
		},
		{
			name:   "Feb 28 late evening ahead of UTC rolls onto leap day",
			input:  "2000-02-28T23:30:00-01:00",
			wantTS: "2000-02-29T00:30:00Z",
		},
		{
			name:   "same rollback with fractional precision kept",
			input:  "2000-02-29T00:30:00.5+01:00",
			wantTS: "2000-02-28T23:30:00.5Z",
		},
		{
			name:   "leap day at Z keeps its written date",
			input:  "2000-02-29T12:00:00Z",
			wantTS: "2000-02-29T12:00:00Z",
		},
		// Legal month and year boundaries convert the same way; the written
		// date is valid, the UTC date is simply different.
		{
			name:   "March 31 evening ahead of UTC rolls onto April 1",
			input:  "2000-03-31T23:30:00-01:00",
			wantTS: "2000-04-01T00:30:00Z",
		},
		{
			name:   "April 1 early morning behind UTC rolls back to March 31",
			input:  "2000-04-01T00:30:00+01:00",
			wantTS: "2000-03-31T23:30:00Z",
		},
		{
			name:   "Dec 31 evening ahead of UTC rolls into the next year",
			input:  "1999-12-31T23:30:00-01:00",
			wantTS: "2000-01-01T00:30:00Z",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachTimestampKey(t, tc.input, func(t *testing.T, line string) {
				result := normalizeOne(t, line)
				if result["ok"] != true {
					t.Fatalf("legal date crossing midnight must succeed: %s -> %#v", line, result)
				}
				event := eventOf(t, result)
				if got := event["timestamp"]; got != tc.wantTS {
					t.Fatalf("%s -> timestamp %v, want %q", line, got, tc.wantTS)
				}
				// The event is normalized, not dropped: the action field
				// survives the cross-midnight conversion unchanged.
				if got := event["action"]; got != "a" {
					t.Fatalf("action lost across midnight conversion: %v", got)
				}
			})
		})
	}
}

// TestNormalizeCalendarNonexistentDates is the core validity guard: each
// date below must fail in the exact year/month in which it is written, for
// both key spellings, with an error attributed to "timestamp" and no event.
// The offending literal must appear verbatim in the error — nothing may
// adjust it to a neighboring date first.
func TestNormalizeCalendarNonexistentDates(t *testing.T) {
	bad := []struct {
		name  string
		value string
	}{
		{"1900 is not a leap year", "1900-02-29T00:00:00Z"},
		{"2100 is not a leap year", "2100-02-29T00:00:00Z"},
		{"1999 common-year February has no 29", "1999-02-29T00:00:00Z"},
		{"2001 common-year February has no 29", "2001-02-29T00:00:00Z"},
		{"2023 common-year February has no 29", "2023-02-29T08:15:30Z"},
		{"even leap-year February has no 30", "2000-02-30T00:00:00Z"},
		{"even leap-year February has no 31", "2000-02-31T00:00:00Z"},
		{"no month has a day 00", "2000-02-00T00:00:00Z"},
		{"April 31 must not become May 1", "2001-04-31T00:00:00Z"},
		{"June 31 must not become July 1", "2000-06-31T00:00:00Z"},
		{"September 31 must not become October 1", "2000-09-31T12:00:00Z"},
		{"November 31 must not become December 1", "2000-11-31T12:00:00Z"},
		{"a legal offset never rescues a nonexistent local date", "2001-04-31T23:30:00-01:00"},
		{"a leap-day spelling does not rescue a non-leap year under offset", "1900-02-29T00:30:00+01:00"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			forEachTimestampKey(t, tc.value, func(t *testing.T, line string) {
				result := normalizeOne(t, line)
				if result["ok"] != false {
					t.Fatalf("nonexistent date %q must fail, got event %#v", tc.value, result)
				}
				if _, exists := result["event"]; exists {
					t.Fatalf("nonexistent date %q must not emit a partial event", tc.value)
				}
				msg, _ := result["error"].(string)
				if !strings.Contains(msg, FieldTimestamp) {
					t.Fatalf("error for %q must be attributed to %q even via alias, got %q", tc.value, FieldTimestamp, msg)
				}
				if !strings.Contains(msg, "day out of range") {
					t.Fatalf("error for %q must report the calendar day problem, got %q", tc.value, msg)
				}
				// The rejected spelling is quoted back verbatim: it was not
				// carried into the next month or otherwise rewritten.
				if !strings.Contains(msg, tc.value) {
					t.Fatalf("error must quote the original value %q, got %q", tc.value, msg)
				}
			})
		})
	}
}

// TestNormalizeCalendarValidBoundaryDates is the positive control sitting
// beside the rejection table: the dates neighboring the rejected ones are
// genuinely valid and must keep succeeding, so the guard cannot be an
// over-broad day cap.
func TestNormalizeCalendarValidBoundaryDates(t *testing.T) {
	ok := map[string]string{
		"2000-02-29T12:00:00Z":      "2000-02-29T12:00:00Z", // 2000 is a leap year
		"2024-02-29T12:00:00Z":      "2024-02-29T12:00:00Z", // 2024 is a leap year
		"1900-02-28T12:00:00Z":      "1900-02-28T12:00:00Z", // Feb 28 valid in 1900
		"2001-02-28T12:00:00Z":      "2001-02-28T12:00:00Z", // Feb 28 valid in a common year
		"2001-04-30T12:00:00Z":      "2001-04-30T12:00:00Z", // last valid April day
		"2000-12-31T23:59:59Z":      "2000-12-31T23:59:59Z",
		"2000-01-01T00:00:00Z":      "2000-01-01T00:00:00Z",
		"2000-02-29T00:00:00+01:00": "2000-02-28T23:00:00Z",
		"2000-02-28T23:59:59-01:00": "2000-02-29T00:59:59Z",
	}
	for in, want := range ok {
		forEachTimestampKey(t, in, func(t *testing.T, line string) {
			result := normalizeOne(t, line)
			if result["ok"] != true {
				t.Fatalf("valid date %q must be accepted, got %#v", in, result)
			}
			if got := eventOf(t, result)["timestamp"]; got != want {
				t.Fatalf("valid date %q -> %v, want %q", in, got, want)
			}
		})
	}
}

// TestNormalizeCalendarCanonicalAndAliasAgreement covers both keys on one
// line: legal values written as different dates with different offsets
// merge when they denote the same UTC instant, but one nonexistent date
// fails the whole line regardless of which spelling carries it — even when
// carrying the invalid day first would land on the same instant the legal
// value names.
func TestNormalizeCalendarCanonicalAndAliasAgreement(t *testing.T) {
	t.Run("same leap-day instant written two ways merges", func(t *testing.T) {
		lines := []string{
			`{"timestamp":"2000-02-29T00:30:00+01:00","time":"2000-02-28T23:30:00Z","action":"a"}`,
			`{"timestamp":"2000-02-28T23:30:00Z","time":"2000-02-29T00:30:00+01:00","action":"a"}`,
			`{"timestamp":"2000-02-29T00:30:00Z","time":"2000-02-28T23:30:00-01:00","action":"a"}`,
			`{"timestamp":"2000-02-28T23:30:00-01:00","time":"2000-02-29T00:30:00Z","action":"a"}`,
		}
		wants := []string{
			"2000-02-28T23:30:00Z",
			"2000-02-28T23:30:00Z",
			"2000-02-29T00:30:00Z",
			"2000-02-29T00:30:00Z",
		}
		for i, line := range lines {
			result := normalizeOne(t, line)
			if result["ok"] != true {
				t.Fatalf("case %d: equivalent legal dates must merge, got %#v", i, result)
			}
			if got := eventOf(t, result)["timestamp"]; got != wants[i] {
				t.Fatalf("case %d: merged timestamp %v, want %q", i, got, wants[i])
			}
			if got := eventOf(t, result)["action"]; got != "a" {
				t.Fatalf("case %d: action missing after merge: %v", i, got)
			}
		}
	})

	t.Run("one nonexistent date fails the whole line", func(t *testing.T) {
		cases := []struct {
			name  string
			input string
			bad   string // the literal that must survive verbatim in the error
		}{
			{
				name:  "illegal Feb 29 under alias, legal value under canonical",
				input: `{"timestamp":"1900-02-28T00:00:00Z","time":"1900-02-29T00:00:00Z","action":"a"}`,
				bad:   "1900-02-29T00:00:00Z",
			},
			{
				name:  "illegal Feb 29 under canonical, legal value under alias",
				input: `{"timestamp":"1900-02-29T00:00:00Z","time":"1900-02-28T00:00:00Z","action":"a"}`,
				bad:   "1900-02-29T00:00:00Z",
			},
			{
				name:  "April 31 under alias, April 30 under canonical",
				input: `{"timestamp":"2001-04-30T00:00:00Z","time":"2001-04-31T00:00:00Z","action":"a"}`,
				bad:   "2001-04-31T00:00:00Z",
			},
			{
				name:  "Feb 30 carried forward would equal the legal March 1",
				input: `{"timestamp":"2000-03-01T00:30:00Z","time":"2000-02-30T00:30:00Z","action":"a"}`,
				bad:   "2000-02-30T00:30:00Z",
			},
			{
				name:  "April 31 carried forward would equal the legal May 1",
				input: `{"timestamp":"2001-05-01T00:00:00Z","time":"2001-04-31T00:00:00Z","action":"a"}`,
				bad:   "2001-04-31T00:00:00Z",
			},
			{
				name:  "both values nonexistent still fails, not merges",
				input: `{"timestamp":"1900-02-29T00:00:00Z","time":"2001-04-31T00:00:00Z","action":"a"}`,
				bad:   "2001-04-31T00:00:00Z",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				result := normalizeOne(t, tc.input)
				if result["ok"] != false {
					t.Fatalf("line with one nonexistent date must fail, got %#v", result)
				}
				if _, exists := result["event"]; exists {
					t.Fatalf("failure must not carry an event: %#v", result)
				}
				msg, _ := result["error"].(string)
				if !strings.Contains(msg, FieldTimestamp) {
					t.Fatalf("error must be attributed to %q regardless of alias spelling, got %q", FieldTimestamp, msg)
				}
				if !strings.Contains(msg, "day out of range") {
					t.Fatalf("error must report the calendar day problem, got %q", msg)
				}
				if !strings.Contains(msg, tc.bad) {
					t.Fatalf("error must quote the invalid literal %q, got %q", tc.bad, msg)
				}
				// Validity is decided per written value; the bad spelling is
				// never normalized first and then treated as a conflict.
				if strings.Contains(msg, "conflicting values") {
					t.Fatalf("nonexistent date must be rejected as invalid, not compared: %q", msg)
				}
			})
		}
	})
}

// TestNormalizeCalendarMixedStream proves line-level isolation over a
// realistic stretch: legal leap-day conversions, nonexistent dates, and
// ordinary legal records are interleaved (with blank lines). Every
// non-blank physical line yields exactly one result, bad dates fail only
// their own line, later legal records still come out in input order with
// their original physical line numbers, and the returned failure count
// counts exactly the date failures — the run is not a read or write error.
func TestNormalizeCalendarMixedStream(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":"2000-02-29T00:30:00+01:00","action":"a1"}`, // line 1: legal, rolls to Feb 28
		``, // line 2 blank
		`{"time":"1900-02-29T00:00:00Z","action":"b2"}`,      // line 3: bad date under alias
		`{"timestamp":"2026-03-15T09:00:00Z","action":"c3"}`, // line 4: ordinary legal record
		`   `, // line 5 blank
		`{"timestamp":"2001-04-31T12:00:00Z","action":"d4"}`,      // line 6: April 31, must not carry
		`{"time":"2000-02-28T23:30:00-01:00","action":"e5"}`,      // line 7: legal, rolls onto Feb 29
		`{"timestamp":"2023-02-29T00:00:00Z","action":"f6"}`,      // line 8: common-year Feb 29
		`{"timestamp":"2000-04-01T00:30:00+01:00","action":"g7"}`, // line 9: legal, rolls to Mar 31
	}, "\n") + "\n"

	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("date failures are per-line, not stream errors: %v", err)
	}
	if errors.Is(err, ErrLogRead) || errors.Is(err, ErrLogWrite) {
		t.Fatalf("invalid dates must never be classified as I/O failures: %v", err)
	}
	if failures != 3 {
		t.Fatalf("exactly the 3 nonexistent-date lines must fail, got %d", failures)
	}

	results := decodeResults(t, out.Bytes())
	if len(results) != 7 {
		t.Fatalf("each of the 7 non-blank lines must produce exactly one result, got %d: %#v", len(results), results)
	}

	want := []struct {
		line   float64
		ok     bool
		action string
		ts     string // only checked on success
	}{
		{1, true, "a1", "2000-02-28T23:30:00Z"},
		{3, false, "b2", ""},
		{4, true, "c3", "2026-03-15T09:00:00Z"},
		{6, false, "d4", ""},
		{7, true, "e5", "2000-02-29T00:30:00Z"},
		{8, false, "f6", ""},
		{9, true, "g7", "2000-03-31T23:30:00Z"},
	}
	for i, w := range want {
		r := results[i]
		if r["line"] != w.line {
			t.Fatalf("result %d must keep physical line number %v, got %v (%#v)", i, w.line, r["line"], r)
		}
		if w.ok {
			if r["ok"] != true {
				t.Fatalf("line %v must succeed, got %#v", w.line, r)
			}
			event := eventOf(t, r)
			if event["action"] != w.action {
				t.Fatalf("line %v action/order mismatch: %v", w.line, event["action"])
			}
			if event["timestamp"] != w.ts {
				t.Fatalf("line %v timestamp %v, want %q", w.line, event["timestamp"], w.ts)
			}
			continue
		}
		if r["ok"] != false {
			t.Fatalf("line %v with nonexistent date must fail, got %#v", w.line, r)
		}
		if _, exists := r["event"]; exists {
			t.Fatalf("line %v failure must not contain an event", w.line)
		}
		msg, _ := r["error"].(string)
		if msg == "" {
			t.Fatalf("line %v failure must carry an error message", w.line)
		}
		if !strings.Contains(msg, FieldTimestamp) {
			t.Fatalf("line %v error must name %q, got %q", w.line, FieldTimestamp, msg)
		}
		if !strings.Contains(msg, "day out of range") {
			t.Fatalf("line %v error must be the calendar failure, got %q", w.line, msg)
		}
	}
}
