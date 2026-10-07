package main

// CLI-level regression coverage for the UTC year-window rule
// (0000-9999 inclusive) as users actually hit it: logs arrive on stdin and
// per-line JSON results leave on stdout, so these tests execute the real
// compiled binary and pin the relationship between result records and the
// process exit status.
//
// A timestamp can spell a real four-digit-year date with a legal offset and
// still escape the window once converted to UTC:
//
//	0000-01-01T00:00:00+00:01 -> -0001-12-31T23:59:00Z
//	9999-12-31T23:59:59-00:01 -> 10000-01-01T00:00:59Z
//
// RFC3339Nano cannot serialize either result, so such a line must be an
// ordinary per-line failure — physical line number, ok:false, a reason that
// states the UTC year range, attributed to "timestamp", with no event and no
// success timestamp carrying a signed or five-digit year. An offset that
// lands exactly on 0000 or 9999 is the inclusive endpoint and must still
// succeed. The rule is identical under "timestamp" and the "time" alias, it
// is applied to both values before any same-instant merge or conflict
// comparison, and object member order never changes the outcome. Failures
// also survive --source-cidr filtering: the filter only suppresses
// successful events whose source misses the network.

import (
	"regexp"
	"strings"
	"testing"
)

// fourDigitUTCYear matches a canonical success timestamp beginning with an
// unsigned four-digit year; every successful event in this file must serialize
// that way (and end in "Z"), so a signed "-0001" or five-digit "10000" success
// value fails the test wherever it appears.
var fourDigitUTCYear = regexp.MustCompile(`^\d{4}-`)

// yearLine wraps one RFC3339 value under either timestamp key, with an action
// so the success path has an event to carry.
func yearLine(key, ts, action string) string {
	return `{"` + key + `":"` + ts + `","action":"` + action + `"}`
}

// bothYearKeys runs one check with the value under "timestamp" and under
// "time"; both spellings must behave identically at the CLI boundary.
func bothYearKeys(ts, action string) []string {
	return []string{
		yearLine("timestamp", ts, action),
		yearLine("time", ts, action),
	}
}

// assertYearOverflowFailure checks one ok:false record produced by a UTC
// year overflow: original physical line, no event, and a reason that names
// the timestamp field and the 0000-9999 UTC window rather than presenting a
// value conflict.
func assertYearOverflowFailure(t *testing.T, r map[string]any, wantLine float64) {
	t.Helper()
	if r["line"] != wantLine || r["ok"] != false {
		t.Fatalf("physical line %v must be reported with ok:false, got %#v", wantLine, r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("an out-of-range UTC year must not emit an event: %#v", r)
	}
	msg, _ := r["error"].(string)
	if !strings.Contains(msg, "timestamp") {
		t.Fatalf("error must be attributed to %q even under the alias, got %q", "timestamp", msg)
	}
	if !strings.Contains(msg, "UTC year") || !strings.Contains(msg, "0000-9999") {
		t.Fatalf("error must state the UTC year 0000-9999 window, got %q", msg)
	}
	if strings.Contains(strings.ToLower(msg), "conflict") {
		t.Fatalf("an out-of-range value is invalid, not a conflict of two legal times: %q", msg)
	}
}

// assertFourDigitSuccesses scans every result: success events must serialize
// a four-digit unsigned UTC year, and failures must carry no event at all.
// This is the guarantee that no signed or five-digit year ever leaves the
// process as a successful timestamp.
func assertFourDigitSuccesses(t *testing.T, results []map[string]any) {
	t.Helper()
	for _, r := range results {
		if r["ok"] != true {
			if _, exists := r["event"]; exists {
				t.Fatalf("failed record must carry no event: %#v", r)
			}
			continue
		}
		ts, _ := eventOf(t, r)["timestamp"].(string)
		if !fourDigitUTCYear.MatchString(ts) || !strings.HasSuffix(ts, "Z") {
			t.Fatalf("success timestamp must be a four-digit UTC year, got %q in %#v", ts, r)
		}
	}
}

// The two overflow directions named in the rule, through the real binary
// under either timestamp key: a plus offset at the lower written edge lands
// in the previous year and a minus offset at the upper edge lands in the
// next year. Each is an ordinary per-line failure (exit 1, stderr empty),
// never a success carrying "-0001" or "10000".
func TestNormalizeCLIUTCYearOverflowFailsExitOne(t *testing.T) {
	cases := []struct {
		name string
		ts   string
	}{
		{"plus one minute at 0000 lands in year -1", "0000-01-01T00:00:00+00:01"},
		{"plus one hour at 0000 lands in year -1", "0000-01-01T00:00:59+01:00"},
		{"minus one minute at 9999 lands in year 10000", "9999-12-31T23:59:59-00:01"},
		{"minus one hour at 9999 lands in year 10000", "9999-12-31T23:00:00-01:00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, line := range bothYearKeys(tc.ts, "a") {
				result := runNormalizeCLI(t, strings.NewReader(line+"\n"))
				if result.exitCode != 1 {
					t.Fatalf("overflow %q must exit 1, got %d (stderr: %q)", tc.ts, result.exitCode, result.stderr)
				}
				if result.stderr != "" {
					t.Fatalf("per-line failures belong in stdout records, not stderr: %q", result.stderr)
				}
				results := decodeStdoutResults(t, result.stdout)
				if len(results) != 1 {
					t.Fatalf("exactly one failure record expected, got %#v", results)
				}
				assertYearOverflowFailure(t, results[0], 1)
				assertFourDigitSuccesses(t, results)
				// The offending signed/five-digit year may appear inside the
				// error reason, but never as a success timestamp.
				if strings.Contains(result.stdout, `"timestamp":"-`) {
					t.Fatalf("stdout must not carry a negative-year success timestamp: %q", result.stdout)
				}
				if strings.Contains(result.stdout, `"timestamp":"10000`) {
					t.Fatalf("stdout must not carry a five-digit-year success timestamp: %q", result.stdout)
				}
			}
		})
	}
}

// Timestamps whose UTC conversion lands exactly on a range endpoint are
// legal — the endpoints are inclusive — including ordinary edge instants,
// the +00:00 spelling rendered as Z, and fractional seconds whose real
// precision survives and whose trailing zeros are still trimmed. A batch of
// only such logs exits 0 with empty stderr.
func TestNormalizeCLIUTCYearInclusiveBoundariesSucceedExitZero(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"lower endpoint written in Z", "0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"},
		{"offset lands exactly on the lower endpoint", "0000-01-01T00:01:00+00:01", "0000-01-01T00:00:00Z"},
		{"minus offset stays inside year 0000", "0000-01-01T00:00:00-23:59", "0000-01-01T23:59:00Z"},
		{"fraction at the lower edge keeps precision", "0000-01-01T00:00:00.123456+00:00", "0000-01-01T00:00:00.123456Z"},
		{"upper endpoint written in Z", "9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z"},
		{"offset lands exactly on the upper endpoint", "9999-12-31T23:58:59-00:01", "9999-12-31T23:59:59Z"},
		{"fraction lands exactly on the upper endpoint", "9999-12-31T23:58:59.123456789-00:01", "9999-12-31T23:59:59.123456789Z"},
		{"trailing-zero trim still applies at the upper edge", "9999-12-31T23:59:59.100000000Z", "9999-12-31T23:59:59.1Z"},
		{"real nanosecond precision survives at the upper edge", "9999-12-31T23:59:59.000000001Z", "9999-12-31T23:59:59.000000001Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, line := range bothYearKeys(tc.in, "edge") {
				result := runNormalizeCLI(t, strings.NewReader(line+"\n"))
				if result.exitCode != 0 {
					t.Fatalf("boundary %q must exit 0, got %d (stderr: %q, stdout: %q)",
						tc.in, result.exitCode, result.stderr, result.stdout)
				}
				if result.stderr != "" {
					t.Fatalf("a clean boundary run needs no diagnostics, got %q", result.stderr)
				}
				results := decodeStdoutResults(t, result.stdout)
				if len(results) != 1 || results[0]["ok"] != true {
					t.Fatalf("boundary %q must succeed, got %#v", tc.in, results)
				}
				event := eventOf(t, results[0])
				if got := event["timestamp"]; got != tc.want {
					t.Fatalf("boundary %q -> %v, want %q", tc.in, got, tc.want)
				}
				if event["action"] != "edge" {
					t.Fatalf("the action must survive at the edge: %#v", event)
				}
				assertFourDigitSuccesses(t, results)
			}
		})
	}
}

// With both timestamp keys present, validity is checked on each value before
// the two are compared: one overflowing side fails the whole line even when
// the other side is legal, and even when both sides overflow identically.
// Such a line is an invalid-value failure attributed to "timestamp", never a
// conflict between two legal times, in every key assignment and member order.
func TestNormalizeCLIUTCYearOverflowWithBothKeysFailsNotConflicts(t *testing.T) {
	lines := []string{
		// Lower edge: one legal endpoint value, one value one minute over.
		`{"timestamp":"0000-01-01T00:00:00Z","time":"0000-01-01T00:00:00+00:01","action":"a"}`,
		`{"time":"0000-01-01T00:00:00+00:01","timestamp":"0000-01-01T00:00:00Z","action":"a"}`,
		`{"timestamp":"0000-01-01T00:00:00+00:01","time":"0000-01-01T00:00:00Z","action":"a"}`,
		// Same pair with action written first; member order must not matter.
		`{"action":"a","timestamp":"0000-01-01T00:00:00Z","time":"0000-01-01T00:00:00+00:01"}`,
		// Upper edge: legal 9999 endpoint next to a value that converts to 10000.
		`{"timestamp":"9999-12-31T23:59:59Z","time":"9999-12-31T23:59:59-00:01","action":"a"}`,
		`{"time":"9999-12-31T23:59:59Z","timestamp":"9999-12-31T23:59:59-00:01","action":"a"}`,
		`{"timestamp":"9999-12-31T23:59:59-00:01","time":"9999-12-31T23:59:59Z","action":"a"}`,
		// Both keys carry the same overflowing instant: still invalid, not a
		// successful merge of "equal" values.
		`{"timestamp":"9999-12-31T23:59:59-00:01","time":"9999-12-31T23:59:59-00:01","action":"a"}`,
	}
	for i, line := range lines {
		result := runNormalizeCLI(t, strings.NewReader(line+"\n"))
		if result.exitCode != 1 {
			t.Fatalf("case %d: one overflowing key must force exit 1, got %d (stderr: %q, stdout: %q)",
				i, result.exitCode, result.stderr, result.stdout)
		}
		if result.stderr != "" {
			t.Fatalf("case %d: per-line failures stay off stderr: %q", i, result.stderr)
		}
		results := decodeStdoutResults(t, result.stdout)
		if len(results) != 1 {
			t.Fatalf("case %d: expected one failure record, got %#v", i, results)
		}
		assertYearOverflowFailure(t, results[0], 1)
		assertFourDigitSuccesses(t, results)
	}
}

// Two legal values that convert to one edge instant still merge into a single
// canonical "timestamp" (the alias disappears), regardless of which member is
// written first.
func TestNormalizeCLIUTCYearLegalEdgesWithBothKeysMerge(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{
			name: "lower edge, canonical first",
			line: `{"timestamp":"0000-01-01T00:00:00Z","time":"0000-01-01T00:01:00+00:01","action":"a"}`,
			want: "0000-01-01T00:00:00Z",
		},
		{
			name: "lower edge, alias first",
			line: `{"time":"0000-01-01T00:01:00+00:01","action":"a","timestamp":"0000-01-01T00:00:00Z"}`,
			want: "0000-01-01T00:00:00Z",
		},
		{
			name: "upper edge, canonical first",
			line: `{"timestamp":"9999-12-31T23:59:59Z","time":"9999-12-31T23:58:59-00:01","action":"a"}`,
			want: "9999-12-31T23:59:59Z",
		},
		{
			name: "upper edge, alias first",
			line: `{"action":"a","time":"9999-12-31T23:58:59-00:01","timestamp":"9999-12-31T23:59:59Z"}`,
			want: "9999-12-31T23:59:59Z",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := runNormalizeCLI(t, strings.NewReader(tc.line+"\n"))
			if result.exitCode != 0 || result.stderr != "" {
				t.Fatalf("legal same-instant edge values must run clean: exit=%d stderr=%q stdout=%q",
					result.exitCode, result.stderr, result.stdout)
			}
			results := decodeStdoutResults(t, result.stdout)
			if len(results) != 1 || results[0]["ok"] != true {
				t.Fatalf("same edge instant must merge successfully, got %#v", results)
			}
			event := eventOf(t, results[0])
			if got := event["timestamp"]; got != tc.want {
				t.Fatalf("merged timestamp %v, want %q", got, tc.want)
			}
			if _, exists := event["time"]; exists {
				t.Fatalf("merged event must keep only the canonical field: %#v", event)
			}
			assertFourDigitSuccesses(t, results)
		})
	}
}

// The full user path: overflow lines sandwiched between legal logs, blank
// physical lines between them, and a final complete record with no trailing
// newline (a clean EOF). Processing must continue past each overflow, keep
// input order and original physical line numbers, emit error-only records
// for the two overflows, and exit 1 with empty stderr. The legal edge logs
// before and after keep four-digit UTC timestamps.
func TestNormalizeCLIUTCYearOverflowMixedStreamExitOne(t *testing.T) {
	input := "{\"timestamp\":\"0000-01-01T00:01:00+00:01\",\"action\":\"a\"}\n" + // line 1: legal, lands on lower endpoint
		"\n" + // line 2: blank, only advances the counter
		"{\"timestamp\":\"0000-01-01T00:00:00+00:01\",\"action\":\"b\"}\n" + // line 3: overflow to year -1
		"{\"timestamp\":\"2026-04-15T12:00:00Z\",\"action\":\"c\"}\n" + // line 4: ordinary legal
		"  \t  \n" + // line 5: blank
		"{\"time\":\"9999-12-31T23:59:59-00:01\",\"action\":\"d\"}\n" + // line 6: overflow to year 10000 via alias
		"{\"timestamp\":\"9999-12-31T23:58:59-00:01\",\"action\":\"e\"}" // line 7: legal, lands on upper endpoint, no trailing newline

	result := runNormalizeCLI(t, strings.NewReader(input))

	if result.exitCode != 1 {
		t.Fatalf("two overflow lines must set exit 1 even with later legal logs, got %d (stderr: %q)",
			result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in their stdout records, not stderr: %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 5 {
		t.Fatalf("the five non-blank lines must each yield one record, got %#v", results)
	}
	wantLines := []float64{1, 3, 4, 6, 7}
	wantOK := []bool{true, false, true, false, true}
	for i, r := range results {
		if r["line"] != wantLines[i] || r["ok"] != wantOK[i] {
			t.Fatalf("record %d must be physical line %v with ok=%v, got %#v", i, wantLines[i], wantOK[i], r)
		}
	}

	// Successful records keep input order and their converted edge/ordinary times.
	if got := eventOf(t, results[0])["timestamp"]; got != "0000-01-01T00:00:00Z" {
		t.Fatalf("line 1 must land exactly on the lower endpoint, got %v", got)
	}
	if eventOf(t, results[0])["action"] != "a" {
		t.Fatalf("line 1 event content lost: %#v", results[0])
	}
	if got := eventOf(t, results[2])["timestamp"]; got != "2026-04-15T12:00:00Z" {
		t.Fatalf("line 4 must pass through untouched, got %v", got)
	}
	last := eventOf(t, results[4])
	if got := last["timestamp"]; got != "9999-12-31T23:59:59Z" || last["action"] != "e" {
		t.Fatalf("line 7 must land exactly on the upper endpoint with its action intact: %#v", last)
	}

	// Overflow records are error-only at their physical lines and explain the range.
	assertYearOverflowFailure(t, results[1], 3)
	assertYearOverflowFailure(t, results[3], 6)
	assertFourDigitSuccesses(t, results)
}

// The same mixed shape with nothing but legal boundary logs ends cleanly:
// exit 0, stderr empty, one ok:true record per non-blank line.
func TestNormalizeCLIUTCYearLegalBoundariesOnlyExitZero(t *testing.T) {
	input := "{\"timestamp\":\"0000-01-01T00:01:00+00:01\",\"action\":\"a\"}\n" +
		"\n" +
		"{\"time\":\"0000-01-01T00:00:00Z\",\"action\":\"b\"}\n" +
		"   \n" +
		"{\"timestamp\":\"9999-12-31T23:58:59-00:01\",\"action\":\"c\"}\n" +
		"{\"timestamp\":\"9999-12-31T23:59:59.100000000Z\",\"action\":\"d\"}\n"

	result := runNormalizeCLI(t, strings.NewReader(input))
	if result.exitCode != 0 {
		t.Fatalf("only-legal boundary logs must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("a clean edge run needs no diagnostics, got %q", result.stderr)
	}
	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 4 {
		t.Fatalf("four non-blank legal lines must yield four records, got %#v", results)
	}
	wantLines := []float64{1, 3, 5, 6}
	for i, r := range results {
		if r["line"] != wantLines[i] || r["ok"] != true {
			t.Fatalf("record %d must be an ok:true result on physical line %v: %#v", i, wantLines[i], r)
		}
	}
	wantTimes := []string{
		"0000-01-01T00:00:00Z",
		"0000-01-01T00:00:00Z",
		"9999-12-31T23:59:59Z",
		"9999-12-31T23:59:59.1Z",
	}
	for i, want := range wantTimes {
		if got := eventOf(t, results[i])["timestamp"]; got != want {
			t.Fatalf("record %d timestamp %v, want %q", i, got, want)
		}
	}
	assertFourDigitSuccesses(t, results)
}

// Under --source-cidr the filter only suppresses successful events whose
// source misses the network. Overflow lines must still be reported as
// failures with their physical line numbers and UTC-year reasons — whether
// their source is inside or outside the network — so the exit status stays 1
// and the failure can never be filtered away. In-range legal events are
// filtered normally: an out-of-range-source legal log produces no record.
func TestNormalizeCLIUTCYearOverflowSurvivesSourceFilter(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("in-range-ok", "192.0.2.10"),                                                    // line 1: kept
		`{"timestamp":"0000-01-01T00:00:00+00:01","action":"overflow-out","source_ip":"198.51.100.20"}`, // line 2: failure, source outside
		"", // line 3: blank
		validCIDRSource("out-of-range-ok", "198.51.100.21"),                                         // line 4: legal but filtered out: no record
		`{"time":"9999-12-31T23:59:59-00:01","action":"overflow-out2","source_ip":"198.51.100.22"}`, // line 5: failure, source outside
		`{"timestamp":"0000-01-01T00:00:00+00:01","action":"overflow-in","source_ip":"192.0.2.99"}`, // line 6: failure, source INSIDE
		validCIDRSource("in-range-ok2", "192.0.2.11"),                                               // line 7: kept
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.2.123/24")

	if result.exitCode != 1 {
		t.Fatalf("overflow lines must force exit 1 even under a source filter, got %d (stderr: %q)",
			result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures stay off stderr even when filtered: %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	// Two kept successes (lines 1, 7) plus all three failures (lines 2, 5, 6);
	// the legal-but-outside line 4 produces nothing.
	if len(results) != 5 {
		t.Fatalf("expected 2 kept successes + 3 failures, got %#v", results)
	}
	wantLines := []float64{1, 2, 5, 6, 7}
	wantOK := []bool{true, false, false, false, true}
	for i, r := range results {
		if r["line"] != wantLines[i] || r["ok"] != wantOK[i] {
			t.Fatalf("record %d must be physical line %v with ok=%v: %#v", i, wantLines[i], wantOK[i], r)
		}
	}

	first := eventOf(t, results[0])
	if first["action"] != "in-range-ok" || first["source_ip"] != "192.0.2.10" {
		t.Fatalf("line 1 must be admitted normally: %#v", first)
	}
	assertYearOverflowFailure(t, results[1], 2)
	assertYearOverflowFailure(t, results[2], 5)
	assertYearOverflowFailure(t, results[3], 6)
	last := eventOf(t, results[4])
	if last["action"] != "in-range-ok2" || last["source_ip"] != "192.0.2.11" {
		t.Fatalf("line 7 must be admitted after the failures: %#v", last)
	}
	assertFourDigitSuccesses(t, results)
}
