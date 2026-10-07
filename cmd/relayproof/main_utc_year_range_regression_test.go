package main

// CLI-level regression coverage for the UTC year window (0000-9999, both
// endpoints inclusive) after timezone conversion, exercised against the real
// compiled binary exactly as a user runs it: logs arrive on stdin and
// per-line JSON results leave on stdout.
//
// A timestamp can spell an existing four-digit date with a legal offset yet
// convert to an instant outside the representable year window:
// 0000-01-01T00:00:00+00:01 lands in the previous year and
// 9999-12-31T23:59:59-00:01 lands in the next one. Such lines must fail as
// timestamp errors (physical line number, ok:false, a reason that names the
// UTC year overflow, no event), never as a success carrying a signed or
// five-digit year. Instants whose conversion lands exactly on 0000 or 9999
// must still succeed, with a four-digit UTC timestamp and the existing
// fractional-second precision and trailing-zero trimming. The same rule
// applies under "timestamp" and its alias "time": with both keys present, an
// overflow on either side fails the whole line as an invalid timestamp
// rather than being ignored or reported as a conflict between two legal
// times, while two legal spellings of one boundary instant still merge;
// object member order never changes any result. Filtering successes with
// --source-cidr must not hide an overflow failure whose source is outside
// the network, while ordinary out-of-network successes stay filtered.

import (
	"strings"
	"testing"
)

// yearLine wraps one timestamp value (under either timestamp key) in a log
// object with an action.
func yearLine(key, ts, action string) string {
	return `{"` + key + `":"` + ts + `","action":"` + action + `"}`
}

// overflowReason is the exact per-line reason for a converted UTC year
// outside the window, parameterized by the year the conversion reaches.
func overflowReason(year string) string {
	return `field "timestamp": invalid RFC3339 timestamp: UTC year ` + year +
		` out of range (0000-9999) after timezone conversion`
}

// The two overflow directions, under both the canonical "timestamp" and the
// alias "time": each run is exit 1 with empty stderr, one ok:false record on
// line 1 carrying the physical line number, an error attributed to
// timestamp that explains the UTC year overflow, and no event — in
// particular no success timestamp with a signed (-0001) or five-digit
// (10000) year.
func TestNormalizeCLIUTCYearOverflowFails(t *testing.T) {
	cases := []struct {
		name     string
		ts       string
		utcYear  string
		negative bool
	}{
		{"positive offset at year 0000 lands in year -1", "0000-01-01T00:00:00+00:01", "-1", true},
		{"negative offset at year 9999 lands in year 10000", "9999-12-31T23:59:59-00:01", "10000", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range []string{"timestamp", "time"} {
				input := yearLine(key, tc.ts, "edge") + "\n"
				result := runNormalizeCLI(t, strings.NewReader(input))

				if result.exitCode != 1 {
					t.Fatalf("%s via %q must exit 1, got %d (stderr: %q)", tc.ts, key, result.exitCode, result.stderr)
				}
				if result.stderr != "" {
					t.Fatalf("per-line failures belong in stdout records, not stderr: %q", result.stderr)
				}

				records := decodeStdoutResults(t, result.stdout)
				if len(records) != 1 {
					t.Fatalf("expected exactly one failure record, got %#v", records)
				}
				bad := records[0]
				if bad["line"] != float64(1) || bad["ok"] != false {
					t.Fatalf("overflow must be reported on physical line 1 with ok:false: %#v", bad)
				}
				if _, exists := bad["event"]; exists {
					t.Fatalf("an out-of-range UTC year must not emit an event: %#v", bad)
				}
				if got := bad["error"]; got != overflowReason(tc.utcYear) {
					t.Fatalf("overflow reason mismatch:\n got %v\nwant %q", got, overflowReason(tc.utcYear))
				}
				// The negative/five-digit year may appear only inside the
				// explanatory reason, never as a success value; the record
				// carries no event at all.
				if tc.negative && strings.Contains(result.stdout, "-0001-") {
					t.Fatalf("stdout must not render a signed four-digit year: %q", result.stdout)
				}
				if strings.Contains(result.stdout, `"timestamp":"10000-`) {
					t.Fatalf("stdout must not render a five-digit success year: %q", result.stdout)
				}
			}
		})
	}
}

// Instants adjacent to the overflow cases — including ones whose conversion
// lands exactly on a window endpoint — must succeed, via either timestamp
// key: the four-digit UTC year is kept, the zone marker is Z, and fractional
// seconds keep their real precision with trailing zeros trimmed (and a
// .0 fraction disappears entirely).
func TestNormalizeCLIUTCYearEndpointsAccepted(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"year 0000 written in UTC", "0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"},
		{"year 9999 written in UTC", "9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z"},
		{"conversion lands exactly on 0000-01-01T00:00:00Z", "0000-01-01T00:01:00+00:01", "0000-01-01T00:00:00Z"},
		{"conversion lands exactly on 9999-12-31T23:59:59Z", "9999-12-31T23:58:59-00:01", "9999-12-31T23:59:59Z"},
		{"zero fraction at the low endpoint is dropped", "0000-01-01T00:00:00.0Z", "0000-01-01T00:00:00Z"},
		{"trailing fraction zeros trimmed at the high endpoint", "9999-12-31T23:59:59.500Z", "9999-12-31T23:59:59.5Z"},
		{"real fraction precision kept when reaching year 0000", "0000-01-01T00:01:00.10+00:01", "0000-01-01T00:00:00.1Z"},
		{"nine-digit fraction kept when reaching year 9999", "9999-12-31T23:58:59.123456789-00:01", "9999-12-31T23:59:59.123456789Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range []string{"timestamp", "time"} {
				result := runNormalizeCLI(t, strings.NewReader(yearLine(key, tc.in, "edge")+"\n"))
				if result.exitCode != 0 {
					t.Fatalf("%q via %q is an in-window instant, got exit %d (stderr: %q)",
						tc.in, key, result.exitCode, result.stderr)
				}
				if result.stderr != "" {
					t.Fatalf("a clean endpoint run needs no diagnostics, got %q", result.stderr)
				}
				records := decodeStdoutResults(t, result.stdout)
				if len(records) != 1 || records[0]["ok"] != true {
					t.Fatalf("expected one ok record for %q, got %#v", tc.in, records)
				}
				event := eventOf(t, records[0])
				if got := event["timestamp"]; got != tc.want {
					t.Fatalf("%q via %q -> %v, want %q", tc.in, key, got, tc.want)
				}
				got, _ := event["timestamp"].(string)
				if len(got) < 5 || got[4] != '-' || !strings.HasSuffix(got, "Z") {
					t.Fatalf("endpoint output must be a four-digit-year UTC time, got %q", got)
				}
			}
		})
	}
}

// With both timestamp keys present, an out-of-window value on either side
// fails the whole line as an invalid timestamp even when the other side is a
// legal boundary instant: it must not be ignored, and it must not be framed
// as a conflict between two legal values. Two legal spellings of the same
// boundary instant still merge into one timestamp. Object member order
// changes none of these results.
func TestNormalizeCLIDualTimestampKeysYearOverflowFails(t *testing.T) {
	failures := []struct {
		name  string
		input string
		year  string
	}{
		{
			name:  "legal canonical at 0000, alias overflows to -1",
			input: `{"timestamp":"0000-01-01T00:00:00Z","time":"0000-01-01T00:00:00+00:01","action":"a"}`,
			year:  "-1",
		},
		{
			name:  "same values with members written in reverse order",
			input: `{"action":"a","time":"0000-01-01T00:00:00+00:01","timestamp":"0000-01-01T00:00:00Z"}`,
			year:  "-1",
		},
		{
			name:  "canonical overflows to 10000, legal alias at 9999",
			input: `{"timestamp":"9999-12-31T23:59:59-00:01","time":"9999-12-31T23:59:59Z","action":"a"}`,
			year:  "10000",
		},
		{
			name:  "same values with members written in reverse order",
			input: `{"time":"9999-12-31T23:59:59Z","action":"a","timestamp":"9999-12-31T23:59:59-00:01"}`,
			year:  "10000",
		},
	}
	for _, tc := range failures {
		t.Run(tc.name, func(t *testing.T) {
			result := runNormalizeCLI(t, strings.NewReader(tc.input+"\n"))
			if result.exitCode != 1 {
				t.Fatalf("one overflowing side must fail the line: exit %d (stderr: %q)", result.exitCode, result.stderr)
			}
			if result.stderr != "" {
				t.Fatalf("per-line failures belong in stdout, got stderr %q", result.stderr)
			}
			records := decodeStdoutResults(t, result.stdout)
			if len(records) != 1 {
				t.Fatalf("expected one failure record, got %#v", records)
			}
			bad := records[0]
			if bad["line"] != float64(1) || bad["ok"] != false {
				t.Fatalf("overflow must be line 1 ok:false regardless of member order: %#v", bad)
			}
			if _, exists := bad["event"]; exists {
				t.Fatalf("an overflowing value must not leave a partial event: %#v", bad)
			}
			msg, _ := bad["error"].(string)
			if msg != overflowReason(tc.year) {
				t.Fatalf("error mismatch:\n got %q\nwant %q", msg, overflowReason(tc.year))
			}
			if strings.Contains(msg, "conflicting values") {
				t.Fatalf("an overflow is an invalid value, not a legal-value conflict: %q", msg)
			}
		})
	}

	// Member order must produce byte-identical results for each value
	// assignment: key sorting happens before validation.
	pairs := [][2]string{
		{
			`{"timestamp":"0000-01-01T00:00:00Z","time":"0000-01-01T00:00:00+00:01","action":"a"}`,
			`{"time":"0000-01-01T00:00:00+00:01","timestamp":"0000-01-01T00:00:00Z","action":"a"}`,
		},
		{
			`{"timestamp":"9999-12-31T23:59:59-00:01","time":"9999-12-31T23:59:59Z","action":"a"}`,
			`{"time":"9999-12-31T23:59:59Z","timestamp":"9999-12-31T23:59:59-00:01","action":"a"}`,
		},
	}
	for i, pair := range pairs {
		first := runNormalizeCLI(t, strings.NewReader(pair[0]+"\n"))
		second := runNormalizeCLI(t, strings.NewReader(pair[1]+"\n"))
		if first.stdout != second.stdout || first.exitCode != second.exitCode || first.stderr != second.stderr {
			t.Fatalf("pair %d: member order changed the result:\n%s\nvs\n%s", i, first.stdout, second.stdout)
		}
	}

	// Both sides legal and denoting the same boundary instant merge into one
	// timestamp — at either endpoint and regardless of member order.
	merges := []struct {
		input string
		want  string
	}{
		{`{"timestamp":"0000-01-01T00:00:00Z","time":"0000-01-01T00:01:00+00:01","action":"a"}`, "0000-01-01T00:00:00Z"},
		{`{"time":"0000-01-01T00:01:00+00:01","timestamp":"0000-01-01T00:00:00Z","action":"a"}`, "0000-01-01T00:00:00Z"},
		{`{"timestamp":"9999-12-31T23:59:59Z","time":"9999-12-31T23:58:59-00:01","action":"a"}`, "9999-12-31T23:59:59Z"},
		{`{"time":"9999-12-31T23:58:59-00:01","timestamp":"9999-12-31T23:59:59Z","action":"a"}`, "9999-12-31T23:59:59Z"},
	}
	for i, tc := range merges {
		result := runNormalizeCLI(t, strings.NewReader(tc.input+"\n"))
		if result.exitCode != 0 {
			t.Fatalf("merge case %d must succeed, got exit %d: %q", i, result.exitCode, result.stdout)
		}
		records := decodeStdoutResults(t, result.stdout)
		if len(records) != 1 || records[0]["ok"] != true {
			t.Fatalf("merge case %d expected one ok record, got %#v", i, records)
		}
		if got := eventOf(t, records[0])["timestamp"]; got != tc.want {
			t.Fatalf("merge case %d -> %v, want %q", i, got, tc.want)
		}
	}
}

// Overflow failures interleaved with legal logs: later legal records keep
// coming in input order with their original physical line numbers, blank
// lines consume line numbers but produce nothing, the run ends normally with
// exit 1 and empty stderr, and the failure records carry no event.
func TestNormalizeCLIUTCYearOverflowMixedStream(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"first"}`,        // line 1: legal
		`{"time":"0000-01-01T00:00:00+00:01","action":"underflow"}`,   // line 2: -> year -1 (alias key)
		``, // line 3: blank
		`{"timestamp":"9999-12-31T23:59:59-00:01","action":"overflow"}`, // line 4: -> year 10000
		`{"timestamp":"0000-01-01T00:01:00+00:01","action":"edge-low"}`,  // line 5: legal, lands exactly on 0000
		`   `, // line 6: blank
		`{"timestamp":"9999-12-31T23:58:59-00:01","action":"edge-high"}`, // line 7: legal, lands exactly on 9999, no trailing newline
	}, "\n")

	result := runNormalizeCLI(t, strings.NewReader(input))

	if result.exitCode != 1 {
		t.Fatalf("normal EOF with two overflow lines must exit 1, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line reasons belong in stdout records, not stderr: %q", result.stderr)
	}

	records := decodeStdoutResults(t, result.stdout)
	if len(records) != 5 {
		t.Fatalf("blank lines produce nothing; expected 5 records for lines 1,2,4,5,7, got %#v", records)
	}

	want := []struct {
		line float64
		ok   bool
		// For successes: exact canonical timestamp. For failures: exact reason.
		timestamp string
		error     string
	}{
		{1, true, "2026-01-02T00:00:00Z", ""},
		{2, false, "", overflowReason("-1")},
		{4, false, "", overflowReason("10000")},
		{5, true, "0000-01-01T00:00:00Z", ""},
		{7, true, "9999-12-31T23:59:59Z", ""},
	}
	for i, w := range want {
		got := records[i]
		if got["line"] != w.line {
			t.Fatalf("record %d must keep physical line %v, got %v: %#v", i, w.line, got["line"], got)
		}
		if got["ok"] != w.ok {
			t.Fatalf("line %v ok = %v, want %v: %#v", w.line, got["ok"], w.ok, got)
		}
		if w.ok {
			event := eventOf(t, got)
			if event["timestamp"] != w.timestamp {
				t.Fatalf("line %v timestamp %v, want %q", w.line, event["timestamp"], w.timestamp)
			}
		} else {
			if _, exists := got["event"]; exists {
				t.Fatalf("line %v failure must carry no event: %#v", w.line, got)
			}
			if got["error"] != w.error {
				t.Fatalf("line %v error %v, want %q", w.line, got["error"], w.error)
			}
		}
	}
}

// A stream containing only legal boundary timestamps — direct and reached by
// conversion, including trimmed fractions — exits 0 with empty stderr.
func TestNormalizeCLIUTCYearOnlyLegalEdgesExitsZero(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":"0000-01-01T00:00:00Z","action":"low"}`,
		`{"timestamp":"9999-12-31T23:59:59Z","action":"high"}`,
		`{"time":"0000-01-01T00:01:00+00:01","action":"low-via-offset"}`,
		`{"timestamp":"9999-12-31T23:58:59.123000000-00:01","action":"high-frac"}`,
	}, "\n") + "\n"

	result := runNormalizeCLI(t, strings.NewReader(input))
	if result.exitCode != 0 {
		t.Fatalf("all in-window boundary instants must exit 0, got %d (stdout: %q, stderr: %q)",
			result.exitCode, result.stdout, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("a clean boundary batch needs no diagnostics, got %q", result.stderr)
	}
	records := decodeStdoutResults(t, result.stdout)
	if len(records) != 4 {
		t.Fatalf("expected 4 ok records, got %#v", records)
	}
	want := []string{
		"0000-01-01T00:00:00Z",
		"9999-12-31T23:59:59Z",
		"0000-01-01T00:00:00Z",
		"9999-12-31T23:59:59.123Z",
	}
	for i, r := range records {
		if r["ok"] != true {
			t.Fatalf("record %d must be ok: %#v", i, r)
		}
		if got := eventOf(t, r)["timestamp"]; got != want[i] {
			t.Fatalf("record %d timestamp %v, want %q", i, got, want[i])
		}
	}
}

// --source-cidr filters only successes: an overflow failure whose source is
// outside the network must stay a failure record with its physical line
// number, UTC-year reason, and no event, and still force exit 1 — as must an
// overflow line carrying no source at all. Out-of-network legal successes
// stay filtered, while in-network boundary successes come through normally.
func TestNormalizeCLIUTCYearOverflowSurvivesCIDRFilter(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":"0000-01-01T00:00:00Z","action":"in-low","source_ip":"192.0.2.7"}`,        // line 1: kept
		`{"timestamp":"0000-01-01T00:00:00+00:01","action":"underflow-outside","source_ip":"198.51.100.9"}`, // line 2: fail, source outside
		`{"timestamp":"9999-12-31T23:59:59Z","action":"outside-ok","source_ip":"198.51.100.10"}`,  // line 3: legal, filtered out
		``, // line 4: blank
		`{"time":"9999-12-31T23:58:59-00:01","action":"in-high","source_ip":"192.0.2.8"}`,         // line 5: kept (alias key)
		`{"timestamp":"9999-12-31T23:59:59-00:01","action":"overflow-no-source"}`,                 // line 6: fail, no source
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.2.0/24")

	if result.exitCode != 1 {
		t.Fatalf("overflow failures must force exit 1 through the filter, got %d (stderr: %q)",
			result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("filtering needs no diagnostics, got %q", result.stderr)
	}

	records := decodeStdoutResults(t, result.stdout)
	if len(records) != 4 {
		t.Fatalf("expected 2 kept successes + 2 overflow failures, got %#v", records)
	}

	if records[0]["line"] != float64(1) || records[0]["ok"] != true {
		t.Fatalf("in-network low-edge success must be kept on line 1: %#v", records[0])
	}
	first := eventOf(t, records[0])
	if first["timestamp"] != "0000-01-01T00:00:00Z" || first["source_ip"] != "192.0.2.7" {
		t.Fatalf("kept low-edge event mismatch: %#v", first)
	}

	outsideFailure := records[1]
	if outsideFailure["line"] != float64(2) || outsideFailure["ok"] != false {
		t.Fatalf("out-of-network overflow must still be reported on line 2: %#v", outsideFailure)
	}
	if _, exists := outsideFailure["event"]; exists {
		t.Fatalf("overflow failure must not carry an event despite its out-of-network source: %#v", outsideFailure)
	}
	if outsideFailure["error"] != overflowReason("-1") {
		t.Fatalf("out-of-network overflow must keep its UTC-year reason, got %v", outsideFailure["error"])
	}

	// Line 3 (out-of-network legal) and line 4 (blank) must leave no gap:
	// the next record is line 5.
	if records[2]["line"] != float64(5) || records[2]["ok"] != true {
		t.Fatalf("in-network high-edge success must be kept on physical line 5: %#v", records[2])
	}
	fifth := eventOf(t, records[2])
	if fifth["timestamp"] != "9999-12-31T23:59:59Z" || fifth["source_ip"] != "192.0.2.8" {
		t.Fatalf("kept high-edge event mismatch: %#v", fifth)
	}

	noSourceFailure := records[3]
	if noSourceFailure["line"] != float64(6) || noSourceFailure["ok"] != false {
		t.Fatalf("overflow without a source must still be reported on line 6: %#v", noSourceFailure)
	}
	if _, exists := noSourceFailure["event"]; exists {
		t.Fatalf("overflow without a source must carry no event: %#v", noSourceFailure)
	}
	if noSourceFailure["error"] != overflowReason("10000") {
		t.Fatalf("no-source overflow must keep its UTC-year reason, got %v", noSourceFailure["error"])
	}
}
