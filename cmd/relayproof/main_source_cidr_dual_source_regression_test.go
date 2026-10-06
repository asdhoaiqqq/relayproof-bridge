package main

// End-to-end regression coverage for the normalize --source-cidr filter when
// one log line supplies BOTH source_ip and src_ip at once. These tests drive
// the real compiled binary, so they pin exactly what the shell observes:
// records on stdout, diagnostics on stderr, and the exit status.
//
// The filter must not let one source value mask a problem in the other:
//
//   - 192.0.2.7 and ::ffff:192.0.2.7 are both legal and equivalent, merge to
//     one source printed 192.0.2.7, and that single event is admitted; the
//     equivalent spellings of an outside address merge too and are dropped
//     with no record and no failure (a clean, empty run).
//   - ::192.0.2.7 stays the IPv6 address ::c000:207: beside 192.0.2.7 it is a
//     source_ip conflict, not a mapped merge that slips through the filter.
//   - two legal but distinct addresses fail whether one is in the network
//     and the other out or both are out: one ok:false record, no event, a
//     source_ip conflict reason; swapping which field is written first or
//     which name carries the in/out value, or merely permuting members,
//     never changes the failure or its reason.
//   - one legal value beside an illegal address or an explicit null is that
//     address/type error under the name source_ip, never a merge, never a
//     silent drop, and never a conflict between two legal values.
//
// Failures keep physical line numbers among blank lines, dropped legal
// lines and in-network hits, end with exit 1 and empty stderr, and their
// reasons are byte-identical to an unfiltered run's.

import (
	"strings"
	"testing"
)

const cliDualFilter = "192.0.2.0/24"

// cliDualLine builds one log carrying BOTH source fields with raw JSON
// value literals, in the fixed order timestamp, source_ip, src_ip, action.
func cliDualLine(canonVal, aliasVal string) string {
	return `{"timestamp":"2026-01-02T00:00:00Z","source_ip":` + canonVal +
		`,"src_ip":` + aliasVal + `,"action":"x"}`
}

// cliDualOrdered builds one dual-source log whose members follow the exact
// given (key, raw-value) order, so writing order itself can be varied while
// the field set stays fixed.
func cliDualOrdered(specs ...[2]string) string {
	parts := make([]string, len(specs))
	for i, s := range specs {
		parts[i] = `"` + s[0] + `":` + s[1]
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// runDual runs one newline-terminated dual-source log through normalize with
// the filter arguments and decodes its result records.
func runDual(t *testing.T, line string, args ...string) cliResult {
	t.Helper()
	return runNormalizeCLIArgs(t, strings.NewReader(line+"\n"), args...)
}

// singleFailure runs one line, asserts exit 1 with empty stderr and exactly
// one ok:false, event-less record, and returns its error text.
func singleFailure(t *testing.T, line string, args ...string) string {
	t.Helper()
	result := runDual(t, line, args...)
	if result.exitCode != 1 {
		t.Fatalf("line must exit 1, got %d (stderr %q): %s", result.exitCode, result.stderr, line)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in stdout records, got stderr %q", result.stderr)
	}
	records := decodeStdoutResults(t, result.stdout)
	if len(records) != 1 || records[0]["ok"] != false {
		t.Fatalf("expected exactly one failure record, got %#v: %s", records, line)
	}
	if records[0]["line"] != float64(1) {
		t.Fatalf("failure must keep physical line 1: %#v", records[0])
	}
	if _, exists := records[0]["event"]; exists {
		t.Fatalf("a failed line must carry no event: %#v", records[0])
	}
	msg, _ := records[0]["error"].(string)
	if msg == "" {
		t.Fatalf("failure must explain itself: %#v", records[0])
	}
	return msg
}

// The headline merge: both values legal and equivalent. In either mapped
// spelling and under either source name, they merge into one record whose
// source_ip is the dotted IPv4 192.0.2.7, and the /24 filter admits it with
// exit 0 and empty stderr.
func TestNormalizeCLIDualEquivalentMappedMergeAdmitted(t *testing.T) {
	pairs := [][2]string{
		{`"192.0.2.7"`, `"::ffff:192.0.2.7"`},
		{`"::ffff:192.0.2.7"`, `"192.0.2.7"`},
		{`"192.0.2.7"`, `"::FFFF:C000:0207"`},
		{`"::FFFF:C000:0207"`, `"::ffff:192.0.2.7"`},
	}
	for _, p := range pairs {
		line := cliDualLine(p[0], p[1])
		result := runDual(t, line, "--source-cidr", cliDualFilter)
		if result.exitCode != 0 || result.stderr != "" {
			t.Fatalf("equivalent mapped pair must be a clean admitted success, got exit=%d stderr=%q: %s",
				result.exitCode, result.stderr, line)
		}
		records := decodeStdoutResults(t, result.stdout)
		if len(records) != 1 || records[0]["ok"] != true {
			t.Fatalf("expected one admitted success, got %#v: %s", records, line)
		}
		if got := eventOf(t, records[0])["source_ip"]; got != "192.0.2.7" {
			t.Fatalf("merged source_ip = %v, want 192.0.2.7: %s", got, line)
		}
	}
}

// Two legal equivalent values that both normalize to an address OUTSIDE the
// network still merge, but the merged result is dropped: no stdout, no
// stderr, exit 0.
func TestNormalizeCLIDualEquivalentMappedBothOutsideDropped(t *testing.T) {
	pairs := [][2]string{
		{`"198.51.100.7"`, `"::ffff:198.51.100.7"`},
		{`"::ffff:198.51.100.7"`, `"198.51.100.7"`},
		{`"198.51.100.7"`, `"::FFFF:C633:6407"`},
	}
	for _, p := range pairs {
		result := runDual(t, cliDualLine(p[0], p[1]), "--source-cidr", cliDualFilter)
		if result.exitCode != 0 {
			t.Fatalf("a legal merged-outside line must exit 0, got %d (stderr %q)", result.exitCode, result.stderr)
		}
		if result.stdout != "" || result.stderr != "" {
			t.Fatalf("two equivalent outside values must leave no record and no diagnostic, got %q / %q",
				result.stdout, result.stderr)
		}
	}
}

// ::192.0.2.7 is genuine IPv6 (::c000:207), not a mapped spelling: beside
// 192.0.2.7 it must fail as a source_ip conflict even though the IPv4 side
// is inside the selected network, and regardless of which name carries it.
func TestNormalizeCLIDualCompatibleIPv6ConflictsNotMerged(t *testing.T) {
	assignments := [][2]string{
		{`"::192.0.2.7"`, `"192.0.2.7"`},
		{`"192.0.2.7"`, `"::192.0.2.7"`},
		{`"0:0:0:0:0:0:c000:207"`, `"192.0.2.7"`},
		{`"192.0.2.7"`, `"0:0:0:0:0:0:c000:207"`},
	}
	for _, p := range assignments {
		msg := singleFailure(t, cliDualLine(p[0], p[1]), "--source-cidr", cliDualFilter)
		for _, want := range []string{"source_ip", "conflicting values", "::c000:207", "192.0.2.7"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("conflict must name %q, got %q", want, msg)
			}
		}
		if strings.Contains(msg, "invalid IP address") {
			t.Fatalf("two legal addresses must not be reported invalid: %q", msg)
		}
	}
}

// Two legal but distinct addresses always fail the whole line: one in the
// network and one out, or both out. Swapping the values between source_ip
// and src_ip never changes the conclusion (only the values' order in the
// message), and every member permutation yields the identical error text.
func TestNormalizeCLIDualDistinctAddressesConflictAcrossArrangements(t *testing.T) {
	cases := []struct {
		name string
		a, b string
	}{
		{"one in one out", "192.0.2.7", "198.51.100.7"},
		{"both out", "198.51.100.8", "198.51.100.9"},
	}
	ts := [2]string{"timestamp", `"2026-01-02T00:00:00Z"`}
	act := [2]string{"action", `"x"`}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, p := range [][2]string{{tc.a, tc.b}, {tc.b, tc.a}} {
				canon := [2]string{"source_ip", `"` + p[0] + `"`}
				alias := [2]string{"src_ip", `"` + p[1] + `"`}
				// Three distinct writing orders, including the pair swapped
				// and members moved ahead of the companions.
				orderings := []string{
					cliDualOrdered(ts, canon, alias, act),
					cliDualOrdered(ts, alias, canon, act),
					cliDualOrdered(act, canon, ts, alias),
					cliDualOrdered(alias, act, ts, canon),
				}
				var wantMsg string
				for i, line := range orderings {
					msg := singleFailure(t, line, "--source-cidr", cliDualFilter)
					if i == 0 {
						wantMsg = msg
					} else if msg != wantMsg {
						t.Fatalf("rearranging members changed the reason:\n got: %q\nwant: %q", msg, wantMsg)
					}
					for _, want := range []string{"source_ip", "conflicting values"} {
						if !strings.Contains(msg, want) {
							t.Fatalf("reason must name %q: %q", want, msg)
						}
					}
					if strings.Contains(msg, "invalid IP address") {
						t.Fatalf("two legal addresses must not be reported invalid: %q", msg)
					}
				}
			}
		})
	}
}

// One legal value beside an illegal address or an explicit null reports the
// underlying address/type error under the canonical name source_ip — never a
// merge, never a filter drop, and never a conflict between two legal values —
// regardless of which source name holds the bad value and whether the legal
// one is in or out of the network.
func TestNormalizeCLIDualOneBadValueReportsUnderlyingError(t *testing.T) {
	cases := []struct {
		name     string
		legal    string
		bad      string
		wantSubs []string
	}{
		{"invalid beside in-network legal", "192.0.2.7", `"not-an-ip"`, []string{"invalid IP address", "not-an-ip"}},
		{"invalid beside out-of-network legal", "198.51.100.7", `"not-an-ip"`, []string{"invalid IP address", "not-an-ip"}},
		{"null beside in-network legal", "192.0.2.7", `null`, []string{"value must be a string", "got null"}},
		{"null beside out-of-network legal", "198.51.100.7", `null`, []string{"value must be a string", "got null"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legal := `"` + tc.legal + `"`
			for _, p := range [][2]string{{legal, tc.bad}, {tc.bad, legal}} {
				msg := singleFailure(t, cliDualLine(p[0], p[1]), "--source-cidr", cliDualFilter)
				for _, want := range append([]string{"source_ip"}, tc.wantSubs...) {
					if !strings.Contains(msg, want) {
						t.Fatalf("error %q must contain %q", msg, want)
					}
				}
				if strings.Contains(msg, "conflicting values") {
					t.Fatalf("a single bad value is not a conflict of two legal values: %q", msg)
				}
			}
		})
	}
}

// The full mixed batch: dual-source problems sit between an in-network hit,
// an out-of-network legal line, blank lines, merged-success lines and a
// trailing in-network hit. Failures keep their physical line numbers and
// class-specific reasons with no event; dropped and blank lines never
// renumber; the trailing hit still emits; exit 1 with empty stderr.
func TestNormalizeCLIDualMixedBatchLineNumbersAndExit(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("lead-in", "192.0.2.10"),         // line 1 kept
		cliDualLine(`"192.0.2.7"`, `"::ffff:192.0.2.7"`), // line 2 kept (merged)
		"", // line 3 blank
		cliDualLine(`"192.0.2.7"`, `"198.51.100.7"`),           // line 4 conflict (in/out)
		cliDualLine(`"198.51.100.8"`, `"198.51.100.9"`),        // line 5 conflict (both out)
		cliDualLine(`"::192.0.2.7"`, `"192.0.2.7"`),            // line 6 conflict (v6/v4)
		cliDualLine(`"192.0.2.7"`, `"not-an-ip"`),              // line 7 invalid address
		cliDualLine(`null`, `"192.0.2.7"`),                     // line 8 explicit null
		"",                                                     // line 9 blank
		validCIDRSource("outside-single", "198.51.100.10"),     // line 10 dropped
		cliDualLine(`"198.51.100.7"`, `"::ffff:198.51.100.7"`), // line 11 merged then dropped
		validCIDRSource("tail-in", "192.0.2.11"),               // line 12 kept
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", cliDualFilter)
	if result.exitCode != 1 {
		t.Fatalf("five problem lines must force exit 1, got %d (stderr %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in stdout records, got stderr %q", result.stderr)
	}
	records := decodeStdoutResults(t, result.stdout)
	if len(records) != 8 {
		t.Fatalf("expected 3 kept successes + 5 failures = 8 records, got %#v", records)
	}

	want := []struct {
		line   float64
		ok     bool
		marker string
	}{
		{1, true, "lead-in"},
		{2, true, "x"},
		{4, false, "conflicting values"},
		{5, false, "conflicting values"},
		{6, false, "conflicting values"},
		{7, false, "invalid IP address"},
		{8, false, "got null"},
		{12, true, "tail-in"},
	}
	for i, w := range want {
		got := records[i]
		if got["line"] != w.line || got["ok"] != w.ok {
			t.Fatalf("record %d must be physical line %v ok=%v, got %#v", i, w.line, w.ok, got)
		}
		if !w.ok {
			if _, exists := got["event"]; exists {
				t.Fatalf("line %v failure must carry no event: %#v", w.line, got)
			}
			msg, _ := got["error"].(string)
			if !strings.Contains(msg, "source_ip") || !strings.Contains(msg, w.marker) {
				t.Fatalf("line %v reason must name source_ip and contain %q, got %q", w.line, w.marker, msg)
			}
		}
	}
	if got := eventOf(t, records[1])["source_ip"]; got != "192.0.2.7" {
		t.Fatalf("line 2 merged source must print 192.0.2.7, got %v", got)
	}

	// Parity: the same batch without the flag fails the same five lines with
	// byte-identical reasons (and additionally emits lines 10 and 11).
	unfiltered := runNormalizeCLI(t, strings.NewReader(input))
	if unfiltered.exitCode != 1 || unfiltered.stderr != "" {
		t.Fatalf("unfiltered run must also exit 1 with empty stderr, got %d / %q",
			unfiltered.exitCode, unfiltered.stderr)
	}
	plain := decodeStdoutResults(t, unfiltered.stdout)
	if len(plain) != 10 {
		t.Fatalf("unfiltered run must emit the 8 filtered records plus lines 10 and 11, got %#v", plain)
	}
	byLine := map[float64]map[string]any{}
	for _, r := range plain {
		byLine[r["line"].(float64)] = r
	}
	for i, w := range want {
		if w.ok {
			continue
		}
		u := byLine[w.line]
		if u == nil || u["ok"] != false {
			t.Fatalf("unfiltered run must also fail line %v: %#v", w.line, u)
		}
		if u["error"] != records[i]["error"] {
			t.Fatalf("line %v reason must match the unfiltered run:\nfiltered:   %q\nunfiltered: %q",
				w.line, records[i]["error"], u["error"])
		}
	}
}

// A batch containing only legal-but-outside dual-source lines (equivalent
// values that merge) and blank lines is a clean empty run under the filter:
// no stdout, no stderr, exit 0.
func TestNormalizeCLIDualAllLegalMissesEmptyExitZero(t *testing.T) {
	input := strings.Join([]string{
		cliDualLine(`"198.51.100.7"`, `"::ffff:198.51.100.7"`),
		"",
		cliDualLine(`"::FFFF:C633:6407"`, `"198.51.100.7"`),
		cliDualLine(`"198.51.100.8"`, `"::ffff:198.51.100.8"`),
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", cliDualFilter)
	if result.exitCode != 0 {
		t.Fatalf("an all-legal, fully filtered batch must exit 0, got %d (stderr %q)",
			result.exitCode, result.stderr)
	}
	if result.stdout != "" || result.stderr != "" {
		t.Fatalf("no surviving records means empty stdout/stderr, got %q / %q", result.stdout, result.stderr)
	}
}
