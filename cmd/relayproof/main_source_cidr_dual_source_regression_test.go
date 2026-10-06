package main

// End-to-end regression coverage for the interaction between
// `normalize --source-cidr 192.0.2.0/24` and the existing dual-source rule:
// a log that supplies both source_ip and src_ip must have both values legal
// and equal after normalization before it can merge into one successful event
// that is then admitted. These tests run the real binary so exit status,
// stdout and stderr are pinned exactly as a shell pipeline observes them.
//
// The filter selects only successful events and must never let one source
// value mask the other's problem: a conflict between two legal addresses
// (whether one is in-network and the other out, or both are out), an invalid
// address on one side, or an explicit null on one side is still reported as
// an ok:false record with the original reason and no event — never merged to
// the in-network value and never silently dropped as out-of-network.
// ::192.0.2.7 stays a genuine IPv6 address and conflicts with 192.0.2.7
// rather than mapping into the network. Failure records keep their original
// physical line numbers alongside in-network successes, out-of-network legal
// events and blank lines; the run exits 1 with empty stderr. A batch of only
// legal-but-unhit sources exits 0 with empty stdout. With the filter off,
// every failure reason is identical.

import (
	"strings"
	"testing"
)

// dualSourceCIDROpt is the option every test below uses.
var dualSourceCIDROpt = []string{"--source-cidr", "192.0.2.0/24"}

// dualSourceLine builds one log carrying both source names with the given
// raw JSON value literals, the other mapped fields legal.
func dualSourceLine(canonical, alias string) string {
	return `{"timestamp":"2026-01-02T00:00:00Z","source_ip":` + canonical +
		`,"src_ip":` + alias + `,"action":"ok"}`
}

// requireSourceConflict asserts the single result is an ok:false source_ip
// conflict with no event and not an invalid-address/type error.
func requireSourceConflict(t *testing.T, r map[string]any) {
	t.Helper()
	if r["ok"] != false {
		t.Fatalf("two legal distinct sources must fail: %#v", r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("conflict must carry no event: %#v", r)
	}
	msg, _ := r["error"].(string)
	if !strings.Contains(msg, `"source_ip"`) || !strings.Contains(msg, "conflicting values") {
		t.Fatalf("must report a source_ip conflict, got %q", msg)
	}
	if strings.Contains(msg, "invalid IP address") || strings.Contains(msg, "got null") {
		t.Fatalf("two legal addresses must not read as invalid/null: %q", msg)
	}
}

// TestNormalizeCLIDualSourceEquivalentMergeAdmits pins the headline merge:
// 192.0.2.7 and ::ffff:192.0.2.7 merge into one admitted success printed in
// dotted form (in either canonical/alias binding), while two equivalents
// both outside the network leave no record and no failure.
func TestNormalizeCLIDualSourceEquivalentMergeAdmits(t *testing.T) {
	for _, line := range []string{
		dualSourceLine(`"192.0.2.7"`, `"::ffff:192.0.2.7"`),
		dualSourceLine(`"::ffff:192.0.2.7"`, `"192.0.2.7"`),
	} {
		result := runNormalizeCLIArgs(t, strings.NewReader(line+"\n"), dualSourceCIDROpt...)
		if result.exitCode != 0 || result.stderr != "" {
			t.Fatalf("equivalent in-network pair must exit 0 cleanly, got %d stderr=%q", result.exitCode, result.stderr)
		}
		results := decodeStdoutResults(t, result.stdout)
		if len(results) != 1 || results[0]["ok"] != true {
			t.Fatalf("equivalent pair must merge into one success: %#v", results)
		}
		if got := eventOf(t, results[0])["source_ip"]; got != "192.0.2.7" {
			t.Fatalf("merged source_ip = %v, want 192.0.2.7", got)
		}
	}

	// Both equivalents outside: still a valid merge, but the filter drops it.
	outside := dualSourceLine(`"198.51.100.7"`, `"::ffff:198.51.100.7"`) + "\n"
	dropped := runNormalizeCLIArgs(t, strings.NewReader(outside), dualSourceCIDROpt...)
	if dropped.exitCode != 0 {
		t.Fatalf("legal-but-outside pair must exit 0, got %d (stderr %q)", dropped.exitCode, dropped.stderr)
	}
	if dropped.stdout != "" || dropped.stderr != "" {
		t.Fatalf("both equivalents out of network must leave no record, got %q / %q",
			dropped.stdout, dropped.stderr)
	}
	// Without a filter that same line is one successful dotted-form event,
	// proving the empty filtered output was a drop rather than a conflict.
	unfiltered := runNormalizeCLI(t, strings.NewReader(outside))
	if unfiltered.exitCode != 0 || unfiltered.stderr != "" {
		t.Fatalf("unfiltered equivalent pair must succeed cleanly, got %d stderr=%q",
			unfiltered.exitCode, unfiltered.stderr)
	}
	ur := decodeStdoutResults(t, unfiltered.stdout)
	if len(ur) != 1 || ur[0]["ok"] != true || eventOf(t, ur[0])["source_ip"] != "198.51.100.7" {
		t.Fatalf("unfiltered out-of-network equivalents must merge to 198.51.100.7: %#v", ur)
	}
}

// TestNormalizeCLIDualSourceCompatibleIPv6Conflicts pins that
// ::192.0.2.7 paired with 192.0.2.7 is a source conflict in either binding
// and either member order: it never merges into the filter hit, never drops
// silently, and names the normalized IPv6 ::c000:207.
func TestNormalizeCLIDualSourceCompatibleIPv6Conflicts(t *testing.T) {
	lines := map[string]string{
		"compat canonical":            dualSourceLine(`"::192.0.2.7"`, `"192.0.2.7"`),
		"compat alias":                dualSourceLine(`"192.0.2.7"`, `"::192.0.2.7"`),
		"compat canonical order flip": `{"timestamp":"2026-01-02T00:00:00Z","action":"ok","src_ip":"192.0.2.7","source_ip":"::192.0.2.7"}`,
		"compat alias order flip":     `{"timestamp":"2026-01-02T00:00:00Z","action":"ok","src_ip":"::192.0.2.7","source_ip":"192.0.2.7"}`,
	}
	for name, line := range lines {
		t.Run(name, func(t *testing.T) {
			result := runNormalizeCLIArgs(t, strings.NewReader(line+"\n"), dualSourceCIDROpt...)
			if result.exitCode != 1 {
				t.Fatalf("conflict must exit 1, got %d (stderr %q)", result.exitCode, result.stderr)
			}
			if result.stderr != "" {
				t.Fatalf("per-line conflict must not hit stderr, got %q", result.stderr)
			}
			results := decodeStdoutResults(t, result.stdout)
			if len(results) != 1 || results[0]["line"] != float64(1) {
				t.Fatalf("one conflict record on line 1, got %#v", results)
			}
			requireSourceConflict(t, results[0])
			if msg, _ := results[0]["error"].(string); !strings.Contains(msg, "::c000:207") {
				t.Fatalf("conflict must name normalized IPv6 ::c000:207, got %q", msg)
			}
		})
	}
}

// TestNormalizeCLIDualSourceDistinctLegalAlwaysConflict requires two legal
// but different addresses to fail in all placements: one in/one out (either
// address under either name, members in either order) and two distinct
// out-of-network addresses. Member-order-only swaps keep the exact same
// record; every filtered failure record is byte-identical without the filter.
func TestNormalizeCLIDualSourceDistinctLegalAlwaysConflict(t *testing.T) {
	good := "192.0.2.7"
	out1 := "198.51.100.7"
	out2 := "198.51.100.20"
	lines := []string{
		// one in, one out — all canonical/alias bindings
		dualSourceLine(`"`+good+`"`, `"`+out1+`"`),
		dualSourceLine(`"`+out1+`"`, `"`+good+`"`),
		// same bindings, members written in reverse order
		`{"timestamp":"2026-01-02T00:00:00Z","src_ip":"` + out1 + `","source_ip":"` + good + `","action":"ok"}`,
		// two distinct, both outside — both bindings
		dualSourceLine(`"`+out1+`"`, `"`+out2+`"`),
		dualSourceLine(`"`+out2+`"`, `"`+out1+`"`),
	}
	var memberOrderPair string // stdout of the canonical-order in/out line
	for i, line := range lines {
		result := runNormalizeCLIArgs(t, strings.NewReader(line+"\n"), dualSourceCIDROpt...)
		if result.exitCode != 1 || result.stderr != "" {
			t.Fatalf("case %d: distinct legal sources must exit 1 with empty stderr, got %d stderr=%q",
				i, result.exitCode, result.stderr)
		}
		results := decodeStdoutResults(t, result.stdout)
		if len(results) != 1 {
			t.Fatalf("case %d: exactly one failure record, got %#v", i, results)
		}
		requireSourceConflict(t, results[0])

		// With the filter off, the exact same record (same line, reason,
		// absence of event) must come out.
		unfiltered := runNormalizeCLI(t, strings.NewReader(line+"\n"))
		if unfiltered.exitCode != 1 {
			t.Fatalf("case %d: unfiltered conflict must also exit 1, got %d", i, unfiltered.exitCode)
		}
		if unfiltered.stdout != result.stdout {
			t.Fatalf("case %d: filter must not change the conflict record:\nfiltered:   %q\nunfiltered: %q",
				i, result.stdout, unfiltered.stdout)
		}

		// The member-order-only reversal (line index 0 vs 2) must keep the
		// complete record byte-identical.
		if i == 0 {
			memberOrderPair = result.stdout
		}
		if i == 2 && result.stdout != memberOrderPair {
			t.Fatalf("reversing member order changed the conflict record:\n%s\nvs\n%s",
				memberOrderPair, result.stdout)
		}
	}
}

// TestNormalizeCLIDualSourceOneInvalidOrNull pins that a single bad source —
// invalid address or explicit null, on either side and regardless of the
// other value's network — fails with the matching invalid-address/type error
// under field name source_ip: never merged, never filtered away, and never
// misreported as a conflict between two legal values.
func TestNormalizeCLIDualSourceOneInvalidOrNull(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantSub   string
		forbidden string
	}{
		{
			name:      "legal in-net canonical, invalid alias",
			line:      dualSourceLine(`"192.0.2.7"`, `"not-an-ip"`),
			wantSub:   `invalid IP address "not-an-ip" (no port allowed)`,
			forbidden: "conflicting values",
		},
		{
			name:      "invalid canonical, legal in-net alias",
			line:      dualSourceLine(`"999.1.1.1"`, `"::ffff:192.0.2.7"`),
			wantSub:   `invalid IP address "999.1.1.1" (no port allowed)`,
			forbidden: "conflicting values",
		},
		{
			name:      "legal out-net canonical, invalid alias",
			line:      dualSourceLine(`"198.51.100.7"`, `"not-an-ip"`),
			wantSub:   `invalid IP address "not-an-ip" (no port allowed)`,
			forbidden: "conflicting values",
		},
		{
			name:      "invalid canonical, legal out-net alias",
			line:      dualSourceLine(`"not-an-ip"`, `"198.51.100.7"`),
			wantSub:   `invalid IP address "not-an-ip" (no port allowed)`,
			forbidden: "conflicting values",
		},
		{
			name:      "legal in-net canonical, null alias, members reversed",
			line:      `{"timestamp":"2026-01-02T00:00:00Z","src_ip":null,"source_ip":"192.0.2.7","action":"ok"}`,
			wantSub:   `"source_ip": value must be a string, got null`,
			forbidden: "conflicting values",
		},
		{
			name:      "null canonical, legal in-net alias",
			line:      dualSourceLine(`null`, `"::ffff:192.0.2.7"`),
			wantSub:   `"source_ip": value must be a string, got null`,
			forbidden: "conflicting values",
		},
		{
			name:      "legal out-net canonical, null alias",
			line:      dualSourceLine(`"198.51.100.7"`, `null`),
			wantSub:   `"source_ip": value must be a string, got null`,
			forbidden: "conflicting values",
		},
		{
			name:      "null canonical, legal out-net alias",
			line:      dualSourceLine(`null`, `"198.51.100.7"`),
			wantSub:   `"source_ip": value must be a string, got null`,
			forbidden: "conflicting values",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := runNormalizeCLIArgs(t, strings.NewReader(tc.line+"\n"), dualSourceCIDROpt...)
			if result.exitCode != 1 || result.stderr != "" {
				t.Fatalf("bad-source line must exit 1 with empty stderr, got %d stderr=%q",
					result.exitCode, result.stderr)
			}
			results := decodeStdoutResults(t, result.stdout)
			if len(results) != 1 || results[0]["ok"] != false {
				t.Fatalf("exactly one ok:false record, got %#v", results)
			}
			if _, exists := results[0]["event"]; exists {
				t.Fatalf("bad-source line must carry no event: %#v", results[0])
			}
			msg, _ := results[0]["error"].(string)
			if !strings.Contains(msg, tc.wantSub) {
				t.Fatalf("reason must contain %q, got %q", tc.wantSub, msg)
			}
			if strings.Contains(msg, tc.forbidden) {
				t.Fatalf("one bad value must not be reported as %q: %q", tc.forbidden, msg)
			}

			// The same bad-source line, filter off: identical record and the
			// field is still named source_ip.
			unfiltered := runNormalizeCLI(t, strings.NewReader(tc.line+"\n"))
			if unfiltered.exitCode != 1 {
				t.Fatalf("unfiltered bad-source line must exit 1, got %d", unfiltered.exitCode)
			}
			if unfiltered.stdout != result.stdout {
				t.Fatalf("filter must not change the bad-source record:\nfiltered:   %q\nunfiltered: %q",
					result.stdout, unfiltered.stdout)
			}
		})
	}
}

// TestNormalizeCLIDualSourceBatchLineNumbersAndExitStatus places every source
// problem in one batch alongside an in-network success, an out-of-network
// legal event and a blank line. Failures must keep their original physical
// line numbers and reasons with no event, dropped/blank lines must not
// renumber, later successes emit normally, the run ends normally with
// failures (exit 1, stderr empty), and the filtered failure records are
// byte-identical to an unfiltered run's.
func TestNormalizeCLIDualSourceBatchLineNumbersAndExitStatus(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"hit-before","source_ip":"192.0.2.5"}`, // 1 kept
		dualSourceLine(`"192.0.2.7"`, `"198.51.100.7"`),                                      // 2 conflict (in/out)
		dualSourceLine(`"198.51.100.1"`, `"::ffff:198.51.100.1"`),                            // 3 merged success, dropped
		"", // 4 blank
		dualSourceLine(`"::192.0.2.7"`, `"192.0.2.7"`),                                      // 5 conflict (IPv6)
		dualSourceLine(`"192.0.2.7"`, `"not-an-ip"`),                                        // 6 invalid address
		dualSourceLine(`null`, `"192.0.2.7"`),                                               // 7 null type
		dualSourceLine(`"198.51.100.2"`, `"198.51.100.3"`),                                  // 8 conflict (both out)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"hit-after","source_ip":"192.0.2.9"}`, // 9 kept
		`{"timestamp":"2026-01-02T00:00:00Z","action":"outside","source_ip":"10.0.0.1"}`,    // 10 legal, dropped
	}, "\n") + "\n"

	filtered := runNormalizeCLIArgs(t, strings.NewReader(input), dualSourceCIDROpt...)
	if filtered.exitCode != 1 {
		t.Fatalf("a normal end with four bad lines must exit 1, got %d (stderr %q)",
			filtered.exitCode, filtered.stderr)
	}
	if filtered.stderr != "" {
		t.Fatalf("per-line failures belong in stdout records, stderr must be empty, got %q", filtered.stderr)
	}

	fRecords := decodeStdoutResults(t, filtered.stdout)
	// Kept lines 1 and 9; failure lines 2, 5, 6, 7, 8 -> 2 + 5 = 7 records.
	if len(fRecords) != 7 {
		t.Fatalf("expected 2 kept successes + 5 failures = 7 records, got %d: %#v", len(fRecords), fRecords)
	}
	wantLines := []float64{1, 2, 5, 6, 7, 8, 9}
	for i, ln := range wantLines {
		if fRecords[i]["line"] != ln {
			t.Fatalf("record %d must carry physical line %v, got %v", i, ln, fRecords[i]["line"])
		}
	}
	if fRecords[0]["ok"] != true || eventOf(t, fRecords[0])["action"] != "hit-before" {
		t.Fatalf("record 0 must be the line-1 in-network hit: %#v", fRecords[0])
	}
	if fRecords[6]["ok"] != true || eventOf(t, fRecords[6])["action"] != "hit-after" {
		t.Fatalf("record 6 must be the line-9 hit emitted normally after the failures: %#v", fRecords[6])
	}
	requireSourceConflict(t, fRecords[1]) // line 2 in/out
	requireSourceConflict(t, fRecords[2]) // line 5 IPv6
	// line 6 invalid address, line 7 null
	if msg, _ := fRecords[3]["error"].(string); !strings.Contains(msg, `invalid IP address "not-an-ip"`) {
		t.Fatalf("line 6 must keep its invalid-address reason, got %q", fRecords[3]["error"])
	}
	if fRecords[3]["ok"] != false {
		t.Fatalf("line 6 must be ok:false: %#v", fRecords[3])
	}
	if _, exists := fRecords[3]["event"]; exists {
		t.Fatalf("line 6 must carry no event")
	}
	if msg, _ := fRecords[4]["error"].(string); !strings.Contains(msg, "value must be a string, got null") {
		t.Fatalf("line 7 must keep its null type reason, got %q", fRecords[4]["error"])
	}
	if fRecords[4]["ok"] != false {
		t.Fatalf("line 7 must be ok:false: %#v", fRecords[4])
	}
	if _, exists := fRecords[4]["event"]; exists {
		t.Fatalf("line 7 must carry no event")
	}
	requireSourceConflict(t, fRecords[5]) // line 8 both out

	// Unfiltered: the failure records (lines 2,5,6,7,8) must be byte-identical
	// to the filtered run's — same physical numbers and reasons.
	unfiltered := runNormalizeCLI(t, strings.NewReader(input))
	if unfiltered.exitCode != 1 {
		t.Fatalf("unfiltered batch with the same bad lines must exit 1, got %d", unfiltered.exitCode)
	}
	uRecords := decodeStdoutResults(t, unfiltered.stdout)
	byLine := func(rs []map[string]any) map[float64]map[string]any {
		m := make(map[float64]map[string]any)
		for _, r := range rs {
			m[r["line"].(float64)] = r
		}
		return m
	}
	uByLine := byLine(uRecords)
	for _, ln := range []float64{2, 5, 6, 7, 8} {
		fr, ok1 := byLine(fRecords)[ln]
		ur, ok2 := uByLine[ln]
		if !ok1 || !ok2 {
			t.Fatalf("line %v failure missing (filtered=%v unfiltered=%v)", ln, ok1, ok2)
		}
		if !recordsEqual(fr, ur) {
			t.Fatalf("line %v failure differs with/without filter:\n%#v\n%#v", ln, fr, ur)
		}
	}
}

// recordsEqual compares two decoded result records semantically.
func recordsEqual(a, b map[string]any) bool {
	if a["line"] != b["line"] || a["ok"] != b["ok"] {
		return false
	}
	ae, aeOK := a["event"]
	be, beOK := b["event"]
	if aeOK != beOK {
		return false
	}
	if aeOK && !mapsEqual(ae.(map[string]any), be.(map[string]any)) {
		return false
	}
	return a["error"] == b["error"]
}

func mapsEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestNormalizeCLIDualSourceAllLegalUnhitExitsZero pins the all-miss case:
// when every log is legal (equivalent pairs outside the network, genuine
// equal IPv6 pairs, absent/IPv6 sources) nothing is admitted, so stdout is
// empty and the process exits 0 with empty stderr.
func TestNormalizeCLIDualSourceAllLegalUnhitExitsZero(t *testing.T) {
	input := strings.Join([]string{
		dualSourceLine(`"198.51.100.7"`, `"::ffff:198.51.100.7"`),
		dualSourceLine(`"::192.0.2.7"`, `"::192.0.2.7"`),
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"v6","source_ip":"2001:db8::1"}`,
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), dualSourceCIDROpt...)
	if result.exitCode != 0 {
		t.Fatalf("all legal but unhit sources must exit 0, got %d (stderr %q)",
			result.exitCode, result.stderr)
	}
	if result.stdout != "" || result.stderr != "" {
		t.Fatalf("all-miss batch must leave stdout and stderr empty, got %q / %q",
			result.stdout, result.stderr)
	}
}
