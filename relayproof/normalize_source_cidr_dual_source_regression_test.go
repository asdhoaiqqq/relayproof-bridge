package relayproof

// Regression coverage for the source network filter's interaction with the
// existing source_ip/src_ip merge rules when ONE log line carries both
// source fields at once. The filter runs only after whole-line
// normalization, so it may decide success emission but never the validity of
// either value:
//
//   - 192.0.2.7 and ::ffff:192.0.2.7 are two legal, equivalent spellings:
//     they merge into one source, printed 192.0.2.7, and a /24 filter then
//     admits the single success; the equivalent spellings of an address
//     outside the network merge too and are then dropped silently (no
//     record, no failure).
//   - ::192.0.2.7 is a genuine IPv6 address (::c000:207), NOT the mapped
//     spelling: beside 192.0.2.7 it is a source_ip value conflict, never a
//     merge that hits the filter through the IPv4 side.
//   - two legal but distinct addresses conflict whether one is in the
//     network and the other out, or both are out: one ok:false record with
//     the source_ip conflict reason and no event. Swapping the two fields'
//     writing order, swapping which name carries the in/out value, or
//     permuting object members changes nothing about the failure.
//   - one legal value beside an invalid address or an explicit null is the
//     corresponding address/type error under the canonical name source_ip —
//     never a merge, never a filter drop, and never a "conflicting values"
//     report between two legal addresses.
//
// Failure records keep their physical line numbers in a mixed stream, later
// successes still emit, and every failure reason is byte-for-byte the same
// with and without the filter.

import (
	"strings"
	"testing"
)

// Mapped spellings of one IN-network source, 192.0.2.7. Every pairing in
// this list must normalize to the single dotted string "192.0.2.7".
var dualMappedInSpellings = []string{"192.0.2.7", "::ffff:192.0.2.7", "::FFFF:C000:0207"}

// Mapped spellings of one OUT-of-network source, 198.51.100.7. They merge
// with each other exactly as the in-network family does; the merged result
// is then what the filter decides about.
var dualMappedOutSpellings = []string{"198.51.100.7", "::ffff:198.51.100.7", "::FFFF:C633:6407"}

// Spellings of the distinct IPv6 address ::c000:207. It embeds the same
// trailing 32 bits as 192.0.2.7 but is never an IPv4-mapped address.
var dualCompatibleSpellings = []string{"::192.0.2.7", "0:0:0:0:0:0:c000:207"}

func dualStringLit(s string) string { return `"` + s + `"` }

// Raw JSON value literals for the two non-string / non-IP defects.
const (
	dualBadIPRaw = `"not-an-ip"`
	dualNullRaw  = `null`
)

// dualLine builds one log carrying BOTH source keys (source_ip with
// canonVal, src_ip with aliasVal, raw JSON literals) beside valid companions.
func dualLine(canonVal, aliasVal string) string {
	return joinObject([]kv{
		{key: FieldTimestamp, val: validTS},
		{key: FieldSourceIP, val: canonVal},
		{key: "src_ip", val: aliasVal},
		{key: FieldAction, val: validAction},
	})
}

// dualOrderings is dualLine with every object-member permutation: 24
// arrangements that move the two source entries and their companions around.
func dualSourcePermutations(canonVal, aliasVal string) []string {
	return permuteKV([]kv{
		{key: FieldTimestamp, val: validTS},
		{key: FieldSourceIP, val: canonVal},
		{key: "src_ip", val: aliasVal},
		{key: FieldAction, val: validAction},
	})
}

// dualFiltered runs one complete dual-source line through the filtered
// stream and returns its (at most one) results plus failure count.
func dualFiltered(t *testing.T, line string, filter *SourceCIDRFilter) ([]map[string]any, int) {
	t.Helper()
	return runNormalizeFiltered(t, line+"\n", filter)
}

// assertDualFailureParity runs one dual-source problem line with and without
// the /24 filter and requires both runs to report the SAME failure: exactly
// one ok:false record at line 1, no event, and a byte-identical error. It
// returns that shared error text for further class-specific assertions.
func assertDualFailureParity(t *testing.T, line string, filter *SourceCIDRFilter) string {
	t.Helper()
	filtered, fFailures := dualFiltered(t, line, filter)
	unfiltered := runNormalize(t, line+"\n")
	if fFailures != 1 || len(filtered) != 1 {
		t.Fatalf("filtered run must report exactly one failure, got %d records failures=%d: %#v", len(filtered), fFailures, filtered)
	}
	if len(unfiltered) != 1 {
		t.Fatalf("unfiltered run must report exactly one record, got %#v", unfiltered)
	}
	fr, ur := filtered[0], unfiltered[0]
	if fr["line"] != float64(1) || ur["line"] != float64(1) || fr["ok"] != false || ur["ok"] != false {
		t.Fatalf("both runs must fail on line 1: filtered=%#v unfiltered=%#v", fr, ur)
	}
	if _, exists := fr["event"]; exists {
		t.Fatalf("a dual-source failure must carry no event: %#v", fr)
	}
	if _, exists := ur["event"]; exists {
		t.Fatalf("the unfiltered run must carry no event either: %#v", ur)
	}
	fMsg, _ := fr["error"].(string)
	uMsg, _ := ur["error"].(string)
	if fMsg == "" || fMsg != uMsg {
		t.Fatalf("failure reason must be identical with and without the filter:\nfiltered:   %q\nunfiltered: %q", fMsg, uMsg)
	}
	return fMsg
}

// TestSourceCIDRDualMappedEquivalentMergeAdmitted pins the headline rule:
// both source values must independently be legal AND normalize to the same
// address before they merge; once merged, 192.0.2.7 in any mapped spelling
// prints as 192.0.2.7 and is admitted, while equivalent spellings of an
// outside address merge and are then dropped with no record and no failure.
func TestSourceCIDRDualMappedEquivalentMergeAdmitted(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}

	for _, a := range dualMappedInSpellings {
		for _, b := range dualMappedInSpellings {
			// Member order never changes the merged success.
			shared := assertOrderInvariant(t, dualSourcePermutations(dualStringLit(a), dualStringLit(b)), true, nil)
			if got := eventOf(t, shared)["source_ip"]; got != "192.0.2.7" {
				t.Fatalf("%q + %q must merge to 192.0.2.7, got %v", a, b, got)
			}
			// Through the filtered stream: exactly one admitted record, zero
			// failures, printed in dotted IPv4 form.
			results, failures := dualFiltered(t, dualLine(dualStringLit(a), dualStringLit(b)), &filter)
			if failures != 0 || len(results) != 1 || results[0]["ok"] != true {
				t.Fatalf("%q + %q must be one clean admitted success, got %#v failures=%d", a, b, results, failures)
			}
			if got := eventOf(t, results[0])["source_ip"]; got != "192.0.2.7" {
				t.Fatalf("merged output source_ip = %v, want 192.0.2.7", got)
			}
		}
	}

	for _, a := range dualMappedOutSpellings {
		for _, b := range dualMappedOutSpellings {
			// The merge itself still succeeds without a filter...
			plain := runNormalize(t, dualLine(dualStringLit(a), dualStringLit(b))+"\n")
			if len(plain) != 1 || plain[0]["ok"] != true {
				t.Fatalf("%q + %q are equivalent legal values and must merge unfiltered: %#v", a, b, plain)
			}
			if got := eventOf(t, plain[0])["source_ip"]; got != "198.51.100.7" {
				t.Fatalf("merged outside source = %v, want 198.51.100.7", got)
			}
			// ...but both equivalent values being outside means the merged
			// result is dropped: no record AND no failure.
			results, failures := dualFiltered(t, dualLine(dualStringLit(a), dualStringLit(b)), &filter)
			if failures != 0 || len(results) != 0 {
				t.Fatalf("two equivalent outside values must leave no record and no failure, got %#v failures=%d",
					results, failures)
			}
		}
	}
}

// TestSourceCIDRDualCompatibleIPv6ConflictsInsteadOfMerging pins that
// ::192.0.2.7 is the IPv6 address ::c000:207: beside 192.0.2.7 it conflicts
// under source_ip regardless of which key carries which spelling or where
// the members sit, and the conflict is emitted even though the IPv4 side is
// inside the selected network.
func TestSourceCIDRDualCompatibleIPv6ConflictsInsteadOfMerging(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, compat := range dualCompatibleSpellings {
		for _, mapped := range dualMappedInSpellings {
			assignments := [][2]string{{compat, mapped}, {mapped, compat}}
			for _, pair := range assignments {
				// Every member permutation of one assignment is byte-identical,
				// and both normalized addresses appear in the conflict reason.
				shared := assertOrderInvariant(t,
					dualSourcePermutations(dualStringLit(pair[0]), dualStringLit(pair[1])), false,
					[]string{FieldSourceIP, "conflicting values", "::c000:207", "192.0.2.7"})
				if msg, _ := shared["error"].(string); strings.Contains(msg, "invalid IP address") {
					t.Fatalf("two legal addresses must not be reported invalid: %q", msg)
				}
				// The filter must not let the in-network IPv4 value mask the
				// IPv6 value: exactly one failure record survives filtering.
				msg := assertDualFailureParity(t, dualLine(dualStringLit(pair[0]), dualStringLit(pair[1])), &filter)
				if !strings.Contains(msg, "::c000:207") || !strings.Contains(msg, "192.0.2.7") {
					t.Fatalf("conflict must name both distinct values, got %q", msg)
				}
			}
		}
	}
}

// TestSourceCIDRDualDistinctLegalAddressesConflictRegardlessOfNetwork
// requires two legal but different values to fail the line in every network
// configuration: one in / one out, and both out. Swapping the values
// between the canonical name and the alias changes only the values' order in
// the message, never the conclusion; member permutation changes nothing at
// all. The filtered and unfiltered reasons agree exactly.
func TestSourceCIDRDualDistinctLegalAddressesConflictRegardlessOfNetwork(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		a, b string
	}{
		{"one in network one out", "192.0.2.7", "198.51.100.7"},
		{"both out of network", "198.51.100.8", "198.51.100.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assignments := [][2]string{{tc.a, tc.b}, {tc.b, tc.a}}
			for _, pair := range assignments {
				// Member-order invariance: same canonical result for all 24.
				shared := assertOrderInvariant(t,
					dualSourcePermutations(dualStringLit(pair[0]), dualStringLit(pair[1])), false,
					[]string{FieldSourceIP, "conflicting values", tc.a, tc.b})
				if msg, _ := shared["error"].(string); strings.Contains(msg, "invalid IP address") {
					t.Fatalf("two legal addresses must conflict, not be invalid: %q", msg)
				}
				// Filtered output: one failure, same reason as unfiltered.
				msg := assertDualFailureParity(t, dualLine(dualStringLit(pair[0]), dualStringLit(pair[1])), &filter)
				if !strings.Contains(msg, FieldSourceIP) {
					t.Fatalf("conflict reason must name %q: %q", FieldSourceIP, msg)
				}
			}
		})
	}
}

// TestSourceCIDRDualOneBadValueReportsItsOwnError pins that a legal value
// never masks the other source's defect: an illegal address string reports
// the invalid-address error and an explicit null reports the type error,
// each under the canonical name source_ip, whether the legal side is in or
// out of the network and regardless of key/value placement. Neither is a
// legal-value conflict, neither is merged, and neither is filtered away. The
// error is byte-identical across all 48 arrangements of both assignments and
// identical with and without the filter.
func TestSourceCIDRDualOneBadValueReportsItsOwnError(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		legal    string
		bad      string // raw JSON literal
		wantSubs []string
	}{
		{"bad address beside in-network legal", "192.0.2.7", `"not-an-ip"`, []string{"invalid IP address", "not-an-ip"}},
		{"bad address beside out-of-network legal", "198.51.100.7", `"not-an-ip"`, []string{"invalid IP address", "not-an-ip"}},
		{"explicit null beside in-network legal", "192.0.2.7", `null`, []string{"value must be a string", "got null"}},
		{"explicit null beside out-of-network legal", "198.51.100.7", `null`, []string{"value must be a string", "got null"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legal := dualStringLit(tc.legal)
			// Union every member permutation of BOTH name assignments: the
			// offending literal is reported no matter which key holds it, so
			// the complete result is one canonical failure.
			variants := append(
				dualSourcePermutations(legal, tc.bad),
				dualSourcePermutations(tc.bad, legal)...,
			)
			wantSubs := append([]string{FieldSourceIP}, tc.wantSubs...)
			shared := assertOrderInvariant(t, variants, false, wantSubs)
			if msg, _ := shared["error"].(string); strings.Contains(msg, "conflicting values") {
				t.Fatalf("a defect in one value is not a conflict of two legal values: %q", msg)
			}

			// Both assignments surface through the filter with the exact
			// unfiltered reason and one failure each.
			for _, pair := range [][2]string{{legal, tc.bad}, {tc.bad, legal}} {
				msg := assertDualFailureParity(t, dualLine(pair[0], pair[1]), &filter)
				for _, sub := range tc.wantSubs {
					if !strings.Contains(msg, sub) {
						t.Fatalf("error %q must contain %q", msg, sub)
					}
				}
				if !strings.Contains(msg, FieldSourceIP) {
					t.Fatalf("the reason must use the canonical field name %q: %q", FieldSourceIP, msg)
				}
			}
		})
	}
}

// TestSourceCIDRDualProblemsKeepLineNumbersInMixedStream places every
// dual-source class among single-field in-network successes, single-field
// out-of-network successes and blank lines. Failure records keep their
// original physical line numbers and class-specific reasons with no event,
// dropped and blank lines do not renumber anything, and the trailing
// in-network success still emits. Each failure reason is exactly what the
// unfiltered run reports for the same line.
func TestSourceCIDRDualProblemsKeepLineNumbersInMixedStream(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	singleIn := func(action, ip string) string {
		return joinObject([]kv{
			{key: FieldTimestamp, val: validTS},
			{key: FieldAction, val: dualStringLit(action)},
			{key: FieldSourceIP, val: dualStringLit(ip)},
		})
	}
	input := strings.Join([]string{
		singleIn("lead-in", "192.0.2.10"),                                       // line 1 admitted
		dualLine(dualStringLit("192.0.2.7"), dualStringLit("::ffff:192.0.2.7")), // line 2 admitted (merged)
		"", // line 3 blank
		dualLine(dualStringLit("192.0.2.7"), dualStringLit("198.51.100.7")),    // line 4 conflict (in/out)
		dualLine(dualStringLit("198.51.100.8"), dualStringLit("198.51.100.9")), // line 5 conflict (both out)
		dualLine(dualStringLit("::192.0.2.7"), dualStringLit("192.0.2.7")),     // line 6 conflict (v6 vs v4)
		dualLine(dualStringLit("192.0.2.7"), dualBadIPRaw),                     // line 7 invalid address
		dualLine(dualNullRaw, dualStringLit("192.0.2.7")),                      // line 8 explicit null
		"", // line 9 blank
		singleIn("outside-single", "198.51.100.10"),                                   // line 10 dropped
		dualLine(dualStringLit("198.51.100.7"), dualStringLit("::ffff:198.51.100.7")), // line 11 merged then dropped
		singleIn("tail-in", "192.0.2.11"),                                             // line 12 admitted
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &filter)
	if failures != 5 {
		t.Fatalf("the five dual-source problem lines must count as failures, got %d", failures)
	}
	if len(results) != 8 {
		t.Fatalf("expected 3 admitted successes + 5 failures = 8 records, got %#v", results)
	}

	type expected struct {
		line     float64
		ok       bool
		marker   string
		sourceIP string
	}
	want := []expected{
		{1, true, "lead-in", "192.0.2.10"},
		{2, true, "login", "192.0.2.7"}, // merged mapped pair keeps validAction, prints dotted
		{4, false, "conflicting values", ""},
		{5, false, "conflicting values", ""},
		{6, false, "conflicting values", ""},
		{7, false, "invalid IP address", ""},
		{8, false, "got null", ""},
		{12, true, "tail-in", "192.0.2.11"},
	}
	for i, w := range want {
		got := results[i]
		if got["line"] != w.line || got["ok"] != w.ok {
			t.Fatalf("record %d must be physical line %v ok=%v, got %#v", i, w.line, w.ok, got)
		}
		if !w.ok {
			if _, exists := got["event"]; exists {
				t.Fatalf("line %v failure must carry no event: %#v", w.line, got)
			}
			msg, _ := got["error"].(string)
			if !strings.Contains(msg, FieldSourceIP) || !strings.Contains(msg, w.marker) {
				t.Fatalf("line %v error must name %q and contain %q, got %q", w.line, FieldSourceIP, w.marker, msg)
			}
			continue
		}
		event := eventOf(t, got)
		if event["action"] != w.marker || event["source_ip"] != w.sourceIP {
			t.Fatalf("line %v event mismatch: %#v", w.line, event)
		}
	}

	// Parity: every failure record's line/ok/error is identical in the
	// unfiltered run (which additionally emits lines 10 and 11 as successes).
	unfiltered := runNormalize(t, input)
	byLine := map[float64]map[string]any{}
	for _, r := range unfiltered {
		byLine[r["line"].(float64)] = r
	}
	for i, w := range want {
		if w.ok {
			continue
		}
		u := byLine[w.line]
		if u["error"] != results[i]["error"] {
			t.Fatalf("line %v reason must match unfiltered run:\nfiltered:   %q\nunfiltered: %q",
				w.line, results[i]["error"], u["error"])
		}
		if _, exists := u["event"]; exists {
			t.Fatalf("unfiltered failure on line %v must carry no event", w.line)
		}
	}
}

// TestSourceCIDRDualAllLegalMissesEndCleanEmpty pins that a batch made only
// of legal-but-outside dual-source lines (equivalent values that merge) is a
// clean no-output run: the stream error is nil, zero failures, and no record
// is emitted — the filter distinguishes these from genuine conflicts.
func TestSourceCIDRDualAllLegalMissesEndCleanEmpty(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		dualLine(dualStringLit("198.51.100.7"), dualStringLit("::ffff:198.51.100.7")),
		dualLine(dualStringLit("::FFFF:C633:6407"), dualStringLit("198.51.100.7")),
		dualLine(dualStringLit("198.51.100.8"), dualStringLit("::ffff:198.51.100.8")),
		"",
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &filter)
	if failures != 0 {
		t.Fatalf("legal merged-outside lines are not failures, got %d", failures)
	}
	if len(results) != 0 {
		t.Fatalf("every legal source missed the network, so no record may be emitted, got %#v", results)
	}
}
