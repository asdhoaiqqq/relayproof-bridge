package relayproof

// Regression coverage for the --source-cidr filter's interaction with the
// existing dual-source rule: when one log carries both source_ip and src_ip,
// both values must be legal and normalize to the same address before the
// successful event is merged and then admitted. The filter selects only
// successful events; it must never let one source value mask the other's
// problem — neither a conflict between two legal addresses, nor an invalid
// address / explicit null on one side, is ever merged away or silently
// filtered out.
//
// Every assertion here is pinned with --source-cidr 192.0.2.0/24 semantics
// while the other mapped fields stay legal, and each failure reason is also
// required to be byte-identical to an unfiltered run of the same logs.

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// dualSourceCIDR is the network every test below filters on.
const dualSourceCIDR = "192.0.2.0/24"

// dualSourceLog builds a single log line in which source_ip takes canonical
// and src_ip takes alias (both raw JSON value literals), alongside legal
// timestamp/action companions. JSON key order in the object is the natural
// declaration order for readability — order invariance is asserted separately
// with permuteKV rather than relied on here.
func dualSourceLog(canonical, alias string) string {
	return joinObject([]kv{
		{key: FieldTimestamp, val: validTSLiteral},
		{key: FieldSourceIP, val: canonical},
		{key: "src_ip", val: alias},
		{key: FieldAction, val: validActLiteral},
	})
}

// dualSourceOrderings returns every key ordering of the four members
// (timestamp, source_ip, src_ip, action) for a canonical/alias source pair —
// 4! = 24 arrangements. These cover both writing src_ip before source_ip
// (member-order swap) and, in callers that swap which value is bound to which
// name, swapping in/out addresses across canonical and alias.
func dualSourceOrderings(canonical, alias string) []string {
	return permuteKV([]kv{
		{key: FieldTimestamp, val: validTSLiteral},
		{key: FieldSourceIP, val: canonical},
		{key: "src_ip", val: alias},
		{key: FieldAction, val: validActLiteral},
	})
}

// assertSourceConflictFailure requires the single emitted record to be an
// ok:false source_ip conflict with no event, naming both normalized addresses
// in the error (a two-legal-address conflict, not an invalid-address or
// type error).
func assertSourceConflictFailure(t *testing.T, r map[string]any) {
	t.Helper()
	if r["ok"] != false {
		t.Fatalf("two legal distinct sources must fail whole line: %#v", r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("conflicting sources must not emit an event: %#v", r)
	}
	msg, _ := r["error"].(string)
	if !strings.Contains(msg, FieldSourceIP) || !strings.Contains(msg, "conflicting values") {
		t.Fatalf("error must report a source_ip value conflict, got %q", msg)
	}
	if strings.Contains(msg, "invalid IP address") || strings.Contains(msg, "got null") {
		t.Fatalf("two legal addresses must not be reported as invalid/null: %q", msg)
	}
}

// assertSourceInvalidAddress requires the single emitted record to be an
// ok:false source_ip invalid-address failure with no event, and not a
// conflict between legal values.
func assertSourceInvalidAddress(t *testing.T, r map[string]any) {
	t.Helper()
	if r["ok"] != false {
		t.Fatalf("a bad source value must fail whole line: %#v", r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("bad source must not emit an event: %#v", r)
	}
	msg, _ := r["error"].(string)
	if !strings.Contains(msg, FieldSourceIP) || !strings.Contains(msg, "invalid IP address") {
		t.Fatalf("error must report an invalid source_ip address, got %q", msg)
	}
	if strings.Contains(msg, "conflicting values") {
		t.Fatalf("an invalid value is not a conflict between legal addresses: %q", msg)
	}
}

// assertSourceNullType requires the single emitted record to be an ok:false
// source_ip type error for an explicit null, with no event and no conflict.
func assertSourceNullType(t *testing.T, r map[string]any) {
	t.Helper()
	if r["ok"] != false {
		t.Fatalf("an explicit null source must fail whole line: %#v", r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("null source must not emit an event: %#v", r)
	}
	msg, _ := r["error"].(string)
	if !strings.Contains(msg, FieldSourceIP) || !strings.Contains(msg, "value must be a string, got null") {
		t.Fatalf("error must report source_ip null type error, got %q", msg)
	}
	if strings.Contains(msg, "conflicting values") {
		t.Fatalf("a null is not a conflict between legal addresses: %q", msg)
	}
}

// runDualSource runs one dual-source log through both the filtered and
// unfiltered reader and returns (filtered results, filtered failures,
// unfiltered results). It pins filtered==unfiltered for the failure path:
// enabling the filter must not change the failure reason.
func runDualSource(t *testing.T, input string) ([]map[string]any, int, []map[string]any) {
	t.Helper()
	filter, err := ParseSourceCIDRFilter(dualSourceCIDR)
	if err != nil {
		t.Fatal(err)
	}
	fResults, fFail := runNormalizeFiltered(t, input, &filter)
	uResults := runNormalize(t, input)
	return fResults, fFail, uResults
}

// TestDualSourceMappedEquivalentMergeAndAdmit pins the headline merge:
// 192.0.2.7 and ::ffff:192.0.2.7 are the same legal address in two spellings,
// so they merge into one successful event that the filter admits, printing
// the dotted form. The same merge using only the mapped spelling is dropped
// cleanly when both equivalents normalize outside the network.
func TestDualSourceMappedEquivalentMergeAndAdmit(t *testing.T) {
	// In-network equivalent pair: merge then admit, in every member ordering.
	for _, in := range dualSourceOrderings(`"192.0.2.7"`, `"::ffff:192.0.2.7"`) {
		fResults, fFail, uResults := runDualSource(t, in)
		if fFail != 0 || len(fResults) != 1 || fResults[0]["ok"] != true {
			t.Fatalf("equivalent in-network pair must merge into one admitted success: %s -> %#v failures=%d",
				in, fResults, fFail)
		}
		event := eventOf(t, fResults[0])
		if event["source_ip"] != "192.0.2.7" {
			t.Fatalf("merged source_ip = %v, want 192.0.2.7 (%s)", event["source_ip"], in)
		}
		if event["timestamp"] != "2026-01-02T00:00:00Z" || event["action"] != "ok" {
			t.Fatalf("other mapped fields must stay legal: %#v (%s)", event, in)
		}
		if _, exists := event["extra"]; exists {
			t.Fatalf("no unknown fields were given, extra must be absent: %#v (%s)", event, in)
		}
		// Unfiltered the same line is a success; enabling the filter must
		// not alter that record.
		if len(uResults) != 1 || uResults[0]["ok"] != true {
			t.Fatalf("unfiltered equivalent pair must also succeed: %#v", uResults)
		}
		if !jsonEqualResult(fResults[0], uResults[0]) {
			t.Fatalf("filter must not change the merged success:\nfiltered:   %#v\nunfiltered: %#v", fResults[0], uResults[0])
		}
	}

	// Two equivalents both outside the network: they still merge into a
	// valid success, but the filter drops it — no record and no failure.
	outside := dualSourceLog(`"198.51.100.7"`, `"::ffff:198.51.100.7"`)
	fResults, fFail, uResults := runDualSource(t, outside)
	if fFail != 0 {
		t.Fatalf("equivalent out-of-network pair must not be a failure, got %d", fFail)
	}
	if len(fResults) != 0 {
		t.Fatalf("both equivalents out of network must produce no record, got %#v", fResults)
	}
	// ... but the merge is genuinely valid: unfiltered it is one ok event
	// with the dotted form, proving this is a filter drop rather than a
	// conflict.
	if len(uResults) != 1 || uResults[0]["ok"] != true {
		t.Fatalf("out-of-network equivalents must merge validly without a filter: %#v", uResults)
	}
	if got := eventOf(t, uResults[0])["source_ip"]; got != "198.51.100.7" {
		t.Fatalf("out-of-network equivalents must merge to 198.51.100.7, got %v", got)
	}
}

// TestDualSourceMappedPairEitherDirection pins that which spelling sits
// under source_ip versus src_ip does not matter for the merge/admit decision:
// 192.0.2.7 under the alias + ::ffff:192.0.2.7 under the canonical still
// merges into 192.0.2.7 and is admitted.
func TestDualSourceMappedPairEitherDirection(t *testing.T) {
	for _, pair := range [][2]string{
		{`"192.0.2.7"`, `"::ffff:192.0.2.7"`},
		{`"::ffff:192.0.2.7"`, `"192.0.2.7"`},
	} {
		for _, in := range dualSourceOrderings(pair[0], pair[1]) {
			filter, err := ParseSourceCIDRFilter(dualSourceCIDR)
			if err != nil {
				t.Fatal(err)
			}
			results, failures := runNormalizeFiltered(t, in, &filter)
			if failures != 0 || len(results) != 1 || results[0]["ok"] != true {
				t.Fatalf("mapped pair %s/%s must merge and admit in any order: %s -> %#v",
					pair[0], pair[1], in, results)
			}
			if got := eventOf(t, results[0])["source_ip"]; got != "192.0.2.7" {
				t.Fatalf("merged source_ip = %v, want 192.0.2.7", got)
			}
		}
	}
}

// TestDualSourceCompatibleIPv6NeverMergesIntoFilter pins that ::192.0.2.7
// stays a genuine IPv6 address: paired with 192.0.2.7 in either binding it is
// reported as a source_ip conflict — even though the plain/mapped 192.0.2.7
// side would hit the filter — and is never merged then admitted, nor silently
// dropped as "outside the network".
func TestDualSourceCompatibleIPv6NeverMergesIntoFilter(t *testing.T) {
	for _, pair := range [][2]string{
		{`"::192.0.2.7"`, `"192.0.2.7"`}, // ::192.0.2.7 under canonical
		{`"192.0.2.7"`, `"::192.0.2.7"`}, // ::192.0.2.7 under alias
	} {
		for _, in := range dualSourceOrderings(pair[0], pair[1]) {
			fResults, fFail, uResults := runDualSource(t, in)
			if fFail != 1 || len(fResults) != 1 {
				t.Fatalf("::192.0.2.7 vs 192.0.2.7 must be one counted failure: %s -> %#v failures=%d",
					in, fResults, fFail)
			}
			assertSourceConflictFailure(t, fResults[0])
			msg, _ := fResults[0]["error"].(string)
			if !strings.Contains(msg, "::c000:207") {
				t.Fatalf("conflict must name the normalized IPv6 ::c000:207, got %q (%s)", msg, in)
			}
			// Member-order-only swaps (same canonical/alias bindings) produce
			// the identical reason; checked across all 24 orderings here.
			if !jsonEqualResult(fResults[0], uResults[0]) {
				t.Fatalf("filter must not change the conflict reason:\nfiltered:   %#v\nunfiltered: %#v",
					fResults[0], uResults[0])
			}
		}
	}
}

// TestDualSourceDistinctLegalAddressesAlwaysFail requires two legal but
// different addresses to always yield one ok:false source_ip conflict,
// whether one is in-network and the other out, or both are out of network.
// The in-network value must not win and merge; the out-of-network location
// must not cause a silent drop. Swapping which address is bound to canonical
// versus alias, or reversing member order, changes neither the failure nor
// (for member-order-only swaps) the exact reason.
func TestDualSourceDistinctLegalAddressesAlwaysFail(t *testing.T) {
	const (
		inAddr   = `"192.0.2.7"`
		outAddr  = `"198.51.100.7"`
		outAddr2 = `"198.51.100.20"`
	)
	pairs := [][2]string{
		{inAddr, outAddr},   // one in, one out
		{outAddr, inAddr},   // swapped across canonical/alias
		{outAddr, outAddr2}, // both out, distinct
		{outAddr2, outAddr}, // both out, distinct, bindings swapped
	}
	for _, pair := range pairs {
		for _, in := range dualSourceOrderings(pair[0], pair[1]) {
			fResults, fFail, uResults := runDualSource(t, in)
			if fFail != 1 || len(fResults) != 1 {
				t.Fatalf("distinct legal addresses must be one counted failure: %s -> %#v failures=%d",
					in, fResults, fFail)
			}
			assertSourceConflictFailure(t, fResults[0])
			if !jsonEqualResult(fResults[0], uResults[0]) {
				t.Fatalf("filter must not change the conflict reason:\ninput:      %s\nfiltered:   %#v\nunfiltered: %#v",
					in, fResults[0], uResults[0])
			}
		}
	}
}

// TestDualSourceMemberOrderSwapKeepsReason pins that, with canonical/alias
// bindings held fixed, merely reversing the two members' writing order keeps
// the complete conflict reason (which normalized address is named first)
// byte-identical. This distinguishes member-order swaps from value swaps:
// candidates are validated in sorted-key order, so position is irrelevant.
func TestDualSourceMemberOrderSwapKeepsReason(t *testing.T) {
	// Same bindings (canonical=192.0.2.7, alias=198.51.100.7), two member
	// orders — all 24 permutations collapse to one canonical result.
	inputs := dualSourceOrderings(`"192.0.2.7"`, `"198.51.100.7"`)
	filter, err := ParseSourceCIDRFilter(dualSourceCIDR)
	if err != nil {
		t.Fatal(err)
	}
	var want string
	for i, in := range inputs {
		var out bytes.Buffer
		if _, err := NormalizeReaderFiltered(strings.NewReader(in), &out, &filter); err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		got := out.String()
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("member-order change altered the result:\ninput: %s\ngot:  %s\nwant: %s", in, got, want)
		}
	}
	// Sanity: the shared result is the in-first conflict naming 192.0.2.7.
	if !strings.Contains(want, "192.0.2.7") || !strings.Contains(want, "198.51.100.7") {
		t.Fatalf("shared reason must name both addresses: %q", want)
	}
}

// TestDualSourceOneInvalidOrNullNotMergedOrFiltered pins that when one source
// value is legal and the other is an invalid address or explicit null, the
// line fails with the corresponding invalid-address / type error — never
// merged to the good value, never silently filtered on the good value's
// location, and never misreported as a conflict between two legal values.
// The field named in the reason stays source_ip regardless of which side is
// bad, and reasons are identical with and without the filter.
func TestDualSourceOneInvalidOrNullNotMergedOrFiltered(t *testing.T) {
	cases := []struct {
		name      string
		canonical string
		alias     string
		assert    func(*testing.T, map[string]any)
		badValue  string // exact raw bad value the reason must quote; empty for explicit null (whose assert pins the type text)
	}{
		{
			name:      "canonical legal in-net, alias invalid address",
			canonical: `"192.0.2.7"`,
			alias:     `"not-an-ip"`,
			assert:    assertSourceInvalidAddress,
			badValue:  `"not-an-ip"`,
		},
		{
			name:      "canonical invalid address, alias legal in-net",
			canonical: `"999.1.1.1"`,
			alias:     `"::ffff:192.0.2.7"`,
			assert:    assertSourceInvalidAddress,
			badValue:  `"999.1.1.1"`,
		},
		{
			name:      "canonical legal out-net, alias invalid address",
			canonical: `"198.51.100.7"`,
			alias:     `"not-an-ip"`,
			assert:    assertSourceInvalidAddress,
			badValue:  `"not-an-ip"`,
		},
		{
			name:      "canonical invalid address, alias legal out-net",
			canonical: `"not-an-ip"`,
			alias:     `"198.51.100.7"`,
			assert:    assertSourceInvalidAddress,
			badValue:  `"not-an-ip"`,
		},
		{
			name:      "canonical legal in-net, alias explicit null",
			canonical: `"192.0.2.7"`,
			alias:     `null`,
			assert:    assertSourceNullType,
		},
		{
			name:      "canonical explicit null, alias legal in-net",
			canonical: `null`,
			alias:     `"::ffff:192.0.2.7"`,
			assert:    assertSourceNullType,
		},
		{
			name:      "canonical legal out-net, alias explicit null",
			canonical: `"198.51.100.7"`,
			alias:     `null`,
			assert:    assertSourceNullType,
		},
		{
			name:      "canonical explicit null, alias legal out-net",
			canonical: `null`,
			alias:     `"198.51.100.7"`,
			assert:    assertSourceNullType,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, in := range dualSourceOrderings(tc.canonical, tc.alias) {
				fResults, fFail, uResults := runDualSource(t, in)
				if fFail != 1 || len(fResults) != 1 {
					t.Fatalf("one-bad-source line must be one counted failure: %s -> %#v failures=%d",
						in, fResults, fFail)
				}
				tc.assert(t, fResults[0])
				if tc.badValue != "" {
					if msg, _ := fResults[0]["error"].(string); !strings.Contains(msg, tc.badValue) {
						t.Fatalf("reason must quote the exact bad value %s, got %q", tc.badValue, msg)
					}
				}
				if !jsonEqualResult(fResults[0], uResults[0]) {
					t.Fatalf("filter must not change the failure reason:\ninput:      %s\nfiltered:   %#v\nunfiltered: %#v",
						in, fResults[0], uResults[0])
				}
			}
		})
	}
}

// jsonEqualResult compares two decoded results for semantic equality (the
// line field is a float64 when decoded without UseNumber; both come from the
// same run helpers, so types agree).
func jsonEqualResult(a, b map[string]any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb)
}

// TestDualSourceBatchPreservesPhysicalLineNumbers drives all the source
// problems through one batch that also contains an in-network success, an
// out-of-network legal event, and a blank line. Filtered: the in-network
// success and later successes still emit; failures keep their ORIGINAL
// physical line numbers; dropped/blank lines never renumber; later successes
// emit normally. Unfiltered: every failure reason is identical.
func TestDualSourceBatchPreservesPhysicalLineNumbers(t *testing.T) {
	filter, err := ParseSourceCIDRFilter(dualSourceCIDR)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		// line 1: in-network single-source success (control).
		`{"timestamp":` + validTSLiteral + `,"action":"hit-before","source_ip":"192.0.2.5"}`,
		// line 2: two legal distinct, one in one out -> conflict failure.
		dualSourceLog(`"192.0.2.7"`, `"198.51.100.7"`),
		// line 3: equivalent pair both outside -> merged success, dropped.
		dualSourceLog(`"198.51.100.1"`, `"::ffff:198.51.100.1"`),
		// line 4: blank -> skipped, still counts.
		"",
		// line 5: ::192.0.2.7 vs 192.0.2.7 -> conflict failure.
		dualSourceLog(`"::192.0.2.7"`, `"192.0.2.7"`),
		// line 6: one invalid address -> invalid-address failure.
		dualSourceLog(`"192.0.2.7"`, `"not-an-ip"`),
		// line 7: one explicit null -> type failure.
		dualSourceLog(`null`, `"192.0.2.7"`),
		// line 8: two distinct legal both outside -> conflict failure.
		dualSourceLog(`"198.51.100.2"`, `"198.51.100.3"`),
		// line 9: later in-network success -> must emit normally.
		`{"timestamp":` + validTSLiteral + `,"action":"hit-after","source_ip":"192.0.2.9"}`,
		// line 10: later out-of-network single-source legal -> dropped.
		`{"timestamp":` + validTSLiteral + `,"action":"outside","source_ip":"10.0.0.1"}`,
	}, "\n") + "\n"

	var fOut, uOut bytes.Buffer
	fFailures, err := NormalizeReaderFiltered(strings.NewReader(input), &fOut, &filter)
	if err != nil {
		t.Fatalf("filtered run error: %v", err)
	}
	uFailures, err := NormalizeReader(strings.NewReader(input), &uOut)
	if err != nil {
		t.Fatalf("unfiltered run error: %v", err)
	}

	// Five bad lines (2,5,6,7,8) regardless of the filter.
	if fFailures != 5 || uFailures != 5 {
		t.Fatalf("five bad lines must be counted with and without filter, got %d and %d", fFailures, uFailures)
	}

	decode := func(b *bytes.Buffer) []map[string]any {
		var rs []map[string]any
		dec := json.NewDecoder(b)
		for {
			var m map[string]any
			if err := dec.Decode(&m); err != nil {
				if err == io.EOF {
					return rs
				}
				t.Fatalf("decode: %v", err)
			}
			rs = append(rs, m)
		}
	}
	fResults := decode(&fOut)
	uResults := decode(&uOut)

	// Filtered: lines 1 (hit), 2,5,6,7,8 (failures), 9 (hit) = 7 records.
	if len(fResults) != 7 {
		t.Fatalf("expected 2 admitted successes + 5 failures = 7 records, got %d: %#v", len(fResults), fResults)
	}
	wantFilteredLines := []float64{1, 2, 5, 6, 7, 8, 9}
	for i, ln := range wantFilteredLines {
		if fResults[i]["line"] != ln {
			t.Fatalf("filtered record %d must carry physical line %v, got %v: %#v",
				i, ln, fResults[i]["line"], fResults[i])
		}
	}
	if fResults[0]["ok"] != true || eventOf(t, fResults[0])["action"] != "hit-before" {
		t.Fatalf("record 0 must be the line-1 in-network hit: %#v", fResults[0])
	}
	if fResults[6]["ok"] != true || eventOf(t, fResults[6])["action"] != "hit-after" {
		t.Fatalf("record 6 must be the line-9 in-network hit, emitted normally after the failures: %#v", fResults[6])
	}
	// Failure records 1..5 carry no event and keep their source_ip reasons.
	for i := 1; i <= 5; i++ {
		if fResults[i]["ok"] != false {
			t.Fatalf("record %d (line %v) must be a failure: %#v", i, wantFilteredLines[i], fResults[i])
		}
		if _, exists := fResults[i]["event"]; exists {
			t.Fatalf("failure record %d must carry no event: %#v", i, fResults[i])
		}
		msg, _ := fResults[i]["error"].(string)
		if !strings.Contains(msg, FieldSourceIP) {
			t.Fatalf("failure record %d must name source_ip, got %q", i, msg)
		}
	}
	assertSourceConflictFailure(t, fResults[1]) // line 2
	assertSourceConflictFailure(t, fResults[2]) // line 5
	assertSourceInvalidAddress(t, fResults[3])  // line 6
	assertSourceNullType(t, fResults[4])        // line 7
	assertSourceConflictFailure(t, fResults[5]) // line 8

	// Without filter: lines 1,2,3,5,6,7,8,9,10 emit (line 3 and 10 survive
	// as successes), blank line 4 only counts. = 9 records.
	if len(uResults) != 9 {
		t.Fatalf("unfiltered expected 9 records (no blank line 4), got %d: %#v", len(uResults), uResults)
	}
	wantUnfilteredLines := []float64{1, 2, 3, 5, 6, 7, 8, 9, 10}
	for i, ln := range wantUnfilteredLines {
		if uResults[i]["line"] != ln {
			t.Fatalf("unfiltered record %d must carry physical line %v, got %v", i, ln, uResults[i]["line"])
		}
	}
	// Every filtered failure record equals its unfiltered counterpart (same
	// physical line, same reason, no event).
	for _, ln := range []float64{2, 5, 6, 7, 8} {
		var fR, uR map[string]any
		for _, r := range fResults {
			if r["line"] == ln {
				fR = r
			}
		}
		for _, r := range uResults {
			if r["line"] == ln {
				uR = r
			}
		}
		if !jsonEqualResult(fR, uR) {
			t.Fatalf("line %v failure must be identical with/without filter:\nfiltered:   %#v\nunfiltered: %#v",
				ln, fR, uR)
		}
	}
}

// TestDualSourceAllMissCleanEmpty pins that a batch consisting entirely of
// legal logs whose (merged) sources all miss the network — equivalent pairs
// both outside, genuine IPv6 pairs, absent sources — ends normally: stdout
// empty, zero failures. Conflicts and invalid values are deliberately absent
// so this exercises the all-miss case rather than the failure case.
func TestDualSourceAllMissCleanEmpty(t *testing.T) {
	filter, err := ParseSourceCIDRFilter(dualSourceCIDR)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		dualSourceLog(`"198.51.100.7"`, `"::ffff:198.51.100.7"`),                       // equivalent, both out
		dualSourceLog(`"::192.0.2.7"`, `"::192.0.2.7"`),                                // genuine IPv6 pair, both out
		`{"timestamp":` + validTSLiteral + `,"action":"no-source"}`,                    // absent source
		`{"timestamp":` + validTSLiteral + `,"action":"v6","source_ip":"2001:db8::1"}`, // IPv6
	}, "\n") + "\n"

	var out bytes.Buffer
	failures, err := NormalizeReaderFiltered(strings.NewReader(input), &out, &filter)
	if err != nil {
		t.Fatalf("all-miss run error: %v", err)
	}
	if failures != 0 {
		t.Fatalf("all logs legal -> zero failures even though nothing is admitted, got %d", failures)
	}
	if out.Len() != 0 {
		t.Fatalf("every valid log missed the network, so stdout must be empty, got %q", out.String())
	}
}
