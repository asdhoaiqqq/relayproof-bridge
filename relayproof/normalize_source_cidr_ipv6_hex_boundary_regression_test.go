package relayproof

// Regression coverage for an IPv6 source network whose prefix length does
// not fall on a hex-digit (nibble) boundary — the IPv6 analogue of the
// non-octet-aligned IPv4 cases in normalize_source_cidr_boundary_regression_test.go.
//
// The network 2001:db8:1:2:abff::1234/73 selects 2001:db8:1:2:ab80::/73:
// /73 means 64 group-aligned bits plus 9 bits of the fifth group, so the
// boundary splits the low nibble of the fifth group. That group ranges over
// ab80..abff, and the eighth group still varies freely:
//
//   - 2001:db8:1:2:ab80::                       is the first address,
//   - 2001:db8:1:2:abff:ffff:ffff:ffff          is the last address,
//   - 2001:db8:1:2:ab7f:ffff:ffff:ffff          is immediately below,
//   - 2001:db8:1:2:ac00::                       is immediately above.
//
// The mask is applied to the filter argument's host bits, so spelling it with
// another in-range host address or with the full (uncompressed) form of the
// same address changes neither the admitted range nor the canonical network
// string. Membership is always decided on the fully normalized source, so a
// source arriving through source_ip or src_ip, in compressed or full
// spelling, shares one decision and one normalized output form. Filtering
// still removes only successful events: a valid event outside the network is
// a dropped success, while a malformed line stays a counted failure with its
// original physical line number, reason, and no event — the two outcomes are
// never conflated, and neither is a read/write fault. The standard-name/alias
// merge and conflict rules are unchanged by the filter.

import (
	"strings"
	"testing"
)

// hexBoundaryCIDR is the host-spelled network under test, and
// hexBoundaryCanonical is the network it must mask to.
const (
	hexBoundaryCIDR      = "2001:db8:1:2:abff::1234/73"
	hexBoundaryCanonical = "2001:db8:1:2:ab80::/73"
)

// hexBoundarySpellings are equivalent ways to spell the very same /73
// network: the documented host-spelled compressed form, another legal host
// address inside the range (including the range's own first and last
// addresses), and the full uncompressed spelling of the documented address.
var hexBoundarySpellings = []string{
	"2001:db8:1:2:abff::1234/73",                // documented spelling
	"2001:db8:1:2:abab::1/73",                   // another in-range host address
	"2001:db8:1:2:ab80::/73",                    // the range's first address
	"2001:db8:1:2:abff:ffff:ffff:ffff/73",       // the range's last address
	"2001:db8:0001:0002:abff:0000:0000:1234/73", // full spelling of the documented address
}

// TestParseSourceCIDRFilterIPv6HexBoundaryCanonicalization pins that the
// /73 prefix, which lands inside the low nibble of the fifth group, masks the
// argument to 2001:db8:1:2:ab80::/73 for every equivalent spelling.
func TestParseSourceCIDRFilterIPv6HexBoundaryCanonicalization(t *testing.T) {
	for _, spelled := range hexBoundarySpellings {
		f, err := ParseSourceCIDRFilter(spelled)
		if err != nil {
			t.Fatalf("ParseSourceCIDRFilter(%q) unexpected error: %v", spelled, err)
		}
		if got := f.String(); got != hexBoundaryCanonical {
			t.Fatalf("ParseSourceCIDRFilter(%q).String() = %q, want %q", spelled, got, hexBoundaryCanonical)
		}
	}
}

// TestSourceCIDRFilterIPv6HexBoundaryMembership pins the exact admitted
// range against the normalized-address strings the filter compares: both
// range ends and interior addresses are admitted; the addresses immediately
// outside either edge are not. The probes are given in compressed and full
// spellings to prove the decision uses the normalized address.
func TestSourceCIDRFilterIPv6HexBoundaryMembership(t *testing.T) {
	filter, err := ParseSourceCIDRFilter(hexBoundaryCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if got := filter.String(); got != hexBoundaryCanonical {
		t.Fatalf("canonical network = %q, want %q", got, hexBoundaryCanonical)
	}

	inside := []string{
		"2001:db8:1:2:ab80::",              // first address of the range
		"2001:db8:1:2:ab80:0:0:0",          // first address, full spelling
		"2001:db8:1:2:abff::1234",          // the host the option was spelled with
		"2001:db8:1:2:ab9a::1",             // another interior legal source
		"2001:db8:1:2:abff:0:0:1234",       // spelled host, full spelling
		"2001:db8:1:2:abff:ffff:ffff:ffff", // last address of the range
	}
	outside := []string{
		"2001:db8:1:2:ab7f:ffff:ffff:ffff", // immediately below the range
		"2001:db8:1:2:ac00::",              // immediately above the range
		"2001:db8:1:2:ac00:0:0:0",          // immediately above, full spelling
		"2001:db8:1:1::",                   // a different IPv6 network
		"2001:db8:1:2::1",                  // fifth group zero: outside ab80..abff
		"fe80::1",                          // link-local
		"::1",                              // loopback
		"192.0.2.1",                        // an IPv4 source never matches IPv6
	}
	for _, ip := range inside {
		if !filter.admits(ip) {
			t.Errorf("%s must admit range address %q", hexBoundaryCanonical, ip)
		}
	}
	for _, ip := range outside {
		if filter.admits(ip) {
			t.Errorf("%s must not admit %q", hexBoundaryCanonical, ip)
		}
	}
	// An absent source is never admitted.
	if filter.admits("") {
		t.Errorf("an absent source_ip must never be admitted by %s", filter)
	}
}

// TestSourceCIDRFilterIPv6HexBoundarySpellingsAgree pins that every
// equivalent spelling of the /73 network parses to the one canonical network
// and admits exactly the same probe set as the documented spelling.
func TestSourceCIDRFilterIPv6HexBoundarySpellingsAgree(t *testing.T) {
	reference, err := ParseSourceCIDRFilter(hexBoundaryCIDR)
	if err != nil {
		t.Fatal(err)
	}
	probes := []string{
		"2001:db8:1:2:ab7f:ffff:ffff:ffff",
		"2001:db8:1:2:ab80::",
		"2001:db8:1:2:ab9a::1",
		"2001:db8:1:2:abff::1234",
		"2001:db8:1:2:abff:ffff:ffff:ffff",
		"2001:db8:1:2:ac00::",
		"2001:db8:0001:0002:abff:0000:0000:1234",
		"fe80::1",
		"192.0.2.1",
		"",
	}
	for _, spelled := range hexBoundarySpellings {
		f, err := ParseSourceCIDRFilter(spelled)
		if err != nil {
			t.Fatalf("ParseSourceCIDRFilter(%q) unexpected error: %v", spelled, err)
		}
		if got := f.String(); got != hexBoundaryCanonical {
			t.Fatalf("spelling %q must canonicalize to %q, got %q", spelled, hexBoundaryCanonical, got)
		}
		for _, probe := range probes {
			if f.admits(probe) != reference.admits(probe) {
				t.Fatalf("spelling %q disagrees with %q on probe %q", spelled, hexBoundaryCIDR, probe)
			}
		}
	}
}

// TestSourceCIDRFilterIPv6HexBoundaryStreamBehavior is the headline mixed
// batch under the /73 filter: boundary hits (first/last/interior, compressed
// and full spellings, via source_ip and src_ip), the two just-outside
// addresses, a blank line, and a just-outside line whose timestamp is
// invalid. Only the in-range successes are emitted, in input order with their
// original physical line numbers and full content (timestamp, action, extra)
// and no filter marker; dropped lines and the blank line never renumber later
// records; the invalid outside line keeps its line number and timestamp
// reason with no event and counts as exactly one failure, while the legal
// hit after it still emits.
func TestSourceCIDRFilterIPv6HexBoundaryStreamBehavior(t *testing.T) {
	filter, err := ParseSourceCIDRFilter(hexBoundaryCIDR)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		// line 1: range first address, standard name.
		`{"timestamp":` + validTS + `,"action":"range-first","source_ip":"2001:db8:1:2:ab80::"}`,
		// line 2: interior address via the alias, full spelling.
		`{"timestamp":` + validTS + `,"action":"interior-full","src_ip":"2001:db8:1:2:ab9a:0:0:1","trace":"t-7"}`,
		// line 3: the host the option was spelled with, compressed.
		`{"timestamp":` + validTS + `,"action":"spelled-host","source_ip":"2001:db8:1:2:abff::1234"}`,
		// line 4: range last address.
		`{"timestamp":` + validTS + `,"action":"range-last","source_ip":"2001:db8:1:2:abff:ffff:ffff:ffff"}`,
		// line 5: immediately below the range -> dropped success.
		`{"timestamp":` + validTS + `,"action":"just-below","source_ip":"2001:db8:1:2:ab7f:ffff:ffff:ffff"}`,
		// line 6: immediately above the range -> dropped success.
		`{"timestamp":` + validTS + `,"action":"just-above","source_ip":"2001:db8:1:2:ac00::"}`,
		// line 7: another IPv6 network -> dropped success.
		`{"timestamp":` + validTS + `,"action":"other-v6","source_ip":"2001:db8:1:1::1"}`,
		// line 8: an IPv4 source never matches the IPv6 network -> dropped.
		`{"timestamp":` + validTS + `,"action":"plain-v4","source_ip":"192.0.2.1"}`,
		// line 9: absent source -> dropped.
		`{"timestamp":` + validTS + `,"action":"no-source"}`,
		// line 10: blank -> skipped, still counts.
		"",
		// line 11: immediately outside the range with an invalid timestamp ->
		// failure, not a filtered success.
		`{"timestamp":"not-a-time","action":"broken-outside","source_ip":"2001:db8:1:2:ac00::"}`,
		// line 12: legal in-range hit after the failure, with extra evidence.
		`{"timestamp":` + validTS + `,"action":"tail-hit","src_ip":"2001:db8:1:2:abff:0:0:1234","keep":{"n":2}}`,
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &filter)

	if failures != 1 {
		t.Fatalf("the one malformed outside line must count as a failure; filtered successes must not, got %d", failures)
	}
	if len(results) != 6 {
		t.Fatalf("expected 5 admitted successes + 1 failure = 6 records, got %d: %#v", len(results), results)
	}

	want := []struct {
		line     float64
		ok       bool
		action   string
		sourceIP string
	}{
		{1, true, "range-first", "2001:db8:1:2:ab80::"},
		{2, true, "interior-full", "2001:db8:1:2:ab9a::1"},
		{3, true, "spelled-host", "2001:db8:1:2:abff::1234"},
		{4, true, "range-last", "2001:db8:1:2:abff:ffff:ffff:ffff"},
		{11, false, "broken-outside", ""},
		{12, true, "tail-hit", "2001:db8:1:2:abff::1234"},
	}
	for i, w := range want {
		got := results[i]
		if got["line"] != w.line || got["ok"] != w.ok {
			t.Fatalf("record %d mismatch: want line=%v ok=%v, got %#v", i, w.line, w.ok, got)
		}
		if _, marked := got["filtered"]; marked {
			t.Fatalf("record %d must carry no filter marker: %#v", i, got)
		}
		if !w.ok {
			if _, exists := got["event"]; exists {
				t.Fatalf("the outside malformed line must carry no event: %#v", got)
			}
			if msg, _ := got["error"].(string); !strings.Contains(msg, FieldTimestamp) {
				t.Fatalf("the failure must keep its original timestamp reason, got %q", msg)
			}
			continue
		}
		event := eventOf(t, got)
		if event["action"] != w.action || event["source_ip"] != w.sourceIP {
			t.Fatalf("record %d event mismatch: %#v", i, event)
		}
		if event["timestamp"] != "2026-01-02T00:00:00Z" {
			t.Fatalf("record %d timestamp must normalize as without the filter, got %v", i, event["timestamp"])
		}
	}

	// extra fields survive the filter exactly as in the unfiltered output.
	if got := eventOf(t, results[1])["extra"].(map[string]any)["trace"]; got != "t-7" {
		t.Fatalf("extra fields of an admitted alias line must survive filtering, got %#v", got)
	}
	if got := eventOf(t, results[5])["extra"].(map[string]any)["keep"].(map[string]any)["n"]; got != float64(2) {
		t.Fatalf("nested extra content of an admitted line must survive filtering, got %#v", got)
	}
}

// TestSourceCIDRFilterIPv6HexBoundaryAdmittedRecordsMatchUnfiltered pins
// that filtering changes nothing about an admitted record: the in-range
// events are byte-for-byte the same records an unfiltered run emits for the
// same lines.
func TestSourceCIDRFilterIPv6HexBoundaryAdmittedRecordsMatchUnfiltered(t *testing.T) {
	inRangeLines := []string{
		`{"timestamp":` + validTS + `,"action":"a","source_ip":"2001:db8:1:2:ab80::"}`,
		`{"timestamp":` + validTS + `,"action":"b","src_ip":"2001:db8:0001:0002:abff:0000:0000:1234"}`,
		`{"timestamp":` + validTS + `,"action":"c","source_ip":"2001:db8:1:2:abff:ffff:ffff:ffff"}`,
	}
	outOfRangeLine := `{"timestamp":` + validTS + `,"action":"x","source_ip":"2001:db8:1:2:ac00::"}`

	filter, err := ParseSourceCIDRFilter(hexBoundaryCIDR)
	if err != nil {
		t.Fatal(err)
	}
	// Interleave one dropped out-of-range success between the hits.
	filteredInput := strings.Join([]string{inRangeLines[0], outOfRangeLine, inRangeLines[1], inRangeLines[2]}, "\n") + "\n"
	results, failures := runNormalizeFiltered(t, filteredInput, &filter)
	if failures != 0 || len(results) != 3 {
		t.Fatalf("three in-range hits and one dropped success: got %#v failures=%d", results, failures)
	}
	// The unfiltered control runs the very same batch: the dropped line is an
	// ordinary success there, but each admitted record must equal its
	// corresponding unfiltered record on the same physical line.
	unfiltered := runNormalize(t, filteredInput)
	if len(unfiltered) != 4 {
		t.Fatalf("unfiltered control should have four records: %#v", unfiltered)
	}
	byLine := make(map[float64]map[string]any, len(unfiltered))
	for _, r := range unfiltered {
		byLine[r["line"].(float64)] = r
	}
	for _, got := range results {
		want, ok := byLine[got["line"].(float64)]
		if !ok {
			t.Fatalf("no unfiltered counterpart for admitted record %#v", got)
		}
		if !jsonEqualResult(got, want) {
			t.Fatalf("admitted record must equal its unfiltered counterpart:\nfiltered:   %#v\nunfiltered: %#v", got, want)
		}
	}
}

// TestSourceCIDRFilterIPv6HexBoundaryAliasMergeAndConflict pins that the
// standard name/alias behavior is untouched at this boundary: equivalent
// compressed/full spellings of one in-range address merge into one admitted
// normalized event, while two legal distinct addresses (one just inside, one
// just outside) are a counted conflict failure regardless of the filter, not
// a merge to the in-range value and not a silent drop.
func TestSourceCIDRFilterIPv6HexBoundaryAliasMergeAndConflict(t *testing.T) {
	filter, err := ParseSourceCIDRFilter(hexBoundaryCIDR)
	if err != nil {
		t.Fatal(err)
	}

	// Equivalent spellings (compressed alias + full canonical) merge.
	merged := joinObject([]kv{
		{key: FieldTimestamp, val: validTSLiteral},
		{key: FieldSourceIP, val: `"2001:db8:0001:0002:abff:0000:0000:1234"`},
		{key: "src_ip", val: `"2001:db8:1:2:abff::1234"`},
		{key: FieldAction, val: validActLiteral},
	})
	results, failures := runNormalizeFiltered(t, merged, &filter)
	if failures != 0 || len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("equivalent in-range spellings must merge into one admitted success: %#v failures=%d", results, failures)
	}
	if got := eventOf(t, results[0])["source_ip"]; got != "2001:db8:1:2:abff::1234" {
		t.Fatalf("merged source must normalize once, got %v", got)
	}

	// A just-inside and a just-outside legal address never merge; the line is
	// a conflict failure even though one value would be admitted on its own.
	conflictCases := [][2]string{
		{`"2001:db8:1:2:abff::1234"`, `"2001:db8:1:2:ac00::"`},
		{`"2001:db8:1:2:ac00::"`, `"2001:db8:1:2:ab80::"`},
	}
	for _, pair := range conflictCases {
		line := joinObject([]kv{
			{key: FieldTimestamp, val: validTSLiteral},
			{key: FieldSourceIP, val: pair[0]},
			{key: "src_ip", val: pair[1]},
			{key: FieldAction, val: validActLiteral},
		})
		results, failures := runNormalizeFiltered(t, line, &filter)
		if failures != 1 || len(results) != 1 || results[0]["ok"] != false {
			t.Fatalf("distinct legal sources must be one counted conflict: %s -> %#v failures=%d", line, results, failures)
		}
		if _, exists := results[0]["event"]; exists {
			t.Fatalf("a conflict must carry no event: %#v", results[0])
		}
		msg, _ := results[0]["error"].(string)
		if !strings.Contains(msg, FieldSourceIP) || !strings.Contains(msg, "conflicting values") {
			t.Fatalf("reason must be a source_ip conflict, got %q", msg)
		}
	}
}

// TestSourceCIDRFilterIPv6HexBoundaryAllMissesCleanEmpty pins that a batch
// of valid logs whose sources all sit immediately outside the /73 network —
// plus a blank line and an absent source — ends normally with empty output
// and zero failures: a filtered success is not a failure and not an I/O
// fault.
func TestSourceCIDRFilterIPv6HexBoundaryAllMissesCleanEmpty(t *testing.T) {
	filter, err := ParseSourceCIDRFilter(hexBoundaryCIDR)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"timestamp":` + validTS + `,"action":"just-below","source_ip":"2001:db8:1:2:ab7f:ffff:ffff:ffff"}`,
		`{"timestamp":` + validTS + `,"action":"just-above","source_ip":"2001:db8:1:2:ac00::"}`,
		"",
		`{"timestamp":` + validTS + `,"action":"v4","source_ip":"192.0.2.1"}`,
		`{"timestamp":` + validTS + `,"action":"no-source"}`,
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &filter)
	if failures != 0 {
		t.Fatalf("all-valid input must have zero failures even when nothing is admitted, got %d", failures)
	}
	if len(results) != 0 {
		t.Fatalf("every valid log missed the network, so no record may be emitted, got %#v", results)
	}
}
