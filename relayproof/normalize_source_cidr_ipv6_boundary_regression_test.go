package relayproof

// Regression coverage for an IPv6 source network whose prefix length does not
// fall on a hex-digit boundary, where a mask computed against the wrong
// digit silently widens or narrows the admitted range:
//
//   - 2001:db8:1:2:abff::1234/73 admits exactly
//     2001:db8:1:2:ab80:: - 2001:db8:1:2:abff:ffff:ffff:ffff. The prefix
//     keeps 9 bits of the fifth group, so the boundary sits inside the
//     third hex digit of "abff" (0xabff masked down to 0xab80): both range
//     ends are admitted, the addresses immediately before and after the
//     range are not.
//
// Spelling the same network with a different in-range host address — or
// with the full uncompressed IPv6 form of one — changes neither the
// canonical network nor the selection. A boundary source arrives through
// source_ip or src_ip interchangeably, and compressed and full spellings
// of one source share one decision and one normalized output form. Dropped
// lines and blank lines never renumber later records, an out-of-range line
// with an invalid timestamp is still a counted failure with its reason and
// no event, and a batch in which every valid log misses the network ends
// cleanly with empty output and zero failures.

import (
	"strings"
	"testing"
)

// TestSourceCIDRFilterIPv6HexDigitBoundaryMembership pins the exact
// admitted range of the /73 network against the normalized-address strings
// the filter actually compares.
func TestSourceCIDRFilterIPv6HexDigitBoundaryMembership(t *testing.T) {
	f, err := ParseSourceCIDRFilter("2001:db8:1:2:abff::1234/73")
	if err != nil {
		t.Fatalf("ParseSourceCIDRFilter unexpected error: %v", err)
	}
	if got := f.String(); got != "2001:db8:1:2:ab80::/73" {
		t.Fatalf("host bits must be masked to the canonical network, got %q", got)
	}
	inside := []string{
		"2001:db8:1:2:ab80::",              // first address of the range
		"2001:db8:1:2:ab80:1:2:3",          // interior address
		"2001:db8:1:2:abff::1234",          // the host the option was spelled with
		"2001:db8:1:2:abff:ffff:ffff:ffff", // last address of the range
	}
	outside := []string{
		"2001:db8:1:2:ab7f:ffff:ffff:ffff", // immediately below the range
		"2001:db8:1:2:ac00::",              // immediately above the range
		"2001:db8:1:3::1",                  // a different network entirely
	}
	for _, ip := range inside {
		if !f.admits(ip) {
			t.Errorf("2001:db8:1:2:ab80::/73 must admit range address %q", ip)
		}
	}
	for _, ip := range outside {
		if f.admits(ip) {
			t.Errorf("2001:db8:1:2:ab80::/73 must not admit %q", ip)
		}
	}
}

// TestSourceCIDRFilterIPv6BoundarySpellingsAgree pins that writing the same
// /73 network with a different in-range host address — including the
// range's own first and last addresses and the full uncompressed spelling
// of the original host — parses to the same canonical network and admits
// exactly the same sources.
func TestSourceCIDRFilterIPv6BoundarySpellingsAgree(t *testing.T) {
	const canonical = "2001:db8:1:2:ab80::/73"
	spellings := []string{
		"2001:db8:1:2:abff::1234/73",                // the original host spelling
		"2001:db8:1:2:ab80::/73",                    // the canonical network itself
		"2001:db8:1:2:abff:ffff:ffff:ffff/73",       // the last address of the range
		"2001:db8:1:2:ab95:dead:beef:1/73",          // another in-range host
		"2001:db8:0001:0002:abff:0000:0000:1234/73", // full spelling of the original host
	}
	probes := []string{
		"2001:db8:1:2:ab7f:ffff:ffff:ffff",
		"2001:db8:1:2:ab80::",
		"2001:db8:1:2:ab80:1:2:3",
		"2001:db8:1:2:abff:ffff:ffff:ffff",
		"2001:db8:1:2:ac00::",
		"2001:db8:1:3::1",
	}
	reference, err := ParseSourceCIDRFilter(canonical)
	if err != nil {
		t.Fatal(err)
	}
	for _, spelled := range spellings {
		f, err := ParseSourceCIDRFilter(spelled)
		if err != nil {
			t.Fatalf("ParseSourceCIDRFilter(%q) unexpected error: %v", spelled, err)
		}
		if got := f.String(); got != canonical {
			t.Fatalf("spelling %q must canonicalize to %q, got %q", spelled, canonical, got)
		}
		for _, probe := range probes {
			if f.admits(probe) != reference.admits(probe) {
				t.Fatalf("spelling %q disagrees with %q on %q", spelled, canonical, probe)
			}
		}
	}
}

// TestSourceCIDRFilterIPv6BoundaryStreamBehavior drives a mixed stream
// through the /73 filter: range-edge hits through source_ip and src_ip, a
// full uncompressed spelling of the last range address, the just-outside
// addresses, an absent source, a blank line, and a just-outside line whose
// timestamp is invalid. The admitted events keep input order, physical
// line numbers, their normalized compressed source and their extra fields
// with no filter marker; the invalid line is a counted failure with its
// reason and no event; everything else leaves no trace.
func TestSourceCIDRFilterIPv6BoundaryStreamBehavior(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("2001:db8:1:2:abff::1234/73")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"timestamp":` + validTS + `,"action":"range-first","source_ip":"2001:db8:1:2:ab80::"}`,                        // line 1 admitted
		`{"timestamp":` + validTS + `,"action":"range-last","src_ip":"2001:db8:1:2:abff:ffff:ffff:ffff","trace":"t-9"}`, // line 2 admitted via alias
		`{"timestamp":` + validTS + `,"action":"full-spelling","source_ip":"2001:db8:0001:0002:abff:0000:0000:1234"}`,   // line 3 admitted, prints compressed
		`{"timestamp":` + validTS + `,"action":"just-below","source_ip":"2001:db8:1:2:ab7f:ffff:ffff:ffff"}`,            // line 4 dropped
		`{"timestamp":` + validTS + `,"action":"just-above","source_ip":"2001:db8:1:2:ac00::"}`,                         // line 5 dropped
		`{"timestamp":` + validTS + `,"action":"no-source"}`,                                                            // line 6 dropped (absent)
		``, // line 7 blank
		`{"timestamp":"not-a-time","action":"broken-outside","source_ip":"2001:db8:1:2:ac00::"}`,              // line 8 failure
		`{"timestamp":` + validTS + `,"action":"tail-hit","source_ip":"2001:db8:1:2:ab95::7","keep":{"n":2}}`, // line 9 admitted
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &filter)

	if failures != 1 {
		t.Fatalf("the invalid line must count as one failure even though its source is out of range, got %d", failures)
	}
	if len(results) != 5 {
		t.Fatalf("expected 4 admitted successes + 1 failure = 5 records, got %d: %#v", len(results), results)
	}

	want := []struct {
		line     float64
		ok       bool
		action   string
		sourceIP string
	}{
		{1, true, "range-first", "2001:db8:1:2:ab80::"},
		{2, true, "range-last", "2001:db8:1:2:abff:ffff:ffff:ffff"},
		{3, true, "full-spelling", "2001:db8:1:2:abff::1234"}, // full spelling prints compressed
		{8, false, "broken-outside", ""},
		{9, true, "tail-hit", "2001:db8:1:2:ab95::7"},
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
				t.Fatalf("the out-of-range invalid line must carry no event: %#v", got)
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
	}

	// Field normalization and extra preservation are exactly the unfiltered
	// behavior: the alias-sourced line keeps its extra string, the trailing
	// hit keeps its nested object.
	if got := eventOf(t, results[1])["extra"].(map[string]any)["trace"]; got != "t-9" {
		t.Fatalf("extra fields of an admitted alias line must survive filtering, got %#v", got)
	}
	if got := eventOf(t, results[4])["extra"].(map[string]any)["keep"].(map[string]any)["n"]; got != float64(2) {
		t.Fatalf("nested extra content of an admitted line must survive filtering, got %#v", got)
	}
}

// TestSourceCIDRFilterIPv6BoundaryAllMissesCleanEmpty pins that a batch of
// valid logs whose sources all fall immediately outside the /73 range — or
// are absent — ends normally: no records, zero failures.
func TestSourceCIDRFilterIPv6BoundaryAllMissesCleanEmpty(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("2001:db8:1:2:abff::1234/73")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"timestamp":` + validTS + `,"action":"just-below","source_ip":"2001:db8:1:2:ab7f:ffff:ffff:ffff"}`,
		`{"timestamp":` + validTS + `,"action":"just-above","source_ip":"2001:db8:1:2:ac00::"}`,
		`{"timestamp":` + validTS + `,"action":"no-source"}`,
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &filter)
	if failures != 0 {
		t.Fatalf("an all-valid batch must have zero failures even when nothing is admitted, got %d", failures)
	}
	if len(results) != 0 {
		t.Fatalf("every valid log missed the network, so no record may be emitted, got %#v", results)
	}
}
