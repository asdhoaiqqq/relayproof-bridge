package relayproof

// Regression coverage for source networks whose prefix length does not fall
// on an IPv4 octet boundary, where a mask computed against the wrong octet
// silently widens or narrows the admitted range:
//
//   - 172.16.5.9/12 admits exactly 172.16.0.0 - 172.31.255.255 (the boundary
//     sits inside the second octet): both range ends are admitted, the
//     addresses immediately before and after the range are not.
//   - 192.0.129.7/17 admits exactly 192.0.128.0 - 192.0.255.255 (the boundary
//     sits inside the third octet), with the same edge behavior.
//   - 192.0.2.3/31 is the two-address network 192.0.2.2 - 192.0.2.3: both
//     addresses take part in filtering — neither is set aside as a network or
//     broadcast address — while 192.0.2.1 and 192.0.2.4 stay out.
//
// Spelling the same network with a different in-range host address changes
// nothing, a boundary source arrives through source_ip or src_ip
// interchangeably, and a plain IPv4 address and its IPv4-mapped IPv6 spelling
// share one decision and one dotted output form, while a genuine IPv6 source
// with the same trailing 32 bits never matches. Dropped lines and blank lines
// never renumber later records, an out-of-range line with an invalid
// timestamp is still a counted failure with its reason and no event, and a
// batch in which every valid log misses the network ends cleanly with empty
// output and zero failures.

import (
	"strings"
	"testing"
)

// boundaryRangeCase pins one non-octet-aligned network: its canonical form
// plus the addresses that must and must not be admitted.
type boundaryRangeCase struct {
	name      string
	spelled   string // one host-spelled form of the network
	canonical string
	inside    []string
	outside   []string
}

// boundaryRanges lists the three networks under test with their exact edge
// addresses and the addresses immediately outside each edge.
var boundaryRanges = []boundaryRangeCase{
	{
		name:      "second-octet boundary /12",
		spelled:   "172.16.5.9/12",
		canonical: "172.16.0.0/12",
		inside: []string{
			"172.16.0.0",     // first address of the range
			"172.16.5.9",     // the host the option was spelled with
			"172.31.255.255", // last address of the range
		},
		outside: []string{
			"172.15.255.255", // immediately below the range
			"172.32.0.0",     // immediately above the range
			"10.0.0.1",       // a different private network entirely
		},
	},
	{
		name:      "third-octet boundary /17",
		spelled:   "192.0.129.7/17",
		canonical: "192.0.128.0/17",
		inside: []string{
			"192.0.128.0",   // first address of the range
			"192.0.129.7",   // the host the option was spelled with
			"192.0.255.255", // last address of the range
		},
		outside: []string{
			"192.0.127.255", // immediately below the range
			"192.1.0.0",     // immediately above the range
		},
	},
	{
		name:      "two-address network /31",
		spelled:   "192.0.2.3/31",
		canonical: "192.0.2.2/31",
		inside: []string{
			"192.0.2.2", // not set aside as a network address
			"192.0.2.3", // not set aside as a broadcast address
		},
		outside: []string{
			"192.0.2.1", // immediately below the pair
			"192.0.2.4", // immediately above the pair
		},
	},
}

// TestSourceCIDRFilterNonOctetBoundaryMembership pins the exact admitted
// range of each boundary network against the normalized-address strings the
// filter actually compares.
func TestSourceCIDRFilterNonOctetBoundaryMembership(t *testing.T) {
	for _, tc := range boundaryRanges {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseSourceCIDRFilter(tc.spelled)
			if err != nil {
				t.Fatalf("ParseSourceCIDRFilter(%q) unexpected error: %v", tc.spelled, err)
			}
			if got := f.String(); got != tc.canonical {
				t.Fatalf("ParseSourceCIDRFilter(%q).String() = %q, want %q", tc.spelled, got, tc.canonical)
			}
			for _, ip := range tc.inside {
				if !f.admits(ip) {
					t.Errorf("%s must admit range address %q", tc.canonical, ip)
				}
			}
			for _, ip := range tc.outside {
				if f.admits(ip) {
					t.Errorf("%s must not admit %q", tc.canonical, ip)
				}
			}
		})
	}
}

// TestSourceCIDRFilterBoundaryHostSpellingsAgree pins that writing the same
// network with a different in-range host address — including the range's own
// first and last addresses — parses to the same canonical network and admits
// exactly the same sources.
func TestSourceCIDRFilterBoundaryHostSpellingsAgree(t *testing.T) {
	alternativeSpellings := map[string][]string{
		"172.16.0.0/12":  {"172.16.5.9/12", "172.31.255.255/12", "172.16.0.0/12"},
		"192.0.128.0/17": {"192.0.129.7/17", "192.0.255.255/17", "192.0.128.0/17"},
		"192.0.2.2/31":   {"192.0.2.3/31", "192.0.2.2/31"},
	}
	probes := []string{
		"172.15.255.255", "172.16.0.0", "172.31.255.255", "172.32.0.0",
		"192.0.127.255", "192.0.128.0", "192.0.255.255", "192.1.0.0",
		"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4",
	}
	for canonical, spellings := range alternativeSpellings {
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
				t.Fatalf("host spelling %q must canonicalize to %q, got %q", spelled, canonical, got)
			}
			for _, probe := range probes {
				if f.admits(probe) != reference.admits(probe) {
					t.Fatalf("host spelling %q disagrees with %q on %q", spelled, canonical, probe)
				}
			}
		}
	}
}

// TestSourceCIDRFilterBoundaryStreamBehavior drives a mixed stream through
// the /12 filter: range-edge hits through source_ip and src_ip, a mapped
// spelling of the first range address, the just-outside addresses, a genuine
// IPv6 source whose tail equals an in-range address, an absent source, a
// blank line, and an out-of-range line whose timestamp is invalid. The
// admitted events keep input order, physical line numbers, their normalized
// dotted source and their extra fields with no filter marker; the invalid
// line is a counted failure with its reason and no event; everything else
// leaves no trace.
func TestSourceCIDRFilterBoundaryStreamBehavior(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("172.16.5.9/12")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"timestamp":` + validTS + `,"action":"range-first","source_ip":"172.16.0.0"}`,               // line 1 admitted
		`{"timestamp":` + validTS + `,"action":"range-last","src_ip":"172.31.255.255","trace":"t-9"}`, // line 2 admitted via alias
		`{"timestamp":` + validTS + `,"action":"mapped-first","source_ip":"::ffff:172.16.0.0"}`,       // line 3 admitted, prints dotted
		`{"timestamp":` + validTS + `,"action":"just-below","source_ip":"172.15.255.255"}`,            // line 4 dropped
		`{"timestamp":` + validTS + `,"action":"just-above","source_ip":"172.32.0.0"}`,                // line 5 dropped
		`{"timestamp":` + validTS + `,"action":"v6-same-tail","source_ip":"::172.16.0.0"}`,            // line 6 dropped (genuine IPv6)
		`{"timestamp":` + validTS + `,"action":"no-source"}`,                                          // line 7 dropped (absent)
		``, // line 8 blank
		`{"timestamp":"not-a-time","action":"broken-outside","source_ip":"172.32.0.0"}`,             // line 9 failure
		`{"timestamp":` + validTS + `,"action":"tail-hit","source_ip":"172.16.5.9","keep":{"n":2}}`, // line 10 admitted
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
		{1, true, "range-first", "172.16.0.0"},
		{2, true, "range-last", "172.31.255.255"},
		{3, true, "mapped-first", "172.16.0.0"}, // mapped spelling prints the same dotted address
		{9, false, "broken-outside", ""},
		{10, true, "tail-hit", "172.16.5.9"},
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

// TestSourceCIDRFilterSlash31KeepsBothAddresses pins the two-address network:
// 192.0.2.3/31 admits both 192.0.2.2 and 192.0.2.3 — neither address is
// excluded as a network or broadcast address — while the immediate neighbors
// 192.0.2.1 and 192.0.2.4 are dropped. The same network spelled with its
// other host address selects identically.
func TestSourceCIDRFilterSlash31KeepsBothAddresses(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":` + validTS + `,"action":"below","source_ip":"192.0.2.1"}`,             // line 1 dropped
		`{"timestamp":` + validTS + `,"action":"low-of-pair","source_ip":"192.0.2.2"}`,       // line 2 admitted
		`{"timestamp":` + validTS + `,"action":"high-of-pair","src_ip":"192.0.2.3"}`,         // line 3 admitted via alias
		`{"timestamp":` + validTS + `,"action":"mapped-low","source_ip":"::ffff:192.0.2.2"}`, // line 4 admitted
		`{"timestamp":` + validTS + `,"action":"above","source_ip":"192.0.2.4"}`,             // line 5 dropped
	}, "\n") + "\n"

	var outputs []string
	for _, spelled := range []string{"192.0.2.3/31", "192.0.2.2/31"} {
		filter, err := ParseSourceCIDRFilter(spelled)
		if err != nil {
			t.Fatal(err)
		}
		results, failures := runNormalizeFiltered(t, input, &filter)
		if failures != 0 {
			t.Fatalf("filter %q: an all-valid batch must have zero failures, got %d", spelled, failures)
		}
		if len(results) != 3 {
			t.Fatalf("filter %q: both /31 addresses and the mapped spelling must survive, got %#v", spelled, results)
		}
		wantLines := []float64{2, 3, 4}
		wantActions := []string{"low-of-pair", "high-of-pair", "mapped-low"}
		wantSources := []string{"192.0.2.2", "192.0.2.3", "192.0.2.2"}
		for i := range wantLines {
			if results[i]["line"] != wantLines[i] || results[i]["ok"] != true {
				t.Fatalf("filter %q: record %d must keep physical line %v: %#v", spelled, i, wantLines[i], results[i])
			}
			event := eventOf(t, results[i])
			if event["action"] != wantActions[i] || event["source_ip"] != wantSources[i] {
				t.Fatalf("filter %q: record %d event mismatch: %#v", spelled, i, event)
			}
		}
		var rendered strings.Builder
		for _, r := range results {
			rendered.WriteString(eventOf(t, r)["action"].(string))
			rendered.WriteByte(';')
		}
		outputs = append(outputs, rendered.String())
	}
	if outputs[0] != outputs[1] {
		t.Fatalf("the two host spellings of one /31 must select identically: %q vs %q", outputs[0], outputs[1])
	}
}

// TestSourceCIDRFilterBoundaryAllMissesCleanEmpty pins that a batch of valid
// logs whose sources all fall immediately outside a boundary network — or are
// absent — ends normally: no records, zero failures.
func TestSourceCIDRFilterBoundaryAllMissesCleanEmpty(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.129.7/17")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"timestamp":` + validTS + `,"action":"just-below","source_ip":"192.0.127.255"}`,
		`{"timestamp":` + validTS + `,"action":"just-above","source_ip":"192.1.0.0"}`,
		`{"timestamp":` + validTS + `,"action":"v6-same-tail","source_ip":"::192.0.128.0"}`,
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
