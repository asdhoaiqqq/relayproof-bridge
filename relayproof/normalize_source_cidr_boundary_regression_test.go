package relayproof

// Regression coverage for source networks whose prefix length does not fall
// on an IPv4 octet boundary: /12 splits the second octet, /17 splits the
// third, and /31 is the two-address network. These ranges pin the exact
// first and last admitted addresses, the neighbors just outside each edge,
// and the rule that a /31 keeps BOTH of its addresses — the network address
// and the broadcast address are ordinary members, never excluded. Beyond
// the edges, the file locks the shared behaviors every filter relies on:
// host bits in the argument never change the result, source_ip and src_ip
// follow one rule, plain IPv4 and its IPv4-mapped spellings admit and print
// identically, genuine IPv6 with the same trailing 32 bits never matches,
// an absent source never matches, and filtered-out lines never renumber,
// hide, or discount the lines around them.

import (
	"bytes"
	"strings"
	"testing"
)

// boundaryLog builds one valid log line whose source address arrives under
// the given key (source_ip or its alias src_ip).
func boundaryLog(action, key, source string) string {
	return `{"timestamp":"2026-01-02T00:00:00Z","action":"` + action + `","` + key + `":"` + source + `"}`
}

// boundaryAbsentLog is a valid log line with no source address at all.
const boundaryAbsentLog = `{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}`

// TestSourceCIDRFilterNonOctetBoundaryEdges pins the exact membership of the
// two mid-octet ranges: 172.16.5.9/12 admits 172.16.0.0 through
// 172.31.255.255 and 192.0.129.7/17 admits 192.0.128.0 through
// 192.0.255.255. Each edge address hits, the address one below the first
// and one above the last miss, and the host address spelled in the argument
// is an ordinary member. Mapped spellings of the edges share the IPv4
// result and print dotted; a genuine IPv6 spelling carrying the same
// trailing 32 bits and a missing source are silently filtered.
func TestSourceCIDRFilterNonOctetBoundaryEdges(t *testing.T) {
	cases := []struct {
		name       string
		network    string // argument spelling, host bits set on purpose
		first      string // first admitted address
		last       string // last admitted address
		before     string // first - 1: just outside
		after      string // last + 1: just outside
		mappedLow  string // ::ffff: spelling of first
		mappedHigh string // ::ffff: spelling of last
		compatTail string // genuine IPv6 whose tail equals first
	}{
		{
			name:       "prefix splits the second octet",
			network:    "172.16.5.9/12",
			first:      "172.16.0.0",
			last:       "172.31.255.255",
			before:     "172.15.255.255",
			after:      "172.32.0.0",
			mappedLow:  "::ffff:172.16.0.0",
			mappedHigh: "::ffff:172.31.255.255",
			compatTail: "::172.16.0.0",
		},
		{
			name:       "prefix splits the third octet",
			network:    "192.0.129.7/17",
			first:      "192.0.128.0",
			last:       "192.0.255.255",
			before:     "192.0.127.255",
			after:      "192.1.0.0",
			mappedLow:  "::ffff:192.0.128.0",
			mappedHigh: "::ffff:192.0.255.255",
			compatTail: "::192.0.128.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := ParseSourceCIDRFilter(tc.network)
			if err != nil {
				t.Fatal(err)
			}
			host := strings.SplitN(tc.network, "/", 2)[0]
			input := strings.Join([]string{
				boundaryLog("just-below", "source_ip", tc.before),      // line 1 dropped
				boundaryLog("range-first", "source_ip", tc.first),      // line 2 kept
				boundaryLog("spelled-host", "source_ip", host),         // line 3 kept
				boundaryLog("range-last", "source_ip", tc.last),        // line 4 kept
				boundaryLog("just-above", "source_ip", tc.after),       // line 5 dropped
				boundaryLog("mapped-first", "source_ip", tc.mappedLow), // line 6 kept
				boundaryLog("mapped-last", "source_ip", tc.mappedHigh), // line 7 kept
				boundaryLog("compat-v6", "source_ip", tc.compatTail),   // line 8 dropped (IPv6)
				boundaryAbsentLog, // line 9 dropped (absent)
			}, "\n") + "\n"

			results, failures := runNormalizeFiltered(t, input, &filter)
			if failures != 0 {
				t.Fatalf("every line is valid, so nothing may count as a failure, got %d", failures)
			}
			if len(results) != 5 {
				t.Fatalf("expected the five in-range events (lines 2,3,4,6,7), got %#v", results)
			}
			want := []struct {
				line   float64
				action string
				source string
			}{
				{2, "range-first", tc.first},
				{3, "spelled-host", host},
				{4, "range-last", tc.last},
				{6, "mapped-first", tc.first}, // mapped spelling prints dotted
				{7, "mapped-last", tc.last},
			}
			for i, w := range want {
				got := results[i]
				if got["line"] != w.line || got["ok"] != true {
					t.Fatalf("record %d must be the physical line %v success: %#v", i, w.line, got)
				}
				event := eventOf(t, got)
				if event["action"] != w.action || event["source_ip"] != w.source {
					t.Fatalf("record %d event mismatch: %#v", i, event)
				}
				if _, exists := got["filtered"]; exists {
					t.Fatalf("results must carry no filter marker: %#v", got)
				}
			}
		})
	}
}

// TestSourceCIDRFilterSlash31KeepsBothAddresses pins the two-address network:
// 192.0.2.3/31 is the pair 192.0.2.2-192.0.2.3, and BOTH addresses are
// admitted — the filter performs pure range membership and does not carve
// out the network or broadcast address. The neighbors 192.0.2.1 and
// 192.0.2.4 fall outside.
func TestSourceCIDRFilterSlash31KeepsBothAddresses(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.3/31")
	if err != nil {
		t.Fatal(err)
	}
	if got := filter.String(); got != "192.0.2.2/31" {
		t.Fatalf("the host bit in 192.0.2.3/31 must mask away to 192.0.2.2/31, got %s", got)
	}
	input := strings.Join([]string{
		boundaryLog("just-below", "source_ip", "192.0.2.1"),           // line 1 dropped
		boundaryLog("network-address", "source_ip", "192.0.2.2"),      // line 2 kept
		boundaryLog("broadcast-address", "src_ip", "192.0.2.3"),       // line 3 kept
		boundaryLog("mapped-member", "source_ip", "::ffff:192.0.2.2"), // line 4 kept
		boundaryLog("just-above", "source_ip", "192.0.2.4"),           // line 5 dropped
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &filter)
	if failures != 0 {
		t.Fatalf("every line is valid, so nothing may count as a failure, got %d", failures)
	}
	if len(results) != 3 {
		t.Fatalf("a /31 must keep both of its addresses (and their mapped spellings), got %#v", results)
	}
	want := []struct {
		line   float64
		source string
	}{
		{2, "192.0.2.2"}, // the network address is an ordinary member
		{3, "192.0.2.3"}, // so is the broadcast address of the pair
		{4, "192.0.2.2"}, // mapped spelling of the network address prints dotted
	}
	for i, w := range want {
		got := results[i]
		if got["line"] != w.line || got["ok"] != true {
			t.Fatalf("record %d must be the physical line %v success: %#v", i, w.line, got)
		}
		if event := eventOf(t, got); event["source_ip"] != w.source {
			t.Fatalf("record %d source mismatch: %#v", i, event)
		}
	}
}

// TestSourceCIDRFilterHostSpellingEquivalence pins that the host part of the
// argument is documentation, not selection: every in-range spelling of one
// network canonicalizes to the same filter and therefore produces
// byte-identical output on the same input.
func TestSourceCIDRFilterHostSpellingEquivalence(t *testing.T) {
	input := strings.Join([]string{
		boundaryLog("a", "source_ip", "172.16.0.0"),
		boundaryLog("b", "source_ip", "172.31.255.255"),
		boundaryLog("c", "source_ip", "172.15.255.255"),
		boundaryLog("d", "source_ip", "172.32.0.0"),
		boundaryLog("e", "source_ip", "192.0.128.0"),
		boundaryLog("f", "source_ip", "192.0.255.255"),
		boundaryLog("g", "source_ip", "192.0.127.255"),
		boundaryLog("h", "source_ip", "192.1.0.0"),
		boundaryLog("i", "source_ip", "192.0.2.2"),
		boundaryLog("j", "source_ip", "192.0.2.3"),
		boundaryLog("k", "source_ip", "192.0.2.1"),
		boundaryLog("l", "source_ip", "192.0.2.4"),
	}, "\n") + "\n"

	groups := [][]string{
		{"172.16.5.9/12", "172.31.200.1/12", "172.16.0.0/12"},
		{"192.0.129.7/17", "192.0.255.255/17", "192.0.128.0/17"},
		{"192.0.2.3/31", "192.0.2.2/31"},
	}
	for _, group := range groups {
		var reference string
		for i, spelling := range group {
			filter, err := ParseSourceCIDRFilter(spelling)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			failures, err := NormalizeReaderFiltered(strings.NewReader(input), &out, &filter)
			if err != nil || failures != 0 {
				t.Fatalf("filter %s must run cleanly: failures=%d err=%v", spelling, failures, err)
			}
			if i == 0 {
				reference = out.String()
				continue
			}
			if out.String() != reference {
				t.Fatalf("spellings %s and %s of one network must filter identically:\n%s\nvs\n%s",
					group[0], spelling, reference, out.String())
			}
		}
	}
}

// TestSourceCIDRFilterBoundaryAliasAndMappedEquivalence pins that the edge
// rule is stated once and applied everywhere: a boundary address admitted
// (or rejected) as source_ip is admitted (or rejected) identically as
// src_ip, and a plain IPv4 edge and its IPv4-mapped spelling — including an
// uppercase hex form — share one decision and one dotted output. Genuine
// IPv6 spellings carrying the same trailing 32 bits stay out.
func TestSourceCIDRFilterBoundaryAliasAndMappedEquivalence(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("172.16.5.9/12")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		boundaryLog("plain-last", "source_ip", "172.31.255.255"),         // line 1 kept
		boundaryLog("alias-last", "src_ip", "172.31.255.255"),            // line 2 kept
		boundaryLog("mapped-last", "source_ip", "::ffff:172.31.255.255"), // line 3 kept
		boundaryLog("mapped-hex", "src_ip", "::FFFF:AC1F:FFFF"),          // line 4 kept
		boundaryLog("plain-above", "source_ip", "172.32.0.0"),            // line 5 dropped
		boundaryLog("alias-mapped-above", "src_ip", "::ffff:172.32.0.0"), // line 6 dropped
		boundaryLog("compat-v6", "source_ip", "::172.31.255.255"),        // line 7 dropped (IPv6)
		boundaryLog("global-v6", "src_ip", "2001:db8::ac1f:ffff"),        // line 8 dropped (IPv6)
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &filter)
	if failures != 0 {
		t.Fatalf("every line is valid, so nothing may count as a failure, got %d", failures)
	}
	if len(results) != 4 {
		t.Fatalf("the four IPv4 spellings of the range edge must survive, got %#v", results)
	}
	for i, got := range results {
		if got["line"] != float64(i+1) || got["ok"] != true {
			t.Fatalf("record %d must be the physical line %d success: %#v", i, i+1, got)
		}
		if event := eventOf(t, got); event["source_ip"] != "172.31.255.255" {
			t.Fatalf("record %d must print the shared dotted edge address: %#v", i, event)
		}
	}
}

// TestSourceCIDRFilterBoundaryStreamBookkeeping pins the streaming contract
// around a mid-octet edge: admitted successes keep input order and their
// physical line numbers, dropped valid lines and blank lines renumber
// nothing and add no failure, a time-invalid line just outside the range
// still fails with its reason and no event, later in-range lines keep
// processing, and surviving events keep the standard normalization (alias
// mapping, UTC conversion, action trimming) and their extra fields with no
// filter marker.
func TestSourceCIDRFilterBoundaryStreamBookkeeping(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.129.7/17") // 192.0.128.0 - 192.0.255.255
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"time":"2026-01-02T08:04:05+08:00","event_type":"  login  ","src_ip":"192.0.128.0","user":"alice"}`, // line 1 kept
		boundaryLog("just-below", "source_ip", "192.0.127.255"),                                               // line 2 dropped
		``, // line 3 blank
		`{"timestamp":"not-a-time","action":"broken","source_ip":"192.0.127.255"}`, // line 4 failure, out of range
		boundaryLog("range-last", "source_ip", "192.0.255.255"),                    // line 5 kept
		boundaryLog("just-above", "source_ip", "192.1.0.0"),                        // line 6 dropped
		boundaryLog("mapped-inside", "src_ip", "::ffff:192.0.200.1"),               // line 7 kept
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &filter)
	if failures != 1 {
		t.Fatalf("only the time-invalid line 4 may count as a failure, got %d", failures)
	}
	if len(results) != 4 {
		t.Fatalf("expected 3 admitted successes + 1 failure, got %#v", results)
	}

	// Input order and physical line numbers survive the dropped lines and
	// the blank line.
	wantLines := []float64{1, 4, 5, 7}
	for i, line := range wantLines {
		if results[i]["line"] != line {
			t.Fatalf("record %d must carry physical line %v: %#v", i, line, results[i])
		}
	}

	// The kept successes normalize exactly as an unfiltered run and keep
	// their extension fields; the filter adds no marker of its own.
	first := eventOf(t, results[0])
	if first["timestamp"] != "2026-01-02T00:04:05Z" || first["action"] != "login" || first["source_ip"] != "192.0.128.0" {
		t.Fatalf("standard fields must normalize as without a filter: %#v", first)
	}
	extra, ok := first["extra"].(map[string]any)
	if !ok || extra["user"] != "alice" {
		t.Fatalf("the kept event must preserve its extra fields: %#v", first)
	}
	if eventOf(t, results[2])["source_ip"] != "192.0.255.255" {
		t.Fatalf("the range's last address must survive: %#v", results[2])
	}
	if eventOf(t, results[3])["source_ip"] != "192.0.200.1" {
		t.Fatalf("the mapped in-range source must print dotted: %#v", results[3])
	}
	for i, r := range results {
		if _, exists := r["filtered"]; exists {
			t.Fatalf("record %d must carry no filter marker: %#v", i, r)
		}
	}

	// The out-of-range line with an invalid time is a failure like any
	// other: physical line number, original reason, no event — and it does
	// not stop the in-range lines after it.
	failure := results[1]
	if failure["ok"] != false {
		t.Fatalf("the time-invalid line must fail even outside the range: %#v", failure)
	}
	if _, exists := failure["event"]; exists {
		t.Fatalf("the failure record must carry no event: %#v", failure)
	}
	if msg, _ := failure["error"].(string); !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("the failure must keep its timestamp reason, got %q", msg)
	}
}

// TestSourceCIDRFilterBoundaryAllMissesEmptyResult pins the quiet end case:
// a batch of valid logs that all fall outside the network — just beyond
// each edge, a genuine IPv6 lookalike, and a source-less event — ends
// normally with an empty result and a zero failure count.
func TestSourceCIDRFilterBoundaryAllMissesEmptyResult(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("172.16.5.9/12")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		boundaryLog("just-below", "source_ip", "172.15.255.255"),
		boundaryLog("just-above", "source_ip", "172.32.0.0"),
		boundaryLog("compat-v6", "source_ip", "::172.16.0.0"),
		boundaryLog("global-v6", "src_ip", "2001:db8::ac10:0"),
		boundaryAbsentLog,
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &filter)
	if failures != 0 {
		t.Fatalf("valid-but-unmatched logs are not failures, got %d", failures)
	}
	if len(results) != 0 {
		t.Fatalf("no log matched the network, so no record may be emitted, got %#v", results)
	}
}
