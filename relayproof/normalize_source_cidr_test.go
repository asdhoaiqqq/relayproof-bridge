package relayproof

// Coverage for the optional IPv4 source network filter on the streaming
// entry point. The filter compares the fully normalized source_ip: plain
// IPv4 and IPv4-mapped IPv6 spellings share one result, genuine IPv6
// addresses (including ::192.0.2.1) never match, and host bits spelled in
// the network argument do not narrow the range. Filtering removes only
// successful events; failed lines are always emitted with their physical
// line number and original reason and still count as failures.

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// runNormalizeFiltered parses emitted results like runNormalize while
// reporting the failure count the entry point returned.
func runNormalizeFiltered(t *testing.T, input string, filter *SourceCIDRFilter) ([]map[string]any, int) {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReaderFiltered(strings.NewReader(input), &out, filter)
	if err != nil {
		t.Fatalf("NormalizeReaderFiltered returned error: %v", err)
	}
	var results []map[string]any
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decoding result: %v", err)
		}
		results = append(results, m)
	}
	if got := countFailures(results); got != failures {
		t.Fatalf("NormalizeReaderFiltered returned %d failures but output shows %d", failures, got)
	}
	return results, failures
}

// TestParseSourceCIDRFilterCanonicalization pins the documented grammar and
// the host-bit masking: two spellings of the same network parse to the same
// canonical string, regardless of the host part written.
func TestParseSourceCIDRFilterCanonicalization(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"192.0.2.0/24", "192.0.2.0/24"},
		{"192.0.2.123/24", "192.0.2.0/24"}, // host bits masked away
		{"192.0.2.1/32", "192.0.2.1/32"},
		{"255.255.255.255/32", "255.255.255.255/32"},
		{"0.0.0.0/0", "0.0.0.0/0"},
		{"255.255.255.255/0", "0.0.0.0/0"},
		{"10.20.30.40/8", "10.0.0.0/8"},
		{"10.20.30.40/16", "10.20.0.0/16"},
		{"172.16.5.9/12", "172.16.0.0/12"},
	}
	for _, tc := range cases {
		f, err := ParseSourceCIDRFilter(tc.in)
		if err != nil {
			t.Fatalf("ParseSourceCIDRFilter(%q) unexpected error: %v", tc.in, err)
		}
		if got := f.String(); got != tc.want {
			t.Fatalf("ParseSourceCIDRFilter(%q).String() = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestParseSourceCIDRFilterRejects pins what the option grammar refuses:
// only a dotted decimal IPv4 address, a slash, and a 0-32 prefix length.
func TestParseSourceCIDRFilterRejects(t *testing.T) {
	bad := []string{
		"",
		"192.0.2.0",       // no slash/length
		"192.0.2.0/",      // empty length
		"192.0.2.0/24/32", // extra segment
		"192.0.2/24",      // too few octets
		"192.0.2.0.1/24",  // too many octets
		"192.0.2.0/33",    // prefix too large
		"192.0.2.0/100",
		"192.0.2.0/-1",  // negative length
		"192.0.2.0/24x", // trailing junk
		"256.0.0.0/8",   // octet out of range
		"192.168.1.256/24",
		"192.168.001.1/24", // leading-zero padding
		"01.2.3.4/8",
		"192.0.2.1/024", // padded length
		"::1/128",       // IPv6 form
		"::ffff:192.0.2.0/120",
		"192.0.2.0/0x8", // non-decimal length
		"abc",
		"192.0.2.0/24 ", // trailing space
		" 192.0.2.0/24",
	}
	for _, in := range bad {
		if f, err := ParseSourceCIDRFilter(in); err == nil {
			t.Fatalf("ParseSourceCIDRFilter(%q) must fail, got filter %s", in, f)
		}
	}
}

// TestSourceCIDRFilterAdmitsNormalized checks the membership function
// against the exact strings that appear in normalized output.
func TestSourceCIDRFilterAdmitsNormalized(t *testing.T) {
	block, err := ParseSourceCIDRFilter("192.0.2.123/24")
	if err != nil {
		t.Fatal(err)
	}
	host, err := ParseSourceCIDRFilter("192.0.2.1/32")
	if err != nil {
		t.Fatal(err)
	}
	all, err := ParseSourceCIDRFilter("0.0.0.0/0")
	if err != nil {
		t.Fatal(err)
	}

	inside := []string{"192.0.2.0", "192.0.2.1", "192.0.2.123", "192.0.2.255"}
	outside := []string{
		"192.0.3.0", "198.51.100.1", "0.0.0.0", "255.255.255.255",
		// Normalized genuine IPv6 sources never match an IPv4 network,
		// even with the same trailing 32 bits or a v6-mapped spelling
		// written from outside normalization.
		"::c000:201", "::192.0.2.1", "2001:db8::1", "::1",
	}
	for _, ip := range inside {
		if !block.admits(ip) {
			t.Errorf("/24 must admit %q", ip)
		}
		if !all.admits(ip) {
			t.Errorf("/0 must admit IPv4 %q", ip)
		}
		if ip != "192.0.2.1" && host.admits(ip) {
			t.Errorf("/32 must not admit %q", ip)
		}
	}
	if !host.admits("192.0.2.1") {
		t.Errorf("/32 must admit exactly 192.0.2.1")
	}
	for _, ip := range outside {
		if block.admits(ip) {
			t.Errorf("/24 must not admit %q", ip)
		}
		if host.admits(ip) {
			t.Errorf("/32 must not admit %q", ip)
		}
		if strings.Contains(ip, ":") && all.admits(ip) {
			t.Errorf("/0 matches all IPv4 sources but must not admit IPv6 %q", ip)
		}
	}
	// Absent source is the empty string; it is never admitted.
	for _, f := range []SourceCIDRFilter{block, host, all} {
		if f.admits("") {
			t.Errorf("an absent source_ip must never be admitted by %s", f)
		}
	}
}

// TestSourceCIDRFilterMappedEquivalence pins the headline equivalence:
// 192.0.2.1 and ::ffff:192.0.2.1 normalize to the same source and therefore
// filter identically, while ::192.0.2.1 stays IPv6 and does not.
func TestSourceCIDRFilterMappedEquivalence(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, spelling := range ipv4MappedSpellings {
		input := `{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"` + spelling + `"}`
		results, failures := runNormalizeFiltered(t, input, &filter)
		if failures != 0 || len(results) != 1 {
			t.Fatalf("mapped spelling %q must succeed and be admitted: %#v failures=%d", spelling, results, failures)
		}
		if got := eventOf(t, results[0])["source_ip"]; got != "192.0.2.1" {
			t.Fatalf("spelling %q normalized to %v, want 192.0.2.1", spelling, got)
		}
	}
	for _, spelling := range ipv4CompatibleSpellings {
		input := `{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"` + spelling + `"}`
		results, failures := runNormalizeFiltered(t, input, &filter)
		if failures != 0 || len(results) != 0 {
			t.Fatalf("compatible IPv6 spelling %q must be silently filtered (no record, no failure), got %#v failures=%d",
				spelling, results, failures)
		}
	}
}

// TestSourceCIDRFilterStreamBehavior covers the mixed stream: in-network
// successes are emitted, out-of-network / absent / IPv6 successes are
// dropped silently, blank and dropped lines must not renumber later lines,
// and failures survive regardless of their address.
func TestSourceCIDRFilterStreamBehavior(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.128/25") // 192.0.2.128 - 192.0.2.255
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"in-low-boundary","source_ip":"192.0.2.128"}`,   // line 1 admitted
		`{"timestamp":"2026-01-02T00:00:00Z","action":"in-high-boundary","source_ip":"192.0.2.255"}`,  // line 2 admitted
		`{"timestamp":"2026-01-02T00:00:00Z","action":"out-just-below","source_ip":"192.0.2.127"}`,    // line 3 dropped
		`{"timestamp":"2026-01-02T00:00:00Z","action":"out-other-net","source_ip":"198.51.100.1"}`,    // line 4 dropped
		`{"timestamp":"2026-01-02T00:00:00Z","action":"mapped-in","source_ip":"::ffff:192.0.2.200"}`,  // line 5 admitted
		`{"timestamp":"2026-01-02T00:00:00Z","action":"mapped-out","source_ip":"::ffff:192.0.2.100"}`, // line 6 dropped
		`{"timestamp":"2026-01-02T00:00:00Z","action":"compat-v6","source_ip":"::192.0.2.200"}`,       // line 7 dropped (IPv6)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"plain-v6","source_ip":"2001:db8::1"}`,          // line 8 dropped (IPv6)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}`,                                   // line 9 dropped (absent)
		`{"timestamp":"bad","action":"failed-in-net","source_ip":"192.0.2.200"}`,                      // line 10 failure
		`{"timestamp":"bad","action":"failed-out-net","source_ip":"198.51.100.1"}`,                    // line 11 failure
		`{"timestamp":"bad","action":"failed-absent"}`,                                                // line 12 failure
		``, // line 13 blank
		`{"timestamp":"2026-01-02T00:00:00Z","action":"tail","source_ip":"192.0.2.250"}`, // line 14 admitted
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &filter)

	if failures != 3 {
		t.Fatalf("the three malformed lines must count as failures even under a filter, got %d", failures)
	}
	if len(results) != 7 {
		t.Fatalf("expected 4 admitted successes + 3 failures = 7 records, got %d: %#v", len(results), results)
	}

	type expected struct {
		line float64
		ok   bool
		mark string
	}
	want := []expected{
		{1, true, "in-low-boundary"},
		{2, true, "in-high-boundary"},
		{5, true, "mapped-in"},
		{10, false, "failed-in-net"},
		{11, false, "failed-out-net"},
		{12, false, "failed-absent"},
		{14, true, "tail"},
	}
	for i, w := range want {
		got := results[i]
		if got["line"] != w.line || got["ok"] != w.ok {
			t.Fatalf("record %d mismatch: want line=%v ok=%v, got %#v", i, w.line, w.ok, got)
		}
		if w.ok {
			if eventOf(t, got)["action"] != w.mark {
				t.Fatalf("record %d action mismatch: %#v", i, got)
			}
		} else {
			if _, exists := got["event"]; exists {
				t.Fatalf("failed record %d must not carry an event: %#v", i, got)
			}
			if msg, _ := got["error"].(string); !strings.Contains(msg, FieldTimestamp) {
				t.Fatalf("failed record %d must keep its original reason, got %q", i, msg)
			}
		}
	}
}

// TestSourceCIDRFilterDoesNotRenumberAfterFinalDrop ensures a dropped final
// line without a newline changes nothing about earlier line numbers.
func TestSourceCIDRFilterNoFinalNewlineDropped(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	// Last line is a valid but out-of-network event with no trailing "\n".
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"in","source_ip":"10.0.0.1"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"dropped","source_ip":"192.0.2.1"}`
	results, failures := runNormalizeFiltered(t, input, &filter)
	if failures != 0 || len(results) != 1 {
		t.Fatalf("dropped newline-less tail must add no record or failure, got %#v failures=%d", results, failures)
	}
	if results[0]["line"] != float64(1) || eventOf(t, results[0])["action"] != "in" {
		t.Fatalf("earlier line must be unaffected: %#v", results[0])
	}
}

// TestNormalizeReaderFilteredNilEquivalentToNormalizeReader locks the
// compatibility path: a nil filter is exactly the unfiltered behavior.
func TestNormalizeReaderFilteredNilEquivalentToNormalizeReader(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"192.0.2.1"}` + "\n" +
		`{"timestamp":"bad","action":"b"}` + "\n"
	var plain, filtered bytes.Buffer
	f1, err1 := NormalizeReader(strings.NewReader(input), &plain)
	f2, err2 := NormalizeReaderFiltered(strings.NewReader(input), &filtered, nil)
	if err1 != nil || err2 != nil || f1 != f2 || f1 != 1 {
		t.Fatalf("nil filter must match NormalizeReader: %d/%v vs %d/%v", f1, err1, f2, err2)
	}
	if plain.String() != filtered.String() {
		t.Fatalf("nil filter output differs:\n%s\nvs\n%s", plain.String(), filtered.String())
	}
}
