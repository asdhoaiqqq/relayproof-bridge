package relayproof

// Coverage for IPv6 source networks in the optional --source-cidr filter.
// The grammar accepts any legal IPv6 address spelling (compressed or full,
// no port, no zone) with a decimal 0-128 prefix; host bits are masked, an
// IPv4-mapped argument is rejected rather than converted, and matching stays
// per-family: an IPv6 network admits only sources that normalize to IPv6,
// just as an IPv4 network admits only IPv4.

import (
	"strings"
	"testing"
)

// TestParseSourceCIDRFilterIPv6Canonicalization pins the IPv6 grammar and
// the host-bit masking: compressed and full spellings of one network parse
// to the same canonical string, regardless of the host part written.
func TestParseSourceCIDRFilterIPv6Canonicalization(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"::1/128", "::1/128"},
		{"::/0", "::/0"},
		{"2001:db8::/64", "2001:db8::/64"},
		{"2001:db8::1234/64", "2001:db8::/64"}, // host bits masked away
		{"2001:db8::1/128", "2001:db8::1/128"},
		{"2001:0db8:0000:0000:0000:0000:0000:0001/128", "2001:db8::1/128"}, // full spelling
		{"2001:DB8::ABCD/64", "2001:db8::/64"},                             // case-insensitive
		{"fe80::1234/10", "fe80::/10"},
		{"ff02::1/16", "ff02::/16"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"},
		{"ffff::ffff/0", "::/0"},
		{"2001:db8:dead:beef::1/48", "2001:db8:dead::/48"},
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

// TestParseSourceCIDRFilterIPv6Rejects pins what the IPv6 grammar refuses.
func TestParseSourceCIDRFilterIPv6Rejects(t *testing.T) {
	bad := []string{
		"2001:db8::1",          // no slash/length
		"2001:db8::1/",         // empty length
		"/64",                  // empty address
		"2001:db8::1/64/32",    // extra segment
		"2001:db8::1/129",      // prefix too large
		"2001:db8::1/1000",     // far too large
		"2001:db8::1/-1",       // negative length
		"2001:db8::1/+64",      // signed length
		"2001:db8::1/64x",      // trailing junk
		"2001:db8::1/064",      // padded length
		"2001:db8::1/0x40",     // non-decimal length
		"gg::1/64",             // bad hex
		"2001:db8::1::2/64",    // double compression
		"[2001:db8::1]/64",     // bracketed
		"[2001:db8::1]:443/64", // port
		"fe80::1%eth0/64",      // zone identifier
		"fe80::1%25eth0/64",    // zone identifier, escaped
		"2001:db8::1/64 ",      // trailing space
		" 2001:db8::1/64",      // leading space
		// IPv4-mapped IPv6 in any spelling: rejected, never converted to a
		// 32-bit prefix.
		"::ffff:192.0.2.0/120",
		"::ffff:192.0.2.1/128",
		"::FFFF:C000:0200/120",
		"::ffff:c000:200/120",
		"0:0:0:0:0:ffff:c000:200/120",
	}
	for _, in := range bad {
		if f, err := ParseSourceCIDRFilter(in); err == nil {
			t.Fatalf("ParseSourceCIDRFilter(%q) must fail, got filter %s", in, f)
		}
	}
}

// TestParseSourceCIDRFilterMappedIPv6Hint requires the IPv4-mapped rejection
// to point at the IPv4 network form rather than silently converting.
func TestParseSourceCIDRFilterMappedIPv6Hint(t *testing.T) {
	_, err := ParseSourceCIDRFilter("::ffff:192.0.2.0/120")
	if err == nil {
		t.Fatal("an IPv4-mapped network argument must be rejected")
	}
	if !strings.Contains(err.Error(), "IPv4") {
		t.Fatalf("the rejection must direct the user to the IPv4 network form, got %q", err)
	}
}

// TestSourceCIDRFilterIPv6AdmitsNormalized checks IPv6 membership against
// the exact strings that appear in normalized output, including the
// per-family separation: no IPv4 source is ever admitted by an IPv6 network.
func TestSourceCIDRFilterIPv6AdmitsNormalized(t *testing.T) {
	block, err := ParseSourceCIDRFilter("2001:db8::1234/64") // host bits masked
	if err != nil {
		t.Fatal(err)
	}
	host, err := ParseSourceCIDRFilter("2001:db8::1/128")
	if err != nil {
		t.Fatal(err)
	}
	all, err := ParseSourceCIDRFilter("::/0")
	if err != nil {
		t.Fatal(err)
	}

	inside := []string{"2001:db8::", "2001:db8::1", "2001:db8::1234", "2001:db8::ffff:ffff:ffff:ffff"}
	outside := []string{
		"2001:db8:0:1::1", "2001:db7::1", "fe80::1", "::1",
		// Normalized IPv4 sources never match an IPv6 network, not even
		// under ::/0; the mapped spelling normalizes to the same dotted
		// form and is equally excluded.
		"192.0.2.1", "0.0.0.0", "255.255.255.255",
	}
	for _, ip := range inside {
		if !block.admits(ip) {
			t.Errorf("/64 must admit %q", ip)
		}
		if !all.admits(ip) {
			t.Errorf("::/0 must admit IPv6 %q", ip)
		}
		if ip != "2001:db8::1" && host.admits(ip) {
			t.Errorf("/128 must not admit %q", ip)
		}
	}
	if !host.admits("2001:db8::1") {
		t.Errorf("/128 must admit exactly 2001:db8::1")
	}
	for _, ip := range outside {
		if block.admits(ip) {
			t.Errorf("/64 must not admit %q", ip)
		}
		if host.admits(ip) {
			t.Errorf("/128 must not admit %q", ip)
		}
		if strings.Contains(ip, ":") {
			if !all.admits(ip) {
				t.Errorf("::/0 matches all IPv6 sources and must admit %q", ip)
			}
		} else if all.admits(ip) {
			t.Errorf("::/0 matches all IPv6 sources but must not admit IPv4 %q", ip)
		}
	}
	// Absent source is the empty string; it is never admitted.
	for _, f := range []SourceCIDRFilter{block, host, all} {
		if f.admits("") {
			t.Errorf("an absent source_ip must never be admitted by %s", f)
		}
	}
}

// TestSourceCIDRFilterIPv6EquivalenceSpellings pins that matching runs on
// the normalized source_ip: the compressed and full spellings of one IPv6
// source, provided under source_ip or the src_ip alias, admit identically.
func TestSourceCIDRFilterIPv6EquivalenceSpellings(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("2001:db8::/64")
	if err != nil {
		t.Fatal(err)
	}
	spellings := []string{
		"2001:db8::1",
		"2001:0db8:0000:0000:0000:0000:0000:0001",
		"2001:DB8::1",
	}
	for _, field := range []string{FieldSourceIP, "src_ip"} {
		for _, spelling := range spellings {
			input := `{"timestamp":` + validTS + `,"action":` + validAction + `,"` + field + `":"` + spelling + `"}`
			results, failures := runNormalizeFiltered(t, input, &filter)
			if failures != 0 || len(results) != 1 {
				t.Fatalf("%s %q must succeed and be admitted: %#v failures=%d", field, spelling, results, failures)
			}
			if got := eventOf(t, results[0])["source_ip"]; got != "2001:db8::1" {
				t.Fatalf("%s %q normalized to %v, want 2001:db8::1", field, spelling, got)
			}
		}
	}
}

// TestSourceCIDRFilterIPv6CompatibleAddress pins that ::192.0.2.1 — a
// genuine IPv6 address, never the mapped 192.0.2.1 — is admitted by an IPv6
// network that contains it, while the IPv4-mapped spelling of the same 32
// bits normalizes to IPv4 and is dropped by every IPv6 network.
func TestSourceCIDRFilterIPv6CompatibleAddress(t *testing.T) {
	exact, err := ParseSourceCIDRFilter("::c000:201/128")
	if err != nil {
		t.Fatal(err)
	}
	input := `{"timestamp":` + validTS + `,"action":"compat","source_ip":"::192.0.2.1"}` + "\n" +
		`{"timestamp":` + validTS + `,"action":"mapped","source_ip":"::ffff:192.0.2.1"}` + "\n"
	results, failures := runNormalizeFiltered(t, input, &exact)
	if failures != 0 || len(results) != 1 {
		t.Fatalf("only the genuine IPv6 source may survive an IPv6 filter: %#v failures=%d", results, failures)
	}
	if results[0]["line"] != float64(1) || eventOf(t, results[0])["source_ip"] != "::c000:201" {
		t.Fatalf("the survivor must be line 1 with its IPv6 source: %#v", results[0])
	}

	all, err := ParseSourceCIDRFilter("::/0")
	if err != nil {
		t.Fatal(err)
	}
	results, failures = runNormalizeFiltered(t, input, &all)
	if failures != 0 || len(results) != 1 {
		t.Fatalf("::/0 must admit every IPv6 source and no IPv4 source: %#v failures=%d", results, failures)
	}
	if eventOf(t, results[0])["action"] != "compat" {
		t.Fatalf("::/0 must keep only the genuine IPv6 event: %#v", results[0])
	}
}

// TestSourceCIDRFilterIPv6StreamBehavior covers the mixed stream under an
// IPv6 filter: in-network IPv6 successes are emitted, out-of-network /
// absent / IPv4 successes are dropped silently, dropped lines must not
// renumber later lines, and failures survive regardless of their address.
func TestSourceCIDRFilterIPv6StreamBehavior(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("2001:db8::8000/33") // 2001:db8:: - 2001:db8:7fff:ffff:ffff:ffff:ffff:ffff
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"in-low-boundary","source_ip":"2001:db8::"}`,                              // line 1 admitted
		`{"timestamp":"2026-01-02T00:00:00Z","action":"in-high-boundary","source_ip":"2001:db8:7fff:ffff:ffff:ffff:ffff:ffff"}`, // line 2 admitted
		`{"timestamp":"2026-01-02T00:00:00Z","action":"out-just-above","source_ip":"2001:db8:8000::"}`,                          // line 3 dropped
		`{"timestamp":"2026-01-02T00:00:00Z","action":"out-other-net","source_ip":"fe80::1"}`,                                   // line 4 dropped
		`{"timestamp":"2026-01-02T00:00:00Z","action":"full-spelling","source_ip":"2001:0db8:0000:0000:0000:0000:0000:0001"}`,   // line 5 admitted
		`{"timestamp":"2026-01-02T00:00:00Z","action":"via-alias","src_ip":"2001:db8:1234::1"}`,                                 // line 6 admitted
		`{"timestamp":"2026-01-02T00:00:00Z","action":"plain-v4","source_ip":"192.0.2.1"}`,                                      // line 7 dropped (IPv4)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"mapped-v4","source_ip":"::ffff:192.0.2.1"}`,                              // line 8 dropped (normalizes to IPv4)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}`,                                                             // line 9 dropped (absent)
		`{"timestamp":"bad","action":"failed-in-net","source_ip":"2001:db8:1234::1"}`,                                           // line 10 failure
		`{"timestamp":"bad","action":"failed-out-net","source_ip":"fe80::1"}`,                                                   // line 11 failure
		`{"timestamp":"bad","action":"failed-absent"}`,                                                                          // line 12 failure
		``, // line 13 blank
		`{"timestamp":"2026-01-02T00:00:00Z","action":"tail","source_ip":"2001:db8:7fff::1"}`, // line 14 admitted
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &filter)

	if failures != 3 {
		t.Fatalf("the three malformed lines must count as failures even under a filter, got %d", failures)
	}
	if len(results) != 8 {
		t.Fatalf("expected 5 admitted successes + 3 failures = 8 records, got %d: %#v", len(results), results)
	}

	type expected struct {
		line float64
		ok   bool
		mark string
	}
	want := []expected{
		{1, true, "in-low-boundary"},
		{2, true, "in-high-boundary"},
		{5, true, "full-spelling"},
		{6, true, "via-alias"},
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
			if msg, _ := got["error"].(string); msg == "" {
				t.Fatalf("failed record %d must keep its original reason", i)
			}
		}
	}
}
