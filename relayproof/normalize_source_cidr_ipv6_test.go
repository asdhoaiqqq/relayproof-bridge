package relayproof

// Coverage for the IPv6 form of the optional source network filter. The
// filter stays one-network-either-family: a parsed IPv6 network masks host
// bits and renders canonically (compressed or full input spelling alike),
// /128 admits one address and ::/0 every normalized IPv6 source, and an
// IPv6 network never admits an IPv4 source (the ::ffff: mapped family
// included) while an IPv4 network never admits an IPv6 source. Filtering
// still removes only successful events: failed lines keep their physical
// line number and reason regardless of address family.

import (
	"strings"
	"testing"
)

// TestParseSourceCIDRFilterIPv6Canonicalization pins host-bit masking and
// compressed/full spelling equivalence for the IPv6 grammar.
func TestParseSourceCIDRFilterIPv6Canonicalization(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"2001:db8::/64", "2001:db8::/64"},
		{"2001:db8::1234/64", "2001:db8::/64"}, // host bits masked away
		{"2001:db8:0:0:0:0:0:1/64", "2001:db8::/64"},
		{"2001:0db8:0000:0000:0000:0000:0000:0000/64", "2001:db8::/64"},
		{"2001:db8::1/128", "2001:db8::1/128"},
		{"::1/128", "::1/128"},
		{"::/0", "::/0"},
		{"fe80::abcd:1234/10", "fe80::/10"},
		{"2001:db8:1:2:3:4:5:6/48", "2001:db8:1::/48"},
		// ::192.0.2.1 is a genuine IPv6 address (not a mapping), so it is a
		// legal IPv6 network; masked host bits render in hex.
		{"::192.0.2.1/120", "::c000:200/120"},
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

// TestParseSourceCIDRFilterIPv6Rejects pins the shapes the IPv6 grammar
// refuses: bad addresses, out-of-range or padded prefix lengths, ports and
// zones, and the IPv4-mapped family (which must be written as IPv4).
func TestParseSourceCIDRFilterIPv6Rejects(t *testing.T) {
	bad := []string{
		"2001:db8::/129",    // prefix too large
		"2001:db8::/1000",   // pattern caps at three digits but value still out of range
		"2001:db8::/-1",     // negative length
		"2001:db8::/64x",    // trailing junk on the length
		"2001:db8::/064",    // padded length
		"2001:db8::/00",     // padded length
		"2001:db8::1",       // no slash/length
		"2001:db8::1/",      // empty length
		"2001:db8::1/64/64", // extra segment
		"1::2::3/64",        // two compression markers
		"1:2:3:4:5:6:7:8:9/64",
		"2001:db8::g1/64",              // non-hex group
		"fe80::1%eth0/64",              // zone identifier
		"[2001:db8::1]:443/64",         // brackets and port
		" 2001:db8::1/64",              // leading space
		"2001:db8::1/64 ",              // trailing space
		"::ffff:192.0.2.0/120",         // IPv4-mapped: use the IPv4 network
		"::ffff:c000:0201/120",         // mapped spelling in hex
		"::ffff:0:0/96",                // the mapped prefix itself
		"0:0:0:0:0:ffff:192.0.2.1/128", // mapped, full spelling
	}
	for _, in := range bad {
		if f, err := ParseSourceCIDRFilter(in); err == nil {
			t.Fatalf("ParseSourceCIDRFilter(%q) must fail, got filter %s", in, f)
		}
	}
	// Legal boundary addresses/lengths that the reject list must not sweep
	// in: /0, /128, and a dotted-decimal tail that is a genuine IPv6
	// address (the last 32 bits, not an IPv4 mapping).
	for _, ok := range []string{"2001:db8::/0", "2001:db8::/128", "2001:db8::1.2.3.4/64"} {
		if _, err := ParseSourceCIDRFilter(ok); err != nil {
			t.Fatalf("the boundary value %q must be accepted, got %v", ok, err)
		}
	}
}

// TestParseSourceCIDRFilterIPv6MappedRejectionMessage ensures the mapped
// rejection points the caller at the IPv4 spelling rather than silently
// converting the prefix.
func TestParseSourceCIDRFilterIPv6MappedRejectionMessage(t *testing.T) {
	_, err := ParseSourceCIDRFilter("::ffff:192.0.2.0/120")
	if err == nil {
		t.Fatal("an IPv4-mapped network must be rejected")
	}
	msg := err.Error()
	if !strings.Contains(msg, "IPv4-mapped") || !strings.Contains(msg, "IPv4 network") {
		t.Fatalf("rejection must explain the mapped family and its IPv4 spelling, got %q", msg)
	}
}

// TestSourceCIDRFilterIPv6AdmitsNormalized checks the IPv6 membership
// function against the exact strings normalization emits, including the
// family boundary in both directions and the address extremes.
func TestSourceCIDRFilterIPv6AdmitsNormalized(t *testing.T) {
	block, err := ParseSourceCIDRFilter("2001:db8::1234/64")
	if err != nil {
		t.Fatal(err)
	}
	if got := block.String(); got != "2001:db8::/64" {
		t.Fatalf("host bits must be masked in the rendered network, got %q", got)
	}
	host, err := ParseSourceCIDRFilter("2001:db8::abcd/128")
	if err != nil {
		t.Fatal(err)
	}
	all, err := ParseSourceCIDRFilter("::/0")
	if err != nil {
		t.Fatal(err)
	}

	inside := []string{
		"2001:db8::", "2001:db8::1", "2001:db8::1234",
		"2001:db8:0:0:0:0:0:1", "2001:db8::ffff:ffff:ffff:ffff",
	}
	outside := []string{
		"2001:db8:1::1", "fe80::1", "::1",
		// An IPv4 source never matches an IPv6 network even via the mapped
		// spelling it normalized from.
		"192.0.2.1",
	}
	for _, ip := range inside {
		if !block.admits(ip) {
			t.Errorf("/64 must admit %q", ip)
		}
		if !all.admits(ip) {
			t.Errorf("::/0 must admit IPv6 %q", ip)
		}
		if ip != "2001:db8::abcd" && host.admits(ip) {
			t.Errorf("/128 must not admit %q", ip)
		}
	}
	if !host.admits("2001:db8::abcd") {
		t.Error("/128 must admit exactly 2001:db8::abcd")
	}
	for _, ip := range outside {
		if block.admits(ip) {
			t.Errorf("/64 must not admit %q", ip)
		}
		if host.admits(ip) {
			t.Errorf("/128 must not admit %q", ip)
		}
	}
	// ::/0 covers every genuine IPv6 source but no normalized IPv4 one.
	if !all.admits("::c000:201") {
		t.Error("::/0 must admit the genuine IPv6 spelling ::c000:201")
	}
	for _, v4 := range []string{"192.0.2.1", "0.0.0.0", "255.255.255.255"} {
		if all.admits(v4) {
			t.Errorf("::/0 must not admit IPv4 source %q", v4)
		}
	}
	// Absent source is the empty string; it is never admitted by either family.
	for _, f := range []SourceCIDRFilter{block, host, all} {
		if f.admits("") {
			t.Errorf("an absent source_ip must never be admitted by %s", f)
		}
	}
}

// TestSourceCIDRFilterFamilyBoundary pins cross-family non-matching in
// both directions using one pair of filters and sources.
func TestSourceCIDRFilterFamilyBoundary(t *testing.T) {
	v4, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	// A genuine IPv6 network covering ::c000:201 (the normalized form of
	// the IPv4-compatible spelling ::192.0.2.1).
	v6, err := ParseSourceCIDRFilter("::/96")
	if err != nil {
		t.Fatal(err)
	}
	if !v6.admits("::c000:201") {
		t.Error("::/96 must admit the genuine IPv6 source ::c000:201")
	}
	if v6.admits("192.0.2.1") {
		t.Error("an IPv6 network must not admit normalized IPv4 192.0.2.1")
	}
	if v4.admits("::c000:201") {
		t.Error("an IPv4 network must not admit genuine IPv6 ::c000:201")
	}
	if !v4.admits("192.0.2.1") {
		t.Error("/24 must admit 192.0.2.1")
	}
}

// TestSourceCIDRFilterIPv6StreamBehavior covers the mixed stream under an
// IPv6 filter: in-range IPv6 successes (compressed, full, compatible-tail
// spellings) are emitted with unchanged content and line numbers; IPv4,
// mapped, out-of-range and absent successes are dropped silently; failures
// survive regardless of family and keep counting physical lines.
func TestSourceCIDRFilterIPv6StreamBehavior(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("2001:db8::5678/64")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"in-compressed","source_ip":"2001:db8::1"}`,    // 1 admitted
		`{"timestamp":"2026-01-02T00:00:00Z","action":"in-full","src_ip":"2001:db8:0:0:0:0:0:2"}`,    // 2 admitted via alias
		`{"timestamp":"2026-01-02T00:00:00Z","action":"in-hostbits","source_ip":"2001:db8::ffff:f"}`, // 3 admitted
		`{"timestamp":"2026-01-02T00:00:00Z","action":"other-v6","source_ip":"2001:db8:1::1"}`,       // 4 dropped
		`{"timestamp":"2026-01-02T00:00:00Z","action":"plain-v4","source_ip":"192.0.2.1"}`,           // 5 dropped (family)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"mapped","source_ip":"::ffff:192.0.2.1"}`,      // 6 dropped (family)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"compat-in","source_ip":"::c000:201"}`,         // 7 dropped (outside)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}`,                                  // 8 dropped (absent)
		`{"timestamp":"bad","action":"failed-v6","source_ip":"2001:db8::9"}`,                         // 9 failure (in range)
		`{"timestamp":"bad","action":"failed-v4","source_ip":"192.0.2.9"}`,                           // 10 failure (IPv4)
		`{"timestamp":"bad","action":"failed-absent"}`,                                               // 11 failure
		``, // 12 blank
		`{"timestamp":"2026-01-02T00:00:00Z","action":"tail","source_ip":"2001:db8::abcd"}`, // 13 admitted
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &filter)

	if failures != 3 {
		t.Fatalf("the three malformed lines must count as failures even under an IPv6 filter, got %d", failures)
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
		{1, true, "in-compressed"},
		{2, true, "in-full"},
		{3, true, "in-hostbits"},
		{9, false, "failed-v6"},
		{10, false, "failed-v4"},
		{11, false, "failed-absent"},
		{13, true, "tail"},
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

// TestSourceCIDRFilterIPv6ColonZeroAllAndOne pins ::/0 and /128 behavior
// through the streaming entry point, including equivalence spellings of
// the one /128 address.
func TestSourceCIDRFilterIPv6ColonZeroAndOneTwoEight(t *testing.T) {
	exact, err := ParseSourceCIDRFilter("::1/128")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"loopback","source_ip":"0:0:0:0:0:0:0:1"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"other-v6","source_ip":"2001:db8::1"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"v4","source_ip":"192.0.2.1"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"none"}`,
	}, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, &exact)
	if failures != 0 || len(results) != 1 {
		t.Fatalf("/128 must keep only the full-spelling loopback, got %#v failures=%d", results, failures)
	}
	if eventOf(t, results[0])["source_ip"] != "::1" {
		t.Fatalf("full spelling must normalize to ::1: %#v", results[0])
	}

	all, err := ParseSourceCIDRFilter("::/0")
	if err != nil {
		t.Fatal(err)
	}
	results, failures = runNormalizeFiltered(t, input, &all)
	if failures != 0 || len(results) != 2 {
		t.Fatalf("::/0 must keep both IPv6 events but no IPv4 or absent source, got %#v failures=%d", results, failures)
	}
	for _, r := range results {
		if !strings.Contains(eventOf(t, r)["source_ip"].(string), ":") {
			t.Fatalf("::/0 must not admit an IPv4 source: %#v", r)
		}
	}
}
