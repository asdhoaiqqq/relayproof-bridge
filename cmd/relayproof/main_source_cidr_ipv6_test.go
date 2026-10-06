package main

// End-to-end coverage for IPv6 networks in the normalize --source-cidr
// option against the real compiled binary: which successful events survive
// an IPv6 filter, that IPv4 sources are never admitted by one, that failures
// are never hidden, and that malformed IPv6 option values exit 2 with empty
// stdout before any stdin byte is consumed.

import (
	"strings"
	"testing"
)

// The core IPv6 filter through the CLI: host bits in the argument are
// masked, compressed and full spellings of one source share one result, the
// src_ip alias admits identically, IPv4 sources (plain or IPv4-mapped),
// absent sources and other networks are dropped, the surviving records keep
// their original physical line numbers and full event content, and the run
// is still clean (exit 0, stderr empty).
func TestNormalizeCLISourceCIDRIPv6FiltersSuccesses(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("plain-in", "2001:db8::7"),                                         // line 1 kept
		validCIDRSource("full-spelling", "2001:0db8:0000:0000:0000:0000:0000:0008"),        // line 2 kept (prints compressed)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"via-alias","src_ip":"2001:db8::9"}`, // line 3 kept
		validCIDRSource("other-v6-net", "2001:db8:0:1::7"),                                 // line 4 dropped: outside
		validCIDRSource("plain-v4", "192.0.2.7"),                                           // line 5 dropped: IPv4
		validCIDRSource("mapped-v4", "::ffff:192.0.2.7"),                                   // line 6 dropped: normalizes to IPv4
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}`,                        // line 7 dropped
		validCIDRSource("edge-high", "2001:db8::ffff:ffff:ffff:ffff"),                      // line 8 kept
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "2001:db8::1234/64")

	if result.exitCode != 0 {
		t.Fatalf("a fully valid, partially filtered stream must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("filtering successes needs no diagnostics, got %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 4 {
		t.Fatalf("expected the four in-network events, got %#v", results)
	}
	want := []struct {
		line     float64
		action   string
		sourceIP string
	}{
		{1, "plain-in", "2001:db8::7"},
		{2, "full-spelling", "2001:db8::8"}, // full spelling prints compressed
		{3, "via-alias", "2001:db8::9"},
		{8, "edge-high", "2001:db8::ffff:ffff:ffff:ffff"},
	}
	for i, w := range want {
		got := results[i]
		if got["line"] != w.line || got["ok"] != true {
			t.Fatalf("record %d must keep physical line %v and ok:true: %#v", i, w.line, got)
		}
		event := eventOf(t, got)
		if event["action"] != w.action || event["source_ip"] != w.sourceIP {
			t.Fatalf("record %d event mismatch: %#v", i, event)
		}
		if _, exists := got["filtered"]; exists {
			t.Fatalf("results must carry no filter marker: %#v", got)
		}
	}
}

// /128 matches exactly one IPv6 address (in any spelling); ::/0 matches
// every normalized IPv6 source but no IPv4 or absent source.
func TestNormalizeCLISourceCIDRIPv6Extremes(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("exact", "2001:db8::1"),
		validCIDRSource("exact-full", "2001:0db8:0000:0000:0000:0000:0000:0001"),
		validCIDRSource("neighbor", "2001:db8::2"),
		validCIDRSource("v4", "192.0.2.1"),
		`{"timestamp":"2026-01-02T00:00:00Z","action":"none"}`,
	}, "\n") + "\n"

	host := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr=2001:db8::1/128")
	if host.exitCode != 0 || host.stderr != "" {
		t.Fatalf("/128 run must be clean: exit=%d stderr=%q", host.exitCode, host.stderr)
	}
	hostResults := decodeStdoutResults(t, host.stdout)
	if len(hostResults) != 2 {
		t.Fatalf("/128 must keep only the two spellings of one address, got %#v", hostResults)
	}
	if hostResults[0]["line"] != float64(1) || hostResults[1]["line"] != float64(2) {
		t.Fatalf("/128 survivors must keep lines 1 and 2: %#v", hostResults)
	}

	all := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "::/0")
	if all.exitCode != 0 || all.stderr != "" {
		t.Fatalf("::/0 run must be clean: exit=%d stderr=%q", all.exitCode, all.stderr)
	}
	allResults := decodeStdoutResults(t, all.stdout)
	if len(allResults) != 3 {
		t.Fatalf("::/0 keeps the three IPv6 events but no IPv4/absent source, got %#v", allResults)
	}
	if allResults[2]["line"] != float64(3) {
		t.Fatalf("::/0 survivors must be lines 1-3: %#v", allResults)
	}
}

// The IPv6 filter never hides bad logs: a malformed line is emitted with its
// line number, original reason and no event whether its address is in or out
// of the network, later lines keep processing, and exit 1 reflects the
// failures even though every legal event was filtered out.
func TestNormalizeCLISourceCIDRIPv6FailuresStillReported(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("kept", "2001:db8::9"),                       // line 1 kept
		`{"timestamp":"bad","action":"x","source_ip":"2001:db8::9"}`, // line 2 failure, in network
		`{"timestamp":"bad","action":"x","source_ip":"fe80::9"}`,     // line 3 failure, out of network
		`{"timestamp":"bad","action":"x"}`,                           // line 4 failure, no source
		validCIDRSource("dropped", "fe80::1"),                        // line 5 dropped success
		validCIDRSource("tail", "2001:db8::10"),                      // line 6 kept
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "2001:db8::/64")

	if result.exitCode != 1 {
		t.Fatalf("three bad lines must force exit 1 regardless of the filter, got %d", result.exitCode)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in result records, got %q", result.stderr)
	}
	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 5 {
		t.Fatalf("expected 2 kept successes + 3 failures, got %#v", results)
	}
	wantLines := []float64{1, 2, 3, 4, 6}
	for i, line := range wantLines {
		if results[i]["line"] != line {
			t.Fatalf("record %d must carry physical line %v: %#v", i, line, results[i])
		}
	}
	for i := 1; i <= 3; i++ {
		bad := results[i]
		if bad["ok"] != false {
			t.Fatalf("record %d must be a failure: %#v", i, bad)
		}
		if _, exists := bad["event"]; exists {
			t.Fatalf("failure record %d must have no event: %#v", i, bad)
		}
		if msg, _ := bad["error"].(string); !strings.Contains(msg, "timestamp") {
			t.Fatalf("failure record %d must keep its original reason, got %q", i, msg)
		}
	}
	if eventOf(t, results[4])["action"] != "tail" {
		t.Fatalf("the line after the failures and the dropped success must survive: %#v", results[4])
	}
}

// When no success remains under an IPv6 filter, the stream still ends
// normally: exit 0 with empty stdout and stderr.
func TestNormalizeCLISourceCIDRIPv6AllFilteredExitsZero(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("v4", "192.0.2.1"),
		validCIDRSource("other-v6", "fe80::1"),
		`{"timestamp":"2026-01-02T00:00:00Z","action":"none"}`,
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "2001:db8::/64")
	if result.exitCode != 0 {
		t.Fatalf("all-valid-but-filtered input must exit 0, got %d (stderr %q)", result.exitCode, result.stderr)
	}
	if result.stdout != "" || result.stderr != "" {
		t.Fatalf("no surviving records means empty stdout/stderr, got %q / %q", result.stdout, result.stderr)
	}
}

// Every malformed IPv6 --source-cidr value exits 2 with a stderr explanation
// and empty stdout, before the log stream is consumed — including the
// IPv4-mapped spelling, which must be rejected rather than converted.
func TestNormalizeCLISourceCIDRIPv6BadOptionExitsTwoWithoutReading(t *testing.T) {
	// First line fails normalization; second line would succeed.
	stdinContent := `{"timestamp":"not-a-time","action":"x"}` + "\n" +
		validCIDRSource("kept", "2001:db8::1") + "\n"
	cases := []struct {
		name string
		args []string
	}{
		{"ipv6 no slash", []string{"--source-cidr", "2001:db8::1"}},
		{"ipv6 empty prefix", []string{"--source-cidr", "2001:db8::1/"}},
		{"ipv6 prefix 129", []string{"--source-cidr", "2001:db8::1/129"}},
		{"ipv6 padded prefix", []string{"--source-cidr", "2001:db8::1/064"}},
		{"ipv6 bad address", []string{"--source-cidr", "2001:db8::1::2/64"}},
		{"ipv6 with port", []string{"--source-cidr", "[2001:db8::1]:443/64"}},
		{"ipv6 with zone", []string{"--source-cidr", "fe80::1%eth0/64"}},
		{"ipv4-mapped", []string{"--source-cidr", "::ffff:192.0.2.0/120"}},
		{"ipv4-mapped hex", []string{"--source-cidr", "::FFFF:C000:200/120"}},
		{"ipv6 duplicate", []string{"--source-cidr", "2001:db8::/64", "--source-cidr", "fe80::/10"}},
		{"ipv6 duplicate mixed form", []string{"--source-cidr=2001:db8::/64", "--source-cidr", "fe80::/10"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := runNormalizeCLIArgs(t, strings.NewReader(stdinContent), tc.args...)
			if result.exitCode != 2 {
				t.Fatalf("bad option must exit 2, got %d (stdout %q stderr %q)", result.exitCode, result.stdout, result.stderr)
			}
			if result.stdout != "" {
				t.Fatalf("a parameter error must leave stdout empty and must not process stdin, got %q", result.stdout)
			}
			if !strings.HasPrefix(result.stderr, "normalize: ") {
				t.Fatalf("diagnostic must carry the normalize: prefix, got %q", result.stderr)
			}
			if !strings.Contains(result.stderr, "source-cidr") {
				t.Fatalf("diagnostic should name the option, got %q", result.stderr)
			}
		})
	}
}

// The IPv4-mapped rejection must direct the user to the IPv4 network form.
func TestNormalizeCLISourceCIDRMappedIPv6Diagnostic(t *testing.T) {
	result := runNormalizeCLIArgs(t, strings.NewReader(""), "--source-cidr", "::ffff:192.0.2.0/120")
	if result.exitCode != 2 {
		t.Fatalf("an IPv4-mapped network must exit 2, got %d", result.exitCode)
	}
	if !strings.Contains(result.stderr, "IPv4") {
		t.Fatalf("the diagnostic must point at the IPv4 network form, got %q", result.stderr)
	}
}
