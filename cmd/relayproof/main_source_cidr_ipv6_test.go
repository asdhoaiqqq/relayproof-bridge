package main

// End-to-end coverage for an IPv6 --source-cidr option against the real
// compiled binary: an IPv6 network selects only normalized IPv6 sources
// (compressed and full spellings, via source_ip or src_ip, host bits in
// the argument masked), leaves IPv4 sources and their ::ffff: mappings to
// IPv4 filters, keeps surviving records byte-for-byte with original line
// numbers, never hides bad logs, and reports every malformed IPv6 option
// with exit 2 and empty stdout before stdin is touched.

import (
	"strings"
	"testing"
)

// The IPv6 /64 filter through the CLI: host bits in the argument are
// masked, compressed and full spellings share a result, genuine IPv6
// sources are kept, IPv4 and mapped sources, absent sources and other
// IPv6 networks are dropped, and the run is clean (exit 0, stderr empty)
// with no filter marker on the records.
func TestNormalizeCLISourceCIDRIPv6FiltersSuccesses(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("compressed-in", "2001:db8::1"),
		validCIDRSource("full-in", "2001:db8:0:0:0:0:0:2"),
		validCIDRSource("hostbits-in", "2001:db8::ffff:ffff:ffff:ffff"),
		validCIDRSource("other-v6", "2001:db8:1::1"),
		validCIDRSource("plain-v4", "192.0.2.1"),
		validCIDRSource("mapped-v4", "::ffff:192.0.2.1"),
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}`,
		validCIDRSource("loopback", "::1"),
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "2001:db8::5678/64")

	if result.exitCode != 0 {
		t.Fatalf("a fully valid, partially filtered stream must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("filtering successes needs no diagnostics, got %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 3 {
		t.Fatalf("expected the three in-network IPv6 events, got %#v", results)
	}
	want := []struct {
		line     float64
		action   string
		sourceIP string
	}{
		{1, "compressed-in", "2001:db8::1"},
		{2, "full-in", "2001:db8::2"},
		{3, "hostbits-in", "2001:db8::ffff:ffff:ffff:ffff"},
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

// ::/0 keeps every normalized IPv6 source but no IPv4 one; /128 keeps one
// address in either of its equivalent spellings. Both forms (separate and
// equals-attached) of the option work.
func TestNormalizeCLISourceCIDRIPv6Extremes(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("loopback", "0:0:0:0:0:0:0:1"),
		validCIDRSource("loopback-compressed", "::1"),
		validCIDRSource("other-v6", "2001:db8::1"),
		validCIDRSource("compat", "::c000:201"),
		validCIDRSource("v4", "192.0.2.1"),
		validCIDRSource("v4-mapped", "::ffff:192.0.2.1"),
		`{"timestamp":"2026-01-02T00:00:00Z","action":"none"}`,
	}, "\n") + "\n"

	host := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr=::1/128")
	if host.exitCode != 0 || host.stderr != "" {
		t.Fatalf("/128 run must be clean: exit=%d stderr=%q", host.exitCode, host.stderr)
	}
	hostResults := decodeStdoutResults(t, host.stdout)
	if len(hostResults) != 2 {
		t.Fatalf("/128 must keep only the two spellings of ::1, got %#v", hostResults)
	}
	if hostResults[0]["line"] != float64(1) || hostResults[1]["line"] != float64(2) {
		t.Fatalf("/128 survivors must keep lines 1 and 2: %#v", hostResults)
	}

	all := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "::/0")
	if all.exitCode != 0 || all.stderr != "" {
		t.Fatalf("::/0 run must be clean: exit=%d stderr=%q", all.exitCode, all.stderr)
	}
	allResults := decodeStdoutResults(t, all.stdout)
	if len(allResults) != 4 {
		t.Fatalf("::/0 keeps the four IPv6 events but no IPv4/mapped/absent source, got %#v", allResults)
	}
	for i, line := range []float64{1, 2, 3, 4} {
		if allResults[i]["line"] != line {
			t.Fatalf("::/0 survivors must be lines 1-4: %#v", allResults)
		}
	}
}

// The IPv4-compatible spelling ::192.0.2.1 stays a genuine IPv6 source:
// it normalizes to ::c000:201 and hits an IPv6 network containing it,
// while still never hitting any IPv4 network. Its mapped cousin keeps
// hitting only the IPv4 network.
func TestNormalizeCLISourceCIDRIPv6CompatibleTail(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("compat", "::192.0.2.1"),
		validCIDRSource("mapped", "::ffff:192.0.2.1"),
		validCIDRSource("plain-v4", "192.0.2.1"),
	}, "\n") + "\n"

	v6 := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "::/96")
	if v6.exitCode != 0 || v6.stderr != "" {
		t.Fatalf("IPv6 run must be clean: exit=%d stderr=%q", v6.exitCode, v6.stderr)
	}
	v6Results := decodeStdoutResults(t, v6.stdout)
	if len(v6Results) != 1 {
		t.Fatalf("::/96 must keep only the genuine IPv6 ::c000:201, got %#v", v6Results)
	}
	if got := eventOf(t, v6Results[0])["source_ip"]; got != "::c000:201" {
		t.Fatalf("::192.0.2.1 must normalize to ::c000:201, got %v", got)
	}

	v4 := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.2.0/24")
	if v4.exitCode != 0 || v4.stderr != "" {
		t.Fatalf("IPv4 run must be clean: exit=%d stderr=%q", v4.exitCode, v4.stderr)
	}
	v4Results := decodeStdoutResults(t, v4.stdout)
	if len(v4Results) != 2 {
		t.Fatalf("the /24 must keep the mapped and plain IPv4 spellings but not ::c000:201, got %#v", v4Results)
	}
	for i, want := range []string{"192.0.2.1", "192.0.2.1"} {
		if got := eventOf(t, v4Results[i])["source_ip"]; got != want {
			t.Fatalf("record %d source must be 192.0.2.1, got %v", i, got)
		}
	}
}

// Under an IPv6 filter the filter still never hides bad logs: malformed
// lines with IPv6, IPv4 and absent sources are all emitted with line,
// reason and no event, later lines keep processing, and exit 1 reflects
// the failures even when every legal event was filtered away.
func TestNormalizeCLISourceCIDRIPv6FailuresStillReported(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("kept", "2001:db8::9"),                       // line 1 kept
		`{"timestamp":"bad","action":"x","source_ip":"2001:db8::9"}`, // line 2 failure, in network
		`{"timestamp":"bad","action":"x","source_ip":"192.0.2.9"}`,   // line 3 failure, IPv4
		`{"timestamp":"bad","action":"x","source_ip":"fe80::1"}`,     // line 4 failure, other IPv6
		`{"timestamp":"bad","action":"x"}`,                           // line 5 failure, no source
		"   ",                                                        // line 6 blank
		validCIDRSource("dropped", "fe80::abcd"),                     // line 7 dropped success
		validCIDRSource("tail", "2001:db8::a"),                       // line 8 kept
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "2001:db8::/64")

	if result.exitCode != 1 {
		t.Fatalf("four bad lines must force exit 1 regardless of the IPv6 filter, got %d", result.exitCode)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in result records, got %q", result.stderr)
	}
	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 6 {
		t.Fatalf("expected 2 kept successes + 4 failures, got %#v", results)
	}
	wantLines := []float64{1, 2, 3, 4, 5, 8}
	for i, line := range wantLines {
		if results[i]["line"] != line {
			t.Fatalf("record %d must carry physical line %v: %#v", i, line, results[i])
		}
	}
	for i := 1; i <= 4; i++ {
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
	if eventOf(t, results[5])["action"] != "tail" {
		t.Fatalf("the line after the failures must survive: %#v", results[5])
	}
}

// An IPv6 filter that admits none of the valid input is still a clean
// empty run: exit 0, empty stdout and stderr.
func TestNormalizeCLISourceCIDRIPv6AllFilteredExitsZero(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("a", "2001:db8:1::1"),
		"",
		validCIDRSource("b", "192.0.2.1"),
		`{"timestamp":"2026-01-02T00:00:00Z","action":"c"}`,
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr=2001:db8::/64")
	if result.exitCode != 0 {
		t.Fatalf("all-valid-but-filtered input must exit 0, got %d (stderr %q)", result.exitCode, result.stderr)
	}
	if result.stdout != "" || result.stderr != "" {
		t.Fatalf("no surviving records means empty stdout/stderr, got %q / %q", result.stdout, result.stderr)
	}
}

// IPv6 option parameter errors share the IPv4 contract: exit 2, empty
// stdout (proving stdin was not consumed), and a normalize: diagnostic
// that names the option. The mapped-family case specifically must point
// the caller at an IPv4 network instead of silently converting /120.
func TestNormalizeCLISourceCIDRIPv6BadOptionExitsTwoWithoutReading(t *testing.T) {
	stdinContent := `{"timestamp":"not-a-time","action":"x"}` + "\n" +
		validCIDRSource("kept", "2001:db8::1") + "\n"
	cases := []struct {
		name       string
		args       []string
		wantInText string
	}{
		{"prefix 129", []string{"--source-cidr", "2001:db8::/129"}, "out of range"},
		{"prefix 1000", []string{"--source-cidr", "2001:db8::/1000"}, "must be an IP network"},
		{"padded prefix", []string{"--source-cidr", "2001:db8::/064"}, "leading zero"},
		{"bad compression", []string{"--source-cidr", "1::2::3/64"}, "invalid IPv6"},
		{"non-hex group", []string{"--source-cidr=2001:db8::g/64"}, "invalid IPv6"},
		{"zone id", []string{"--source-cidr", "fe80::1%eth0/64"}, "invalid IPv6"},
		{"bracketed port", []string{"--source-cidr", "[2001:db8::1]:443/64"}, "invalid IPv6"},
		{"no slash", []string{"--source-cidr", "2001:db8::1"}, "must be an IP network"},
		{"mapped network", []string{"--source-cidr", "::ffff:192.0.2.0/120"}, "IPv4 network"},
		{"mapped network attached", []string{"--source-cidr=::ffff:c000:201/128"}, "IPv4 network"},
		{"duplicate", []string{"--source-cidr", "2001:db8::/64", "--source-cidr=fe80::/10"}, "at most once"},
		{"duplicate across families", []string{"--source-cidr=192.0.2.0/24", "--source-cidr", "2001:db8::/64"}, "at most once"},
		{"empty value", []string{"--source-cidr", ""}, "must be an IP network"},
		{"empty attached", []string{"--source-cidr="}, "must be an IP network"},
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
			if !strings.Contains(result.stderr, tc.wantInText) {
				t.Fatalf("diagnostic should contain %q, got %q", tc.wantInText, result.stderr)
			}
		})
	}
}

// A legitimate IPv6 filter keeps surviving records byte-identical to an
// unfiltered run: selection changes nothing about the emitted JSON.
func TestNormalizeCLISourceCIDRIPv6OutputMatchesUnfiltered(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("in", "2001:db8::7"),
		validCIDRSource("out", "fe80::1"),
	}, "\n") + "\n"

	filtered := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "2001:db8::/64")
	unfiltered := runNormalizeCLI(t, strings.NewReader(validCIDRSource("in", "2001:db8::7")+"\n"))
	if filtered.exitCode != 0 || unfiltered.exitCode != 0 {
		t.Fatalf("both runs must exit 0, got %d and %d", filtered.exitCode, unfiltered.exitCode)
	}
	if filtered.stdout != unfiltered.stdout {
		t.Fatalf("kept record must be identical with and without the filter:\nfiltered:   %s\nunfiltered: %s",
			filtered.stdout, unfiltered.stdout)
	}
}
