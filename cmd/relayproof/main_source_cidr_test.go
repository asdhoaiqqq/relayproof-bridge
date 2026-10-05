package main

// End-to-end coverage for the normalize --source-cidr option against the
// real compiled binary: which successful events survive the filter, that
// failures are never hidden, that line numbers keep counting physical
// lines, and that every malformed option exits 2 with empty stdout before
// any stdin byte is consumed.

import (
	"strings"
	"testing"
)

// validCIDRSource builds one valid log line carrying sourceIP.
func validCIDRSource(action, sourceIP string) string {
	return `{"timestamp":"2026-01-02T00:00:00Z","action":"` + action + `","source_ip":"` + sourceIP + `"}`
}

// The core /24 filter through the CLI: host bits in the argument are
// masked, plain IPv4 and its ::ffff: mapping share one result, genuine
// IPv6 (including ::192.0.2.1), absent sources and other networks are
// dropped, the surviving records keep their original physical line
// numbers and full event content with no filter marker, and the run is
// still clean (exit 0, stderr empty).
func TestNormalizeCLISourceCIDRFiltersSuccesses(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("plain-in", "192.0.2.50"),                   // line 1 kept
		validCIDRSource("mapped-in", "::ffff:192.0.2.1"),            // line 2 kept (printed dotted)
		validCIDRSource("compat-v6", "::192.0.2.50"),                // line 3 dropped: real IPv6
		validCIDRSource("plain-v6", "2001:db8::1"),                  // line 4 dropped: IPv6
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}`, // line 5 dropped
		validCIDRSource("other-net", "198.51.100.50"),               // line 6 dropped
		validCIDRSource("edge-high", "192.0.2.255"),                 // line 7 kept
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.2.123/24")

	if result.exitCode != 0 {
		t.Fatalf("a fully valid, partially filtered stream must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("filtering successes needs no diagnostics, got %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 3 {
		t.Fatalf("expected the three in-network events, got %#v", results)
	}
	want := []struct {
		line     float64
		action   string
		sourceIP string
	}{
		{1, "plain-in", "192.0.2.50"},
		{2, "mapped-in", "192.0.2.1"}, // ::ffff: form prints the same IPv4
		{7, "edge-high", "192.0.2.255"},
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

// /32 matches exactly one address (in either mapped spelling); /0 matches
// every normalized IPv4 source but no IPv6 or absent source.
func TestNormalizeCLISourceCIDRExtremes(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("exact", "192.0.2.1"),
		validCIDRSource("exact-mapped", "::ffff:192.0.2.1"),
		validCIDRSource("neighbor", "192.0.2.2"),
		validCIDRSource("v6", "2001:db8::1"),
		`{"timestamp":"2026-01-02T00:00:00Z","action":"none"}`,
	}, "\n") + "\n"

	host := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr=192.0.2.1/32")
	if host.exitCode != 0 || host.stderr != "" {
		t.Fatalf("/32 run must be clean: exit=%d stderr=%q", host.exitCode, host.stderr)
	}
	hostResults := decodeStdoutResults(t, host.stdout)
	if len(hostResults) != 2 {
		t.Fatalf("/32 must keep only the two spellings of one address, got %#v", hostResults)
	}
	if hostResults[0]["line"] != float64(1) || hostResults[1]["line"] != float64(2) {
		t.Fatalf("/32 survivors must keep lines 1 and 2: %#v", hostResults)
	}

	all := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "0.0.0.0/0")
	if all.exitCode != 0 || all.stderr != "" {
		t.Fatalf("/0 run must be clean: exit=%d stderr=%q", all.exitCode, all.stderr)
	}
	allResults := decodeStdoutResults(t, all.stdout)
	if len(allResults) != 3 {
		t.Fatalf("/0 keeps the three IPv4 events but no IPv6/absent source, got %#v", allResults)
	}
	if allResults[2]["line"] != float64(3) {
		t.Fatalf("/0 survivors must be lines 1-3: %#v", allResults)
	}
}

// The filter never hides bad logs and never turns one into a success: a
// malformed line in-network, out-of-network, IPv6-looking, and
// source-less is emitted in every case with its line number, original
// reason and no event, later lines keep processing, and exit 1 reflects
// the failures even though every legal event was filtered out.
func TestNormalizeCLISourceCIDRFailuresStillReported(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("kept", "192.0.2.9"),                          // line 1 kept
		`{"timestamp":"bad","action":"x","source_ip":"192.0.2.9"}`,    // line 2 failure, in network
		`{"timestamp":"bad","action":"x","source_ip":"198.51.100.9"}`, // line 3 failure, out of network
		`{"timestamp":"bad","action":"x","source_ip":"::192.0.2.9"}`,  // line 4 failure, IPv6 tail
		`{"timestamp":"bad","action":"x"}`,                            // line 5 failure, no source
		"   ",                                                         // line 6 blank
		validCIDRSource("dropped", "198.51.100.1"),                    // line 7 dropped success
		validCIDRSource("tail", "192.0.2.10"),                         // line 8 kept
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.2.0/24")

	if result.exitCode != 1 {
		t.Fatalf("four bad lines must force exit 1 regardless of the filter, got %d", result.exitCode)
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
		t.Fatalf("the line after the failures and the dropped success must survive: %#v", results[5])
	}
}

// When no success remains, the stream still ends normally: exit 0 with
// zero failures means an empty stdout, and the filter itself changes
// nothing about line numbering of the records that do come out.
func TestNormalizeCLISourceCIDRAllFilteredExitsZero(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("a", "10.0.0.1"),
		"",
		validCIDRSource("b", "198.51.100.1"),
		`{"timestamp":"2026-01-02T00:00:00Z","action":"c"}`,
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.2.0/24")
	if result.exitCode != 0 {
		t.Fatalf("all-valid-but-filtered input must exit 0, got %d (stderr %q)", result.exitCode, result.stderr)
	}
	if result.stdout != "" || result.stderr != "" {
		t.Fatalf("no surviving records means empty stdout/stderr, got %q / %q", result.stdout, result.stderr)
	}
}

// Every malformed --source-cidr option exits 2 with a stderr explanation
// and empty stdout, before the log stream is consumed. The stdin carries
// both an invalid line and a valid one: had the process touched stdin, the
// invalid line would produce a failure record (and exit status 1), so the
// mandated empty stdout plus exit 2 proves option parsing runs first.
func TestNormalizeCLISourceCIDRBadOptionExitsTwoWithoutReading(t *testing.T) {
	// First line fails normalization; second line would succeed.
	stdinContent := `{"timestamp":"not-a-time","action":"x"}` + "\n" +
		validCIDRSource("kept", "10.0.0.1") + "\n"
	cases := []struct {
		name string
		args []string
	}{
		{"missing value", []string{"--source-cidr"}},
		{"empty value separate", []string{"--source-cidr", ""}},
		{"empty value attached", []string{"--source-cidr="}},
		{"no slash", []string{"--source-cidr", "192.0.2.0"}},
		{"prefix 33", []string{"--source-cidr", "192.0.2.0/33"}},
		{"octet 256", []string{"--source-cidr", "256.0.0.0/8"}},
		{"padded octet", []string{"--source-cidr", "192.168.001.0/24"}},
		{"padded prefix", []string{"--source-cidr", "192.0.2.1/024"}},
		{"ipv6 network", []string{"--source-cidr", "::1/128"}},
		{"junk", []string{"--source-cidr", "ten-dot-zero"}},
		{"duplicate separate", []string{"--source-cidr", "10.0.0.0/8", "--source-cidr", "11.0.0.0/8"}},
		{"duplicate mixed form", []string{"--source-cidr=10.0.0.0/8", "--source-cidr", "11.0.0.0/8"}},
		{"unknown argument", []string{"--source-cidr", "10.0.0.0/8", "--verbose"}},
		{"bare unknown option", []string{"--network"}},
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
			if !strings.Contains(result.stderr, "source-cidr") && tc.name != "bare unknown option" {
				t.Fatalf("diagnostic should name the option, got %q", result.stderr)
			}
		})
	}
}
