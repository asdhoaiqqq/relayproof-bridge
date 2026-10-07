package main

// End-to-end regression coverage for an IPv6 --source-cidr whose prefix
// lands inside a hex digit, exercised against the real compiled binary:
//
//	--source-cidr 2001:db8:1:2:abff::1234/73
//
// selects 2001:db8:1:2:ab80::/73. The fifth group's low nibble is the one
// varying part of the prefix, so the range covers fifth group ab80..abff and
// ends at 2001:db8:1:2:abff:ffff:ffff:ffff; the immediate neighbors are
// 2001:db8:1:2:ab7f:ffff:ffff:ffff and 2001:db8:1:2:ac00::. These tests pin
// the two range edges through source_ip and src_ip and through compressed and
// full spellings, the host-bit masking across equivalent argument spellings,
// physical line-number stability past dropped and blank lines, and the
// distinction between a filtered-out success (no record, exit still 0) and a
// malformed outside line (ok:false with its line and reason, exit 1).

import (
	"strings"
	"testing"
)

// hexBoundaryCIDRArg is the documented host-spelled /73 option; every
// equivalent spelling in hexBoundaryCIDRArgVariants must mask to the same
// 2001:db8:1:2:ab80::/73 network.
const hexBoundaryCIDRArg = "2001:db8:1:2:abff::1234/73"

// hexBoundaryCIDRArgVariants all denote the same /73 network: another
// in-range host address, the range's own edges, and the full uncompressed
// spelling of the documented address.
var hexBoundaryCIDRArgVariants = []string{
	"2001:db8:1:2:abff::1234/73",
	"2001:db8:1:2:abab::1/73",
	"2001:db8:1:2:ab80::/73",
	"2001:db8:1:2:abff:ffff:ffff:ffff/73",
	"2001:db8:0001:0002:abff:0000:0000:1234/73",
}

// validCIDRAliasSource builds one valid log line whose source arrives
// through the src_ip alias instead of source_ip.
func validCIDRAliasSource(action, sourceIP string) string {
	return `{"timestamp":"2026-01-02T00:00:00Z","action":"` + action + `","src_ip":"` + sourceIP + `"}`
}

// The /73 filter through the CLI: the first and last range addresses and
// interior hits (compressed/full, source_ip/src_ip) survive with normalized
// sources and original line numbers; the two immediate neighbors, another
// IPv6 network, an IPv4 source and an absent source are dropped silently; a
// blank line produces nothing without renumbering. The run is clean
// (exit 0, stderr empty) with no filter marker on the records.
func TestNormalizeCLISourceCIDRIPv6HexBoundaryFiltersSuccesses(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("range-first", "2001:db8:1:2:ab80::"),             // line 1 kept
		validCIDRAliasSource("interior-full", "2001:db8:1:2:ab9a:0:0:1"),  // line 2 kept (alias, full)
		validCIDRSource("spelled-host", "2001:db8:1:2:abff::1234"),        // line 3 kept
		validCIDRSource("range-last", "2001:db8:1:2:abff:ffff:ffff:ffff"), // line 4 kept
		validCIDRSource("just-below", "2001:db8:1:2:ab7f:ffff:ffff:ffff"), // line 5 dropped
		validCIDRSource("just-above", "2001:db8:1:2:ac00::"),              // line 6 dropped
		validCIDRSource("other-v6", "2001:db8:1:1::1"),                    // line 7 dropped
		validCIDRSource("plain-v4", "192.0.2.1"),                          // line 8 dropped (family)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}`,       // line 9 dropped (absent)
		"", // line 10 blank
		validCIDRAliasSource("tail-hit", "2001:db8:1:2:abff:0:0:1234"), // line 11 kept
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", hexBoundaryCIDRArg)

	if result.exitCode != 0 {
		t.Fatalf("a fully valid, partially filtered stream must exit 0, got %d (stderr %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("filtering successes needs no diagnostics, got %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 5 {
		t.Fatalf("expected the five in-range IPv6 events, got %#v", results)
	}
	want := []struct {
		line     float64
		action   string
		sourceIP string
	}{
		{1, "range-first", "2001:db8:1:2:ab80::"},
		{2, "interior-full", "2001:db8:1:2:ab9a::1"},
		{3, "spelled-host", "2001:db8:1:2:abff::1234"},
		{4, "range-last", "2001:db8:1:2:abff:ffff:ffff:ffff"},
		{11, "tail-hit", "2001:db8:1:2:abff::1234"},
	}
	for i, w := range want {
		got := results[i]
		if got["line"] != w.line || got["ok"] != true {
			t.Fatalf("record %d must keep physical line %v and ok:true: %#v", i, w.line, got)
		}
		if _, exists := got["filtered"]; exists {
			t.Fatalf("results must carry no filter marker: %#v", got)
		}
		event := eventOf(t, got)
		if event["action"] != w.action || event["source_ip"] != w.sourceIP {
			t.Fatalf("record %d event mismatch: %#v", i, event)
		}
	}
}

// A valid event immediately outside the network is a filtered success, while
// a malformed line immediately outside the network is still a log failure:
// it keeps its physical line number and timestamp reason with no event and
// forces exit 1; the in-range legal logs before and after it are emitted, and
// stderr stays empty. The two outcomes must not be conflated.
func TestNormalizeCLISourceCIDRIPv6HexBoundaryOutsideFailureKeepsLine(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("hit-before", "2001:db8:1:2:ab80::1"), // line 1 kept
		validCIDRSource("outside-ok", "2001:db8:1:2:ac00::"),  // line 2 dropped success
		"", // line 3 blank
		`{"timestamp":"not-a-time","action":"broken-outside","source_ip":"2001:db8:1:2:ab7f:ffff:ffff:ffff"}`, // line 4 failure
		validCIDRAliasSource("hit-after", "2001:db8:1:2:abff::1"),                                             // line 5 kept
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", hexBoundaryCIDRArg)

	if result.exitCode != 1 {
		t.Fatalf("the one malformed outside line must force exit 1, got %d (stderr %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("a per-line failure belongs in its result record, got %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 3 {
		t.Fatalf("expected 2 in-range successes + 1 failure, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("record 0 must be the line-1 hit: %#v", results[0])
	}
	if eventOf(t, results[0])["action"] != "hit-before" {
		t.Fatalf("record 0 action mismatch: %#v", results[0])
	}

	bad := results[1]
	if bad["line"] != float64(4) || bad["ok"] != false {
		t.Fatalf("the malformed outside line must keep physical line 4 and ok:false: %#v", bad)
	}
	if _, exists := bad["event"]; exists {
		t.Fatalf("the malformed outside line must carry no event: %#v", bad)
	}
	if msg, _ := bad["error"].(string); !strings.Contains(msg, "timestamp") {
		t.Fatalf("the failure must keep its original timestamp reason, got %q", msg)
	}

	if results[2]["line"] != float64(5) || results[2]["ok"] != true {
		t.Fatalf("the in-range line after the failure must still be emitted: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "hit-after" {
		t.Fatalf("record 2 action mismatch: %#v", results[2])
	}
}

// Every equivalent spelling of the /73 argument — a different in-range host
// address and the full spelling of the same address — selects exactly the
// same records and produces byte-identical stdout, each as a clean run.
func TestNormalizeCLISourceCIDRIPv6HexBoundaryEquivalentArguments(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("range-first", "2001:db8:1:2:ab80::"),
		validCIDRSource("spelled-host", "2001:db8:1:2:abff::1234"),
		validCIDRSource("range-last", "2001:db8:1:2:abff:ffff:ffff:ffff"),
		validCIDRSource("just-below", "2001:db8:1:2:ab7f:ffff:ffff:ffff"),
		validCIDRSource("just-above", "2001:db8:1:2:ac00::"),
		validCIDRAliasSource("full-host", "2001:db8:0001:0002:abff:0000:0000:1234"),
	}, "\n") + "\n"

	var reference string
	for i, arg := range hexBoundaryCIDRArgVariants {
		// Exercise both the separated and equals-attached option forms.
		var result cliResult
		if i%2 == 0 {
			result = runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", arg)
		} else {
			result = runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr="+arg)
		}
		if result.exitCode != 0 || result.stderr != "" {
			t.Fatalf("argument %q must be a clean filter: exit=%d stderr=%q", arg, result.exitCode, result.stderr)
		}
		records := decodeStdoutResults(t, result.stdout)
		if len(records) != 4 {
			t.Fatalf("argument %q must keep the four in-range events, got %#v", arg, records)
		}
		if i == 0 {
			reference = result.stdout
			continue
		}
		if result.stdout != reference {
			t.Fatalf("argument %q selects differently from %q:\n%q\nvs\n%q",
				arg, hexBoundaryCIDRArgVariants[0], result.stdout, reference)
		}
	}
}

// A batch whose valid logs all fall immediately outside the /73 network ends
// cleanly: exit 0 and empty stdout/stderr — those are filtered successes, not
// failures. A trailing blank line changes nothing.
func TestNormalizeCLISourceCIDRIPv6HexBoundaryAllFilteredExitsZero(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("just-below", "2001:db8:1:2:ab7f:ffff:ffff:ffff"),
		validCIDRSource("just-above", "2001:db8:1:2:ac00::"),
		"",
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}`,
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", hexBoundaryCIDRArg)
	if result.exitCode != 0 {
		t.Fatalf("all-valid-but-filtered input must exit 0, got %d (stderr %q)", result.exitCode, result.stderr)
	}
	if result.stdout != "" || result.stderr != "" {
		t.Fatalf("no surviving records means empty stdout/stderr, got %q / %q", result.stdout, result.stderr)
	}
}
