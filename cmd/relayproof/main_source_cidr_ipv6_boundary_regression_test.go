package main

// CLI-level regression coverage for an IPv6 source network whose prefix
// length does not fall on a hex-digit boundary, exercised against the real
// compiled binary. 2001:db8:1:2:abff::1234/73 admits exactly
// 2001:db8:1:2:ab80:: - 2001:db8:1:2:abff:ffff:ffff:ffff (the prefix keeps
// 9 bits of the fifth group, so the boundary sits inside the third hex
// digit of "abff"): both range ends survive, the addresses immediately
// outside the range do not, and a boundary source works through source_ip
// and src_ip alike, with compressed and full spellings of one source
// sharing one decision and one normalized output form. Spelling the option
// with another in-range host address — or with the full uncompressed form
// of one — selects byte-identically. An out-of-range log with an invalid
// timestamp is still a counted failure with its reason and no event, later
// in-range logs keep coming with their physical line numbers, and a batch
// in which every valid log misses the network exits 0 with empty output.

import (
	"strings"
	"testing"
)

// The /73 range through the CLI: the first and last range addresses are
// kept with their physical line numbers and normalized sources, the
// adjacent addresses and an absent source are dropped silently, and the
// run stays clean (exit 0, stderr empty, no filter marker on any record).
func TestNormalizeCLISourceCIDRIPv6HexDigitBoundary(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("range-first", "2001:db8:1:2:ab80::"),                                                    // line 1 kept
		`{"timestamp":"2026-01-02T00:00:00Z","action":"range-last","src_ip":"2001:db8:1:2:abff:ffff:ffff:ffff"}`, // line 2 kept, via the alias
		validCIDRSource("full-spelling", "2001:db8:0001:0002:abff:0000:0000:1234"),                               // line 3 kept, prints compressed
		validCIDRSource("just-below", "2001:db8:1:2:ab7f:ffff:ffff:ffff"),                                        // line 4 dropped
		validCIDRSource("just-above", "2001:db8:1:2:ac00::"),                                                     // line 5 dropped
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}`,                                              // line 6 dropped
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "2001:db8:1:2:abff::1234/73")

	if result.exitCode != 0 {
		t.Fatalf("a fully valid, partially filtered stream must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("filtering successes needs no diagnostics, got %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 3 {
		t.Fatalf("expected the three in-range IPv6 events, got %#v", results)
	}
	want := []struct {
		line     float64
		action   string
		sourceIP string
	}{
		{1, "range-first", "2001:db8:1:2:ab80::"},
		{2, "range-last", "2001:db8:1:2:abff:ffff:ffff:ffff"},
		{3, "full-spelling", "2001:db8:1:2:abff::1234"},
	}
	for i, w := range want {
		got := results[i]
		if got["line"] != w.line || got["ok"] != true {
			t.Fatalf("record %d must keep physical line %v and ok:true: %#v", i, w.line, got)
		}
		if _, marked := got["filtered"]; marked {
			t.Fatalf("record %d must carry no filter marker: %#v", i, got)
		}
		event := eventOf(t, got)
		if event["action"] != w.action || event["source_ip"] != w.sourceIP {
			t.Fatalf("record %d event mismatch: %#v", i, event)
		}
	}
}

// Spelling the /73 network with another in-range host address, or with the
// full uncompressed form of the original host, selects byte-identically
// and renders the same canonical network.
func TestNormalizeCLISourceCIDRIPv6BoundarySpellingsSelectIdentically(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("range-first", "2001:db8:1:2:ab80::"),
		validCIDRSource("range-last", "2001:db8:1:2:abff:ffff:ffff:ffff"),
		validCIDRSource("just-below", "2001:db8:1:2:ab7f:ffff:ffff:ffff"),
		validCIDRSource("just-above", "2001:db8:1:2:ac00::"),
	}, "\n") + "\n"

	spellings := []string{
		"2001:db8:1:2:abff::1234/73",
		"2001:db8:1:2:ab80::/73",
		"2001:db8:1:2:abff:ffff:ffff:ffff/73",
		"2001:db8:0001:0002:abff:0000:0000:1234/73",
	}
	var outputs []string
	for _, spelled := range spellings {
		result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", spelled)
		if result.exitCode != 0 || result.stderr != "" {
			t.Fatalf("filter %q must run clean: exit=%d stderr=%q", spelled, result.exitCode, result.stderr)
		}
		results := decodeStdoutResults(t, result.stdout)
		if len(results) != 2 {
			t.Fatalf("filter %q must keep exactly the two range-edge events, got %#v", spelled, results)
		}
		outputs = append(outputs, result.stdout)
	}
	for i := 1; i < len(outputs); i++ {
		if outputs[i] != outputs[0] {
			t.Fatalf("spellings %q and %q of one /73 network must produce identical output:\n%s\nvs\n%s",
				spellings[0], spellings[i], outputs[0], outputs[i])
		}
	}
}

// A time-invalid log whose source lies immediately outside the /73 range
// is still a counted failure — physical line number, timestamp reason, no
// event — and the in-range logs around it keep their input order and
// physical line numbers. Exit 1, stderr empty: the dropped valid events
// are filtered successes, not failures, and the bad log is a log failure,
// not a read or write fault.
func TestNormalizeCLISourceCIDRIPv6BoundaryFailureStillCounted(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("range-first", "2001:db8:1:2:ab80::"),                            // line 1 kept
		`{"timestamp":"not-a-time","action":"broken","source_ip":"2001:db8:1:2:ac00::"}`, // line 2 failure, just outside
		"", // line 3 blank
		validCIDRSource("dropped", "2001:db8:1:2:ab7f:ffff:ffff:ffff"),    // line 4 dropped, just outside
		validCIDRSource("range-last", "2001:db8:1:2:abff:ffff:ffff:ffff"), // line 5 kept
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "2001:db8:1:2:abff::1234/73")

	if result.exitCode != 1 {
		t.Fatalf("the invalid line must force exit 1 even though its source is out of range, got %d", result.exitCode)
	}
	if result.stderr != "" {
		t.Fatalf("per-line reasons belong in stdout records, not stderr, got %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 3 {
		t.Fatalf("expected 2 kept successes + 1 failure, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("the range-first log must succeed on line 1: %#v", results[0])
	}
	failure := results[1]
	if failure["line"] != float64(2) || failure["ok"] != false {
		t.Fatalf("the invalid log must be reported as line 2 with ok:false: %#v", failure)
	}
	if _, exists := failure["event"]; exists {
		t.Fatalf("the invalid line must carry no event: %#v", failure)
	}
	if msg, _ := failure["error"].(string); !strings.Contains(msg, "timestamp") {
		t.Fatalf("the failure must keep its original timestamp reason, got %q", msg)
	}
	if results[2]["line"] != float64(5) || results[2]["ok"] != true {
		t.Fatalf("the range-last log must keep physical line 5 past the failure, blank line and dropped line: %#v", results[2])
	}
	if eventOf(t, results[2])["source_ip"] != "2001:db8:1:2:abff:ffff:ffff:ffff" {
		t.Fatalf("the range-last event must survive intact: %#v", results[2])
	}
}

// A batch in which every valid log misses the /73 network ends normally:
// exit 0, empty stdout and stderr, nothing counted as a failure.
func TestNormalizeCLISourceCIDRIPv6BoundaryAllMissExitsZero(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("just-below", "2001:db8:1:2:ab7f:ffff:ffff:ffff"),
		validCIDRSource("just-above", "2001:db8:1:2:ac00::"),
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}`,
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr=2001:db8:1:2:abff::1234/73")
	if result.exitCode != 0 {
		t.Fatalf("an all-valid, fully filtered batch must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stdout != "" || result.stderr != "" {
		t.Fatalf("no surviving records means empty stdout/stderr, got %q / %q", result.stdout, result.stderr)
	}
}
