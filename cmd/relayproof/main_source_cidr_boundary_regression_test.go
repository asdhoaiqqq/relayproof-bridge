package main

// CLI-level regression coverage for source networks whose prefix length does
// not fall on an IPv4 octet boundary, exercised against the real compiled
// binary. 172.16.5.9/12 admits exactly 172.16.0.0 - 172.31.255.255 and
// 192.0.129.7/17 admits exactly 192.0.128.0 - 192.0.255.255: both range ends
// survive, the addresses immediately outside each range do not, and a
// boundary source works through source_ip and src_ip alike, with plain IPv4
// and its ::ffff: mapping sharing one decision and one dotted output form
// while genuine IPv6 with the same trailing bits never matches. The
// two-address network 192.0.2.3/31 keeps both 192.0.2.2 and 192.0.2.3 — no
// network/broadcast exclusion — and spelling it as 192.0.2.2/31 selects
// byte-identically. An out-of-range log with an invalid timestamp is still a
// counted failure with its reason and no event, later in-range logs keep
// coming with their physical line numbers, and a batch in which every valid
// log misses the network exits 0 with empty output.

import (
	"strings"
	"testing"
)

// The /12 and /17 ranges through the CLI: first and last range addresses are
// kept with their physical line numbers and normalized dotted sources, the
// adjacent addresses, a genuine IPv6 look-alike and an absent source are
// dropped silently, and the run stays clean (exit 0, stderr empty, no filter
// marker on any record).
func TestNormalizeCLISourceCIDRNonOctetBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		option string
		// lines holds (source field, source address) pairs; kept marks the
		// ones the network must admit.
		lines []struct {
			field string
			addr  string
			kept  bool
		}
	}{
		{
			name:   "second-octet boundary /12",
			option: "172.16.5.9/12",
			lines: []struct {
				field string
				addr  string
				kept  bool
			}{
				{"source_ip", "172.16.0.0", true},        // first address of the range
				{"src_ip", "172.31.255.255", true},       // last address, via the alias
				{"source_ip", "::ffff:172.16.0.0", true}, // mapped spelling of the first address
				{"source_ip", "172.15.255.255", false},   // immediately below
				{"source_ip", "172.32.0.0", false},       // immediately above
				{"source_ip", "::172.16.0.0", false},     // genuine IPv6 with an in-range tail
				{"", "", false},                          // absent source
			},
		},
		{
			name:   "third-octet boundary /17",
			option: "192.0.129.7/17",
			lines: []struct {
				field string
				addr  string
				kept  bool
			}{
				{"source_ip", "192.0.128.0", true},          // first address of the range
				{"src_ip", "192.0.255.255", true},           // last address, via the alias
				{"source_ip", "::ffff:192.0.255.255", true}, // mapped spelling of the last address
				{"source_ip", "192.0.127.255", false},       // immediately below
				{"source_ip", "192.1.0.0", false},           // immediately above
				{"source_ip", "::192.0.128.0", false},       // genuine IPv6 with an in-range tail
				{"", "", false},                             // absent source
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var inputLines []string
			var want []struct {
				line   float64
				action string
				source string
			}
			for i, l := range tc.lines {
				action := l.addr
				if action == "" {
					action = "no-source"
				}
				var line string
				if l.field == "" {
					line = `{"timestamp":"2026-01-02T00:00:00Z","action":"` + action + `"}`
				} else {
					line = `{"timestamp":"2026-01-02T00:00:00Z","action":"` + action + `","` + l.field + `":"` + l.addr + `"}`
				}
				inputLines = append(inputLines, line)
				if l.kept {
					want = append(want, struct {
						line   float64
						action string
						source string
					}{float64(i + 1), action, strings.TrimPrefix(l.addr, "::ffff:")})
				}
			}
			input := strings.Join(inputLines, "\n") + "\n"

			result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", tc.option)
			if result.exitCode != 0 {
				t.Fatalf("a fully valid, partially filtered stream must exit 0, got %d (stderr: %q)",
					result.exitCode, result.stderr)
			}
			if result.stderr != "" {
				t.Fatalf("filtering successes needs no diagnostics, got %q", result.stderr)
			}

			results := decodeStdoutResults(t, result.stdout)
			if len(results) != len(want) {
				t.Fatalf("expected %d admitted records, got %#v", len(want), results)
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
				if event["action"] != w.action || event["source_ip"] != w.source {
					t.Fatalf("record %d event mismatch: %#v", i, event)
				}
			}
		})
	}
}

// The /31 two-address network through the CLI: both addresses of the pair
// survive — neither is treated as a network or broadcast address — the
// immediate neighbors do not, and spelling the option with the pair's other
// address produces byte-identical output.
func TestNormalizeCLISourceCIDRSlash31KeepsBothAddresses(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("below", "192.0.2.1"),
		validCIDRSource("low-of-pair", "192.0.2.2"),
		validCIDRSource("high-of-pair", "192.0.2.3"),
		validCIDRSource("above", "192.0.2.4"),
	}, "\n") + "\n"

	var outputs []string
	for _, spelled := range []string{"192.0.2.3/31", "192.0.2.2/31"} {
		result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", spelled)
		if result.exitCode != 0 || result.stderr != "" {
			t.Fatalf("filter %q must run clean: exit=%d stderr=%q", spelled, result.exitCode, result.stderr)
		}
		results := decodeStdoutResults(t, result.stdout)
		if len(results) != 2 {
			t.Fatalf("filter %q must keep exactly the two addresses of the pair, got %#v", spelled, results)
		}
		for i, w := range []struct {
			line   float64
			action string
			source string
		}{
			{2, "low-of-pair", "192.0.2.2"},
			{3, "high-of-pair", "192.0.2.3"},
		} {
			if results[i]["line"] != w.line || results[i]["ok"] != true {
				t.Fatalf("filter %q: record %d must keep physical line %v: %#v", spelled, i, w.line, results[i])
			}
			event := eventOf(t, results[i])
			if event["action"] != w.action || event["source_ip"] != w.source {
				t.Fatalf("filter %q: record %d event mismatch: %#v", spelled, i, event)
			}
		}
		outputs = append(outputs, result.stdout)
	}
	if outputs[0] != outputs[1] {
		t.Fatalf("the two host spellings of one /31 must produce identical output:\n%s\nvs\n%s",
			outputs[0], outputs[1])
	}
}

// A time-invalid log whose source lies immediately outside the /17 range is
// still a counted failure — physical line number, timestamp reason, no event
// — and the in-range logs around it keep their input order and physical line
// numbers. Exit 1, stderr empty.
func TestNormalizeCLISourceCIDRBoundaryFailureStillCounted(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("range-first", "192.0.128.0"),                              // line 1 kept
		`{"timestamp":"not-a-time","action":"broken","source_ip":"192.0.127.255"}`, // line 2 failure, just outside
		"",                                      // line 3 blank
		validCIDRSource("dropped", "192.1.0.0"), // line 4 dropped, just outside
		validCIDRSource("range-last", "192.0.255.255"), // line 5 kept
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.129.7/17")

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
	if eventOf(t, results[2])["source_ip"] != "192.0.255.255" {
		t.Fatalf("the range-last event must survive intact: %#v", results[2])
	}
}

// A batch in which every valid log misses the boundary network ends
// normally: exit 0, empty stdout and stderr, nothing counted as a failure.
func TestNormalizeCLISourceCIDRBoundaryAllMissExitsZero(t *testing.T) {
	input := strings.Join([]string{
		validCIDRSource("just-below", "192.0.127.255"),
		validCIDRSource("just-above", "192.1.0.0"),
		validCIDRSource("v6-same-tail", "::192.0.255.255"),
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}`,
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.129.7/17")
	if result.exitCode != 0 {
		t.Fatalf("an all-valid, fully filtered batch must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stdout != "" || result.stderr != "" {
		t.Fatalf("no surviving records means empty stdout/stderr, got %q / %q", result.stdout, result.stderr)
	}
}
