package main

// End-to-end coverage for the normalize --source-cidr option: successful
// events are limited to one IPv4 network while failures keep surfacing,
// exit codes follow the existing 0/1/2 contract, and malformed or repeated
// options fail before stdin is read with empty stdout. These tests execute
// the real compiled binary built in TestMain.

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// runNormalizeCLIArgs is runNormalizeCLI with explicit subcommand arguments.
func runNormalizeCLIArgs(t *testing.T, stdin io.Reader, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(normalizeBin, append([]string{"normalize"}, args...)...)
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := cliResult{stdout: stdout.String(), stderr: stderr.String()}
	switch {
	case err == nil:
		result.exitCode = 0
	default:
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("normalize process could not run: %v", err)
		}
		result.exitCode = exitErr.ExitCode()
	}
	return result
}

// A filtered run keeps only in-net successes in input order, drops the rest
// silently (no failure records, no stderr), preserves physical line
// numbers, and exits 0 when no bad log line remains.
func TestNormalizeCLISourceCIDRFiltersSuccesses(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"192.0.2.5"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"b","source_ip":"198.51.100.7"}` + "\n" +
		"\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"c","source_ip":"::ffff:192.0.2.1"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"d","source_ip":"::192.0.2.1"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"e"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"g","source_ip":"192.0.2.250"}` +
		"" // no trailing newline on the last line

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr=192.0.2.123/24")
	if result.exitCode != 0 {
		t.Fatalf("all lines legal, filtering must exit 0, got %d (stderr %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("a clean filtered run must keep stderr empty, got %q", result.stderr)
	}
	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 3 {
		t.Fatalf("only the three in-net IPv4 successes survive, got %#v", results)
	}
	if results[0]["line"] != float64(1) || eventOf(t, results[0])["source_ip"] != "192.0.2.5" {
		t.Fatalf("line 1 mismatch: %#v", results[0])
	}
	if results[1]["line"] != float64(4) || eventOf(t, results[1])["source_ip"] != "192.0.2.1" {
		t.Fatalf("mapped IPv6 on physical line 4 must match as 192.0.2.1: %#v", results[1])
	}
	if results[2]["line"] != float64(7) || eventOf(t, results[2])["source_ip"] != "192.0.2.250" {
		t.Fatalf("newline-less in-net tail on line 7 must be processed: %#v", results[2])
	}
}

// A bad line outside the network (or without an address, or IPv6) is still a
// failure: ok:false with its line and reason, no event, later lines keep
// processing, and the process exits 1.
func TestNormalizeCLISourceCIDRDoesNotHideFailures(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"192.0.2.5"}` + "\n" +
		`{"timestamp":"nope","action":"b","source_ip":"10.0.0.1"}` + "\n" +
		`{"timestamp":"nope","action":"c"}` + "\n" +
		`{"timestamp":"nope","action":"d","source_ip":"2001:db8::1"}` + "\n" +
		"not json\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"f","source_ip":"192.0.2.6"}` + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.2.0/24")
	if result.exitCode != 1 {
		t.Fatalf("four bad lines must set exit 1 even off-net, got %d (stderr %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in result records, got stderr %q", result.stderr)
	}
	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 6 {
		t.Fatalf("2 in-net successes plus 4 failures = 6 records, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("in-net line 1 must be kept: %#v", results[0])
	}
	for i, lineNo := range []float64{2, 3, 4, 5} {
		rec := results[i+1]
		if rec["line"] != lineNo || rec["ok"] != false {
			t.Fatalf("record %d must be the failure at line %v: %#v", i+1, lineNo, rec)
		}
		if _, exists := rec["event"]; exists {
			t.Fatalf("failure line %v must not carry an event: %#v", lineNo, rec)
		}
		if rec["error"] == "" {
			t.Fatalf("failure line %v must keep its original error reason", lineNo)
		}
	}
	if results[5]["line"] != float64(6) || results[5]["ok"] != true {
		t.Fatalf("trailing in-net line 6 must still be processed: %#v", results[5])
	}
}

// /0 keeps every normalized IPv4 source; /32 keeps exactly one address.
func TestNormalizeCLISourceCIDREndpoints(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"0.0.0.0"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"b","source_ip":"255.255.255.255"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"c","source_ip":"::ffff:8.8.8.8"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"d","source_ip":"::1"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"e"}` + "\n"

	all := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr=0.0.0.0/0")
	if all.exitCode != 0 || all.stderr != "" {
		t.Fatalf("/0 run must be clean: code=%d stderr=%q", all.exitCode, all.stderr)
	}
	allResults := decodeStdoutResults(t, all.stdout)
	if len(allResults) != 3 {
		t.Fatalf("/0 must keep exactly the IPv4 sources, got %#v", allResults)
	}

	one := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "8.8.8.8/32")
	if one.exitCode != 0 || one.stderr != "" {
		t.Fatalf("/32 run must be clean: code=%d stderr=%q", one.exitCode, one.stderr)
	}
	oneResults := decodeStdoutResults(t, one.stdout)
	if len(oneResults) != 1 || eventOf(t, oneResults[0])["source_ip"] != "8.8.8.8" ||
		oneResults[0]["line"] != float64(3) {
		t.Fatalf("/32 must keep only physical line 3 normalized to 8.8.8.8, got %#v", oneResults)
	}
}

// Every malformed or disallowed option exits 2 with a stderr explanation and
// empty stdout. The option is rejected before input processing, so feeding a
// directory as stdin must still surface the parameter problem rather than a
// read error.
func TestNormalizeCLISourceCIDRInvalidOptionExitsTwo(t *testing.T) {
	dir, err := os.Open(".")
	if err != nil {
		t.Fatalf("opening directory as stdin: %v", err)
	}
	defer dir.Close()

	cases := []struct {
		name  string
		args  []string
		stdin io.Reader
	}{
		{"missing value at end", []string{"--source-cidr"}, strings.NewReader("")},
		{"empty equals value", []string{"--source-cidr="}, strings.NewReader("")},
		{"not a cidr", []string{"--source-cidr=192.0.2.0"}, strings.NewReader("")},
		{"prefix too large", []string{"--source-cidr=192.0.2.0/33"}, strings.NewReader("")},
		{"negative prefix", []string{"--source-cidr", "192.0.2.0/-1"}, strings.NewReader("")},
		{"ipv6 network", []string{"--source-cidr=::ffff:0:0/96"}, strings.NewReader("")},
		{"leading zero octets", []string{"--source-cidr=192.168.001.0/24"}, strings.NewReader("")},
		{"octet out of range", []string{"--source-cidr=999.0.0.0/8"}, strings.NewReader("")},
		{"duplicate equals", []string{"--source-cidr=192.0.2.0/24", "--source-cidr=10.0.0.0/8"}, strings.NewReader("")},
		{"duplicate space form", []string{"--source-cidr", "192.0.2.0/24", "--source-cidr", "10.0.0.0/8"}, strings.NewReader("")},
		{"unknown argument", []string{"--source-cidr=192.0.2.0/24", "logs.jsonl"}, strings.NewReader("")},
		{"unknown flag", []string{"--bogus"}, strings.NewReader("")},
		{"directory stdin still reports the bad option first", []string{"--source-cidr=bad"}, dir},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := runNormalizeCLIArgs(t, tc.stdin, tc.args...)
			if result.exitCode != 2 {
				t.Fatalf("bad option must exit 2, got %d: stderr=%q", result.exitCode, result.stderr)
			}
			if result.stdout != "" {
				t.Fatalf("parameter failure must leave stdout empty, got %q", result.stdout)
			}
			if !strings.HasPrefix(result.stderr, "normalize: ") || !strings.Contains(result.stderr, "source-cidr") {
				t.Fatalf("stderr must explain the --source-cidr problem, got %q", result.stderr)
			}
		})
	}
}

// Omitting the option reproduces the historical command byte for byte, and
// an all-filtered stream still exits 0 with empty stdout.
func TestNormalizeCLISourceCIDROmissionAndAllFiltered(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"10.0.0.1"}` + "\n" +
		`{"timestamp":"bad","action":"b"}` + "\n"

	plain := runNormalizeCLI(t, strings.NewReader(input))
	withExplicitUnrelated := runNormalizeCLIArgs(t, strings.NewReader(input))
	if plain.exitCode != withExplicitUnrelated.exitCode ||
		plain.stdout != withExplicitUnrelated.stdout ||
		plain.stderr != withExplicitUnrelated.stderr {
		t.Fatalf("no --source-cidr must behave identically: %#v vs %#v", plain, withExplicitUnrelated)
	}
	if plain.exitCode != 1 {
		t.Fatalf("the one bad line must still set exit 1, got %d", plain.exitCode)
	}
	if len(decodeStdoutResults(t, plain.stdout)) != 2 {
		t.Fatalf("without a filter both lines must be emitted")
	}

	allFiltered := runNormalizeCLIArgs(t,
		strings.NewReader(`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"10.0.0.1"}`+"\n"),
		"--source-cidr=192.0.2.0/24")
	if allFiltered.exitCode != 0 {
		t.Fatalf("all-legal but all-filtered input must exit 0, got %d", allFiltered.exitCode)
	}
	if allFiltered.stdout != "" || allFiltered.stderr != "" {
		t.Fatalf("nothing matched means empty stdout and stderr, got %q / %q",
			allFiltered.stdout, allFiltered.stderr)
	}
}
