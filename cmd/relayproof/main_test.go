// Black-box regression tests for the normalize subcommand entry point.
// They run the real compiled binary and judge it only by its exit status
// and the exact bytes on stdout and stderr, so the contract users see —
// per-line JSON results on stdout, diagnostics on stderr, and the exit
// code summarizing the run — stays pinned. Everything runs locally with
// no network access and no dependence on wall-clock time.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// binaryPath is the relayproof binary built once for the whole test run.
var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "relayproof-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, "creating temp dir:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)
	binaryPath = filepath.Join(dir, "relayproof")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building relayproof binary:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// runNormalize executes `relayproof normalize` with the given stdin and
// reports the exit status plus what landed on each stream.
func runNormalizeCLI(t *testing.T, stdin io.Reader) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(binaryPath, "normalize")
	cmd.Stdin = stdin
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		exitCode = 0
	} else {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running normalize: %v", err)
		}
		exitCode = exitErr.ExitCode()
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// decodeResults requires stdout to be nothing but whole JSON result
// objects, one per line — no help text, no prompts, no partial records.
func decodeResults(t *testing.T, stdout string) []map[string]any {
	t.Helper()
	var results []map[string]any
	dec := json.NewDecoder(strings.NewReader(stdout))
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				return results
			}
			t.Fatalf("stdout must be pure per-line JSON results, decode error %v after %d records: %q", err, len(results), stdout)
		}
		if _, ok := m["line"]; !ok {
			t.Fatalf("every stdout record must be a result with a line number, got %#v", m)
		}
		if _, ok := m["ok"]; !ok {
			t.Fatalf("every stdout record must be a result with an ok flag, got %#v", m)
		}
		results = append(results, m)
	}
}

func eventOf(t *testing.T, r map[string]any) map[string]any {
	t.Helper()
	event, ok := r["event"].(map[string]any)
	if !ok {
		t.Fatalf("result has no event: %#v", r)
	}
	return event
}

// A clean run of valid logs exits 0 with only per-line JSON on stdout and
// nothing on stderr. Alias field names map to the canonical ones, the
// timestamp is converted to UTC, the action is trimmed, and unmapped
// fields survive in extra with their JSON types intact.
func TestCLIAllValidExitsZero(t *testing.T) {
	input := `{"time":"2026-01-02T08:04:05+08:00","event_type":"  login  ","src_ip":"2001:db8::1","user":"alice","retries":2,"ok":true}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"logout"}` + "\n"
	stdout, stderr, code := runNormalizeCLI(t, strings.NewReader(input))
	if code != 0 {
		t.Fatalf("all-valid input must exit 0, got %d (stderr %q)", code, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr must stay empty on a clean run, got %q", stderr)
	}
	results := decodeResults(t, stdout)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %#v", results)
	}

	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must succeed with its line number: %#v", results[0])
	}
	event := eventOf(t, results[0])
	if event["timestamp"] != "2026-01-02T00:04:05Z" {
		t.Fatalf("alias time must map to a UTC canonical timestamp, got %v", event["timestamp"])
	}
	if event["action"] != "login" {
		t.Fatalf("alias event_type must map to a trimmed action, got %v", event["action"])
	}
	if event["source_ip"] != "2001:db8::1" {
		t.Fatalf("alias src_ip must map to source_ip, got %v", event["source_ip"])
	}
	extra, ok := event["extra"].(map[string]any)
	if !ok {
		t.Fatalf("unmapped fields must be kept in extra: %#v", event)
	}
	if extra["user"] != "alice" {
		t.Fatalf("extra string must survive the CLI unchanged, got %v", extra["user"])
	}
	if extra["retries"] != float64(2) {
		t.Fatalf("extra number must keep its JSON number type, got %T (%v)", extra["retries"], extra["retries"])
	}
	if extra["ok"] != true {
		t.Fatalf("extra boolean must keep its JSON boolean type, got %T (%v)", extra["ok"], extra["ok"])
	}

	if results[1]["line"] != float64(2) || results[1]["ok"] != true {
		t.Fatalf("line 2 must succeed with its line number: %#v", results[1])
	}
	event2 := eventOf(t, results[1])
	if event2["timestamp"] != "2026-01-02T00:00:00Z" || event2["action"] != "logout" {
		t.Fatalf("canonical field names must pass through: %#v", event2)
	}
}

// A bad log between two good ones yields ok:false with an explanatory
// error and no event for that line only; the surrounding lines still
// succeed in input order, the run finishes, and the exit status is 1 —
// never 0 just because the last line was valid. stderr stays empty.
func TestCLIMixedValidInvalidValidExitsOne(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}` + "\n" +
		`{"timestamp":"not-a-time","action":"b"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"c"}` + "\n"
	stdout, stderr, code := runNormalizeCLI(t, strings.NewReader(input))
	if code != 1 {
		t.Fatalf("one invalid line must exit 1 after processing everything, got %d (stderr %q)", code, stderr)
	}
	if stderr != "" {
		t.Fatalf("per-line failures belong in stdout results, not stderr, got %q", stderr)
	}
	results := decodeResults(t, stdout)
	if len(results) != 3 {
		t.Fatalf("processing must continue past the bad line: %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must succeed: %#v", results[0])
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != false {
		t.Fatalf("line 2 must fail in place: %#v", results[1])
	}
	msg, _ := results[1]["error"].(string)
	if !strings.Contains(msg, "timestamp") {
		t.Fatalf("the failure result must explain itself, got error %q", msg)
	}
	if _, exists := results[1]["event"]; exists {
		t.Fatalf("a failed line must not carry an event: %#v", results[1])
	}
	if results[2]["line"] != float64(3) || results[2]["ok"] != true {
		t.Fatalf("line 3 must still succeed after the failure: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "c" {
		t.Fatalf("input order must be preserved through the failure: %#v", results[2])
	}
	if strings.Contains(stdout, "usage:") {
		t.Fatalf("stdout must not mix help text into the result stream: %q", stdout)
	}
}

// Blank lines emit no result but still count as physical lines for
// numbering, and a final complete log without a trailing newline is
// processed normally.
func TestCLIBlankLinesAndMissingFinalNewline(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}` + "\n" +
		"\n" +
		"   \t \n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"b"}` // no trailing newline
	stdout, stderr, code := runNormalizeCLI(t, strings.NewReader(input))
	if code != 0 {
		t.Fatalf("blank lines and a newline-less final log must exit 0, got %d (stderr %q)", code, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr must stay empty, got %q", stderr)
	}
	results := decodeResults(t, stdout)
	if len(results) != 2 {
		t.Fatalf("blank lines must produce no results, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 mismatch: %#v", results[0])
	}
	if results[1]["line"] != float64(4) || results[1]["ok"] != true {
		t.Fatalf("line numbers must count blank physical lines, got %#v", results[1])
	}
	if eventOf(t, results[1])["action"] != "b" {
		t.Fatalf("the newline-less final log must be processed normally: %#v", results[1])
	}
}

// Empty input and blank-only input end quietly: no results, no stderr,
// exit 0.
func TestCLIEmptyAndBlankInputExitZero(t *testing.T) {
	for _, input := range []string{"", "\n", "  \n\n\t\n"} {
		stdout, stderr, code := runNormalizeCLI(t, strings.NewReader(input))
		if code != 0 {
			t.Fatalf("input %q must exit 0, got %d (stderr %q)", input, code, stderr)
		}
		if stdout != "" {
			t.Fatalf("input %q must produce no results, got %q", input, stdout)
		}
		if stderr != "" {
			t.Fatalf("input %q must produce no diagnostics, got %q", input, stderr)
		}
	}
}

// A read failure before any complete log is a stream-level problem, not a
// bad log line: exit 2, a "normalize: "-prefixed cause on stderr, and no
// per-line results on stdout. A directory handed in as stdin fails to read
// deterministically on Linux without any fault injection.
func TestCLIReadErrorBeforeAnyLineExitsTwo(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	stdout, stderr, code := runNormalizeCLI(t, dir)
	if code != 2 {
		t.Fatalf("a read failure must exit 2, got %d (stderr %q)", code, stderr)
	}
	if !strings.HasPrefix(stderr, "normalize: ") {
		t.Fatalf("stderr must carry the normalize-prefixed read cause, got %q", stderr)
	}
	if strings.TrimSpace(strings.TrimPrefix(stderr, "normalize: ")) == "" {
		t.Fatalf("the diagnostic must name the read failure, got %q", stderr)
	}
	if stdout != "" {
		t.Fatalf("no complete line means no per-line results, got %q", stdout)
	}
}
