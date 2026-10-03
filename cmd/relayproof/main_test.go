package main

// End-to-end regression coverage for the normalize subcommand as users
// actually invoke it: logs arrive on stdin, per-line JSON results leave on
// stdout, diagnostics leave on stderr, and the exit status summarizes the
// run. These tests execute the real compiled binary so the relationship
// between per-line results, error output, and the process exit code is
// pinned exactly as the shell observes it. Everything runs locally with
// scripted input, so the checks are offline and deterministic.

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// normalizeBin is the compiled relayproof binary shared by all tests in
// this package, built once from the current sources.
var normalizeBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "relayproof-cli-test")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	normalizeBin = filepath.Join(dir, "relayproof")
	build := exec.Command("go", "build", "-o", normalizeBin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("building relayproof for CLI tests: " + err.Error() + "\n" + string(out))
	}
	os.Exit(m.Run())
}

// cliResult captures everything the surrounding shell can observe from one
// normalize invocation.
type cliResult struct {
	stdout   string
	stderr   string
	exitCode int
}

// runNormalizeCLI executes `relayproof normalize` with stdin fed from r and
// records stdout, stderr, and the exit code. A process that cannot be
// started at all fails the test rather than masquerading as an exit status.
func runNormalizeCLI(t *testing.T, stdin io.Reader) cliResult {
	t.Helper()
	cmd := exec.Command(normalizeBin, "normalize")
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

// decodeStdoutResults parses stdout as newline-delimited JSON result
// objects. Any line that is not a JSON object — help text, a plain-text
// notice, a log fragment — fails the test, because stdout must carry
// machine-readable results and nothing else.
func decodeStdoutResults(t *testing.T, stdout string) []map[string]any {
	t.Helper()
	var results []map[string]any
	decoder := json.NewDecoder(strings.NewReader(stdout))
	for {
		var record map[string]any
		if err := decoder.Decode(&record); err != nil {
			if err == io.EOF {
				return results
			}
			t.Fatalf("stdout must contain only JSON result objects, got decode error %v after %d records: %q",
				err, len(results), stdout)
		}
		results = append(results, record)
	}
}

// eventOf extracts the event object of a successful result.
func eventOf(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	event, ok := result["event"].(map[string]any)
	if !ok {
		t.Fatalf("result has no event object: %#v", result)
	}
	return event
}

// A healthy run: every log line normalizes, stdout carries one JSON result
// per line and nothing else, stderr stays silent, and the process exits 0.
// Alias keys must surface under their canonical names, the timestamp must be
// converted to UTC, the action trimmed, and unmapped fields must survive in
// extra with their JSON types intact.
func TestNormalizeCLIAllValidExitsZero(t *testing.T) {
	input := `{"time":"2026-01-02T08:04:05+08:00","src_ip":"2001:db8::1","event_type":"  login  ","user":" alice ","retries":2,"ok":true}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"logout","source_ip":"10.0.0.9","tags":["a","b"],"meta":{"trace":"t-1"}}` + "\n"

	result := runNormalizeCLI(t, strings.NewReader(input))

	if result.exitCode != 0 {
		t.Fatalf("all-valid input must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("a clean run must not write to stderr, got %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 2 {
		t.Fatalf("expected one result per input line, got %#v", results)
	}

	first := results[0]
	if first["line"] != float64(1) || first["ok"] != true {
		t.Fatalf("first result must report line 1 as ok: %#v", first)
	}
	event := eventOf(t, first)
	if event["timestamp"] != "2026-01-02T00:04:05Z" {
		t.Fatalf("alias time must land in timestamp converted to UTC, got %v", event["timestamp"])
	}
	if event["source_ip"] != "2001:db8::1" {
		t.Fatalf("alias src_ip must land in source_ip, got %v", event["source_ip"])
	}
	if event["action"] != "login" {
		t.Fatalf("alias event_type must land in action with whitespace trimmed, got %v", event["action"])
	}
	extra, ok := event["extra"].(map[string]any)
	if !ok {
		t.Fatalf("unmapped fields must be kept in extra: %#v", event)
	}
	if extra["user"] != " alice " {
		t.Fatalf("extra strings must pass through verbatim, got %v", extra["user"])
	}
	if extra["retries"] != float64(2) {
		t.Fatalf("extra numbers must stay numbers, got %#v", extra["retries"])
	}
	if extra["ok"] != true {
		t.Fatalf("extra booleans must stay booleans, got %#v", extra["ok"])
	}

	second := results[1]
	if second["line"] != float64(2) || second["ok"] != true {
		t.Fatalf("second result must report line 2 as ok: %#v", second)
	}
	event = eventOf(t, second)
	if event["action"] != "logout" || event["source_ip"] != "10.0.0.9" {
		t.Fatalf("canonical fields must round-trip unchanged: %#v", event)
	}
	extra, ok = event["extra"].(map[string]any)
	if !ok {
		t.Fatalf("structured extra fields must be kept: %#v", event)
	}
	tags, ok := extra["tags"].([]any)
	if !ok || len(tags) != 2 || tags[0] != "a" || tags[1] != "b" {
		t.Fatalf("extra arrays must keep their element order and types, got %#v", extra["tags"])
	}
	meta, ok := extra["meta"].(map[string]any)
	if !ok || meta["trace"] != "t-1" {
		t.Fatalf("extra objects must survive the command entry intact, got %#v", extra["meta"])
	}
}

// The key mixed-input case: a field-invalid log between two valid ones. The
// bad line gets an ok:false result with an explanatory error and no event,
// the surrounding valid lines still succeed in input order, and the process
// exits 1 — it must neither stop at the first bad line nor let the trailing
// success reset the status to 0. stderr stays empty because the failure is
// described by its own result record.
func TestNormalizeCLIInvalidLineBetweenValidOnesExitsOne(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"first"}` + "\n" +
		`{"timestamp":"not-a-time","action":"broken"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:02Z","action":"last"}` + "\n"

	result := runNormalizeCLI(t, strings.NewReader(input))

	if result.exitCode != 1 {
		t.Fatalf("one invalid log must set exit status 1, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in result records, not stderr, got %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 3 {
		t.Fatalf("processing must continue past the bad line; expected 3 results, got %#v", results)
	}

	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("the leading valid log must succeed on line 1: %#v", results[0])
	}
	if eventOf(t, results[0])["action"] != "first" {
		t.Fatalf("line 1 event content mismatch: %#v", results[0])
	}

	bad := results[1]
	if bad["line"] != float64(2) || bad["ok"] != false {
		t.Fatalf("the invalid log must be reported as line 2 with ok=false: %#v", bad)
	}
	if _, exists := bad["event"]; exists {
		t.Fatalf("a failed line must not carry an event: %#v", bad)
	}
	message, ok := bad["error"].(string)
	if !ok || message == "" {
		t.Fatalf("a failed line must explain itself in error: %#v", bad)
	}
	if !strings.Contains(message, "timestamp") {
		t.Fatalf("the error must name the offending field, got %q", message)
	}

	if results[2]["line"] != float64(3) || results[2]["ok"] != true {
		t.Fatalf("the trailing valid log must still succeed on line 3: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "last" {
		t.Fatalf("line 3 event content mismatch: %#v", results[2])
	}
}

// Duplicate-key detection on the command line: a line whose repeated key is
// hidden behind a JSON unicode escape ("act" + esc for U+0069 + "on"
// decodes to "action") must be reported per line as a duplicate, surrounded
// by legal logs that still succeed in order; a blank line only moves the
// physical line counter. The process must end with status 1 and must not
// recover to 0 because later logs succeed.
func TestNormalizeCLIEscapedDuplicateKeyBetweenValidOnesExitsOne(t *testing.T) {
	// escAction is a literal JSON unicode escape assembled from pieces so
	// the complete escape sequence never appears in this source.
	escAction := "act" + `\` + "u0069on"
	dupLine := `{"timestamp":"2026-01-02T00:00:00Z","action":"dup","` + escAction + `":"dup"}`

	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"first"}` + "\n" +
		dupLine + "\n" +
		"\n" +
		`{"timestamp":"2026-01-02T00:00:02Z","action":"last"}` + "\n"

	result := runNormalizeCLI(t, strings.NewReader(input))

	if result.exitCode != 1 {
		t.Fatalf("one duplicate-key log must set exit status 1 even with later successes, got %d (stderr: %q)",
			result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in result records, not stderr, got %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 3 {
		t.Fatalf("processing must continue past the duplicate; expected 3 results, got %#v", results)
	}

	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("the leading valid log must succeed on line 1: %#v", results[0])
	}
	if eventOf(t, results[0])["action"] != "first" {
		t.Fatalf("line 1 event content mismatch: %#v", results[0])
	}

	bad := results[1]
	if bad["line"] != float64(2) || bad["ok"] != false {
		t.Fatalf("the escaped duplicate must be reported as line 2 with ok=false: %#v", bad)
	}
	if _, exists := bad["event"]; exists {
		t.Fatalf("a duplicate-key line must not carry an event: %#v", bad)
	}
	message, ok := bad["error"].(string)
	if !ok || message == "" {
		t.Fatalf("the duplicate line must explain itself in error: %#v", bad)
	}
	if !strings.Contains(strings.ToLower(message), "duplicate") {
		t.Fatalf("the error must identify a duplicate field, got %q", message)
	}
	if !strings.Contains(message, `"action"`) {
		t.Fatalf("the error must name the decoded field action despite the escaped spelling, got %q", message)
	}

	if results[2]["line"] != float64(4) || results[2]["ok"] != true {
		t.Fatalf("the blank line must only advance numbering; line 4 must succeed: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "last" {
		t.Fatalf("input order must be preserved after the duplicate: %#v", results[2])
	}
}

// Blank lines produce no results but still consume physical line numbers,
// and a final complete log without a trailing newline is processed like any
// other. The run is clean, so the exit status is 0 and stderr stays empty.
func TestNormalizeCLIBlankLinesAndMissingFinalNewline(t *testing.T) {
	input := "\n" +
		"   \n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"alpha"}` + "\n" +
		"\t\n" +
		`{"timestamp":"2026-01-02T00:00:01Z","action":"omega"}` // no trailing newline

	result := runNormalizeCLI(t, strings.NewReader(input))

	if result.exitCode != 0 {
		t.Fatalf("blank lines and a newline-less tail must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("a clean run must not write to stderr, got %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 2 {
		t.Fatalf("blank lines must not produce results, got %#v", results)
	}
	if results[0]["line"] != float64(3) {
		t.Fatalf("line numbers must count blank physical lines, got %#v", results[0])
	}
	if results[0]["ok"] != true || eventOf(t, results[0])["action"] != "alpha" {
		t.Fatalf("line 3 result mismatch: %#v", results[0])
	}
	if results[1]["line"] != float64(5) {
		t.Fatalf("the final log must keep its physical line number 5, got %#v", results[1])
	}
	if results[1]["ok"] != true || eventOf(t, results[1])["action"] != "omega" {
		t.Fatalf("a final line without newline must normalize normally: %#v", results[1])
	}
}

// Empty input — and input holding only blank lines — ends quietly: no
// results, no diagnostics, exit status 0.
func TestNormalizeCLIEmptyOrBlankOnlyInput(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"completely empty", ""},
		{"only blank lines", "\n   \n\t\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := runNormalizeCLI(t, strings.NewReader(tc.input))
			if result.exitCode != 0 {
				t.Fatalf("input without logs must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
			}
			if result.stdout != "" {
				t.Fatalf("no logs means no results on stdout, got %q", result.stdout)
			}
			if result.stderr != "" {
				t.Fatalf("no logs means no diagnostics on stderr, got %q", result.stderr)
			}
		})
	}
}

// A stdin read failure before any complete log line is a stream-level
// problem, not a bad log: the process exits 2, stderr explains the read
// failure with the normalize: prefix, and stdout carries no per-line
// results — the failure must not be disguised as one log's field error.
func TestNormalizeCLIReadErrorExitsTwo(t *testing.T) {
	// Reading a directory fails deterministically on the first Read, before
	// any byte of a log line can arrive.
	dir, err := os.Open(".")
	if err != nil {
		t.Fatalf("opening a directory as failing stdin: %v", err)
	}
	defer dir.Close()

	result := runNormalizeCLI(t, dir)

	if result.exitCode != 2 {
		t.Fatalf("a stdin read failure must exit 2, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stdout != "" {
		t.Fatalf("no complete log line means no results on stdout, got %q", result.stdout)
	}
	if !strings.HasPrefix(result.stderr, "normalize: ") {
		t.Fatalf("the read failure must be reported with the normalize: prefix, got %q", result.stderr)
	}
	if !strings.Contains(strings.ToLower(result.stderr), "read") {
		t.Fatalf("the diagnostic must identify a read failure, got %q", result.stderr)
	}
}
