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
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

// escKey renders key as a JSON member name spelled entirely with unicode
// escapes (with UTF-16 surrogate pairs above the BMP), so tests can feed a
// \uXXXX-encoded key without embedding escape text in the source.
func escKey(key string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range key {
		for _, u := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&b, "\\u%04x", u)
		}
	}
	b.WriteByte('"')
	return b.String()
}

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

// A log line with corrupted characters — invalid UTF-8 bytes or an unpaired
// \uXXXX surrogate escape anywhere in the object, including deep inside
// unmapped fields — is an ordinary per-line failure: one ok:false record with
// the physical line number and a reason that distinguishes the two defects,
// no event, valid lines around it still processed in order, exit status 1,
// and stderr empty. The failure records themselves must be valid UTF-8 JSON:
// corrupted input bytes are never echoed back into the output.
func TestNormalizeCLICorruptedCharactersExitOne(t *testing.T) {
	input := []byte(`{"timestamp":"2026-01-02T00:00:00Z","action":"first"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"bad` + "\xff\xfe" + `"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"ok","extra":{"deep":["` + "\\uD800" + `"]}}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:02Z","action":"last"}` + "\n")

	result := runNormalizeCLI(t, bytes.NewReader(input))

	if result.exitCode != 1 {
		t.Fatalf("corrupted log lines must set exit status 1, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in result records, not stderr, got %q", result.stderr)
	}
	if !utf8.ValidString(result.stdout) {
		t.Fatalf("stdout must be valid UTF-8 even for corrupted input, got %q", result.stdout)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 4 {
		t.Fatalf("processing must continue past corrupted lines; expected 4 results, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("the leading valid log must succeed on line 1: %#v", results[0])
	}

	badUTF8 := results[1]
	if badUTF8["line"] != float64(2) || badUTF8["ok"] != false {
		t.Fatalf("the invalid-UTF-8 log must fail as line 2: %#v", badUTF8)
	}
	if _, exists := badUTF8["event"]; exists {
		t.Fatalf("a corrupted line must not carry an event: %#v", badUTF8)
	}
	msg, _ := badUTF8["error"].(string)
	if !strings.Contains(msg, "UTF-8") {
		t.Fatalf("invalid bytes must be reported as UTF-8 corruption, got %q", msg)
	}

	badEscape := results[2]
	if badEscape["line"] != float64(3) || badEscape["ok"] != false {
		t.Fatalf("the unpaired-escape log must fail as line 3: %#v", badEscape)
	}
	if _, exists := badEscape["event"]; exists {
		t.Fatalf("a corrupted line must not carry an event: %#v", badEscape)
	}
	msg, _ = badEscape["error"].(string)
	if !strings.Contains(msg, "surrogate") {
		t.Fatalf("an unpaired escape deep in extra must be reported as a surrogate problem, got %q", msg)
	}

	if results[3]["line"] != float64(4) || results[3]["ok"] != true {
		t.Fatalf("the trailing valid log must still succeed on line 4: %#v", results[3])
	}
	if eventOf(t, results[3])["action"] != "last" {
		t.Fatalf("line 4 event content mismatch: %#v", results[3])
	}
}

// A duplicate top-level key written with a unicode escape is the same failure
// as a literal repeated key. With one such line between legal logs (and a
// blank line shifting physical numbers), the CLI must emit per-line JSON
// results in order, keep the failure's line number with no event and a reason
// that names the field, and still exit 1: trailing valid lines never reset
// the status. An escape-only spelling of a standard field is a normal event.
func TestNormalizeCLIEscapedDuplicateKeyExitsOne(t *testing.T) {
	dup := `{"timestamp":"2026-01-02T00:00:00Z","action":"first",` + escKey("action") + `:"second"}`
	escapedOnly := `{` + escKey("timestamp") + `:"2026-01-02T08:04:05+08:00",` + escKey("action") + `:"ok"}`
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"first"}` + "\n" +
		dup + "\n" +
		"  \n" +
		`{"timestamp":"2026-01-02T00:00:02Z","action":"last"}` + "\n" +
		escapedOnly

	result := runNormalizeCLI(t, strings.NewReader(input))

	if result.exitCode != 1 {
		t.Fatalf("a duplicate-key line must set exit status 1 even with later valid logs, got %d (stderr: %q)",
			result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in result records, not stderr, got %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 4 {
		t.Fatalf("blank lines produce no output; expected 4 results, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("leading valid log must succeed on line 1: %#v", results[0])
	}
	if eventOf(t, results[0])["action"] != "first" {
		t.Fatalf("line 1 event content mismatch: %#v", results[0])
	}

	bad := results[1]
	if bad["line"] != float64(2) || bad["ok"] != false {
		t.Fatalf("the escaped duplicate key must fail as line 2: %#v", bad)
	}
	if _, exists := bad["event"]; exists {
		t.Fatalf("a failed line must not carry an event: %#v", bad)
	}
	message, ok := bad["error"].(string)
	if !ok || message == "" {
		t.Fatalf("the failed line must explain itself: %#v", bad)
	}
	if !strings.Contains(strings.ToLower(message), "duplicate") || !strings.Contains(message, "action") {
		t.Fatalf("error must identify the duplicate action field, got %q", message)
	}
	if strings.Contains(strings.ToLower(message), "conflict") {
		t.Fatalf("a decoded duplicate key must not be reported as an action conflict: %q", message)
	}

	if results[2]["line"] != float64(4) || results[2]["ok"] != true {
		t.Fatalf("the valid log after the blank line must succeed as line 4: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "last" {
		t.Fatalf("line 4 event content must survive in order: %#v", results[2])
	}

	if results[3]["line"] != float64(5) || results[3]["ok"] != true {
		t.Fatalf("an escape-only standard field spelling must succeed as line 5: %#v", results[3])
	}
	if eventOf(t, results[3])["timestamp"] != "2026-01-02T00:04:05Z" {
		t.Fatalf("escaped-only names must normalize like literal names: %#v", results[3])
	}
}
