package main

// CLI-level regression coverage for the "one physical line must be exactly
// one complete JSON object" boundary, exercised through the public entry
// point users actually invoke. Only space, tab, carriage return and line
// feed are JSON whitespace; vertical tab, form feed, no-break space and the
// ideographic space are content to the JSON grammar and must not be stripped
// away to make a line parse. A second JSON value after the object is also
// rejected. The same special characters stay legal inside a string and are
// kept in a field's value (extra for unknown fields), while the action field
// keeps its existing trim rule. Per-line failures are confined to their own
// physical line, ordinary blank lines produce no record, and a healthy
// read/write exits 1 (failed logs) rather than 2 (a stream fault), with
// stderr empty.

import (
	"bytes"
	"strings"
	"testing"
)

func TestNormalizeCLIDocumentBoundaryIllegalSeparators(t *testing.T) {
	const okLine = `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}`

	// Special bytes are written as Go rune escapes so the test does not rely
	// on invisible raw characters: nbsp/ideo are their literal UTF-8 bytes
	// (illegal as JSON framing), while the action value spells a vertical tab
	// as the six-character JSON escape \u000B (legal string content).
	const (
		nbsp = "\u00a0" // U+00A0 no-break space, literal input byte (not JSON whitespace)
		ideo = "\u3000" // U+3000 ideographic space, literal input byte (not JSON whitespace)
	)
	line6 := `{"timestamp":"2026-01-02T00:00:00Z","action":"mid\u000Bx","note":"` +
		ideo + "kept" + ideo + `"}`

	input := []byte(strings.Join([]string{
		okLine,          // line 1: ok
		"\x0b" + okLine, // line 2: fail — vertical tab before the object
		"",              // line 3: blank, no record
		"  \t ",         // line 4: ordinary whitespace, no record
		okLine + nbsp,   // line 5: fail — no-break space after the object
		line6,           // line 6: ok — escape/raw special chars are string content
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a",` + "\x0c" + `"x":1}`, // line 7: fail — form feed between members
		okLine + `{"b":2}`, // line 8: fail — a second JSON value after the object
		`{"timestamp":"2026-01-02T00:00:03Z","action":"last"}`, // line 9: ok
	}, "\n") + "\r\n") // every record is newline-terminated; the stream ends CRLF

	result := runNormalizeCLI(t, bytes.NewReader(input))

	if result.exitCode != 1 {
		t.Fatalf("failed log lines must set exit status 1, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in result records, not stderr, got %q", result.stderr)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 7 {
		t.Fatalf("blank lines produce no output; expected 7 records, got %#v", results)
	}

	want := []struct {
		line float64
		ok   bool
	}{
		{1, true},
		{2, false},
		{5, false},
		{6, true},
		{7, false},
		{8, false},
		{9, true},
	}
	for i, w := range want {
		if results[i]["line"] != w.line || results[i]["ok"] != w.ok {
			t.Fatalf("record %d must be physical line %v ok=%v, got %#v", i, w.line, w.ok, results[i])
		}
	}

	for _, i := range []int{1, 2, 4, 5} {
		r := results[i]
		if _, exists := r["event"]; exists {
			t.Fatalf("failed line %v must carry no event: %#v", r["line"], r)
		}
		if len(r) != 3 {
			t.Fatalf("a failure record carries exactly line, ok and one error, got %#v", r)
		}
		msg, _ := r["error"].(string)
		if !strings.Contains(msg, "invalid JSON") {
			t.Fatalf("failed line %v must give a JSON syntax reason, got %q", r["line"], msg)
		}
	}

	if got := eventOf(t, results[0])["action"]; got != "a" {
		t.Fatalf("line 1 action mismatch: %#v", results[0])
	}

	// Line 6: a vertical tab expressed through a legal JSON escape is content
	// inside the mapped action, while the ideographic spaces in the unknown
	// field's string stay verbatim at both edges in extra.
	line6Event := eventOf(t, results[3])
	if got := line6Event["action"]; got != "mid\x0bx" {
		t.Fatalf("escaped VT inside action must be preserved as content, got %q", got)
	}
	extra, ok := line6Event["extra"].(map[string]any)
	if !ok {
		t.Fatalf("line 6 must keep its unknown field in extra: %#v", line6Event)
	}
	if got := extra["note"]; got != ideo+"kept"+ideo {
		t.Fatalf("unknown-field string must keep its edge whitespace verbatim, got %q", got)
	}

	if got := eventOf(t, results[6])["action"]; got != "last" {
		t.Fatalf("the CRLF-terminated line 9 must still be processed, got action %v", got)
	}
}

// Legal JSON whitespace framing alone — spaces, tabs and carriage returns
// around the object and between its members — must normalize cleanly through
// the CLI, including a CRLF-terminated record: exit 0 and an empty stderr.
func TestNormalizeCLIDocumentBoundaryLegalWhitespaceFraming(t *testing.T) {
	framed := " \t\r " +
		`{` + " \t\r " + `"timestamp"` + " \t\r " + `:` + " \t\r " +
		`"2026-01-02T00:00:00Z"` + " \t\r " + `,` + " \t\r " +
		`"action"` + " \t\r " + `:` + " \t\r " + `"a"` + " \t\r " + `}` +
		" \t\r "
	input := []byte(framed + "\r\n")

	result := runNormalizeCLI(t, bytes.NewReader(input))

	if result.exitCode != 0 {
		t.Fatalf("JSON-legal whitespace framing must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("a clean run must not write to stderr, got %q", result.stderr)
	}
	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 1 || results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("the framed record must normalize as line 1, got %#v", results)
	}
	if got := eventOf(t, results[0])["action"]; got != "a" {
		t.Fatalf("framed event content mismatch: %#v", results[0])
	}
}
