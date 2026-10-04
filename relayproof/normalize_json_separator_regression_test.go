package relayproof

import (
	"bytes"
	"strings"
	"testing"
)

// Regression coverage for the rule that every normalized log line must be one
// complete JSON object and nothing else. Only the four whitespace code points
// RFC 8259 §2 permits outside a token — space, horizontal tab, carriage
// return, line feed — may surround the document or sit between members; they
// are the boundary between the object and the physical line. Characters that
// bytes.TrimSpace also strips but JSON does not allow (vertical tab U+000B,
// form feed U+000C, no-break space U+00A0, ideographic space U+3000) must
// reach the JSON decoder and fail the whole line as a syntax error: they must
// never be deleted first, and a second JSON value after the object must not
// be ignored. Whitespace *inside* a JSON string has entirely different
// meaning: the same code points (written literally or as \uXXXX escapes) are
// ordinary string content that must survive verbatim in unmapped fields.

// Characters JSON does not accept as whitespace. The first two are ASCII
// controls bytes.TrimSpace removes; the last two are valid UTF-8 runes
// unicode.IsSpace recognizes but JSON does not.
const (
	sepVerticalTab = "\x0b" // U+000B
	sepFormFeed    = "\x0c" // U+000C
	sepNoBreak     = " "    // U+00A0, UTF-8 bytes
	sepIdeographic = "　"    // U+3000, UTF-8 bytes
)

func jsonSeparatorLog() string {
	return `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}`
}

// expectSyntaxFailure normalizes one non-blank line and asserts the whole
// line fails as a JSON syntax problem: one record on the given physical line,
// ok:false, no event (the line was never trimmed into a valid object), and an
// "invalid JSON" reason rather than a field-validation complaint. The bad
// line is a per-line failure, not a stream error.
func expectSyntaxFailure(t *testing.T, input string, wantLine int) string {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("a bad log line is not a stream error, got %v", err)
	}
	if failures != 1 {
		t.Fatalf("the bad line must count as exactly one failure, got %d", failures)
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 1 {
		t.Fatalf("expected exactly one result, got %#v", results)
	}
	r := results[0]
	if r["line"] != float64(wantLine) || r["ok"] != false {
		t.Fatalf("line %d must fail as ok:false, got %#v", wantLine, r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("line must not be accepted after stripping characters: %#v", r)
	}
	msg, _ := r["error"].(string)
	if !strings.Contains(msg, "invalid JSON") {
		t.Fatalf("failure must be a JSON syntax error, got %q", msg)
	}
	return msg
}

// The four JSON whitespace code points may surround a complete object and
// may end records (including CRLF-terminated records); such lines normalize
// successfully with the event intact.
func TestNormalizeLegalJSONWhitespaceAroundObject(t *testing.T) {
	good := jsonSeparatorLog()
	singleLineCases := []struct {
		name  string
		input string
	}{
		{"spaces around", "  " + good + "  "},
		{"horizontal tabs around", "\t\t" + good + "\t"},
		{"carriage returns around", "\r" + good + "\r"},
		{"mixed legal whitespace", " \t\r\n " + good + " \t \r\n"},
		{"trailing legal whitespace only", good + " \t\r "},
		{"final carriage return without newline", good + "\r"},
	}
	for _, tc := range singleLineCases {
		t.Run(tc.name, func(t *testing.T) {
			r := NormalizeLine(1, []byte(tc.input))
			if !r.OK || r.Event == nil {
				t.Fatalf("JSON whitespace must be allowed around the object, got ok=%v err=%q", r.OK, r.Error)
			}
			if r.Event.Action != "a" {
				t.Fatalf("event must parse normally, got %#v", r.Event)
			}
		})
	}

	t.Run("CRLF terminated records through the reader", func(t *testing.T) {
		// Every record, including a CRLF-ended final record and a blank CRLF
		// line, must keep its physical line number and normalize.
		input := strings.Replace(good, `"action":"a"`, `"action":"first"`, 1) + "\r\n" +
			"\r\n" +
			strings.Replace(good, `"action":"a"`, `"action":"last"`, 1) + "\r\n"
		results := runNormalize(t, input)
		if len(results) != 2 {
			t.Fatalf("expected 2 results for 3 CRLF physical lines, got %#v", results)
		}
		if results[0]["line"] != float64(1) || results[0]["ok"] != true {
			t.Fatalf("CRLF record on line 1 must succeed: %#v", results[0])
		}
		if results[1]["line"] != float64(3) || results[1]["ok"] != true {
			t.Fatalf("CRLF record on line 3 must succeed preserving line number: %#v", results[1])
		}
		if eventOf(t, results[1])["action"] != "last" {
			t.Fatalf("last CRLF record must keep its order and content")
		}
	})
}

// Vertical tab, form feed, no-break space, and ideographic space are not JSON
// separators. Wherever one appears outside a string — before the object,
// after it, or between members — the complete, otherwise-valid line must fail
// wholesale with a JSON syntax reason; deleting the character would make the
// same line succeed, which is precisely the rewrite these tests forbid.
func TestNormalizeIllegalSeparatorsFailWholeLine(t *testing.T) {
	good := jsonSeparatorLog()
	illegal := []struct {
		name string
		char string
	}{
		{"vertical tab U+000B", sepVerticalTab},
		{"form feed U+000C", sepFormFeed},
		{"no-break space U+00A0", sepNoBreak},
		{"ideographic space U+3000", sepIdeographic},
	}
	positions := []struct {
		name string
		wrap func(char string) string
	}{
		{"before object", func(c string) string { return c + good }},
		{"after object", func(c string) string { return good + c }},
		{"after object behind legal whitespace", func(c string) string { return good + " \t" + c }},
		{"between members", func(c string) string {
			return `{"timestamp":"2026-01-02T00:00:00Z",` + c + `"action":"a"}`
		}},
		{"between key and colon", func(c string) string {
			return `{"timestamp"` + c + `:"2026-01-02T00:00:00Z","action":"a"}`
		}},
	}
	for _, ic := range illegal {
		for _, pos := range positions {
			t.Run(ic.name+" / "+pos.name, func(t *testing.T) {
				msg := expectSyntaxFailure(t, pos.wrap(ic.char), 1)
				if strings.Contains(msg, "missing required field") {
					t.Fatalf("failure must be syntactic, not a field complaint after char removal: %q", msg)
				}
			})
		}
	}
}

// A line made only of an illegal separator is a failing log line, not a blank
// line: it gets an ok:false record and counts as a failure.
func TestNormalizeIllegalSeparatorOnlyLineIsFailureNotBlank(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
	}{
		{"vertical tab only", sepVerticalTab},
		{"form feed only", sepFormFeed},
		{"no-break space only", sepNoBreak},
		{"ideographic space only", sepIdeographic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectSyntaxFailure(t, tc.line, 1)
		})
	}
}

// After the closing brace the document is finished. Another JSON value or any
// other non-whitespace content must fail the line instead of accepting the
// object prefix; trailing legal whitespace alone stays accepted.
func TestNormalizeContentAfterObjectNotAccepted(t *testing.T) {
	good := jsonSeparatorLog()
	bad := []string{
		good + " 123",
		good + " {}",
		good + ` "stray"`,
		good + " true",
		good + " null",
		good + " x",
		good + ",{}",
		good + "\t\x0b", // illegal separator after legal whitespace
	}
	for i, input := range bad {
		expectSyntaxFailure(t, input, 1)
		_ = i
	}

	// The same object with only legal whitespace after its closing brace
	// remains a valid single-object document.
	results := runNormalize(t, good+" \t\r\n")
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("trailing legal whitespace must still be accepted: %#v", results)
	}
}

// The forbidden-separator characters are only forbidden outside strings.
// Inside a JSON string — in an unmapped field at any depth — literal U+00A0
// and U+3000 are ordinary characters, and U+000B/U+000C reached via legal
// \uXXXX escapes are ordinary characters too. The whole line satisfies the
// field rules, so these strings must be carried in extra with their content
// and leading/trailing whitespace byte-for-byte intact: not cleaned, not
// flagged, and not mistaken for object-level separators.
func TestNormalizeStringContentIsNotObjectWhitespace(t *testing.T) {
	wantSpaces := sepNoBreak + sepNoBreak + " hi " + sepIdeographic
	wantControls := "a\x0bb\x0cc\x0b"
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"run",` +
		`"spaces":"` + wantSpaces + `",` +
		`"controls":"a\u000bb\u000cc\u000B",` +
		`"nested":{"deep":["` + sepNoBreak + `x` + sepIdeographic + `"]}}`
	results := runNormalize(t, input)
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("whitespace characters inside strings must not fail the line: %#v", results)
	}
	extra := extraOf(t, results[0])
	if got := extra["spaces"]; got != wantSpaces {
		t.Fatalf("literal U+00A0/U+3000 and their leading/trailing positions must survive, got %q want %q", got, wantSpaces)
	}
	if got := extra["controls"]; got != wantControls {
		t.Fatalf("legal \\u000B/\\u000C escapes must decode and survive in extra, got %q want %q", got, wantControls)
	}
	nested, ok := extra["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested unknown field must be preserved: %#v", extra["nested"])
	}
	list, ok := nested["deep"].([]any)
	if !ok || len(list) != 1 || list[0] != sepNoBreak+"x"+sepIdeographic {
		t.Fatalf("whitespace chars in nested unknown strings must survive verbatim, got %#v", nested["deep"])
	}

	// The serialized output must still encode the control content rather
	// than dropping it during re-marshaling.
	raw := runNormalizeRaw(t, input)
	if !strings.Contains(raw, `\u000b`) || !strings.Contains(raw, `\u000c`) {
		t.Fatalf("escaped control content must round-trip, got %s", raw)
	}
	if !strings.Contains(raw, sepNoBreak) || !strings.Contains(raw, sepIdeographic) {
		t.Fatalf("literal non-ASCII spaces must round-trip in extra, got %s", raw)
	}
}

// Tolerance for whitespace characters inside unknown-field strings must not
// change the mapped action field's existing trimming rule: leading/trailing
// JSON-legal whitespace around the action value is still removed, while
// whitespace in the middle of the value is content and stays.
func TestNormalizeActionTrimmingRuleUnchanged(t *testing.T) {
	results := runNormalize(t, `{"timestamp":"2026-01-02T00:00:00Z","action":"  run  "}`)
	if results[0]["ok"] != true || eventOf(t, results[0])["action"] != "run" {
		t.Fatalf("leading/trailing action whitespace must still be trimmed: %#v", results[0])
	}

	// Internal characters are never removed: \u000B and an in-string U+00A0
	// survive between non-space letters.
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"x\u000b` + `y` + sepNoBreak + `z"}`
	results = runNormalize(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("control/space characters inside the action string are legal content: %#v", results[0])
	}
	if got := eventOf(t, results[0])["action"]; got != "x\x0by"+sepNoBreak+"z" {
		t.Fatalf("internal action content must survive trimming, got %q", got)
	}
}

// In a mixed stream, illegal-separator and trailing-content failures are
// strictly per-line: original physical line numbers are echoed, each failure
// is ok:false with an "invalid JSON" reason and no event, ordinary blank
// lines only occupy a line number, surrounding valid lines keep their order,
// the failure count covers only actual failure records, and a stream that
// reads and writes cleanly is not a stream-level error.
func TestNormalizeIllegalSeparatorsInMixedStream(t *testing.T) {
	first := strings.Replace(jsonSeparatorLog(), `"action":"a"`, `"action":"first"`, 1)
	middle := strings.Replace(jsonSeparatorLog(), `"action":"a"`, `"action":"middle"`, 1)
	last := strings.Replace(jsonSeparatorLog(), `"action":"a"`, `"action":"last"`, 1)
	input := strings.Join([]string{
		first,                   // line 1: ok
		sepVerticalTab + middle, // line 2: fail, illegal separator before object
		"",                      // line 3: blank, no record
		middle + " 123",         // line 4: fail, value after object
		"   \t ",                // line 5: ordinary blank, no record
		sepNoBreak,              // line 6: fail, illegal separator as whole line
		sepVerticalTab,          // line 7: fail, illegal separator as whole line
		last,                    // line 8: ok
	}, "\n")

	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("per-line JSON failures are not a stream error, got %v", err)
	}
	if failures != 4 {
		t.Fatalf("exactly the four bad log lines must count as failures, got %d", failures)
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 6 {
		t.Fatalf("expected 6 records for 8 physical lines (two blank), got %#v", results)
	}

	want := []struct {
		line int
		ok   bool
	}{
		{1, true}, {2, false}, {4, false}, {6, false}, {7, false}, {8, true},
	}
	for i, w := range want {
		if results[i]["line"] != float64(w.line) || results[i]["ok"] != w.ok {
			t.Fatalf("record %d mismatch: want line %d ok=%v, got %#v", i, w.line, w.ok, results[i])
		}
	}
	for _, i := range []int{1, 2, 3, 4} {
		r := results[i]
		if _, exists := r["event"]; exists {
			t.Fatalf("failing line must not emit an event: %#v", r)
		}
		if !strings.Contains(r["error"].(string), "invalid JSON") {
			t.Fatalf("failing line needs an explicit JSON syntax reason, got %q", r["error"])
		}
	}
	if eventOf(t, results[0])["action"] != "first" || eventOf(t, results[5])["action"] != "last" {
		t.Fatalf("valid lines must keep order and content around failures: %#v %#v", results[0], results[5])
	}
}
