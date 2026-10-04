package relayproof

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// Document-boundary regression coverage. Every physical log line must itself
// be exactly one complete JSON value (and here one JSON object): only the
// four bytes RFC 8259 §2 names as insignificant whitespace — space (U+0020),
// horizontal tab (U+0009), carriage return (U+000D) and line feed (U+000A) —
// may surround the object or separate its members. trimJSONWhitespace strips
// precisely that set and nothing else, and the decoder rejects anything left
// before the object, between members, or after the object. bytes.TrimSpace
// must never be substituted in: it would silently delete U+000B, U+000C and
// a host of Unicode space characters before the syntax check, turning a line
// that is not a legal JSON document into a successful event.
//
// Whitespace inside a JSON string is content, not framing: the same bytes
// that are illegal outside a string are ordinary characters inside an
// unknown field's value and must survive verbatim in extra.

// Boundary characters under test.
const (
	verticalTab       = "\x0b" // U+000B: not JSON whitespace
	formFeed          = "\x0c" // U+000C: not JSON whitespace
	noBreakSpace      = " "    // U+00A0: not JSON whitespace
	ideographicSpace  = "　"    // U+3000: not JSON whitespace
	legalJSONDocument = `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}`
)

// expectSyntaxFailure feeds exactly one non-blank physical line and asserts
// it is rejected as a JSON syntax problem rather than a field problem: one
// ok:false record on line 1, an error mentioning "invalid JSON", no event,
// and no hint that any field was missing or invalid.
func expectSyntaxFailure(t *testing.T, input string) {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("a bad log line is not a stream error, got %v", err)
	}
	if failures != 1 {
		t.Fatalf("the malformed line must count as one failure, got %d", failures)
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 1 {
		t.Fatalf("expected exactly one result, got %#v", results)
	}
	r := results[0]
	if r["line"] != float64(1) || r["ok"] != false {
		t.Fatalf("malformed line must fail as line 1: %#v", r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("a line that is not one complete JSON object must not emit an event: %#v", r)
	}
	msg, _ := r["error"].(string)
	if !strings.Contains(msg, "invalid JSON") {
		t.Fatalf("must be reported as a JSON syntax problem, got %q", msg)
	}
	// It must be a parse-level rejection, not a later field-validation rule:
	// the object never parses, so no "missing required field" or
	// `field "x": <value problem>` verdict is possible.
	if strings.Contains(msg, "missing required field") || strings.Contains(msg, "must not be empty") {
		t.Fatalf("a framing error must not be downgraded to a field-validation error, got %q", msg)
	}
}

// A legal event may be surrounded by — and its members separated by — any
// mix of the four JSON whitespace bytes, including a carriage return with no
// newline. Whitespace after the closing brace is legal trailing whitespace.
func TestNormalizeJSONWhitespaceFramingAccepted(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"spaces around object", "   " + legalJSONDocument + "   "},
		{"horizontal tabs around object", "\t\t" + legalJSONDocument + "\t"},
		{"carriage returns around object", "\r\r" + legalJSONDocument + "\r"},
		{"line feeds around object", "\n\n" + legalJSONDocument + "\n"},
		{"all four whitespace bytes mixed", " \t\r\n \t" + legalJSONDocument + "\r\n\t "},
		{"json whitespace between members",
			// Space, tab and carriage return (but no line feed: in NDJSON a
			// line feed ends the physical record) may pad every gap.
			`{` + " \t\r " + `"timestamp"` + " \t\r " + `:` + " \t\r " +
				`"2026-01-02T00:00:00Z"` + " \t\r " + `,` + " \t\r " +
				`"action"` + " \t\r " + `:` + " \t\r " + `"a"` + " \t\r " + `}`},
		{"carriage return before and after brace, CRLF-terminated",
			"\r " + legalJSONDocument + " \r\r\n"},
		{"record ending in CRLF", legalJSONDocument + "\r\n"},
		{"trailing legal whitespace without final newline", legalJSONDocument + " \t\r"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := runNormalize(t, tc.input)
			if len(results) != 1 || results[0]["ok"] != true {
				t.Fatalf("JSON whitespace framing must be accepted, got %#v", results)
			}
			if got := eventOf(t, results[0])["action"]; got != "a" {
				t.Fatalf("framed event content mismatch: %#v", results[0])
			}
		})
	}
}

// Characters outside JSON's whitespace set must never act as separators, no
// matter where they appear relative to an otherwise complete object with
// valid required fields. The whole line fails as invalid JSON; the bytes are
// not removed first.
func TestNormalizeIllegalSeparatorsBeforeAndAfterObjectFail(t *testing.T) {
	illegal := []struct {
		name string
		char string
	}{
		{"vertical tab U+000B", verticalTab},
		{"form feed U+000C", formFeed},
		{"no-break space U+00A0", noBreakSpace},
		{"ideographic space U+3000", ideographicSpace},
	}
	positions := []struct {
		name string
		wrap func(string, string) string
	}{
		{"before the object", func(_, c string) string { return c + legalJSONDocument }},
		{"after the object", func(_, c string) string { return legalJSONDocument + c }},
		{"leading char mixed with legal whitespace", func(_, c string) string { return " \t" + c + " " + legalJSONDocument }},
		{"trailing char mixed with legal whitespace", func(_, c string) string { return legalJSONDocument + " \t\r " + c }},
		{"char on both sides", func(_, c string) string { return c + legalJSONDocument + c }},
		{"embedded among legal trailing whitespace", func(_, c string) string { return legalJSONDocument + " " + c + "  " }},
	}
	for _, ic := range illegal {
		for _, pos := range positions {
			t.Run(ic.name+" / "+pos.name, func(t *testing.T) {
				expectSyntaxFailure(t, pos.wrap(legalJSONDocument, ic.char))
			})
		}
	}
}

// The same illegal characters between members — after the opening brace,
// around the comma, or before the closing brace — are syntax errors, not
// separators the parser may skip.
func TestNormalizeIllegalSeparatorsBetweenMembersFail(t *testing.T) {
	illegal := []struct {
		name string
		char string
	}{
		{"vertical tab U+000B", verticalTab},
		{"form feed U+000C", formFeed},
		{"no-break space U+00A0", noBreakSpace},
		{"ideographic space U+3000", ideographicSpace},
	}
	positions := []struct {
		name string
		wrap func(string) string
	}{
		{"right after opening brace", func(c string) string {
			return `{` + c + `"timestamp":"2026-01-02T00:00:00Z","action":"a"}`
		}},
		{"between value and comma", func(c string) string {
			return `{"timestamp":"2026-01-02T00:00:00Z"` + c + `,"action":"a"}`
		}},
		{"between comma and next key", func(c string) string {
			return `{"timestamp":"2026-01-02T00:00:00Z",` + c + `"action":"a"}`
		}},
		{"around the member colon", func(c string) string {
			return `{"timestamp"` + c + `:"2026-01-02T00:00:00Z","action":"a"}`
		}},
		{"before the closing brace", func(c string) string {
			return `{"timestamp":"2026-01-02T00:00:00Z","action":"a"` + c + `}`
		}},
		{"surrounded by legal whitespace after comma", func(c string) string {
			return `{"timestamp":"2026-01-02T00:00:00Z", ` + c + ` ,"action":"a"}`
		}},
	}
	for _, ic := range illegal {
		for _, pos := range positions {
			t.Run(ic.name+" / "+pos.name, func(t *testing.T) {
				expectSyntaxFailure(t, pos.wrap(ic.char))
			})
		}
	}
}

// A second JSON value — object, array, scalar, null — or any other non-space
// content after the closing brace makes the line more than one JSON value:
// the leading object must not be accepted on its own. Only legal trailing
// whitespace may follow.
func TestNormalizeContentAfterObjectFails(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"second object", `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}{"timestamp":"2026-01-02T00:00:00Z","action":"b"}`},
		{"second object after whitespace", `{"timestamp":"2026-01-02T00:00:00Z","action":"a"} {"b":2}`},
		{"trailing array", legalJSONDocument + `[]`},
		{"trailing number", legalJSONDocument + `1`},
		{"trailing string", legalJSONDocument + `"x"`},
		{"trailing boolean", legalJSONDocument + `true`},
		{"trailing null", legalJSONDocument + `null`},
		{"trailing ordinary text", legalJSONDocument + `x`},
		{"trailing text after whitespace", legalJSONDocument + `   junk`},
		{"trailing comma", `{"timestamp":"2026-01-02T00:00:00Z","action":"a",}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectSyntaxFailure(t, tc.input)
		})
	}

	t.Run("legal trailing whitespace still accepted", func(t *testing.T) {
		results := runNormalize(t, legalJSONDocument+" \t\r\n ")
		if len(results) != 1 || results[0]["ok"] != true {
			t.Fatalf("legal trailing whitespace must be accepted, got %#v", results)
		}
	})
}

// Whitespace inside a JSON string is content, never framing: the same
// no-break and ideographic spaces that are illegal outside an object are
// ordinary characters inside an unknown field's string and must survive in
// extra with their leading and trailing edges intact.
func TestNormalizeSpecialWhitespaceInsideExtraStringsPreserved(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"no-break space mid-string", "a" + noBreakSpace + "b"},
		{"ideographic space mid-string", "a" + ideographicSpace + "b"},
		{"both spaces mid-string", noBreakSpace + "x" + ideographicSpace},
		{"no-break space at both edges", noBreakSpace + "note" + noBreakSpace},
		{"ideographic space at both edges", ideographicSpace + "note" + ideographicSpace},
		{"mixed special spaces at both edges", " " + noBreakSpace + ideographicSpace + "note" + ideographicSpace + noBreakSpace + " "},
		{"only special spaces", noBreakSpace + ideographicSpace + noBreakSpace},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","note":` + jsonString(tc.value) + `}`
			results := runNormalize(t, input)
			if len(results) != 1 || results[0]["ok"] != true {
				t.Fatalf("special whitespace inside a string must be legal, got %#v", results)
			}
			if got := extraOf(t, results[0])["note"]; got != tc.value {
				t.Fatalf("extra string must survive verbatim including edge whitespace, got %q want %q", got, tc.value)
			}
		})
	}
}

// Vertical tab and form feed cannot occur literally in a JSON string, but
// their legal JSON escapes (\u000B, \u000F... \u000C) are ordinary content:
// the decoded control characters must be preserved in the unknown field's
// extra value, not confused with illegal framing outside the string.
func TestNormalizeEscapedControlWhitespaceInsideExtraStringsPreserved(t *testing.T) {
	cases := []struct {
		name    string
		escaped string // JSON token text, including surrounding quotes
		want    string // decoded Go string that must land in extra
	}{
		{"escaped vertical tab", `"\u000B"`, "\x0b"},
		{"escaped form feed", `"\u000C"`, "\x0c"},
		{"escaped controls around text", `"\u000Bnote\u000C"`, "\x0bnote\x0c"},
		{"both escapes with edges", `" \u000B\u000C "`, " \x0b\x0c "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","note":` + tc.escaped + `}`
			results := runNormalize(t, input)
			if len(results) != 1 || results[0]["ok"] != true {
				t.Fatalf("legal \\uXXXX escapes inside a string must be accepted, got %#v", results)
			}
			if got := extraOf(t, results[0])["note"]; got != tc.want {
				t.Fatalf("decoded control character must be preserved in extra, got %q want %q", got, tc.want)
			}
			// The serialized event must carry the character back as a proper
			// JSON escape (control bytes never appear raw in JSON text).
			raw := runNormalizeRaw(t, input)
			if !strings.Contains(raw, `\u000`) {
				t.Fatalf("control content must round-trip as a JSON escape in output, got %s", raw)
			}
		})
	}
}

// The in-string protection must not extend to the mapped action field: its
// existing rule trims Unicode whitespace from both ends. Ordinary JSON
// whitespace around an action is removed, and an action that is only special
// whitespace is still rejected as empty — preserving unknown-field content
// is not a behavior change for action.
func TestNormalizeActionTrimRuleUnchanged(t *testing.T) {
	t.Run("ordinary spaces around action still trimmed", func(t *testing.T) {
		results := runNormalize(t, `{"timestamp":"2026-01-02T00:00:00Z","action":"  login  "}`)
		if results[0]["ok"] != true || eventOf(t, results[0])["action"] != "login" {
			t.Fatalf("ordinary whitespace around action must still be trimmed: %#v", results[0])
		}
	})
	t.Run("no-break spaces around action still trimmed", func(t *testing.T) {
		results := runNormalize(t, `{"timestamp":"2026-01-02T00:00:00Z","action":`+
			jsonString(noBreakSpace+"login"+noBreakSpace)+`}`)
		if results[0]["ok"] != true || eventOf(t, results[0])["action"] != "login" {
			t.Fatalf("strings.TrimSpace trimming of action must be unchanged, got %#v", results[0])
		}
	})
	t.Run("ideographic spaces around action still trimmed", func(t *testing.T) {
		results := runNormalize(t, `{"timestamp":"2026-01-02T00:00:00Z","action":`+
			jsonString(ideographicSpace+"login"+ideographicSpace)+`}`)
		if results[0]["ok"] != true || eventOf(t, results[0])["action"] != "login" {
			t.Fatalf("strings.TrimSpace trimming of action must be unchanged, got %#v", results[0])
		}
	})
	t.Run("special-whitespace-only action still empty", func(t *testing.T) {
		for _, action := range []string{noBreakSpace, ideographicSpace, noBreakSpace + ideographicSpace} {
			results := runNormalize(t, `{"timestamp":"2026-01-02T00:00:00Z","action":`+jsonString(action)+`}`)
			if results[0]["ok"] != false {
				t.Fatalf("whitespace-only action must fail even for special spaces, got %#v", results[0])
			}
			if msg, _ := results[0]["error"].(string); !strings.Contains(msg, FieldAction) {
				t.Fatalf("empty-action error must name %q, got %q", FieldAction, msg)
			}
		}
	})
	t.Run("same special spaces are content only in the unknown field", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":` +
			jsonString(noBreakSpace+"go"+ideographicSpace) + `,"note":` +
			jsonString(noBreakSpace+"go"+ideographicSpace) + `}`
		results := runNormalize(t, input)
		if results[0]["ok"] != true {
			t.Fatalf("line must succeed, got %#v", results[0])
		}
		if got := eventOf(t, results[0])["action"]; got != "go" {
			t.Fatalf("action edges must be trimmed, got %q", got)
		}
		if got := extraOf(t, results[0])["note"]; got != noBreakSpace+"go"+ideographicSpace {
			t.Fatalf("unknown-field edges must be preserved, got %q", got)
		}
	})
}

// White-box pin for the exact trim set: trimJSONWhitespace must remove only
// the four RFC 8259 whitespace bytes from the document edges. It must keep
// every other whitespace-looking byte so the decoder gets a chance to reject
// it, and it must not touch interior bytes at all.
func TestTrimJSONWhitespaceSet(t *testing.T) {
	const doc = `{"a":1}`

	t.Run("exactly the four JSON whitespace bytes are trimmed", func(t *testing.T) {
		for _, c := range []byte{' ', '\t', '\r', '\n'} {
			raw := bytes.Join([][]byte{{c, c}, []byte(doc), {c}}, nil)
			if got := trimJSONWhitespace(raw); string(got) != doc {
				t.Fatalf("byte %q must be trimmed from the edges, got %q", c, got)
			}
		}
	})

	t.Run("all other whitespace-looking bytes survive at the edges", func(t *testing.T) {
		// Each prefix is one complete non-JSON-whitespace rune (plus one
		// single-byte control); none of their bytes may be in the trim set.
		for _, prefix := range []string{
			"\x0b",             // vertical tab
			"\x0c",             // form feed
			string(rune(0x85)), // U+0085 next line
			noBreakSpace,       // U+00A0
			ideographicSpace,   // U+3000
		} {
			raw := append([]byte(prefix), []byte(doc)...)
			trimmed := trimJSONWhitespace(raw)
			if len(trimmed) != len(raw) || !bytes.HasPrefix(trimmed, []byte(prefix)) {
				t.Fatalf("rune %q must not be trimmed like JSON whitespace, got %q", prefix, trimmed)
			}
		}
	})

	t.Run("interior whitespace is never examined", func(t *testing.T) {
		// Only the surrounding bytes are in scope; bytes inside the document
		// pass through untouched even when they include illegal separators
		// (the decoder, not the trim, is what rejects those).
		raw := []byte(" " + doc + verticalTab + doc + " ")
		trimmed := trimJSONWhitespace(raw)
		if string(trimmed) != doc+verticalTab+doc {
			t.Fatalf("only edge whitespace may be removed, got %q", trimmed)
		}
	})

	t.Run("empty and whitespace-only input", func(t *testing.T) {
		if got := trimJSONWhitespace(nil); len(got) != 0 {
			t.Fatalf("nil input must trim to empty, got %q", got)
		}
		// A line of only non-JSON whitespace is trimmed down to those same
		// bytes, never to empty: it must reach the decoder and fail there
		// rather than looking like a blank line.
		illegalOnly := []byte(verticalTab + formFeed + noBreakSpace + ideographicSpace)
		if got := trimJSONWhitespace(illegalOnly); !bytes.Equal(got, illegalOnly) {
			t.Fatalf("illegal-whitespace-only line must survive trimming, got %q", got)
		}
		if !utf8.Valid(illegalOnly) {
			t.Fatalf("test setup: illegal-only line must be valid UTF-8")
		}
	})
}

// The two whitespace rules live on different layers and must not be
// conflated.
//
// NormalizeLine is the strict JSON-document boundary: a line whose only
// content is non-JSON whitespace is not a JSON object and fails there with a
// syntax reason, regardless of how TrimSpace would classify it.
//
// NormalizeReader keeps its pre-existing, broader blank-line rule
// (strings.TrimSpace on the raw physical line): a line made solely of
// whitespace — including U+000B, U+000C, U+00A0 and U+3000 — occupies a
// physical line number but produces no record and no failure, exactly like a
// line of ordinary spaces. The document-boundary protection therefore bites
// on real event lines (an object framed with such bytes), and the established
// blank-line behavior is unchanged.
func TestNormalizeWhitespaceOnlyLineLayeredBehavior(t *testing.T) {
	illegalOnly := verticalTab + formFeed + noBreakSpace + ideographicSpace

	t.Run("NormalizeLine rejects non-JSON whitespace as a document", func(t *testing.T) {
		r := NormalizeLine(1, []byte(illegalOnly))
		if r.OK || r.Event != nil {
			t.Fatalf("non-JSON whitespace is not a JSON object: %#v", r)
		}
		if !strings.Contains(r.Error, "invalid JSON") {
			t.Fatalf("must be a JSON syntax error, got %q", r.Error)
		}
	})

	t.Run("NormalizeReader treats whitespace-only lines as blank rows", func(t *testing.T) {
		// A legal log, a whitespace-only line (illegal chars included), and
		// another legal log: the middle line keeps its line number but emits
		// nothing and counts no failure.
		input := legalJSONDocument + "\n" + illegalOnly + "\n" + legalJSONDocument + "\n"
		var out bytes.Buffer
		failures, err := NormalizeReader(strings.NewReader(input), &out)
		if err != nil {
			t.Fatalf("a healthy stream must not return an error, got %v", err)
		}
		if failures != 0 {
			t.Fatalf("a whitespace-only line follows the existing blank rule and must not count, got %d", failures)
		}
		results := decodeResults(t, out.Bytes())
		if len(results) != 2 {
			t.Fatalf("the whitespace-only line must produce no record, got %#v", results)
		}
		if results[0]["line"] != float64(1) || results[1]["line"] != float64(3) {
			t.Fatalf("the skipped line must still occupy physical line 2, got %#v", results)
		}
	})
}

// Mixed stream: valid logs, logs framed with illegal separators, a log with
// content after the object, and ordinary blank lines. Each failure is
// confined to its own physical line — original line number, ok:false, a JSON
// reason, no event — surrounding valid logs keep their order, blank lines
// only occupy a number, the failure count covers only actual failure rows,
// and a healthy read/write is not a stream error.
func TestNormalizeIllegalSeparatorsInMixedStream(t *testing.T) {
	input := "" +
		legalJSONDocument + "\n" + // line 1: ok
		verticalTab + legalJSONDocument + "\n" + // line 2: fail (illegal char before)
		"\n" + // line 3: blank, no record
		"   \t  \n" + // line 4: ordinary whitespace, no record
		legalJSONDocument + noBreakSpace + "\n" + // line 5: fail (illegal char after)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"mid"}` + "\n" + // line 6: ok
		`{"timestamp":"2026-01-02T00:00:00Z","action":` +
		jsonString("a"+ideographicSpace+"b") +
		`,"note":` + jsonString(ideographicSpace+"kept"+ideographicSpace) + "}\n" + // line 7: ok (spaces in strings)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a",` + formFeed + `"x":1}` + "\n" + // line 8: fail (illegal char between members)
		legalJSONDocument + `{"b":2}` + "\n" + // line 9: fail (trailing JSON value)
		`{"timestamp":"2026-01-02T00:00:03Z","action":"last"}` + "\r\n" // line 10: ok, CRLF-terminated

	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("per-line failures in a healthy stream must not be a stream error, got %v", err)
	}
	if failures != 4 {
		t.Fatalf("exactly lines 2, 5, 8, 9 must count as failures, got %d", failures)
	}

	results := decodeResults(t, out.Bytes())
	if len(results) != 8 {
		t.Fatalf("8 non-blank physical lines must yield 8 records (blanks yield none), got %#v", results)
	}

	want := []struct {
		line float64
		ok   bool
	}{
		{1, true},
		{2, false},
		{5, false},
		{6, true},
		{7, true},
		{8, false},
		{9, false},
		{10, true},
	}
	for i, w := range want {
		if results[i]["line"] != w.line || results[i]["ok"] != w.ok {
			t.Fatalf("record %d must be physical line %v ok=%v, got %#v", i, w.line, w.ok, results[i])
		}
	}

	for _, i := range []int{1, 2, 5, 6} {
		r := results[i]
		if _, exists := r["event"]; exists {
			t.Fatalf("failed line %v must carry no event: %#v", r["line"], r)
		}
		if msg, _ := r["error"].(string); !strings.Contains(msg, "invalid JSON") {
			t.Fatalf("failed line %v must give a JSON syntax reason, got %q", r["line"], msg)
		}
	}

	if got := eventOf(t, results[0])["action"]; got != "a" {
		t.Fatalf("line 1 action mismatch: %#v", results[0])
	}
	if got := eventOf(t, results[3])["action"]; got != "mid" {
		t.Fatalf("line 6 must follow failures in order, got action %v", got)
	}
	line7 := results[4]
	if got := eventOf(t, line7)["action"]; got != "a"+ideographicSpace+"b" {
		t.Fatalf("line 7 action must keep its in-string content, got %q", got)
	}
	if got := extraOf(t, line7)["note"]; got != ideographicSpace+"kept"+ideographicSpace {
		t.Fatalf("line 7 unknown field must keep edge whitespace verbatim, got %q", got)
	}
	if got := eventOf(t, results[7])["action"]; got != "last" {
		t.Fatalf("line 10 (CRLF) must still be processed after the failures, got action %v", got)
	}
}
