package relayproof

// Regression coverage for the byte offsets carried by character-integrity
// failures. A consumer of the per-line failure records gets one error string
// with an "at byte offset N" position; these tests pin what N means so the
// consumer can slice the raw input at N and land exactly on the corruption:
//
//   - N is a zero-based byte offset into the line content AFTER the legal
//     JSON document whitespace (space, tab, CR, LF) around the object is
//     trimmed — not an offset into the whole input stream, and not a
//     terminal display column.
//   - N counts raw input bytes: Chinese text, emoji, and legal escape
//     sequences before the corruption contribute their on-the-wire byte
//     length, never a display character count or a decoded string length,
//     and nested unknown-field content is located from the line start, not
//     from the field value or an inner object.
//   - Invalid UTF-8 points at the first byte that cannot form a legal
//     character (the start of a truncated multi-byte sequence); an unpaired
//     surrogate escape points at the backslash opening the escape, and the
//     message distinguishes a lone high surrogate from a lone low one.
//   - Correctly paired escapes and plain "uD800" text behind an escaped
//     backslash are not corruption and must not shift the offset of a real
//     problem later in the same line; invalid UTF-8 outranks an unpaired
//     escape even when the escape sits earlier in the line.
//
// The tests only observe NormalizeReader's public records; the normalization
// behavior itself is unchanged.

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// byteOffsetPattern extracts the position a character-integrity failure
// reports for its corruption point.
var byteOffsetPattern = regexp.MustCompile(`at byte offset ([0-9]+)`)

// reportedOffset parses the byte offset out of a failure record's error,
// failing the test when the error carries no position.
func reportedOffset(t *testing.T, msg string) int {
	t.Helper()
	m := byteOffsetPattern.FindStringSubmatch(msg)
	if m == nil {
		t.Fatalf("error %q must carry an \"at byte offset N\" position", msg)
	}
	offset, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parsing offset from %q: %v", msg, err)
	}
	return offset
}

// trimJSONDocumentWhitespace mirrors the normalizer's own trimming, so tests
// can express expectations against the same content the offset counts from:
// the JSON document on the line, without the legal whitespace around it.
func trimJSONDocumentWhitespace(line string) []byte {
	return bytes.Trim([]byte(line), " \t\r\n")
}

// requireOffsetPointsAt asserts the reported offset is exactly the byte
// index of marker within the trimmed line content: a consumer slicing the
// raw input at the reported position lands on the corruption itself.
func requireOffsetPointsAt(t *testing.T, trimmed []byte, offset int, marker string) {
	t.Helper()
	want := bytes.Index(trimmed, []byte(marker))
	if want < 0 {
		t.Fatalf("test bug: marker %q not found in %q", marker, trimmed)
	}
	if offset != want {
		t.Fatalf("offset must locate %q at byte %d of the trimmed line content, got %d", marker, want, offset)
	}
	if !bytes.HasPrefix(trimmed[offset:], []byte(marker)) {
		t.Fatalf("slicing the input at offset %d must land on %q, got %q", offset, marker, trimmed[offset:])
	}
}

// expectOffsetFailure normalizes input as a one-line stream and requires
// exactly one failure record — line 1, ok:false, one error, no event — whose
// error carries a byte offset. It returns the error message and the offset.
func expectOffsetFailure(t *testing.T, input string) (string, int) {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("a corrupted log line is not a stream error, got %v", err)
	}
	if failures != 1 {
		t.Fatalf("the corrupted line must count as one failure, got %d", failures)
	}
	if !utf8.Valid(out.Bytes()) {
		t.Fatalf("output must be valid UTF-8 even for corrupted input: %q", out.Bytes())
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 1 {
		t.Fatalf("expected exactly one result, got %#v", results)
	}
	r := results[0]
	if r["line"] != float64(1) || r["ok"] != false {
		t.Fatalf("the corrupted line must fail as line 1: %#v", r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("a character-corrupted line must not emit an event: %#v", r)
	}
	msg, _ := r["error"].(string)
	if msg == "" {
		t.Fatalf("the failure record must explain itself: %#v", r)
	}
	return msg, reportedOffset(t, msg)
}

// The offset counts from the first byte of the JSON document on the line:
// spaces, tabs, and carriage returns around the object are trimmed away and
// must not move the reported position of the same corruption point, while
// the same characters between tokens inside the object occupy real bytes and
// do move it.
func TestNormalizeOffsetStartsAtTrimmedLineContent(t *testing.T) {
	corrupted := `{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800"}`
	base := bytes.Index([]byte(corrupted), []byte(`\uD800`))

	variants := []struct {
		name  string
		input string
	}{
		{"no surrounding whitespace", corrupted},
		{"leading space", " " + corrupted},
		{"leading tabs", "\t\t" + corrupted},
		{"leading carriage return", "\r" + corrupted},
		{"mixed leading and trailing whitespace", " \t\r" + corrupted + " \t"},
		{"leading spaces and trailing carriage return", "  " + corrupted + "\r"},
	}
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			msg, offset := expectOffsetFailure(t, tc.input+"\n")
			if !strings.Contains(msg, "unpaired") {
				t.Fatalf("expected an unpaired escape failure, got %q", msg)
			}
			if offset != base {
				t.Fatalf("whitespace around the object must not move the offset %d, got %d", base, offset)
			}
			requireOffsetPointsAt(t, trimJSONDocumentWhitespace(tc.input), offset, `\uD800`)
		})
	}

	t.Run("whitespace inside the object still occupies bytes", func(t *testing.T) {
		// Two extra spaces after "{" and one tab before "action" sit inside
		// the document: the same corruption point moves by exactly those
		// three bytes. The tab counts as one byte, not a display column.
		spaced := "{  \"timestamp\":\"2026-01-02T00:00:00Z\",\t\"action\":\"\\uD800\" }"
		_, offset := expectOffsetFailure(t, spaced+"\n")
		if offset != base+3 {
			t.Fatalf("internal whitespace must count as bytes: want offset %d, got %d", base+3, offset)
		}
		requireOffsetPointsAt(t, trimJSONDocumentWhitespace(spaced), offset, `\uD800`)
	})
}

// Content before the corruption point contributes its raw input byte length:
// Chinese characters are three bytes each, an emoji four, and a legal
// \uXXXX escape six — never a display character count and never the length
// of the string those bytes decode to.
func TestNormalizeOffsetCountsInputBytesNotCharacters(t *testing.T) {
	cases := []struct {
		name           string
		action         string
		marker         string
		multibyteAhead bool // raw multi-byte characters precede the corruption
	}{
		{"Chinese text before the bad escape", `登录\uD800`, `\uD800`, true},
		{"emoji before the bad escape", `😀\uDC00`, `\uDC00`, true},
		// A legal BMP escape is six raw bytes decoding to one character; the
		// bad escape sits after those six bytes, not after one.
		{"legal BMP escape before the bad escape", `\u0041\uD800`, `\uD800`, false},
		// A paired surrogate escape is twelve raw bytes decoding to a single
		// astral character; neither twelve-to-one nor twelve-to-four
		// rewrites may apply.
		{"paired surrogate escape before the bad escape", `\uD83D\uDE00\uD800`, `\uD800`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"timestamp":"2026-01-02T00:00:00Z","action":"` + tc.action + `"}`
			_, offset := expectOffsetFailure(t, input+"\n")
			trimmed := trimJSONDocumentWhitespace(input)
			requireOffsetPointsAt(t, trimmed, offset, tc.marker)
			if tc.multibyteAhead {
				if runes := utf8.RuneCount(trimmed[:offset]); runes == offset {
					t.Fatalf("offset %d must count bytes, not display characters", offset)
				}
			}
		})
	}
}

// Corruption inside an unknown field's nested object or array is located
// from the start of the whole line, exactly like corruption in a mapped
// field — never re-anchored to the field value or to the inner object.
func TestNormalizeOffsetInNestedExtraIsLineRelative(t *testing.T) {
	t.Run("unpaired escape deep in a nested object", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","extra":{"deep":["ok","\uD800"]}}`
		_, offset := expectOffsetFailure(t, input+"\n")
		trimmed := trimJSONDocumentWhitespace(input)
		requireOffsetPointsAt(t, trimmed, offset, `\uD800`)
		inner := bytes.Index(trimmed, []byte(`"deep"`))
		if inner < 0 || offset <= inner {
			t.Fatalf("offset %d must reach past the nested container at %d into the line", offset, inner)
		}
	})
	t.Run("invalid UTF-8 deep in a nested array", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","payload":{"list":["ok","` + "\xff" + `"]}}`
		msg, offset := expectOffsetFailure(t, input+"\n")
		if !strings.Contains(msg, "UTF-8") {
			t.Fatalf("expected an invalid UTF-8 failure, got %q", msg)
		}
		requireOffsetPointsAt(t, trimJSONDocumentWhitespace(input), offset, "\xff")
	})
}

// An invalid UTF-8 failure points at the first byte that cannot start or
// continue a legal character. A multi-byte sequence missing its continuation
// bytes is reported at the byte where that sequence begins.
func TestNormalizeInvalidUTF8OffsetPointsAtFirstBadByte(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		marker string
	}{
		{"lone continuation byte after the object",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"a"}` + "\x80", "\x80"},
		{"invalid byte inside a string value",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"log` + "\xff" + `in"}`, "\xff"},
		{"truncated three-byte sequence before the closing quote",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"ab` + "\xe2\x80" + `"}`, "\xe2\x80"},
		{"truncated sequence at the end of the input",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"ab` + "\xe2\x80", "\xe2\x80"},
		{"overlong encoding",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"` + "\xc0\xaf" + `"}`, "\xc0\xaf"},
		{"UTF-8 encoded surrogate",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"` + "\xed\xa0\x80" + `"}`, "\xed\xa0\x80"},
		{"valid multi-byte text before the bad byte",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"登录😀` + "\xff" + `"}`, "\xff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, offset := expectOffsetFailure(t, tc.input+"\n")
			if !strings.Contains(msg, "invalid UTF-8 encoding") {
				t.Fatalf("expected an invalid UTF-8 failure, got %q", msg)
			}
			if strings.Contains(msg, "surrogate") {
				t.Fatalf("UTF-8 corruption must not be reported as an escape problem, got %q", msg)
			}
			requireOffsetPointsAt(t, trimJSONDocumentWhitespace(tc.input), offset, tc.marker)
		})
	}
}

// An unpaired surrogate escape points at the backslash that opens the
// escape, and the reason distinguishes a lone high surrogate from a lone low
// one so the consumer can tell the two corruption shapes apart.
func TestNormalizeSurrogateEscapeOffsetPointsAtBackslash(t *testing.T) {
	cases := []struct {
		name    string
		action  string
		marker  string // raw escape text whose backslash is the corruption point
		kind    string // distinctive phrase for the surrogate kind
		spelled string // the escape as spelled in the error message
	}{
		{"lone high surrogate", `\uD800`, `\uD800`,
			"high surrogate must be followed immediately", `\uD800`},
		{"lone low surrogate", `act\uDC00ion`, `\uDC00`,
			"low surrogate must follow a high surrogate escape", `\uDC00`},
		// A reversed pair fails on the low surrogate that comes first.
		{"reversed surrogate pair", `\uDC00\uD800`, `\uDC00`,
			"low surrogate must follow a high surrogate escape", `\uDC00`},
		// The first of two adjacent high surrogates is already unpaired.
		{"high surrogate before a completed pair", `\uD800\uD800\uDC00`, `\uD800`,
			"high surrogate must be followed immediately", `\uD800`},
		{"high surrogate followed by a BMP escape", `\uD800A`, `\uD800`,
			"high surrogate must be followed immediately", `\uD800`},
		{"low surrogate boundary values", `x\uDFFFy`, `\uDFFF`,
			"low surrogate must follow a high surrogate escape", `\uDFFF`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"timestamp":"2026-01-02T00:00:00Z","action":"` + tc.action + `"}`
			msg, offset := expectOffsetFailure(t, input+"\n")
			if !strings.Contains(msg, "unpaired Unicode escape "+tc.spelled) {
				t.Fatalf("error must name the unpaired escape %s, got %q", tc.spelled, msg)
			}
			if !strings.Contains(msg, tc.kind) {
				t.Fatalf("error must identify the surrogate kind %q, got %q", tc.kind, msg)
			}
			if strings.Contains(msg, "UTF-8") {
				t.Fatalf("an unpaired escape must not be reported as UTF-8 corruption, got %q", msg)
			}
			requireOffsetPointsAt(t, trimJSONDocumentWhitespace(input), offset, tc.marker)
		})
	}
}

// Legal lookalikes are neither flagged themselves nor miscounted: a
// correctly paired surrogate escape, plain "uD800" text behind an escaped
// backslash, and a literal U+FFFD leave the offset of a real corruption
// later in the same line exactly at that corruption's own byte index.
func TestNormalizeLegalLookalikesDoNotShiftCorruptionOffset(t *testing.T) {
	t.Run("unpaired escape after legal lookalikes", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"ok",` +
			`"pair":"\uD83D\uDE00","text":"\\uD800","mark":"�","bad":"\uDC00"}`
		msg, offset := expectOffsetFailure(t, input+"\n")
		if !strings.Contains(msg, "unpaired") || !strings.Contains(msg, "low surrogate") {
			t.Fatalf("the lone low surrogate must be the reported problem, got %q", msg)
		}
		requireOffsetPointsAt(t, trimJSONDocumentWhitespace(input), offset, `\uDC00`)
	})
	t.Run("invalid UTF-8 after legal lookalikes", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"ok",` +
			`"pair":"\uD83D\uDE00","text":"\\uD800","bad":"` + "\xff" + `"}`
		msg, offset := expectOffsetFailure(t, input+"\n")
		if !strings.Contains(msg, "UTF-8") {
			t.Fatalf("the invalid byte must be the reported problem, got %q", msg)
		}
		requireOffsetPointsAt(t, trimJSONDocumentWhitespace(input), offset, "\xff")
	})
}

// When one line carries both an unpaired escape and invalid UTF-8, the
// reported problem is the UTF-8 corruption and the reported position is the
// bad byte's own offset — even when the escape sits earlier in the line.
func TestNormalizeUTF8OffsetReportedEvenWhenEscapeIsEarlier(t *testing.T) {
	t.Run("escape before the invalid byte", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800` + "\xff" + `"}`
		msg, offset := expectOffsetFailure(t, input+"\n")
		if !strings.Contains(msg, "invalid UTF-8 encoding") || strings.Contains(msg, "surrogate") {
			t.Fatalf("invalid UTF-8 must outrank the unpaired escape, got %q", msg)
		}
		trimmed := trimJSONDocumentWhitespace(input)
		requireOffsetPointsAt(t, trimmed, offset, "\xff")
		if escapeAt := bytes.Index(trimmed, []byte(`\uD800`)); offset <= escapeAt {
			t.Fatalf("offset %d must pass the earlier escape at %d and land on the bad byte", offset, escapeAt)
		}
	})
	t.Run("invalid byte before the escape", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"` + "\xff" + `\uD800"}`
		msg, offset := expectOffsetFailure(t, input+"\n")
		if !strings.Contains(msg, "invalid UTF-8 encoding") || strings.Contains(msg, "surrogate") {
			t.Fatalf("invalid UTF-8 must outrank the unpaired escape, got %q", msg)
		}
		requireOffsetPointsAt(t, trimJSONDocumentWhitespace(input), offset, "\xff")
	})
}

// In a stream, every offset is relative to its own line: valid logs and
// blank lines before a corrupted line advance the physical line number
// without adding a single byte to the reported position. Only the corrupted
// lines fail — each with one error and no event — later valid lines keep
// coming out in order, and the returned failure count covers exactly the
// corrupted lines.
func TestNormalizeStreamOffsetsArePerLineWithPhysicalLineNumbers(t *testing.T) {
	escapeLine := `{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800"}`
	utf8Line := `{"timestamp":"2026-01-02T00:00:00Z","action":"bad` + "\xff" + `"}`
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"first"}` + "\n" +
		"\n" +
		"  " + escapeLine + "\n" + // leading spaces: trimmed per line
		utf8Line + "\n" +
		`{"timestamp":"2026-01-02T00:00:02Z","action":"last"}` + "\n"

	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("per-line corruption is not a stream error, got %v", err)
	}
	if failures != 2 {
		t.Fatalf("exactly the two corrupted lines must count, got %d", failures)
	}
	if !utf8.Valid(out.Bytes()) {
		t.Fatalf("output must be valid UTF-8: %q", out.Bytes())
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 4 {
		t.Fatalf("the blank line produces no output; expected 4 results, got %#v", results)
	}

	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must succeed: %#v", results[0])
	}

	// Line 3: the unpaired escape. Its offset counts from this line's own
	// trimmed content — the two leading spaces and every byte of the earlier
	// lines contribute nothing.
	r := results[1]
	if r["line"] != float64(3) || r["ok"] != false {
		t.Fatalf("line 3 must fail with its physical line number: %#v", r)
	}
	if len(r) != 3 {
		t.Fatalf("a failure record carries exactly line, ok and one error, got %#v", r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("line 3 must not emit an event: %#v", r)
	}
	msg, _ := r["error"].(string)
	if !strings.Contains(msg, "unpaired") {
		t.Fatalf("line 3 must be reported as an unpaired escape, got %q", msg)
	}
	requireOffsetPointsAt(t, trimJSONDocumentWhitespace(escapeLine), reportedOffset(t, msg), `\uD800`)

	// Line 4: the invalid UTF-8 byte, located within its own line.
	r = results[2]
	if r["line"] != float64(4) || r["ok"] != false {
		t.Fatalf("line 4 must fail with its physical line number: %#v", r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("line 4 must not emit an event: %#v", r)
	}
	msg, _ = r["error"].(string)
	if !strings.Contains(msg, "invalid UTF-8 encoding") {
		t.Fatalf("line 4 must be reported as UTF-8 corruption, got %q", msg)
	}
	requireOffsetPointsAt(t, trimJSONDocumentWhitespace(utf8Line), reportedOffset(t, msg), "\xff")

	// Line 5: normalization continues after the corrupted lines.
	if results[3]["line"] != float64(5) || results[3]["ok"] != true {
		t.Fatalf("line 5 must still be processed: %#v", results[3])
	}
	if eventOf(t, results[3])["action"] != "last" {
		t.Fatalf("input order must be preserved after corrupted lines: %#v", results[3])
	}
}
