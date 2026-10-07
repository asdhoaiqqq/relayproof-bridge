package relayproof

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// Position regression coverage for the character-integrity failure records.
// A bad line already fails with one ok:false record that names the damage
// kind ("invalid UTF-8 encoding" vs "unpaired Unicode escape" high/low
// surrogate); these tests pin the "at byte offset N" position so consumers of
// the failure stream can navigate back to the exact input bytes.
//
// The contract under test:
//
//   - Offset zero is the first byte of the line content AFTER the legal JSON
//     whitespace surrounding the document has been removed (space, tab,
//     carriage return, line feed), not the first byte of the input stream and
//     not a terminal display column.
//   - Everything inside the document is counted in raw bytes: tabs and spaces
//     between members, multi-byte Chinese text and emoji (by their actual
//     UTF-8 byte lengths, never display columns or rune counts), and the six
//     raw bytes of a \uXXXX escape (never the length of the decoded string).
//   - Offsets are whole-line positions even when the damage is inside an
//     unknown field's nested object or array; counting never restarts at the
//     field value or an inner object.
//   - Invalid UTF-8 is reported at the first byte that cannot form a legal
//     character; a multi-byte sequence missing continuation bytes is reported
//     at the sequence's first byte. An unpaired surrogate escape is reported
//     at the backslash that opens the escape, with lone high and lone low
//     surrogates distinguished. Correctly paired escapes and the plain text
//     behind an escaped backslash are neither damage nor a shift of later
//     positions.
//   - When one line carries both an unpaired escape and invalid UTF-8, the
//     UTF-8 reason and the byte position win even when the escape sits earlier.
//
// Nothing here changes normalization: the allowed characters, the wording of
// the reasons, and the public entry points (NormalizeLine/NormalizeReader)
// are only exercised, never modified.

// byteOffsetPattern extracts the single reported position from a failure
// reason. A failure record names exactly one position.
var byteOffsetPattern = regexp.MustCompile(`at byte offset (\d+)`)

// singleLineFailure runs one non-blank physical line through the public
// streaming entry point and returns its sole failure record, asserting the
// fixed shape of a per-line failure: line 1, ok:false, exactly line/ok/error,
// no event, one failure counted, no stream-level error.
func singleLineFailure(t *testing.T, input string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("a corrupted log line is not a stream-level failure, got %v", err)
	}
	if failures != 1 {
		t.Fatalf("the corrupted line must count as exactly one failure, got %d", failures)
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 1 {
		t.Fatalf("expected exactly one result record, got %#v", results)
	}
	r := results[0]
	if r["line"] != float64(1) || r["ok"] != false {
		t.Fatalf("corrupted line must fail as line 1, got %#v", r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("corrupted line must not carry an event: %#v", r)
	}
	if len(r) != 3 {
		t.Fatalf("a failure record carries exactly line, ok and one error, got %#v", r)
	}
	msg, _ := r["error"].(string)
	if msg == "" {
		t.Fatalf("corrupted line must explain itself: %#v", r)
	}
	return r
}

// expectFailureOffset runs one line and asserts its reason reports exactly
// wantOffset once, that wantOffset is a valid index into the trimmed document,
// and (when anchor is non-zero) that it points at anchor — the byte a consumer
// lands on when following the position. The message is returned for further
// reason-wording assertions.
func expectFailureOffset(t *testing.T, input string, wantOffset int, anchor byte) string {
	t.Helper()
	msg, _ := singleLineFailure(t, input)["error"].(string)
	matches := byteOffsetPattern.FindAllStringSubmatch(msg, -1)
	if len(matches) != 1 {
		t.Fatalf("reason must name exactly one byte offset, got %d in %q", len(matches), msg)
	}
	if matches[0][1] != strconv.Itoa(wantOffset) {
		t.Fatalf("reported offset %s, want %d (reason %q)", matches[0][1], wantOffset, msg)
	}
	trimmed := trimJSONWhitespace([]byte(input))
	if wantOffset < 0 || wantOffset >= len(trimmed) {
		t.Fatalf("offset %d is out of range for a %d-byte document", wantOffset, len(trimmed))
	}
	if anchor != 0 && trimmed[wantOffset] != anchor {
		t.Fatalf("offset %d must land on byte %#x, got %#x (document %q)", wantOffset, anchor, trimmed[wantOffset], trimmed)
	}
	return msg
}

// invalidUTF8OffsetLines are byte-correct lines: the reported offset is
// computed by walking the same raw bytes as production (see invalidUTF8Offset),
// and each expected anchor is located independently with strings.IndexByte in
// the tests below, so the numbers pin behavior rather than restate the
// implementation.
var invalidUTF8OffsetCases = []struct {
	name   string
	input  string
	offset int
	anchor byte
}{
	{
		"illegal byte after an ASCII prefix",
		`{"timestamp":"2026-01-02T00:00:00Z","action":"log` + "\xff" + `in"}`,
		49, 0xff,
	},
	{
		"invalid continuation byte in an unmapped string",
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","note":"` + "\xc3\x28" + `"}`,
		57, 0xc3,
	},
	{
		"truncated three-byte sequence in a field name",
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","no` + "\xe2\x80" + `te":"x"}`,
		52, 0xe2,
	},
	{
		"truncated four-byte sequence in a mapped value",
		`{"timestamp":"2026-01-02T00:00:00Z","action":"` + "\xf0\x9f" + `"}`,
		46, 0xf0,
	},
	{
		"truncated two-byte sequence at end of document",
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a"}` + "\xc3",
		49, 0xc3,
	},
	{
		"lone continuation byte after the object",
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a"}` + "\x80",
		49, 0x80,
	},
	{
		"overlong two-byte encoding",
		`{"timestamp":"2026-01-02T00:00:00Z","action":"` + "\xc0\xaf" + `"}`,
		46, 0xc0,
	},
	{
		"raw surrogate-range bytes deep in nested unknown content",
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","extra":{"deep":["ok","` + "\xed\xa0\x80" + `"]}}`,
		72, 0xed,
	},
	{
		"illegal byte is the first byte of the document",
		"\xff" + `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}`,
		0, 0xff,
	},
}

// Invalid UTF-8 is reported at the first byte that cannot start or continue a
// legal character, as a zero-based byte offset into the trimmed line, and the
// reason stays the UTF-8 reason — never an escape complaint.
func TestNormalizeInvalidUTF8ByteOffsets(t *testing.T) {
	for _, tc := range invalidUTF8OffsetCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := expectFailureOffset(t, tc.input, tc.offset, tc.anchor)
			if !strings.Contains(msg, "UTF-8") {
				t.Fatalf("bad bytes must be reported as UTF-8 corruption, got %q", msg)
			}
			if strings.Contains(msg, "surrogate") || strings.Contains(msg, "escape") {
				t.Fatalf("UTF-8 corruption must not be reported as an escape problem, got %q", msg)
			}
			// Independent whole-line localization: following the offset must
			// land on exactly the raw byte strings.IndexByte finds from the
			// start of the trimmed document.
			trimmed := trimJSONWhitespace([]byte(tc.input))
			if got := strings.IndexByte(string(trimmed), tc.anchor); got != tc.offset {
				t.Fatalf("offset must be the whole-line index %d of the illegal byte, got %d", tc.offset, got)
			}
		})
	}
}

// A multi-byte sequence missing its continuation bytes is located at the
// sequence's lead byte, and every byte before that position must still be
// legal UTF-8: the reported position is the boundary at which decoding breaks.
func TestNormalizeTruncatedMultibytePointsAtSequenceStart(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		offset int
		lead   byte
	}{
		{"truncated three-byte sequence",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"a","no` + "\xe2\x80" + `te":"x"}`, 52, 0xe2},
		{"truncated four-byte sequence",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"` + "\xf0\x9f" + `"}`, 46, 0xf0},
		{"truncated two-byte sequence at end of document",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"a"}` + "\xc3", 49, 0xc3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectFailureOffset(t, tc.input, tc.offset, tc.lead)
			trimmed := trimJSONWhitespace([]byte(tc.input))
			prefix, rest := trimmed[:tc.offset], trimmed[tc.offset:]
			if !utf8.Valid(prefix) {
				t.Fatalf("everything before offset %d must be legal UTF-8, got %q", tc.offset, prefix)
			}
			if utf8.Valid(rest) {
				t.Fatalf("the byte sequence at offset %d must be the first illegal unit, got %q", tc.offset, rest)
			}
		})
	}
}

// Unpaired surrogate escapes are located at the backslash opening the escape,
// counted by raw bytes from the trimmed document start, with lone high and
// lone low surrogates carrying distinct reasons.
func TestNormalizeUnpairedSurrogateOffsets(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		offset int
		escape string // exact raw bytes at the reported offset, e.g. \uD800
		quoted string // how the reason spells the code point (uppercase hex)
		high   bool
	}{
		{"lone high surrogate in mapped value",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800"}`, 46, `\uD800`, `\uD800`, true},
		{"lone low surrogate surrounded by text",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"act\uDC00ion"}`, 49, `\uDC00`, `\uDC00`, false},
		{"lone high surrogate inside timestamp",
			`{"timestamp":"2026-01-02T00:00:00\uD800Z","action":"a"}`, 33, `\uD800`, `\uD800`, true},
		{"reversed pair is a lone low at the first backslash",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"\uDC00\uD800"}`, 46, `\uDC00`, `\uDC00`, false},
		{"lowercase hex digits locate the same backslash",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"\ud800"}`, 46, `\ud800`, `\uD800`, true},
		{"lone high surrogate in a field name",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"a","no\uD800te":"x"}`, 52, `\uD800`, `\uD800`, true},
		{"lone low surrogate in a field name",
			`{"time\uDFFFstamp":"2026-01-02T00:00:00Z","action":"a"}`, 6, `\uDFFF`, `\uDFFF`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := expectFailureOffset(t, tc.input, tc.offset, '\\')
			trimmed := trimJSONWhitespace([]byte(tc.input))
			// The six raw bytes starting at the offset are precisely the
			// escape spelling as written: position is a raw-byte position, not
			// the index of the decoded rune.
			if got := string(trimmed[tc.offset : tc.offset+6]); got != tc.escape {
				t.Fatalf("offset %d must open %q, got %q", tc.offset, tc.escape, got)
			}
			// It is also exactly where that raw spelling begins when the
			// trimmed document is searched whole from byte zero.
			if got := strings.Index(string(trimmed), tc.escape); got != tc.offset {
				t.Fatalf("offset must be the whole-line index %d of %q, got %d", tc.offset, tc.escape, got)
			}
			if !strings.Contains(msg, "unpaired") || !strings.Contains(msg, "surrogate") {
				t.Fatalf("reason must name an unpaired surrogate, got %q", msg)
			}
			if !strings.Contains(msg, tc.quoted) {
				t.Fatalf("reason must quote the code point %q, got %q", tc.quoted, msg)
			}
			if tc.high {
				if !strings.Contains(msg, "high surrogate") {
					t.Fatalf("a lone high surrogate must be distinguished as high, got %q", msg)
				}
			} else {
				if !strings.Contains(msg, "low surrogate") {
					t.Fatalf("a lone low surrogate must be distinguished as low, got %q", msg)
				}
			}
			if strings.Contains(msg, "UTF-8") {
				t.Fatalf("an escape problem must not be reported as UTF-8 corruption, got %q", msg)
			}
		})
	}
}

// Offsets count actual input bytes. Multi-byte Chinese text and emoji before
// the damage push the position by their UTF-8 byte length, not by one display
// column or one rune each; a preceding \uXXXX escape counts its six raw bytes,
// not the single character a JSON decoder would produce.
func TestNormalizeOffsetsCountRawBytes(t *testing.T) {
	t.Run("Chinese text before invalid byte", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"登录` + "\xff" + `"}`
		expectFailureOffset(t, input, 52, 0xff)
		trimmed := trimJSONWhitespace([]byte(input))
		prefix := trimmed[:52]
		if utf8.RuneCount(prefix) >= len(prefix) {
			t.Fatalf("offset must be in bytes: prefix is %d bytes but %d runes", len(prefix), utf8.RuneCount(prefix))
		}
		if strings.IndexByte(string(trimmed), 0xff) != 52 {
			t.Fatalf("offset must equal the raw byte index of 0xff")
		}
	})

	t.Run("Chinese text and emoji before a truncated sequence", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"用户😀` + "\xe2\x80" + `"}`
		expectFailureOffset(t, input, 56, 0xe2)
	})

	t.Run("Chinese text before a lone high surrogate", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"登录\uD800"}`
		expectFailureOffset(t, input, 52, '\\')
	})

	t.Run("a paired escape before a lone high counts its twelve raw bytes", func(t *testing.T) {
		// 😀 written as the two raw escape sequences (12 bytes), then the
		// genuinely unpaired high escape. The reported position counts all 12
		// raw bytes of the legal pair, not the one decoded emoji.
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"` + escGrinning + `\uD800"}`
		msg := expectFailureOffset(t, input, 58, '\\')
		if !strings.Contains(msg, "high surrogate") {
			t.Fatalf("the later escape must be reported as a lone high surrogate, got %q", msg)
		}
		trimmed := trimJSONWhitespace([]byte(input))
		if got := strings.Index(string(trimmed), `\uD800`); got != 58 {
			t.Fatalf("paired escape must not compress to one byte: raw index is %d, reported 58", got)
		}
	})
}

// Adding legal JSON whitespace before or after the document moves neither the
// offset nor any other word of the reason: the position origin is the trimmed
// line content, even when the physical line arrives with a trailing newline.
func TestNormalizeOffsetsIgnoreDocumentBoundaryWhitespace(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		offset int
		anchor byte
	}{
		{"invalid UTF-8", `{"timestamp":"2026-01-02T00:00:00Z","action":"log` + "\xff" + `in"}`, 49, 0xff},
		{"unpaired escape", `{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800"}`, 46, '\\'},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseline := expectFailureOffset(t, tc.line, tc.offset, tc.anchor)
			for _, framed := range []string{
				" " + tc.line,
				"   " + tc.line,
				"\t" + tc.line,
				"\r" + tc.line,
				" \t\r " + tc.line + "  \t\r",
				"\t\t" + tc.line + "\n", // physical line as the splitter delivers it
				"  " + tc.line + " \r\n",
			} {
				msg := expectFailureOffset(t, framed, tc.offset, tc.anchor)
				if msg != baseline {
					t.Fatalf("document-boundary whitespace must not change the reason:\n baseline=%q\n framed  =%q", baseline, msg)
				}
			}
		})
	}
}

// Whitespace inside the document is part of the content: inserting bytes
// between members or inside a string value moves the same corruption point by
// exactly the number of bytes inserted.
func TestNormalizeOffsetsCountInteriorWhitespace(t *testing.T) {
	plain := `{"timestamp":"2026-01-02T00:00:00Z","action":"a` + "\xff" + `"}`
	expectFailureOffset(t, plain, 47, 0xff)

	t.Run("whitespace between members advances the offset", func(t *testing.T) {
		insert := " \t\r " // four legal JSON whitespace bytes before the action key
		padded := strings.Replace(plain, `,"action":`, ","+insert+`"action":`, 1)
		expectFailureOffset(t, padded, 47+len(insert), 0xff)
	})

	t.Run("spaces inside the string value advance the offset", func(t *testing.T) {
		insert := "   " // string content, three raw bytes
		padded := strings.Replace(plain, `"a`+"\xff", `"a`+insert+"\xff", 1)
		expectFailureOffset(t, padded, 47+len(insert), 0xff)
	})
}

// Damage inside an unknown field is located from the start of the whole
// trimmed line, never from the start of the field value, the inner object, or
// the inner array.
func TestNormalizeNestedUnknownContentUsesWholeLineOffset(t *testing.T) {
	t.Run("invalid byte inside nested array", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","extra":{"deep":["ok","x` + "\xff" + `y"]}}`
		expectFailureOffset(t, input, 73, 0xff)
		trimmed := trimJSONWhitespace([]byte(input))
		// The nested string's opening quote is at 71 and its content begins at
		// 72: a value-relative count would report 1, not the whole-line 73.
		if trimmed[71] != '"' {
			t.Fatalf("test setup: inner string quote expected at 71, got %#x in %q", trimmed[71], trimmed)
		}
		if strings.IndexByte(string(trimmed), 0xff) != 73 {
			t.Fatalf("position must be whole-line, not restarted at the nested value")
		}
	})

	t.Run("lone high surrogate inside nested array", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","extra":{"deep":["ok","y\uDBFF"]}}`
		expectFailureOffset(t, input, 73, '\\')
		trimmed := trimJSONWhitespace([]byte(input))
		if strings.Index(string(trimmed), `\uDBFF`) != 73 {
			t.Fatalf("nested escape position must be measured from the line start")
		}
	})

	t.Run("lone low surrogate inside nested object value", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","extra":{"k":"\uDC00"}}`
		msg := expectFailureOffset(t, input, 63, '\\')
		if !strings.Contains(msg, "low surrogate") {
			t.Fatalf("nested lone low must keep its low-surrogate reason, got %q", msg)
		}
		trimmed := trimJSONWhitespace([]byte(input))
		if strings.Index(string(trimmed), `\uDC00`) != 63 {
			t.Fatalf("nested object content must be located from the line start")
		}
	})

	t.Run("lone high surrogate inside nested object key", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","payload":{"a\uD800b":1}}`
		expectFailureOffset(t, input, 62, '\\')
		trimmed := trimJSONWhitespace([]byte(input))
		if strings.Index(string(trimmed), `\uD800`) != 62 {
			t.Fatalf("nested key content must be located from the line start")
		}
	})
}

// Correctly paired surrogate escapes and the literal uD800 text behind an
// escaped backslash are legal; they neither fail the line nor move the
// position of the damage that genuinely follows them.
func TestNormalizeLegalEscapeTextDoesNotShiftPositions(t *testing.T) {
	t.Run("legal escapes alone keep the line successful", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"` + escGrinning +
			`","note":"\\uD800","pair":"` + escGrinning + `"}`
		results := runNormalize(t, input)
		if len(results) != 1 || results[0]["ok"] != true {
			t.Fatalf("paired escapes and escaped-backslash text are not corruption: %#v", results)
		}
		if got := eventOf(t, results[0])["action"]; got != "😀" {
			t.Fatalf("paired escape must decode to the emoji, got %v", got)
		}
		if got := extraOf(t, results[0])["note"]; got != `\uD800` {
			t.Fatalf("escaped-backslash text must survive verbatim, got %v", got)
		}
	})

	t.Run("paired escape before a real lone high does not shift it", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"` + escGrinning + `\uD800"}`
		expectFailureOffset(t, input, 58, '\\')
	})

	t.Run("plain uD800 text before a real lone high does not shift it", func(t *testing.T) {
		// In "\\uD800" the first backslash is escaped and the uD800 after it
		// is ordinary text; the genuine escape is the second \uD800.
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"\\uD800\uD800"}`
		msg := expectFailureOffset(t, input, 53, '\\')
		if !strings.Contains(msg, "high surrogate") {
			t.Fatalf("the second escape must be the lone high, got %q", msg)
		}
		trimmed := trimJSONWhitespace([]byte(input))
		first := strings.Index(string(trimmed), `\uD800`) // lands on plain text at 47
		if first != 47 {
			t.Fatalf("test setup: plain-text occurrence expected at 47, got %d", first)
		}
		if string(trimmed[53:59]) != `\uD800` {
			t.Fatalf("offset 53 must open the real escape, got %q", trimmed[53:59])
		}
	})

	t.Run("paired escape before invalid bytes does not shift the byte offset", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"` + escGrinning + "\xff" + `"}`
		msg := expectFailureOffset(t, input, 58, 0xff)
		if !strings.Contains(msg, "UTF-8") {
			t.Fatalf("invalid byte after a legal pair must be reported as UTF-8 corruption, got %q", msg)
		}
	})

	t.Run("escaped-backslash text before invalid bytes does not shift the offset", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","note":"\\uD800` + "\xff" + `"}`
		expectFailureOffset(t, input, 64, 0xff)
	})
}

// When one line contains both an unpaired surrogate escape and invalid UTF-8,
// the record reports the UTF-8 problem at the illegal byte's offset, whether
// the escape appears earlier or later in the line.
func TestNormalizeMixedCorruptionReportsUTF8Position(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		offset int
		anchor byte
	}{
		{
			"unpaired escape earlier than the invalid byte",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800` + "\xff" + `"}`,
			52, 0xff,
		},
		{
			"invalid byte earlier than the unpaired escape",
			`{"timestamp":"2026-01-02T00:00:00Z","action":"` + "\xff" + `\uD800"}`,
			46, 0xff,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := expectFailureOffset(t, tc.input, tc.offset, tc.anchor)
			if !strings.Contains(msg, "UTF-8") {
				t.Fatalf("UTF-8 corruption must decide the reason regardless of order, got %q", msg)
			}
			if strings.Contains(msg, "surrogate") || strings.Contains(msg, "escape") {
				t.Fatalf("the earlier escape must not be reported, got %q", msg)
			}
		})
	}
}

// NormalizeLine is the other public entry point: it echoes the caller's line
// number unchanged and applies the same trimmed-document byte offset.
func TestNormalizeLineOffsets(t *testing.T) {
	r := NormalizeLine(7, []byte("  "+`{"timestamp":"2026-01-02T00:00:00Z","action":"log`+"\xff"+`in"}`+"\r\n"))
	if r.OK || r.Event != nil || r.Line != 7 {
		t.Fatalf("line 7 must fail without an event, got %#v", r)
	}
	if !strings.Contains(r.Error, "invalid UTF-8 encoding at byte offset 49") {
		t.Fatalf("NormalizeLine must report the trimmed-document offset 49, got %q", r.Error)
	}

	r = NormalizeLine(0, []byte(`{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800"}`))
	if r.OK {
		t.Fatalf("lone high surrogate must fail, got %#v", r)
	}
	if !strings.Contains(r.Error, `unpaired Unicode escape \uD800 at byte offset 46`) {
		t.Fatalf("NormalizeLine must pin the escape backslash at 46, got %q", r.Error)
	}
}

// In a streamed read, corruption is confined to its own physical line: prior
// legal logs and blank lines advance the physical line number but never add to
// the line's byte offset, the corrupted line emits one reason with no event,
// later legal lines continue, the returned failure count equals the corrupted
// lines, and the character problem is not a stream-level error.
func TestNormalizeCorruptionOffsetsInStream(t *testing.T) {
	input := legalJSONDocument + "\n" + // line 1: ok
		"\n" + // line 2: blank, occupies a number only
		`{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800"}` + "\n" + // line 3: fail (escape)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"mid"}` + "\n" + // line 4: ok
		"  " + `{"timestamp":"2026-01-02T00:00:00Z","action":"log` + "\xff" + `in"}` + "\n" + // line 5: fail (UTF-8, framed)
		"  \t \n" + // line 6: blank
		`{"timestamp":"2026-01-02T00:00:03Z","action":"last"}` + "\n" // line 7: ok

	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("per-line character corruption must not be a stream failure, got %v", err)
	}
	if failures != 2 {
		t.Fatalf("exactly the two corrupted lines must count, got %d", failures)
	}
	if !utf8.Valid(out.Bytes()) {
		t.Fatalf("output must stay valid UTF-8: %q", out.Bytes())
	}
	results := decodeResults(t, out.Bytes())
	if len(results) != 5 {
		t.Fatalf("five non-blank lines must yield five records, got %#v", results)
	}

	wantLines := []float64{1, 3, 4, 5, 7}
	for i, line := range wantLines {
		if results[i]["line"] != line {
			t.Fatalf("record %d must carry physical line %v, got %#v", i, line, results[i])
		}
	}
	if results[0]["ok"] != true || results[2]["ok"] != true || results[4]["ok"] != true {
		t.Fatalf("legal lines must succeed around the corruption: %#v", results)
	}

	// Line 3: the physical line number is 3 while the byte offset is still
	// measured from that line's own trimmed content — prior lines add nothing.
	line3 := results[1]
	if line3["ok"] != false {
		t.Fatalf("line 3 must fail: %#v", line3)
	}
	if _, exists := line3["event"]; exists {
		t.Fatalf("line 3 must not emit an event: %#v", line3)
	}
	if got := line3["error"].(string); !strings.Contains(got, `unpaired Unicode escape \uD800 at byte offset 46`) {
		t.Fatalf("line 3 must keep its own line-relative offset 46, got %q", got)
	}

	// Line 5: leading spaces before the object do not move the offset, even
	// though the line sits much deeper in the input stream.
	line5 := results[3]
	if line5["ok"] != false {
		t.Fatalf("line 5 must fail: %#v", line5)
	}
	if _, exists := line5["event"]; exists {
		t.Fatalf("line 5 must not emit an event: %#v", line5)
	}
	if got := line5["error"].(string); !strings.Contains(got, "invalid UTF-8 encoding at byte offset 49") {
		t.Fatalf("line 5 must keep the same trimmed-document offset 49, got %q", got)
	}

	if eventOf(t, results[4])["action"] != "last" {
		t.Fatalf("line 7 must still be processed after the corrupted lines")
	}
}
