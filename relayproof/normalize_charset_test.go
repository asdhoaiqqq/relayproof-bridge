package relayproof

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// Character-integrity coverage: raw input bytes must be valid UTF-8, and
// \uXXXX escapes in any JSON string (field names and values at any depth,
// mapped or not) must form complete surrogate pairs. encoding/json would
// silently rewrite both defects to U+FFFD; these tests pin that the line
// fails instead, with a per-line ok:false record, a distinguishable reason,
// and no event — while legal non-ASCII text, paired escapes, literal U+FFFD,
// and escaped backslashes keep working.

// Escape text for test inputs, written as interpreted strings so the JSON
// \uXXXX sequences reach the normalizer as literal backslash escapes.
const (
	escGrinning    = "\\uD83D\\uDE00" // JSON escape text for 😀
	escReplacement = "\\uFFFD"        // JSON escape text for U+FFFD
)

// expectCharFailure asserts the single input line fails with no event and an
// error message containing every marker, and that the serialized output
// record is itself valid UTF-8 JSON (corrupted input bytes are never echoed
// back into the output).
func expectCharFailure(t *testing.T, input string, markers ...string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("a bad log line is not a stream error, got %v", err)
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
		t.Fatalf("corrupted line must fail as line 1: %#v", r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("corrupted line must not emit an event: %#v", r)
	}
	msg, _ := r["error"].(string)
	if msg == "" {
		t.Fatalf("corrupted line must explain itself: %#v", r)
	}
	if !utf8.ValidString(msg) {
		t.Fatalf("error message must be valid UTF-8, got %q", msg)
	}
	for _, marker := range markers {
		if !strings.Contains(msg, marker) {
			t.Fatalf("error %q must contain %q", msg, marker)
		}
	}
	return r
}

func TestNormalizeInvalidUTF8Fails(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"truncated sequence in mapped value", `{"timestamp":"2026-01-02T00:00:00Z","action":"log` + "\xff" + `in"}`},
		{"invalid byte in unmapped string", `{"timestamp":"2026-01-02T00:00:00Z","action":"a","note":"` + "\xc3\x28" + `"}`},
		{"invalid byte in field name", `{"timestamp":"2026-01-02T00:00:00Z","action":"a","no` + "\xe2\x80" + `te":"x"}`},
		{"invalid byte deep in nested extra", `{"timestamp":"2026-01-02T00:00:00Z","action":"a","extra":{"deep":["ok","` + "\xed\xa0\x80" + `"]}}`},
		{"lone continuation byte", `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}` + "\x80"},
		{"overlong encoding", `{"timestamp":"2026-01-02T00:00:00Z","action":"` + "\xc0\xaf" + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := expectCharFailure(t, tc.input, "UTF-8")
			msg := r["error"].(string)
			if strings.Contains(msg, "surrogate") || strings.Contains(msg, "escape") {
				t.Fatalf("UTF-8 corruption must not be reported as an escape problem, got %q", msg)
			}
		})
	}
}

func TestNormalizeUnpairedSurrogateEscapeFails(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"lone high surrogate as action", `{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800"}`},
		{"lone high surrogate in timestamp", `{"timestamp":"2026-01-02T00:00:00\uD800Z","action":"a"}`},
		{"lone low surrogate as action", `{"timestamp":"2026-01-02T00:00:00Z","action":"act\uDC00ion"}`},
		{"reversed surrogate pair", `{"timestamp":"2026-01-02T00:00:00Z","action":"\uDC00\uD800"}`},
		{"high surrogate at end of string", `{"timestamp":"2026-01-02T00:00:00Z","action":"abc\uD800"}`},
		{"high surrogate followed by BMP escape", `{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800A"}`},
		{"high surrogate followed by another high", `{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800\uD800\uDC00"}`},
		{"high surrogate in field name", `{"timestamp":"2026-01-02T00:00:00Z","action":"a","no\uD800te":"x"}`},
		{"low surrogate in field name", `{"time\uDFFFstamp":"2026-01-02T00:00:00Z","action":"a"}`},
		{"high surrogate deep in nested extra", `{"timestamp":"2026-01-02T00:00:00Z","action":"a","extra":{"deep":["ok","y\uDBFF"]}}`},
		{"low surrogate in input extra object", `{"timestamp":"2026-01-02T00:00:00Z","action":"a","extra":{"k":"\uDC00"}}`},
		{"high surrogate in nested key", `{"timestamp":"2026-01-02T00:00:00Z","action":"a","payload":{"a\uD800b":1}}`},
		{"lowercase hex surrogate", `{"timestamp":"2026-01-02T00:00:00Z","action":"\ud800"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := expectCharFailure(t, tc.input, "unpaired", "surrogate")
			msg := r["error"].(string)
			if strings.Contains(msg, "UTF-8") {
				t.Fatalf("unpaired escape must not be reported as UTF-8 corruption, got %q", msg)
			}
		})
	}
}

// Legal non-ASCII content must keep working: Chinese text, emoji, correctly
// paired surrogate escapes, and a literal U+FFFD the user actually wrote are
// all valid characters, not corruption.
func TestNormalizeLegalUnicodeAccepted(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"登录","user":"用户😀","paired":"😀",` +
		`"escaped_pair":"` + escGrinning + `","replacement":"�","escaped_replacement":"` + escReplacement + `"}`
	results := runNormalize(t, input)
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("legal unicode must succeed, got %#v", results)
	}
	event := eventOf(t, results[0])
	if event["action"] != "登录" {
		t.Fatalf("Chinese action must survive, got %v", event["action"])
	}
	extra := extraOf(t, results[0])
	if extra["user"] != "用户😀" {
		t.Fatalf("Chinese and emoji extra string must survive, got %v", extra["user"])
	}
	if extra["paired"] != "😀" || extra["escaped_pair"] != "😀" {
		t.Fatalf("paired surrogate escapes must decode to the emoji, got %#v", extra)
	}
	if extra["replacement"] != "�" || extra["escaped_replacement"] != "�" {
		t.Fatalf("a literal U+FFFD is valid input, not corruption, got %#v", extra)
	}
}

// A correctly paired surrogate escape in a mapped field decodes to the
// astral character and is a perfectly good action name.
func TestNormalizePairedSurrogateInMappedField(t *testing.T) {
	results := runNormalize(t, `{"timestamp":"2026-01-02T00:00:00Z","action":"`+escGrinning+`"}`)
	if results[0]["ok"] != true {
		t.Fatalf("paired surrogate escape must be accepted, got %#v", results[0])
	}
	if got := eventOf(t, results[0])["action"]; got != "😀" {
		t.Fatalf("paired escape must decode to the emoji, got %v", got)
	}
}

// In "\\uD800" the backslash is escaped, so uD800 is ordinary text: the line
// is valid and the text is preserved byte-for-byte, not treated as an
// escape, not flagged, and not rewritten.
func TestNormalizeEscapedBackslashBeforeUIsPlainText(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"run","note":"\\uD800","seq":"\\` + escGrinning + `"}`
	results := runNormalize(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("escaped backslash text must not be flagged, got %#v", results[0])
	}
	extra := extraOf(t, results[0])
	if extra["note"] != `\uD800` {
		t.Fatalf(`escaped backslash must stay the plain text \uD800, got %v`, extra["note"])
	}
	// After the escaped backslash a real escape can still begin: the paired
	// surrogate here is a genuine escape and decodes to the emoji.
	if extra["seq"] != `\`+"😀" {
		t.Fatalf("escape after escaped backslash must still decode, got %v", extra["seq"])
	}
	raw := runNormalizeRaw(t, input)
	if !strings.Contains(raw, `\\uD800`) {
		t.Fatalf("extra must preserve the escaped-backslash text verbatim, got %s", raw)
	}
}

// The integrity check must not disturb anything else: nested content and
// high-precision numbers in unmapped fields pass through byte-identical on
// lines that also exercise the new scanner.
func TestNormalizeIntegrityCheckPreservesExtraContent(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","payload":{"emoji":"` + escGrinning + `","big":9007199254740993,"list":["中文",1.0000000000000000001,"\\uD800"]}}`
	results := runNormalizeJSON(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("legal nested content must succeed, got %#v", results[0])
	}
	payload, ok := extraOf(t, results[0])["payload"].(map[string]any)
	if !ok {
		t.Fatalf("payload must be preserved, got %#v", extraOf(t, results[0]))
	}
	if payload["emoji"] != "😀" {
		t.Fatalf("paired escape must decode, got %v", payload["emoji"])
	}
	mustNumber(t, payload["big"], "9007199254740993")
	list, ok := payload["list"].([]any)
	if !ok || len(list) != 3 {
		t.Fatalf("nested array must be preserved, got %#v", payload["list"])
	}
	if list[0] != "中文" {
		t.Fatalf("nested Chinese string must survive, got %v", list[0])
	}
	mustNumber(t, list[1], "1.0000000000000000001")
	if list[2] != `\uD800` {
		t.Fatalf("escaped-backslash text must stay verbatim, got %v", list[2])
	}
}

// Corrupted lines in a healthy stream behave like any other invalid log:
// one ok:false record each with the original physical line number, valid
// lines around them still succeed in order, the returned error is nil, and
// the failure count covers exactly the corrupted lines (driving exit 1).
func TestNormalizeCorruptedLinesInMixedStream(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"first"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800"}` + "\n" +
		"\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"bad` + "\xff" + `"}` + "\n" +
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
		t.Fatalf("expected 4 results for 5 physical lines, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must succeed: %#v", results[0])
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != false {
		t.Fatalf("line 2 (unpaired escape) must fail: %#v", results[1])
	}
	if !strings.Contains(results[1]["error"].(string), "surrogate") {
		t.Fatalf("line 2 must be reported as an unpaired escape, got %q", results[1]["error"])
	}
	if results[2]["line"] != float64(4) || results[2]["ok"] != false {
		t.Fatalf("line 4 (invalid UTF-8) must fail with its physical line number: %#v", results[2])
	}
	if !strings.Contains(results[2]["error"].(string), "UTF-8") {
		t.Fatalf("line 4 must be reported as UTF-8 corruption, got %q", results[2]["error"])
	}
	if results[3]["line"] != float64(5) || results[3]["ok"] != true {
		t.Fatalf("line 5 must still be processed: %#v", results[3])
	}
	if eventOf(t, results[3])["action"] != "last" {
		t.Fatalf("input order must be preserved after corrupted lines")
	}
}
