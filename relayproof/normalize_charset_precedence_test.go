package relayproof

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// Precedence coverage for lines where character corruption meets other
// problems. The normalizer checks whole-line character integrity before
// parsing JSON and validating fields, so the failure reason the user sees is
// decided by that order, never by where the problems happen to sit in the
// line: invalid UTF-8 bytes outrank unpaired \uXXXX surrogate escapes, and
// either outranks duplicate top-level keys and field validation. Each
// failing line yields exactly one result record — line, ok:false, one error,
// no event — and corrupted bytes are never repaired into replacement
// characters and handed to the field logic.

// expectPrecedenceFailure asserts the single input line fails with one error
// record whose message contains every marker in contains and none in
// excludes, carries no event, and holds exactly the keys line/ok/error. The
// serialized output must stay valid UTF-8 and must never gain a U+FFFD the
// user did not write: corruption is reported, not repaired.
func expectPrecedenceFailure(t *testing.T, input string, contains, excludes []string) string {
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
	if bytes.Contains(out.Bytes(), []byte("�")) {
		t.Fatalf("corrupted input must not be rewritten with replacement characters: %q", out.Bytes())
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
	if len(r) != 3 {
		t.Fatalf("a failure record carries exactly line, ok and one error, got %#v", r)
	}
	msg, _ := r["error"].(string)
	if msg == "" {
		t.Fatalf("corrupted line must explain itself: %#v", r)
	}
	if !utf8.ValidString(msg) {
		t.Fatalf("error message must be valid UTF-8, got %q", msg)
	}
	for _, marker := range contains {
		if !strings.Contains(msg, marker) {
			t.Fatalf("error %q must contain %q", msg, marker)
		}
	}
	for _, marker := range excludes {
		if strings.Contains(msg, marker) {
			t.Fatalf("error %q must not contain %q", msg, marker)
		}
	}
	return msg
}

// Any invalid UTF-8 byte on the line decides the failure reason, no matter
// what else is wrong with the same line and no matter where the byte sits
// relative to the other problem.
func TestNormalizeInvalidUTF8WinsOverOtherProblems(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		// The escape problem comes first in the line, the invalid byte
		// later: position must not let the escape win.
		{"unpaired escape before invalid byte", `{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800` + "\xff" + `"}`},
		{"invalid byte before unpaired escape", `{"timestamp":"2026-01-02T00:00:00Z","action":"` + "\xff" + `\uD800"}`},
		{"invalid byte with invalid timestamp", `{"timestamp":"not-a-time","action":"a` + "\xff" + `"}`},
		{"invalid byte with duplicate top-level key", `{"timestamp":"2026-01-02T00:00:00Z","action":"a","action":"` + "\xff" + `"}`},
		{"invalid byte with escape, timestamp and duplicate problems", `{"timestamp":"not-a-time","action":"\uD800` + "\xff" + `","action":"b"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectPrecedenceFailure(t, tc.input,
				[]string{"UTF-8"},
				[]string{"surrogate", "escape", "timestamp", "duplicate"})
		})
	}
}

// With the raw bytes legal, an unpaired surrogate escape anywhere in the
// document — a mapped value, a field name, or an unknown field's nested
// object or array — decides the failure reason ahead of timestamp validation
// and the duplicate top-level key rule.
func TestNormalizeUnpairedEscapeWinsOverFieldProblems(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"lone high surrogate in action with invalid timestamp", `{"timestamp":"not-a-time","action":"\uD800"}`},
		{"lone low surrogate in action with invalid timestamp", `{"timestamp":"not-a-time","action":"act\uDC00ion"}`},
		{"reversed pair in action with invalid timestamp", `{"timestamp":"not-a-time","action":"\uDC00\uD800"}`},
		{"high surrogate in field name with duplicate key", `{"timestamp":"2026-01-02T00:00:00Z","action":"a","no\uD800te":"x","action":"b"}`},
		{"low surrogate in nested extra object with invalid timestamp", `{"timestamp":"not-a-time","action":"a","extra":{"k":"\uDC00"}}`},
		{"high surrogate in nested extra array with duplicate key", `{"timestamp":"2026-01-02T00:00:00Z","action":"a","action":"b","list":["ok","\uDBFF"]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectPrecedenceFailure(t, tc.input,
				[]string{"unpaired", "surrogate"},
				[]string{"UTF-8", "timestamp", "duplicate"})
		})
	}
}

// Repairing the same log one character problem at a time must move the
// reported reason through the precedence order: invalid bytes first, then
// the unpaired escape, then the invalid timestamp, and only a fully clean
// line succeeds. The character check neither hides the later problems nor
// turns corrupted input into legal characters for the field logic.
func TestNormalizeCharsetRepairProgression(t *testing.T) {
	stages := []struct {
		name     string
		input    string
		contains []string
		excludes []string
	}{
		{"invalid byte plus unpaired escape plus invalid timestamp",
			`{"timestamp":"not-a-time","action":"\uD800` + "\xff" + `"}`,
			[]string{"UTF-8"}, []string{"surrogate", "timestamp"}},
		{"bytes repaired, escape still unpaired",
			`{"timestamp":"not-a-time","action":"\uD800"}`,
			[]string{"surrogate"}, []string{"UTF-8", "timestamp"}},
		{"escape repaired, timestamp still invalid",
			`{"timestamp":"not-a-time","action":"ok"}`,
			[]string{"timestamp"}, []string{"UTF-8", "surrogate"}},
	}
	for _, stage := range stages {
		t.Run(stage.name, func(t *testing.T) {
			expectPrecedenceFailure(t, stage.input, stage.contains, stage.excludes)
		})
	}

	t.Run("all character problems repaired", func(t *testing.T) {
		results := runNormalize(t, `{"timestamp":"2026-01-02T00:00:00Z","action":"ok"}`)
		if len(results) != 1 || results[0]["ok"] != true {
			t.Fatalf("the fully repaired line must succeed, got %#v", results)
		}
		if got := eventOf(t, results[0])["action"]; got != "ok" {
			t.Fatalf("the repaired action must survive, got %v", got)
		}
	})
}

// Once the characters are legal the character check steps aside completely:
// a duplicate top-level key still fails by the original duplicate rule, and
// an invalid timestamp still fails field validation — the integrity check
// must not make these later problems disappear.
func TestNormalizeCharacterCleanLinesKeepLaterFailures(t *testing.T) {
	t.Run("duplicate top-level key", func(t *testing.T) {
		expectPrecedenceFailure(t,
			`{"timestamp":"2026-01-02T00:00:00Z","action":"a","action":"a"}`,
			[]string{"duplicate", FieldAction},
			[]string{"UTF-8", "surrogate"})
	})
	t.Run("duplicate key with legal paired escapes", func(t *testing.T) {
		expectPrecedenceFailure(t,
			`{"timestamp":"2026-01-02T00:00:00Z","action":"`+escGrinning+`","action":"a"}`,
			[]string{"duplicate", FieldAction},
			[]string{"UTF-8", "surrogate"})
	})
	t.Run("invalid timestamp", func(t *testing.T) {
		expectPrecedenceFailure(t,
			`{"timestamp":"2026-13-02T00:00:00Z","action":"a"}`,
			[]string{FieldTimestamp},
			[]string{"UTF-8", "surrogate", "duplicate"})
	})
}

// Legal lookalikes sharing one line with each other must not be mistaken for
// corruption: a correctly paired surrogate escape, a literal U+FFFD the user
// wrote, and uD800 appearing as plain text behind an escaped backslash all
// pass, with the unknown field's text and nested structure kept in extra.
func TestNormalizeLegalLookalikesSharingOneLine(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"` + escGrinning + `",` +
		`"note":"\\uD800","mark":"�","nested":{"pair":"` + escGrinning + `","list":["\\uD800","�"]}}`
	results := runNormalize(t, input)
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("legal lookalikes must succeed, got %#v", results)
	}
	if got := eventOf(t, results[0])["action"]; got != "😀" {
		t.Fatalf("paired escape in a mapped field must decode to the emoji, got %v", got)
	}
	extra := extraOf(t, results[0])
	if extra["note"] != `\uD800` {
		t.Fatalf(`escaped-backslash text must stay the plain text \uD800, got %v`, extra["note"])
	}
	if extra["mark"] != "�" {
		t.Fatalf("a literal U+FFFD is valid input, got %v", extra["mark"])
	}
	nested, ok := extra["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested unknown structure must be preserved in extra, got %#v", extra["nested"])
	}
	if nested["pair"] != "😀" {
		t.Fatalf("nested paired escape must decode, got %v", nested["pair"])
	}
	list, ok := nested["list"].([]any)
	if !ok || len(list) != 2 || list[0] != `\uD800` || list[1] != "�" {
		t.Fatalf("nested array text must survive verbatim, got %#v", nested["list"])
	}
}
