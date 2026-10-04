package relayproof

import (
	"strings"
	"testing"
)

// Regression coverage for action text comparison when a log carries both
// action and event_type. The two fields are compared as JSON-decoded strings
// with leading/trailing whitespace stripped: different JSON spellings of the
// same text (literal characters versus \uXXXX escapes, surrogate pairs
// included) and different edge whitespace must merge, while text that only
// looks similar — different case, precomposed versus combining accents, or an
// invisible zero-width space at the edge — must stay a conflict. Trimming
// never reaches into the text, and an action that trims to empty fails the
// whole line no matter what the other field holds.

// JSON escape text used in the inputs below, written as interpreted strings
// so the normalizer receives literal backslash escapes to decode.
const (
	escRocket = "\\uD83D\\uDE80" // JSON escape text for 🚀 (U+1F680)
	escNBSP   = "\\u00A0"        // JSON escape text for U+00A0 no-break space
	escZWSP   = "\\u200B"        // JSON escape text for U+200B zero width space
	escIdeoSp = "\\u3000"        // JSON escape text for U+3000 ideographic space
	escCombAc = "\\u0301"        // JSON escape text for U+0301 combining acute accent
)

// Different JSON spellings of the same action text must merge into one
// action: literal characters equal their \uXXXX escapes (including surrogate
// pairs), and ordinary spaces, no-break spaces, and ideographic spaces at the
// edges are stripped before comparing. The merged event keeps a single
// trimmed action and event_type never leaks into extra.
func TestNormalizeActionEquivalentSpellingsMerge(t *testing.T) {
	cases := []struct {
		name      string
		action    string // JSON string literal for the action member
		eventType string // JSON string literal for the event_type member
		want      string // expected decoded action after trimming
	}{
		{
			name:      "literal emoji versus surrogate pair escape",
			action:    `"🚀 deploy"`,
			eventType: `"` + escRocket + ` deploy"`,
			want:      "🚀 deploy",
		},
		{
			name:      "surrogate pair escape versus literal emoji",
			action:    `"` + escRocket + ` deploy"`,
			eventType: `"🚀 deploy"`,
			want:      "🚀 deploy",
		},
		{
			name:      "no-break space edges",
			action:    `"` + escNBSP + `login` + escNBSP + `"`,
			eventType: `"login"`,
			want:      "login",
		},
		{
			name:      "ideographic space edges",
			action:    `"login"`,
			eventType: `"` + escIdeoSp + `login` + escIdeoSp + `"`,
			want:      "login",
		},
		{
			name:      "mixed edge whitespace on both sides",
			action:    `"  login "`,
			eventType: `"` + escIdeoSp + `login` + escNBSP + `"`,
			want:      "login",
		},
		{
			name:      "tab and newline edges",
			action:    `"\tlogin\n"`,
			eventType: `"login"`,
			want:      "login",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"timestamp":"2026-01-02T00:00:00Z","action":` + tc.action + `,"event_type":` + tc.eventType + `}`
			results := runNormalize(t, input)
			if len(results) != 1 || results[0]["ok"] != true {
				t.Fatalf("equivalent action spellings must merge: %s -> %#v", input, results)
			}
			event := eventOf(t, results[0])
			if event["action"] != tc.want {
				t.Fatalf("merged action = %q, want trimmed text %q", event["action"], tc.want)
			}
			if _, exists := event["event_type"]; exists {
				t.Fatalf("event_type must not survive as its own field: %#v", event)
			}
			if extra, exists := event["extra"]; exists {
				t.Fatalf("event_type must not land in extra: %#v", extra)
			}
		})
	}
}

// Comparison stays case-sensitive: Login and login are different actions and
// the whole line fails as an action value conflict — not as an invalid
// character problem, and with no partial event.
func TestNormalizeActionCompareIsCaseSensitive(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"Login","event_type":"login"}`
	results := runNormalize(t, input)
	if len(results) != 1 || results[0]["ok"] != false {
		t.Fatalf("case-different actions must fail the line: %#v", results)
	}
	if _, exists := results[0]["event"]; exists {
		t.Fatalf("conflict must not emit a partial event: %#v", results[0])
	}
	msg, _ := results[0]["error"].(string)
	if !strings.Contains(msg, FieldAction) || !strings.Contains(strings.ToLower(msg), "conflict") {
		t.Fatalf("error must report an action value conflict, got %q", msg)
	}
	if strings.Contains(strings.ToLower(msg), "invalid") {
		t.Fatalf("a value conflict must not be misreported as invalid characters: %q", msg)
	}
}

// é as a single code point (U+00E9) and e followed by a combining acute
// accent (U+0301) render alike but are different actions: together they
// conflict, and each one alone is legal and keeps its own character
// composition in the output — no unification rewrite either way.
func TestNormalizeActionPrecomposedVersusCombiningAccent(t *testing.T) {
	precomposed := "caf\u00e9" // café with U+00E9
	decomposed := "café"      // café with e + U+0301

	input := `{"timestamp":"2026-01-02T00:00:00Z","action":` + jsonString(precomposed) +
		`,"event_type":"cafe` + escCombAc + `"}`
	results := runNormalize(t, input)
	if len(results) != 1 || results[0]["ok"] != false {
		t.Fatalf("precomposed and combining spellings are different actions and must conflict: %#v", results)
	}
	if _, exists := results[0]["event"]; exists {
		t.Fatalf("conflict must not emit a partial event: %#v", results[0])
	}
	msg, _ := results[0]["error"].(string)
	if !strings.Contains(msg, FieldAction) || !strings.Contains(strings.ToLower(msg), "conflict") {
		t.Fatalf("error must report an action value conflict, got %q", msg)
	}
	if strings.Contains(strings.ToLower(msg), "invalid") {
		t.Fatalf("a value conflict must not be misreported as invalid characters: %q", msg)
	}

	// Each spelling alone is a legal action and survives with its own code
	// points intact.
	for _, tc := range []struct {
		name string
		want string
	}{
		{"precomposed alone", precomposed},
		{"decomposed alone", decomposed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results := runNormalize(t, `{"timestamp":"2026-01-02T00:00:00Z","action":`+jsonString(tc.want)+`}`)
			if results[0]["ok"] != true {
				t.Fatalf("action %q alone must be legal: %#v", tc.want, results[0])
			}
			if got := eventOf(t, results[0])["action"]; got != tc.want {
				t.Fatalf("action composition must be preserved verbatim: got %q, want %q", got, tc.want)
			}
		})
	}
}

// Trimming only touches the edges: spaces inside the action are content, so
// "log in" never merges with "login", and a standalone "log in" keeps its
// interior space in the output.
func TestNormalizeActionInteriorSpacesAreContent(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"log in","event_type":"login"}`
	results := runNormalize(t, input)
	if results[0]["ok"] != false {
		t.Fatalf("interior space makes a different action and must conflict: %#v", results)
	}
	msg, _ := results[0]["error"].(string)
	if !strings.Contains(msg, FieldAction) || !strings.Contains(strings.ToLower(msg), "conflict") {
		t.Fatalf("error must report an action value conflict, got %q", msg)
	}

	results = runNormalize(t, `{"timestamp":"2026-01-02T00:00:00Z","action":"  log in  "}`)
	if results[0]["ok"] != true {
		t.Fatalf("interior space alone must be legal: %#v", results[0])
	}
	if got := eventOf(t, results[0])["action"]; got != "log in" {
		t.Fatalf("interior space must survive trimming, got %q", got)
	}
}

// U+200B zero width space is action content, not whitespace: at the edge it
// makes the alias a different action, and an action made of nothing else is
// still legal non-empty text.
func TestNormalizeActionZeroWidthSpaceIsContent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action string
	}{
		{"leading zero width space", `"` + escZWSP + `login"`},
		{"trailing zero width space", `"login` + escZWSP + `"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"timestamp":"2026-01-02T00:00:00Z","action":` + tc.action + `,"event_type":"login"}`
			results := runNormalize(t, input)
			if results[0]["ok"] != false {
				t.Fatalf("zero width space at the edge must conflict with the plain alias: %#v", results)
			}
			msg, _ := results[0]["error"].(string)
			if !strings.Contains(msg, FieldAction) || !strings.Contains(strings.ToLower(msg), "conflict") {
				t.Fatalf("error must report an action value conflict, got %q", msg)
			}
		})
	}

	t.Run("zero width space alone is a legal action", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"` + escZWSP + `"}`
		results := runNormalize(t, input)
		if results[0]["ok"] != true {
			t.Fatalf("a zero-width-space action is non-empty text and must succeed: %#v", results)
		}
		if got := eventOf(t, results[0])["action"]; got != "\u200b" {
			t.Fatalf("zero width space must survive as the action, got %q", got)
		}
	})
}

// An action field that trims to empty fails the whole line as an empty
// action, even when the other action field holds a perfectly legal value —
// the empty value is never ignored.
func TestNormalizeActionEmptyAfterTrimFailsWholeLine(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"event_type blank, action legal", `{"timestamp":"2026-01-02T00:00:00Z","action":"login","event_type":"  "}`},
		{"action blank, event_type legal", `{"timestamp":"2026-01-02T00:00:00Z","action":" ","event_type":"login"}`},
		{"event_type whitespace-only escapes", `{"timestamp":"2026-01-02T00:00:00Z","action":"login","event_type":"` + escNBSP + escIdeoSp + `"}`},
		{"action empty string", `{"timestamp":"2026-01-02T00:00:00Z","action":"","event_type":"login"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := runNormalize(t, tc.input)
			if len(results) != 1 || results[0]["ok"] != false {
				t.Fatalf("an action that trims to empty must fail the line: %s -> %#v", tc.input, results)
			}
			if _, exists := results[0]["event"]; exists {
				t.Fatalf("empty-action failure must not emit a partial event: %#v", results[0])
			}
			msg, _ := results[0]["error"].(string)
			if !strings.Contains(msg, FieldAction) || !strings.Contains(strings.ToLower(msg), "empty") {
				t.Fatalf("error must report an empty action, got %q", msg)
			}
			if strings.Contains(strings.ToLower(msg), "conflict") {
				t.Fatalf("an empty action is not a value conflict: %q", msg)
			}
		})
	}
}

// In a mixed stream, action conflicts and empty actions fail only their own
// records: the output keeps the original physical line numbers and a clear
// reason per failure, later legal logs still come out in input order, and the
// failure count matches the failed records exactly.
func TestNormalizeActionCompareMixedStream(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"first"}` + "\n" +
		"\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"Login","event_type":"login"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"ok","event_type":"  "}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","event_type":"last"}` + "\n"
	results := runNormalize(t, input) // runNormalize already pins failures == failed records
	if len(results) != 4 {
		t.Fatalf("expected 4 results for 5 physical lines, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("leading valid log must succeed on line 1: %#v", results[0])
	}
	if eventOf(t, results[0])["action"] != "first" {
		t.Fatalf("line 1 content must survive in order: %#v", results[0])
	}

	conflict := results[1]
	if conflict["line"] != float64(3) || conflict["ok"] != false {
		t.Fatalf("case conflict must fail on physical line 3: %#v", conflict)
	}
	if _, exists := conflict["event"]; exists {
		t.Fatalf("failed line must not carry an event: %#v", conflict)
	}
	msg, _ := conflict["error"].(string)
	if !strings.Contains(msg, FieldAction) || !strings.Contains(strings.ToLower(msg), "conflict") {
		t.Fatalf("line 3 error must report an action value conflict, got %q", msg)
	}

	empty := results[2]
	if empty["line"] != float64(4) || empty["ok"] != false {
		t.Fatalf("empty action must fail on physical line 4: %#v", empty)
	}
	if _, exists := empty["event"]; exists {
		t.Fatalf("failed line must not carry an event: %#v", empty)
	}
	msg, _ = empty["error"].(string)
	if !strings.Contains(msg, FieldAction) || !strings.Contains(strings.ToLower(msg), "empty") {
		t.Fatalf("line 4 error must report an empty action, got %q", msg)
	}

	if results[3]["line"] != float64(5) || results[3]["ok"] != true {
		t.Fatalf("trailing valid log must still succeed on line 5: %#v", results[3])
	}
	if eventOf(t, results[3])["action"] != "last" {
		t.Fatalf("line 5 content must survive in order: %#v", results[3])
	}
}

// The action trimming and comparison rules apply to the mapped fields only:
// unknown fields keep their text verbatim in extra — edge whitespace is not
// trimmed, case and accent composition are not compared against the action,
// and zero width spaces are left alone.
func TestNormalizeActionRulesDoNotTouchExtra(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"login","event_type":"login",` +
		`"note":" login ",` +
		`"detail":"Login",` +
		`"mood":"café",` +
		`"marker":"` + escZWSP + `login"}`
	results := runNormalize(t, input)
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("look-alike text in unknown fields must not affect the action: %#v", results)
	}
	event := eventOf(t, results[0])
	if event["action"] != "login" {
		t.Fatalf("action mismatch: %#v", event)
	}
	extra := extraOf(t, results[0])
	if extra["note"] != " login " {
		t.Fatalf("extra text must keep its edge whitespace, got %q", extra["note"])
	}
	if extra["detail"] != "Login" {
		t.Fatalf("extra text must not be case-compared with the action, got %q", extra["detail"])
	}
	if extra["mood"] != "café" {
		t.Fatalf("extra accent composition must be preserved verbatim, got %q", extra["mood"])
	}
	if extra["marker"] != "\u200blogin" {
		t.Fatalf("extra zero width space must be preserved verbatim, got %q", extra["marker"])
	}
}
