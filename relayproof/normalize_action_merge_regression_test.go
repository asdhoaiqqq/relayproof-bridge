package relayproof

// Regression coverage for how detection rules read the normalized action when
// one log supplies both action keys ("action" and its alias "event_type").
// Equality is judged only after JSON string decoding and after trimming
// surrounding Unicode whitespace from each side: different JSON spellings of
// the same character merge, while merely look-alike text stays distinct. The
// comparison is exact (case-sensitive, composition-sensitive) and interior
// characters are never trimmed. Every failing line is an isolated per-line
// ok:false record; text in unmapped fields is never subjected to the action
// trim or comparison rules.

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Characters under test, built from code points so the source itself stays
// pure ASCII.
var (
	grinningFace    = string(rune(0x1F600))      // 😀
	eAcute          = string(rune(0x00E9))       // é: single precomposed rune
	combiningEAcute = "e" + string(rune(0x0301)) // e followed by U+0301 combining acute
	zeroWidthSpace  = string(rune(0x200B))       // zero-width space: content, never whitespace-trimmed
)

// pairedEmojiToken is a JSON string literal spelling the grinning face via a
// legal surrogate-pair escape (rather than the literal astral character).
var pairedEmojiToken = "\"" + escGrinning + "\""

const actionMergeTSLiteral = `"2026-01-02T00:00:00Z"`

// dualActionLine places two already-complete JSON string tokens under the two
// action keys on one otherwise-valid log line.
func dualActionLine(actionToken, eventTypeToken string) string {
	return `{"timestamp":` + actionMergeTSLiteral + `,"action":` + actionToken +
		`,"event_type":` + eventTypeToken + `}`
}

// dualActionOrderings returns every member ordering for a line that carries
// the timestamp plus both action keys, so canonical/alias position and input
// order are part of the asserted surface.
func dualActionOrderings(actionToken, eventTypeToken string) []string {
	return dualOrderings(
		kv{key: FieldAction, val: actionToken},
		kv{key: "event_type", val: eventTypeToken},
		kv{key: FieldTimestamp, val: actionMergeTSLiteral},
	)
}

// TestNormalizeActionEquivalentTextMerges pins the spellings that must denote
// one action: a literal astral character and its surrogate-pair escape decode
// to the same rune, and ordinary/no-break/ideographic spaces around the text
// are trimmed before comparison. The merged event keeps exactly one action
// (the trimmed full text), event_type never lands in extra, and rearranging
// members or swapping which spelling sits under which key is byte-invariant.
func TestNormalizeActionEquivalentTextMerges(t *testing.T) {
	cases := []struct {
		name        string
		actionToken string
		aliasToken  string
		want        string
	}{
		{
			name:        "emoji literal versus surrogate-pair escape",
			actionToken: jsonString(grinningFace),
			aliasToken:  pairedEmojiToken,
			want:        grinningFace,
		},
		{
			name:        "surrogate-pair escape versus emoji literal",
			actionToken: pairedEmojiToken,
			aliasToken:  jsonString(grinningFace),
			want:        grinningFace,
		},
		{
			name:        "ordinary spaces around one spelling",
			actionToken: jsonString(" login "),
			aliasToken:  jsonString("login"),
			want:        "login",
		},
		{
			name:        "ordinary spaces swapped to the other key",
			actionToken: jsonString("login"),
			aliasToken:  jsonString(" login "),
			want:        "login",
		},
		{
			name:        "no-break spaces around one spelling",
			actionToken: jsonString(noBreakSpace + "login" + noBreakSpace),
			aliasToken:  jsonString("login"),
			want:        "login",
		},
		{
			name:        "ideographic spaces around one spelling",
			actionToken: jsonString(ideographicSpace + "login" + ideographicSpace),
			aliasToken:  jsonString("login"),
			want:        "login",
		},
		{
			name:        "mixed special edges trimmed to the shared text",
			actionToken: jsonString(noBreakSpace + "x" + ideographicSpace),
			aliasToken:  jsonString(ideographicSpace + "x" + noBreakSpace),
			want:        "x",
		},
		{
			name:        "interior spaces survive trimming when both spellings match",
			actionToken: jsonString("  log in  "),
			aliasToken:  jsonString("log in"),
			want:        "log in",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shared := assertOrderInvariant(t, dualActionOrderings(tc.actionToken, tc.aliasToken), true, nil)
			event := eventOf(t, shared)
			if got := event[FieldAction]; got != tc.want {
				t.Fatalf("merged action = %q, want %q (event %#v)", got, tc.want, event)
			}
			if _, exists := event["extra"]; exists {
				t.Fatalf("merged event_type must not reappear in extra: %#v", event)
			}
			if _, exists := event["event_type"]; exists {
				t.Fatalf("only the canonical action key must survive: %#v", event)
			}
		})
	}
}

// TestNormalizeActionComparisonIsCaseSensitive: values differing only in case
// are different actions. Login/login must fail the whole line as a value
// conflict, in either key placement, never merge into one of the casings.
func TestNormalizeActionComparisonIsCaseSensitive(t *testing.T) {
	for _, pair := range [][2]string{
		{jsonString("Login"), jsonString("login")},
		{jsonString("login"), jsonString("Login")},
	} {
		shared := assertOrderInvariant(
			t, dualActionOrderings(pair[0], pair[1]), false,
			[]string{FieldAction, "conflicting values", "Login", "login"},
		)
		if _, exists := shared["event"]; exists {
			t.Fatalf("case conflict must not carry a partial event: %#v", shared)
		}
	}
}

// TestNormalizeActionCompositionIsContent distinguishes canonical text from a
// look-alike decomposition. Precomposed é (U+00E9) and "e" + combining acute
// (U+0301) render almost identically but are different actions: together they
// conflict rather than merge, and the failure is a value conflict — never an
// illegal-character error. Supplied alone, each spelling is legal and must
// survive with its exact rune composition; normalization never rewrites one
// form into the other.
func TestNormalizeActionCompositionIsContent(t *testing.T) {
	if eAcute == combiningEAcute {
		t.Fatalf("test setup: the two spellings must be distinct strings")
	}
	if utf8.RuneCountInString(eAcute) != 1 || utf8.RuneCountInString(combiningEAcute) != 2 {
		t.Fatalf("test setup: expected 1 vs 2 runes, got %d vs %d",
			utf8.RuneCountInString(eAcute), utf8.RuneCountInString(combiningEAcute))
	}

	t.Run("look-alike compositions conflict together", func(t *testing.T) {
		for _, pair := range [][2]string{
			{jsonString(eAcute), jsonString(combiningEAcute)},
			{jsonString(combiningEAcute), jsonString(eAcute)},
		} {
			shared := assertOrderInvariant(
				t, dualActionOrderings(pair[0], pair[1]), false,
				[]string{FieldAction, "conflicting values"},
			)
			msg, _ := shared["error"].(string)
			for _, bad := range []string{"invalid UTF-8", "surrogate", "illegal", "invalid character"} {
				if strings.Contains(msg, bad) {
					t.Fatalf("two legal spellings must not be reported as %q: %q", bad, msg)
				}
			}
		}
	})

	t.Run("each spelling alone keeps its rune composition", func(t *testing.T) {
		alone := []struct {
			name  string
			input string
			want  string
		}{
			{"precomposed under canonical key",
				`{"timestamp":` + actionMergeTSLiteral + `,"action":` + jsonString(eAcute) + `}`, eAcute},
			{"precomposed under alias key",
				`{"timestamp":` + actionMergeTSLiteral + `,"event_type":` + jsonString(eAcute) + `}`, eAcute},
			{"decomposed under canonical key",
				`{"timestamp":` + actionMergeTSLiteral + `,"action":` + jsonString(combiningEAcute) + `}`, combiningEAcute},
			{"decomposed under alias key",
				`{"timestamp":` + actionMergeTSLiteral + `,"event_type":` + jsonString(combiningEAcute) + `}`, combiningEAcute},
		}
		for _, tc := range alone {
			t.Run(tc.name, func(t *testing.T) {
				results := runNormalize(t, tc.input)
				if results[0]["ok"] != true {
					t.Fatalf("legal spelling must succeed on its own: %#v", results[0])
				}
				got := eventOf(t, results[0])[FieldAction].(string)
				if got != tc.want {
					t.Fatalf("action composition rewritten: got %q want %q", got, tc.want)
				}
				if got == eAcute && tc.want == combiningEAcute || got == combiningEAcute && tc.want == eAcute {
					t.Fatalf("output must not cross the two compositions: got %q want %q", got, tc.want)
				}
			})
		}
	})
}

// TestNormalizeActionInteriorCharactersAreContent: trimming applies only at
// the edges. Spaces (and zero-width spaces) in the middle are part of the
// action and are not deleted before comparison. A zero-width space at an edge
// is likewise content — Unicode whitespace trimming does not remove it — so it
// conflicts with the alias lacking it, while matching ZWSP-bearing spellings
// merge with the ZWSP retained.
func TestNormalizeActionInteriorCharactersAreContent(t *testing.T) {
	conflicts := []struct {
		name string
		a, b string
	}{
		{"interior space versus no space", jsonString("log in"), jsonString("login")},
		{"interior zero-width space versus none", jsonString("log" + zeroWidthSpace + "in"), jsonString("login")},
		{"leading zero-width space not trimmed", jsonString(zeroWidthSpace + "login"), jsonString("login")},
		{"trailing zero-width space not trimmed", jsonString("login" + zeroWidthSpace), jsonString("login")},
	}
	for _, tc := range conflicts {
		t.Run(tc.name, func(t *testing.T) {
			shared := assertOrderInvariant(
				t, dualActionOrderings(tc.a, tc.b), false,
				[]string{FieldAction, "conflicting values"},
			)
			if _, exists := shared["event"]; exists {
				t.Fatalf("content-distinct actions must not emit an event: %#v", shared)
			}
		})
	}

	t.Run("matching zero-width space survives a merge", func(t *testing.T) {
		want := zeroWidthSpace + "login"
		shared := assertOrderInvariant(
			t, dualActionOrderings(jsonString(want), jsonString(" "+want+" ")), true, nil,
		)
		if got := eventOf(t, shared)[FieldAction]; got != want {
			t.Fatalf("zero-width space is content and must survive, got %q want %q", got, want)
		}
	})

	t.Run("a zero-width-space-only action is legal non-empty text", func(t *testing.T) {
		for _, key := range []string{FieldAction, "event_type"} {
			input := `{"timestamp":` + actionMergeTSLiteral + `,"` + key + `":` + jsonString(zeroWidthSpace) + `}`
			results := runNormalize(t, input)
			if results[0]["ok"] != true {
				t.Fatalf("ZWSP-only action must be a valid non-empty action: %#v", results[0])
			}
			got := eventOf(t, results[0])[FieldAction].(string)
			if got != zeroWidthSpace || utf8.RuneCountInString(got) != 1 {
				t.Fatalf("ZWSP-only action must round-trip as one rune, got %q", got)
			}
		}
	})
}

// TestNormalizeActionEmptyAfterTrimFailsWholeLine: if either action field is
// empty once its surrounding whitespace is removed, the whole line fails as
// an empty action — even when the other field carries a legal value. It is
// never dropped to let the legal side win, and it is not demoted to a missing
// field or reported as a conflict.
func TestNormalizeActionEmptyAfterTrimFailsWholeLine(t *testing.T) {
	empties := []string{
		jsonString(""),
		jsonString("   "),
		jsonString("\t\n "),
		jsonString(noBreakSpace),
		jsonString(ideographicSpace),
		jsonString(noBreakSpace + ideographicSpace + " "),
	}
	for _, empty := range empties {
		for _, pair := range [][2]string{
			{empty, jsonString("login")},
			{jsonString("login"), empty},
		} {
			shared := assertOrderInvariant(
				t, dualActionOrderings(pair[0], pair[1]), false,
				[]string{FieldAction, "action must not be empty"},
			)
			msg, _ := shared["error"].(string)
			if strings.Contains(msg, "conflict") {
				t.Fatalf("an empty action is an empty-value error, not a conflict: %q", msg)
			}
		}
	}

	t.Run("whitespace-only alias provided alone fails as empty, not missing", func(t *testing.T) {
		input := `{"timestamp":` + actionMergeTSLiteral + `,"event_type":` + jsonString("   ") + `}`
		results := runNormalize(t, input)
		if results[0]["ok"] != false {
			t.Fatalf("whitespace-only event_type must fail: %#v", results[0])
		}
		msg, _ := results[0]["error"].(string)
		if !strings.Contains(msg, FieldAction) || !strings.Contains(msg, "action must not be empty") {
			t.Fatalf("failure must name an empty %q, got %q", FieldAction, msg)
		}
		if strings.Contains(msg, "missing") {
			t.Fatalf("a provided empty alias must not be treated as an omission: %q", msg)
		}
	})
}

// TestNormalizeActionFailuresAreIsolatedInStream drives several action
// problems through one batch interleaved with valid logs and a blank line.
// Each bad record fails alone with its original physical line number and a
// specific reason; the legal logs before and after still process in order, and
// the failure count equals the number of failing records.
func TestNormalizeActionFailuresAreIsolatedInStream(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":` + actionMergeTSLiteral + `,"action":"first"}`,
		"", // blank: advances the physical line counter, emits nothing
		dualActionLine(jsonString("Login"), jsonString("login")),
		dualActionLine(jsonString("   "), jsonString("login")),
		dualActionLine(jsonString(eAcute), jsonString(combiningEAcute)),
		dualActionLine(jsonString(zeroWidthSpace+"go"), jsonString("go")),
		`{"timestamp":` + actionMergeTSLiteral + `,"action":"last"}`,
	}, "\n")

	results := runNormalize(t, input) // also asserts emitted failures == returned count
	if len(results) != 6 {
		t.Fatalf("expected 6 records for 7 physical lines (one blank), got %d: %#v", len(results), results)
	}

	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must succeed: %#v", results[0])
	}
	if eventOf(t, results[0])[FieldAction] != "first" {
		t.Fatalf("line 1 action must survive in order: %#v", results[0])
	}

	type expect struct {
		line   float64
		substr string
		forbid string
	}
	wants := []expect{
		{3, "conflicting values", ""}, // case difference
		{4, "action must not be empty", "conflict"},
		{5, "conflicting values", "invalid"}, // look-alike composition, not an illegal character
		{6, "conflicting values", ""},        // edge zero-width space
	}
	for i, w := range wants {
		r := results[i+1]
		if r["line"] != w.line || r["ok"] != false {
			t.Fatalf("record %d must be a failure on physical line %v: %#v", i+1, w.line, r)
		}
		if _, exists := r["event"]; exists {
			t.Fatalf("line %v failure must not carry a partial event: %#v", w.line, r)
		}
		msg, _ := r["error"].(string)
		if !strings.Contains(msg, FieldAction) || !strings.Contains(msg, w.substr) {
			t.Fatalf("line %v error must name %q and contain %q, got %q", w.line, FieldAction, w.substr, msg)
		}
		if w.forbid != "" && strings.Contains(msg, w.forbid) {
			t.Fatalf("line %v error must not mention %q: %q", w.line, w.forbid, msg)
		}
	}

	last := results[5]
	if last["line"] != float64(7) || last["ok"] != true {
		t.Fatalf("legal line 7 must still be processed after the failures: %#v", last)
	}
	if eventOf(t, last)[FieldAction] != "last" {
		t.Fatalf("line 7 action must survive in input order: %#v", last)
	}
}

// TestNormalizeUnknownFieldTextSkipsActionRules: look-alike text living in an
// unmapped field (a plain unknown key or the input's own extra) is preserved
// verbatim under the existing extra rules. It is never trimmed like an action
// or compared against the action, and the merged event_type does not appear
// there.
func TestNormalizeUnknownFieldTextSkipsActionRules(t *testing.T) {
	note := zeroWidthSpace + "login"
	label := noBreakSpace + "x" + ideographicSpace
	raw := "  " + zeroWidthSpace + " "
	input := `{"timestamp":` + actionMergeTSLiteral +
		`,"action":` + jsonString(" login ") +
		`,"event_type":` + jsonString("login") +
		`,"note":` + jsonString(note) +
		`,"label":` + jsonString(label) +
		`,"extra":{"raw":` + jsonString(raw) + `}}`

	results := runNormalize(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("unknown-field text must not disturb a valid merge: %#v", results[0])
	}
	event := eventOf(t, results[0])
	if event[FieldAction] != "login" {
		t.Fatalf("action must merge and trim to %q, got %q", "login", event[FieldAction])
	}
	if _, exists := event["event_type"]; exists {
		t.Fatalf("merged alias must not be copied into the event: %#v", event)
	}
	extra := extraOf(t, results[0])
	if extra["note"] != note {
		t.Fatalf("edge zero-width space in unknown text must be preserved, got %q", extra["note"])
	}
	if extra["label"] != label {
		t.Fatalf("special edge spaces in unknown text must be preserved, got %q", extra["label"])
	}
	inner, ok := extra["extra"].(map[string]any)
	if !ok {
		t.Fatalf("input extra must stay a nested unknown field: %#v", extra["extra"])
	}
	if inner["raw"] != raw {
		t.Fatalf("whitespace/ZWSP-only unknown text must be kept verbatim, got %q", inner["raw"])
	}
}
