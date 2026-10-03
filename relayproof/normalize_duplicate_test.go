package relayproof

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

// escKey renders key as a JSON member name in which every rune is spelled via
// a lowercase unicode escape (with UTF-16 surrogate pairs above the BMP),
// e.g. escKey("action") is the nine JSON bytes backslash-u-0-0-6-1... that
// decode back to "action". Building escaped names at runtime keeps the test
// source independent of how inline escape text is transported.
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

// Regression coverage for the duplicate top-level field rule. Duplicates are
// judged by the JSON-decoded member name: a key written with a unicode escape
// is the same member as the literal spelling, so their coexistence fails the
// whole line even when both values are equal. The check runs before field
// validation and therefore must never degrade into a value-conflict error or
// let the later value win.
func TestNormalizeDuplicateKeysAfterJSONUnescaping(t *testing.T) {
	withRequired := func(members string) string {
		return `{"timestamp":"2026-01-02T00:00:00Z","action":"a",` + members + `}`
	}
	cases := []struct {
		name  string
		input string
		field string // decoded member name the error must identify
		diff  bool   // the repeated members carry different values
	}{
		{
			name:  "canonical name escaped then literal, equal values",
			input: withRequired(escKey("action") + `:"a","action":"a"`),
			field: FieldAction,
		},
		{
			name:  "canonical name literal then escaped, different values",
			input: withRequired(`"action":"a",` + escKey("action") + `:"b"`),
			field: FieldAction,
			diff:  true,
		},
		{
			name: "escaped timestamp duplicates literal timestamp",
			input: `{` + escKey("timestamp") + `:"2026-01-02T00:00:00Z",` +
				`"timestamp":"2026-01-02T00:00:00Z","action":"a"}`,
			field: FieldTimestamp,
		},
		{
			name:  "alias name literal and escaped",
			input: withRequired(`"time":"2026-01-02T00:00:00Z",` + escKey("time") + `:"2026-01-02T00:00:00Z"`),
			field: "time",
		},
		{
			name:  "unknown field escaped and literal, equal values",
			input: withRequired(escKey("foo") + `:1,"foo":1`),
			field: "foo",
		},
		{
			name:  "unknown field literal and escaped, different values",
			input: withRequired(`"foo":1,` + escKey("foo") + `:2`),
			field: "foo",
			diff:  true,
		},
		{
			name:  "both members escape-encoded, equal values",
			input: withRequired(escKey("action") + `:"a",` + escKey("action") + `:"a"`),
			field: FieldAction,
		},
		{
			name:  "Chinese member name versus its unicode escape",
			input: withRequired(escKey("事件") + `:1,"事件":2`),
			field: "事件",
			diff:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := runNormalize(t, tc.input)
			if len(results) != 1 || results[0]["ok"] != false {
				t.Fatalf("decoded-same-name members must fail the whole line: %s -> %#v", tc.input, results)
			}
			if _, exists := results[0]["event"]; exists {
				t.Fatalf("duplicate-field failure must not carry an event: %s -> %#v", tc.input, results[0])
			}
			msg, _ := results[0]["error"].(string)
			if !strings.Contains(strings.ToLower(msg), "duplicate") {
				t.Fatalf("error must report a duplicate field, got %q (input %s)", msg, tc.input)
			}
			if !strings.Contains(msg, tc.field) {
				t.Fatalf("error must identify the decoded field name %q, got %q", tc.field, msg)
			}
			if tc.diff && strings.Contains(strings.ToLower(msg), "conflict") {
				t.Fatalf("a decoded duplicate must not be reported as a value conflict: %q", msg)
			}
		})
	}
}

// A standard or alias field written only through escapes must normalize
// exactly like the literal spelling: same canonical event, same extra.
func TestNormalizeEscapedFieldNamesMatchLiteralSpelling(t *testing.T) {
	literal1 := `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}`
	escaped1 := `{` + escKey("timestamp") + `:"2026-01-02T00:00:00Z",` + escKey("action") + `:"a"}`

	literal2 := `{"time":"2026-01-02T08:04:05+08:00","src_ip":"::1","event_type":" login ","user":"alice"}`
	escaped2 := `{` + escKey("time") + `:"2026-01-02T08:04:05+08:00",` +
		escKey("src_ip") + `:"::1",` +
		escKey("event_type") + `:" login ",` +
		escKey("user") + `:"alice"}`

	for i, pair := range [][2]string{{literal1, escaped1}, {literal2, escaped2}} {
		literal := runNormalizeRaw(t, pair[0])
		escaped := runNormalizeRaw(t, pair[1])
		if literal != escaped {
			t.Fatalf("escaped spelling must produce the identical result.\nliteral: %s\nescaped: %s", literal, escaped)
		}
		results := runNormalize(t, pair[1])
		if results[0]["ok"] != true {
			t.Fatalf("escaped-only field names must succeed: %#v", results[0])
		}
		event := eventOf(t, results[0])
		if i == 0 {
			if event["timestamp"] != "2026-01-02T00:00:00Z" || event["action"] != "a" {
				t.Fatalf("escaped canonical names must map normally: %#v", event)
			}
			continue
		}
		if event["timestamp"] != "2026-01-02T00:04:05Z" || event["source_ip"] != "::1" || event["action"] != "login" {
			t.Fatalf("escaped aliases must map to canonical fields: %#v", event)
		}
		if extra, _ := event["extra"].(map[string]any); extra["user"] != "alice" {
			t.Fatalf("escaped unknown name must land in extra decoded, got %#v", event["extra"])
		}
	}
}

// Duplicate detection is scoped to decoded top-level members only. Objects
// nested inside unknown fields — including objects inside array elements and
// inside the input's own "extra" field — keep their repeated members with
// their original order and values; field-like text inside string values must
// not trigger the rule; members differing only by case or by embedded spaces
// stay distinct fields.
func TestNormalizeDuplicateRuleScope(t *testing.T) {
	t.Run("nested repeated members survive verbatim", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a",` +
			`"payload":{"a":1,"a":2},` +
			`"rows":[{"b":1,"b":2},{"c":1}],` +
			`"extra":{"inner":{"x":1,"x":2}}}`
		results := runNormalizeJSON(t, input)
		if results[0]["ok"] != true {
			t.Fatalf("repeated nested members must not fail the line: %#v", results[0])
		}
		raw := runNormalizeRaw(t, input)
		for _, want := range []string{
			`"payload":{"a":1,"a":2}`,
			`"rows":[{"b":1,"b":2},{"c":1}]`,
			`"extra":{"inner":{"x":1,"x":2}}`,
		} {
			if !strings.Contains(raw, want) {
				t.Fatalf("nested members must keep occurrence order and values\nwant %s\n got %s", want, raw)
			}
		}
		extra := extraOf(t, results[0])
		if _, ok := extra["extra"].(map[string]any); !ok {
			t.Fatalf("the input's own extra must stay an ordinary nested unknown field: %#v", extra["extra"])
		}
	})

	t.Run("field-like text inside string values is inert", func(t *testing.T) {
		// The inner text spells two "action" members, but it lives inside a
		// JSON string value; escaping an "i" inside that value changes only
		// the decoded string text.
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a",` +
			`"note":"{\"action\":1, \"action\":2}","invalue":"act` + "\\u0069" + `on twice"}`
		results := runNormalize(t, input)
		if results[0]["ok"] != true {
			t.Fatalf("text inside strings must not be parsed as members: %#v", results[0])
		}
		extra := extraOf(t, results[0])
		if extra["note"] != `{"action":1, "action":2}` {
			t.Fatalf("string value must be preserved verbatim: %v", extra["note"])
		}
		if extra["invalue"] != "action twice" {
			t.Fatalf("the escape inside a string value must decode as value text, got %v", extra["invalue"])
		}
	})

	t.Run("case and space variants are distinct fields", func(t *testing.T) {
		input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a",` +
			`"Foo":1,"foo":2," action":3,"foo bar":4}`
		results := runNormalize(t, input)
		if results[0]["ok"] != true {
			t.Fatalf("case/space-distinct members are not duplicates: %#v", results[0])
		}
		extra := extraOf(t, results[0])
		for _, key := range []string{"Foo", "foo", " action", "foo bar"} {
			if _, ok := extra[key]; !ok {
				t.Fatalf("distinct member %q must be kept in extra: %#v", key, extra)
			}
		}
		if eventOf(t, results[0])["action"] != "a" {
			t.Fatalf("the spaced variant must not touch the mapped action field: %#v", results[0])
		}
	})
}

// A canonical name and its alias are different JSON members, never duplicate
// keys: equal values still merge, and different values are still reported as
// a field conflict (including when one name is escape-encoded).
func TestNormalizeCanonicalAndAliasAreNotDuplicateKeys(t *testing.T) {
	consistent := []string{
		`{"timestamp":"2026-01-02T00:00:00Z","time":"2026-01-02T00:00:00Z","action":"a"}`,
		`{` + escKey("timestamp") + `:"2026-01-02T00:00:00Z","time":"2026-01-02T00:00:00Z","action":"a"}`,
		`{"source_ip":"1.2.3.4","src_ip":"1.2.3.4","timestamp":"2026-01-02T00:00:00Z","action":"a"}`,
		`{"action":"login","event_type":"login","timestamp":"2026-01-02T00:00:00Z"}`,
	}
	for _, in := range consistent {
		results := runNormalize(t, in)
		if results[0]["ok"] != true {
			t.Fatalf("canonical+alias with equal values must merge, not duplicate-fail: %s -> %#v", in, results[0])
		}
	}

	conflicts := []struct {
		input string
		field string
	}{
		{`{"timestamp":"2026-01-02T00:00:00Z","time":"2026-01-02T00:05:00Z","action":"a"}`, FieldTimestamp},
		{`{` + escKey("timestamp") + `:"2026-01-02T00:00:00Z","time":"2026-01-02T00:05:00Z","action":"a"}`, FieldTimestamp},
		{`{"source_ip":"1.2.3.4","src_ip":"5.6.7.8","timestamp":"2026-01-02T00:00:00Z","action":"a"}`, FieldSourceIP},
		{`{"action":"login","event_type":"logout","timestamp":"2026-01-02T00:00:00Z"}`, FieldAction},
	}
	for _, tc := range conflicts {
		results := runNormalize(t, tc.input)
		if results[0]["ok"] != false {
			t.Fatalf("canonical+alias with different values must fail: %s", tc.input)
		}
		msg, _ := results[0]["error"].(string)
		if !strings.Contains(strings.ToLower(msg), "conflict") {
			t.Fatalf("different values must be a value conflict, got %q (%s)", msg, tc.input)
		}
		if strings.Contains(strings.ToLower(msg), "duplicate") {
			t.Fatalf("canonical+alias must never be called duplicate keys: %q", msg)
		}
		if !strings.Contains(msg, tc.field) {
			t.Fatalf("conflict error must name %q, got %q", tc.field, msg)
		}
	}
}

// In a mixed stream, one duplicate-key line fails alone: the surrounding
// legal lines still come out in input order, blank lines only advance the
// physical line counter, the failure keeps its line number with no event, and
// exactly that one line is counted.
func TestNormalizeDuplicateKeyMixedStream(t *testing.T) {
	dupLine := `{"timestamp":"2026-01-02T00:00:00Z","action":"a",` + escKey("action") + `:"b"}`
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"first"}` + "\n" +
		"\n" +
		dupLine + "\n" +
		`{"timestamp":"2026-01-02T00:00:02Z","action":"last"}` + "\n"
	results := runNormalize(t, input)
	if len(results) != 3 {
		t.Fatalf("expected 3 results for 4 physical lines, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("leading valid log must succeed on line 1: %#v", results[0])
	}
	if eventOf(t, results[0])["action"] != "first" {
		t.Fatalf("line 1 content must survive in order: %#v", results[0])
	}
	bad := results[1]
	if bad["line"] != float64(3) || bad["ok"] != false {
		t.Fatalf("duplicate log must fail on physical line 3: %#v", bad)
	}
	if _, exists := bad["event"]; exists {
		t.Fatalf("failed line must not carry an event: %#v", bad)
	}
	msg, _ := bad["error"].(string)
	if !strings.Contains(strings.ToLower(msg), "duplicate") || !strings.Contains(msg, FieldAction) {
		t.Fatalf("error must identify the duplicate %q, got %q", FieldAction, msg)
	}
	if strings.Contains(strings.ToLower(msg), "conflict") {
		t.Fatalf("different values must still be a duplicate error, got %q", msg)
	}
	if results[2]["line"] != float64(4) || results[2]["ok"] != true {
		t.Fatalf("trailing valid log must still succeed on line 4: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "last" {
		t.Fatalf("line 4 content must survive in order: %#v", results[2])
	}
}
