package relayproof

import (
	"reflect"
	"strings"
	"testing"
)

// Regression coverage for duplicate top-level field detection. Duplicates
// are judged by the JSON-decoded field name, so escaped spellings such as
// "act" + bs + "u0069on" are the same key as "action"; the rule applies
// equally to canonical names, aliases, and unknown fields (including
// non-ASCII ones). The check is structural and runs before field validation:
// equal values still fail, differing values are still reported as duplicates
// (never as a value conflict or as the later value winning), and a mistyped
// second occurrence does not turn the error into a type error.

const dupRegTimestamp = "2026-01-02T00:00:00Z"

// bs is a single backslash. The esc* constants below are literal JSON
// unicode escape sequences assembled from pieces, so this source never
// spells a complete escape that some layer could decode on the way to disk.
const bs = `\`

const (
	escTimestamp = bs + "u0074imestamp"        // decodes to "timestamp"
	escSourceIP  = bs + "u0073ource_ip"        // decodes to "source_ip"
	escAction    = "act" + bs + "u0069on"      // decodes to "action"
	escTime      = "t" + bs + "u0069me"        // decodes to "time"
	escSrcIP     = "src_i" + bs + "u0070"      // decodes to "src_ip"
	escEventType = bs + "u0065vent_type"       // decodes to "event_type"
	escFoo       = bs + "u0066oo"              // decodes to "foo"
	escActionCN  = bs + "u52a8" + bs + "u4f5c" // decodes to "动作"
)

func TestNormalizeDuplicateTopLevelKeysUseDecodedName(t *testing.T) {
	cases := []struct {
		name  string
		input string
		// field is the decoded key name that must be identifiable in the
		// error message regardless of which spelling carried the escape.
		field string
	}{
		{
			name: "canonical action: plain then escaped, equal values",
			input: `{"timestamp":"` + dupRegTimestamp + `","action":"a","` +
				escAction + `":"a"}`,
			field: FieldAction,
		},
		{
			name: "canonical action: escaped then plain, equal values",
			input: `{"timestamp":"` + dupRegTimestamp + `","` + escAction +
				`":"a","action":"a"}`,
			field: FieldAction,
		},
		{
			name: "canonical action: plain then escaped, different values",
			input: `{"timestamp":"` + dupRegTimestamp + `","action":"a","` +
				escAction + `":"b"}`,
			field: FieldAction,
		},
		{
			name: "canonical action: escaped then plain, different values",
			input: `{"timestamp":"` + dupRegTimestamp + `","` + escAction +
				`":"a","action":"b"}`,
			field: FieldAction,
		},
		{
			name: "canonical action: both occurrences escaped, different values",
			input: `{"timestamp":"` + dupRegTimestamp + `","` + escAction +
				`":"a","` + escAction + `":"b"}`,
			field: FieldAction,
		},
		{
			name: "canonical timestamp: plain duplicates escaped",
			input: `{"timestamp":"` + dupRegTimestamp + `","` + escTimestamp +
				`":"` + dupRegTimestamp + `","action":"a"}`,
			field: FieldTimestamp,
		},
		{
			name: "canonical source_ip: plain duplicates escaped, equal values",
			input: `{"timestamp":"` + dupRegTimestamp + `","action":"a","source_ip":"127.0.0.1","` +
				escSourceIP + `":"127.0.0.1"}`,
			field: FieldSourceIP,
		},
		{
			name: "alias time: plain duplicates escaped, equal values",
			input: `{"time":"` + dupRegTimestamp + `","` + escTime +
				`":"` + dupRegTimestamp + `","action":"a"}`,
			field: "time",
		},
		{
			name: "alias event_type: escaped duplicates plain, different values",
			input: `{"timestamp":"` + dupRegTimestamp + `","event_type":"a","` +
				escEventType + `":"b"}`,
			field: "event_type",
		},
		{
			name: "alias src_ip: plain duplicates escaped",
			input: `{"timestamp":"` + dupRegTimestamp + `","action":"a","src_ip":"127.0.0.1","` +
				escSrcIP + `":"127.0.0.1"}`,
			field: "src_ip",
		},
		{
			name: "unknown field: plain duplicates escaped, different values",
			input: `{"timestamp":"` + dupRegTimestamp + `","action":"a","foo":1,"` +
				escFoo + `":2}`,
			field: "foo",
		},
		{
			name: "unknown field: both occurrences escaped",
			input: `{"timestamp":"` + dupRegTimestamp + `","action":"a","` +
				escFoo + `":1,"` + escFoo + `":2}`,
			field: "foo",
		},
		{
			name: "non-ASCII unknown field: Chinese name duplicates its unicode escape",
			input: `{"timestamp":"` + dupRegTimestamp + `","action":"a","动作":1,"` +
				escActionCN + `":2}`,
			field: "动作",
		},
		{
			name: "non-ASCII unknown field: escape duplicates the Chinese name",
			input: `{"timestamp":"` + dupRegTimestamp + `","action":"a","` +
				escActionCN + `":1,"动作":2}`,
			field: "动作",
		},
		{
			// Structural duplicate detection precedes value validation: the
			// second occurrence having the wrong type must still surface as
			// the duplicate, not as a type error or a later-value overwrite.
			name: "duplicate reported before the second value's type is checked",
			input: `{"timestamp":"` + dupRegTimestamp + `","action":"a","` +
				escAction + `":1}`,
			field: FieldAction,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := NormalizeLine(42, []byte(tc.input))
			if result.OK {
				t.Fatalf("decoded-name duplicate must fail the whole line: %s", tc.input)
			}
			if result.Line != 42 {
				t.Fatalf("failure must keep the input line number, got %d", result.Line)
			}
			if result.Event != nil {
				t.Fatalf("duplicate failure must not carry an event, got %#v", result.Event)
			}
			msg := result.Error
			if !strings.Contains(strings.ToLower(msg), "duplicate") {
				t.Fatalf("error must identify a duplicate field, got %q", msg)
			}
			if !strings.Contains(msg, `"`+tc.field+`"`) {
				t.Fatalf("error must name the decoded field %q, got %q", tc.field, msg)
			}
			if strings.Contains(strings.ToLower(msg), "conflict") {
				t.Fatalf("duplicate keys must not be reported as a value conflict: %q", msg)
			}
		})
	}
}

// A JSON-escaped spelling used on its own is just the same field name after
// decoding: canonical names map to event fields, aliases map to their
// canonical fields, and unknown fields land in extra under the decoded name.
func TestNormalizeEscapedFieldNamesAloneBehaveLikePlain(t *testing.T) {
	pairs := []struct {
		name    string
		plain   string
		escaped string
	}{
		{
			name:  "escaped canonical timestamp and action",
			plain: `{"timestamp":"2026-01-02T08:04:05+08:00","action":"a"}`,
			escaped: `{"` + escTimestamp + `":"2026-01-02T08:04:05+08:00","` +
				escAction + `":"a"}`,
		},
		{
			name:    "escaped time alias",
			plain:   `{"time":"` + dupRegTimestamp + `","action":"a"}`,
			escaped: `{"` + escTime + `":"` + dupRegTimestamp + `","action":"a"}`,
		},
		{
			name:  "escaped src_ip alias",
			plain: `{"timestamp":"` + dupRegTimestamp + `","action":"a","src_ip":"127.0.0.1"}`,
			escaped: `{"timestamp":"` + dupRegTimestamp + `","action":"a","` +
				escSrcIP + `":"127.0.0.1"}`,
		},
		{
			name:  "escaped event_type alias",
			plain: `{"timestamp":"` + dupRegTimestamp + `","event_type":"login"}`,
			escaped: `{"timestamp":"` + dupRegTimestamp + `","` +
				escEventType + `":"login"}`,
		},
	}
	for _, tc := range pairs {
		t.Run(tc.name, func(t *testing.T) {
			plain := NormalizeLine(1, []byte(tc.plain))
			escaped := NormalizeLine(1, []byte(tc.escaped))
			if !plain.OK || !escaped.OK {
				t.Fatalf("both spellings must succeed: plain=%#v escaped=%#v", plain, escaped)
			}
			if !reflect.DeepEqual(escaped.Event, plain.Event) {
				t.Fatalf("escaped spelling must yield the same event:\nplain:   %#v\nescaped: %#v", plain.Event, escaped.Event)
			}
		})
	}

	// An escaped unknown name reaches extra under its decoded name; so does a
	// non-ASCII name written through unicode escapes.
	unknown := runNormalize(t, `{"timestamp":"`+dupRegTimestamp+`","action":"a","`+
		escFoo+`":1,"`+escActionCN+`":"x"}`)
	if unknown[0]["ok"] != true {
		t.Fatalf("solo escaped unknown fields must succeed: %#v", unknown[0])
	}
	extra := extraOf(t, unknown[0])
	if extra["foo"] != float64(1) {
		t.Fatalf("escaped unknown field must be stored under decoded name foo, got %#v", extra)
	}
	if extra["动作"] != "x" {
		t.Fatalf("escaped Chinese field must be stored under decoded name, got %#v", extra)
	}
}

// Duplicate detection is scoped to decoded top-level keys only. Objects
// nested inside unknown fields — including elements of nested arrays and the
// input's own "extra" — keep their repeated members verbatim: both
// occurrences and their input order reach the output extra, unmerged.
func TestNormalizeNestedDuplicateMembersStayInExtra(t *testing.T) {
	cases := []struct {
		name         string
		input        string
		wantFragment string
		// first/second are the two repeated member's serialized pairs, used
		// to prove both occurrences survive exactly once, unmerged.
		first  string
		second string
	}{
		{
			name: "duplicate members in nested unknown object",
			input: `{"timestamp":"` + dupRegTimestamp + `","action":"a",` +
				`"payload":{"a":1,"a":2,"b":3}}`,
			wantFragment: `"payload":{"a":1,"a":2,"b":3}`,
			first:        `"a":1`,
			second:       `"a":2`,
		},
		{
			name: "duplicate members in array element objects",
			input: `{"timestamp":"` + dupRegTimestamp + `","action":"a",` +
				`"items":[{"id":1,"id":2},{"id":3}]}`,
			wantFragment: `"items":[{"id":1,"id":2},{"id":3}]`,
			first:        `"id":1`,
			second:       `"id":2`,
		},
		{
			name: "duplicate members in the input-provided extra field",
			input: `{"timestamp":"` + dupRegTimestamp + `","action":"a",` +
				`"extra":{"a":1,"a":2}}`,
			wantFragment: `"extra":{"extra":{"a":1,"a":2}}`,
			first:        `"a":1`,
			second:       `"a":2`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := runNormalize(t, tc.input)
			if results[0]["ok"] != true {
				t.Fatalf("nested duplicate members must not fail the line: %#v", results[0])
			}
			raw := runNormalizeRaw(t, tc.input)
			if !strings.Contains(raw, tc.wantFragment) {
				t.Fatalf("nested members must survive verbatim with input order:\nwant fragment %s\ngot %s", tc.wantFragment, raw)
			}
			// Both occurrences must survive independently: nothing merged
			// the pair or dropped one of them.
			if strings.Count(raw, tc.first) != 1 || strings.Count(raw, tc.second) != 1 {
				t.Fatalf("each nested member occurrence must appear exactly once: %s", raw)
			}
		})
	}
}

// Field-name-like text living inside JSON string values is data, not
// structure: doubled field-looking text inside strings never triggers
// duplicate detection.
func TestNormalizeFieldLikeTextInsideStringsIsIgnored(t *testing.T) {
	input := `{"timestamp":"` + dupRegTimestamp + `","action":"a",` +
		`"note":"{\"action\":1,\"action\":2}",` +
		`"also":"action"}`
	results := runNormalize(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("field-like text inside strings must not be treated as keys: %#v", results[0])
	}
	extra := extraOf(t, results[0])
	if got := extra["note"]; got != `{"action":1,"action":2}` {
		t.Fatalf("string value must be preserved verbatim, got %v", got)
	}
	if got := extra["also"]; got != "action" {
		t.Fatalf("string value spelling a field name must stay a string, got %v", got)
	}
}

// Only decoded-identical names collide. Case differences and names carrying
// spaces remain distinct unknown fields and all reach extra.
func TestNormalizeDistinctNamesStayDistinct(t *testing.T) {
	input := `{"timestamp":"` + dupRegTimestamp + `","action":"a",` +
		`"Action":"b","foo":1,"foo ":2}`
	results := runNormalize(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("case- and space-distinct names are different fields: %#v", results[0])
	}
	extra := extraOf(t, results[0])
	if extra["Action"] != "b" {
		t.Fatalf("Action must stay distinct from action, got %#v", extra)
	}
	if extra["foo"] != float64(1) {
		t.Fatalf("foo must be preserved, got %#v", extra)
	}
	if extra["foo "] != float64(2) {
		t.Fatalf("trailing-space name must be a distinct field, got %#v", extra)
	}
	if len(extra) != 3 {
		t.Fatalf("expected exactly the three distinct unknown fields, got %#v", extra)
	}
}

// A canonical name and its alias are different JSON keys by design: they
// must never be flagged as duplicates. Consistent normalized values merge
// (including when one spelling uses escapes); divergent values keep their
// existing field-conflict failure.
func TestNormalizeCanonicalAndAliasAreNotDuplicateKeys(t *testing.T) {
	consistent := []string{
		`{"timestamp":"` + dupRegTimestamp + `","time":"` + dupRegTimestamp + `","action":"a"}`,
		`{"timestamp":"` + dupRegTimestamp + `","` + escTime + `":"` + dupRegTimestamp + `","action":"a"}`,
		`{"timestamp":"` + dupRegTimestamp + `","action":"login","` + escEventType + `":"login"}`,
		`{"timestamp":"` + dupRegTimestamp + `","action":"a","source_ip":"::1","src_ip":"0:0:0:0:0:0:0:1"}`,
	}
	for _, in := range consistent {
		results := runNormalize(t, in)
		if results[0]["ok"] != true {
			t.Fatalf("canonical name plus alias with consistent values must merge, got %#v for %s", results[0], in)
		}
	}

	divergent := []struct {
		input string
		field string
	}{
		{`{"timestamp":"` + dupRegTimestamp + `","time":"2026-01-02T00:01:00Z","action":"a"}`, FieldTimestamp},
		{`{"timestamp":"` + dupRegTimestamp + `","action":"login","` + escEventType + `":"logout"}`, FieldAction},
	}
	for _, tc := range divergent {
		results := runNormalize(t, tc.input)
		if results[0]["ok"] != false {
			t.Fatalf("divergent canonical/alias values must fail: %s", tc.input)
		}
		if _, exists := results[0]["event"]; exists {
			t.Fatalf("conflict failure must not carry an event: %s", tc.input)
		}
		msg, _ := results[0]["error"].(string)
		if strings.Contains(strings.ToLower(msg), "duplicate") {
			t.Fatalf("canonical vs alias must not be a duplicate-key error: %q", msg)
		}
		if !strings.Contains(msg, "conflicting values") || !strings.Contains(msg, tc.field) {
			t.Fatalf("error must be a value conflict on %q, got %q", tc.field, msg)
		}
	}
}

// In a mixed stream, a duplicate-key line fails in isolation: surrounding
// legal logs still come out in input order with their physical line numbers,
// blank lines only advance the counter, and exactly the one line counts as a
// failure (the count drives the CLI exit status).
func TestNormalizeDuplicateKeyMixedStreamKeepsOrderAndLineNumbers(t *testing.T) {
	input := `{"timestamp":"` + dupRegTimestamp + `","action":"first"}` + "\n" +
		"\n" +
		`{"timestamp":"` + dupRegTimestamp + `","action":"dup","` + escAction + `":"dup"}` + "\n" +
		"  \n" +
		`{"timestamp":"` + dupRegTimestamp + `","action":"last"}` + "\n"
	results := runNormalize(t, input)
	if failures := countFailures(results); failures != 1 {
		t.Fatalf("only the duplicate line must count as a failure, got %d", failures)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results over 5 physical lines, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must succeed before the duplicate: %#v", results[0])
	}
	if eventOf(t, results[0])["action"] != "first" {
		t.Fatalf("line 1 must keep its content and position")
	}
	middle := results[1]
	if middle["line"] != float64(3) || middle["ok"] != false {
		t.Fatalf("the duplicate must be reported on physical line 3: %#v", middle)
	}
	if _, exists := middle["event"]; exists {
		t.Fatalf("the duplicate failure must not carry an event: %#v", middle)
	}
	msg, _ := middle["error"].(string)
	if !strings.Contains(strings.ToLower(msg), "duplicate") || !strings.Contains(msg, `"action"`) {
		t.Fatalf("line 3 error must identify the duplicate action field, got %q", msg)
	}
	if results[2]["line"] != float64(5) || results[2]["ok"] != true {
		t.Fatalf("the trailing legal log must still succeed on line 5: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "last" {
		t.Fatalf("input order must be preserved after the failure")
	}
}
