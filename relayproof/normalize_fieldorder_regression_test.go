package relayproof

// Regression coverage for validation-order stability when one log line
// supplies several mapped fields at once. The top-level fields and their
// values are held fixed; only their arrangement (input position, or the
// canonical name versus its alias) changes. The complete NormalizeResult
// — ok and the full error text, with no event on failure — must stay
// identical in every arrangement.

import (
	"encoding/json"
	"strings"
	"testing"
)

// Raw JSON value literals reused across the ordering scenarios.
const (
	validTSLiteral  = `"2026-01-02T00:00:00Z"`
	badTSLiteral    = `"not-a-time"`
	validIPLiteral  = `"1.2.3.4"`
	badIPLiteral    = `"not-an-ip"`
	validActLiteral = `"ok"`
	// Whitespace-only is a provided-but-invalid action, distinct from an
	// absent field.
	badActLiteral = `"   "`
)

type kv struct {
	key string
	val string // raw JSON value literal
}

type fieldChoice struct {
	names []string // input key names that all map to one canonical field
	val   string   // raw JSON value literal
}

func joinObject(specs []kv) string {
	parts := make([]string, len(specs))
	for i, spec := range specs {
		parts[i] = `"` + spec.key + `":` + spec.val
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// permuteKV returns every key ordering of the given fields. Fields and
// values are otherwise untouched.
func permuteKV(specs []kv) []string {
	var out []string
	perm := make([]kv, len(specs))
	used := make([]bool, len(specs))
	var rec func(int)
	rec = func(i int) {
		if i == len(specs) {
			out = append(out, joinObject(perm))
			return
		}
		for j := range specs {
			if used[j] {
				continue
			}
			used[j] = true
			perm[i] = specs[j]
			rec(i + 1)
			used[j] = false
		}
	}
	rec(0)
	return out
}

// expandOrderings produces, for each canonical field, every choice of
// input key name (canonical or alias), crossed with every key ordering.
// Three mapped fields therefore yield 2^3 * 3! = 48 arrangements.
func expandOrderings(choices []fieldChoice) []string {
	var objects []string
	var rec func(int, []kv)
	rec = func(i int, specs []kv) {
		if i == len(choices) {
			objects = append(objects, permuteKV(specs)...)
			return
		}
		for _, name := range choices[i].names {
			next := make([]kv, len(specs)+1)
			copy(next, specs)
			next[len(specs)] = kv{key: name, val: choices[i].val}
			rec(i+1, next)
		}
	}
	rec(0, nil)
	return objects
}

// canonicalResult is the complete serialized result for one line; two
// lines are equivalent only when these bytes are identical.
func canonicalResult(t *testing.T, lineNo int, input string) string {
	t.Helper()
	result := NormalizeLine(lineNo, []byte(input))
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshaling result for %s: %v", input, err)
	}
	return string(b)
}

// assertOrderInvariant feeds every arrangement at the same line position
// and requires byte-identical results, then checks the shared result's
// ok/event shape and that its error names each wanted substring.
func assertOrderInvariant(t *testing.T, inputs []string, wantOK bool, wantSubs []string) map[string]any {
	t.Helper()
	if len(inputs) < 2 {
		t.Fatalf("ordering test needs at least two arrangements, got %d", len(inputs))
	}
	want := canonicalResult(t, 1, inputs[0])
	for _, in := range inputs[1:] {
		if got := canonicalResult(t, 1, in); got != want {
			t.Fatalf("rearranging fields changed the result:\n input: %s\n got:  %s\n want: %s", in, got, want)
		}
	}
	var shared map[string]any
	if err := json.Unmarshal([]byte(want), &shared); err != nil {
		t.Fatalf("decoding shared result: %v", err)
	}
	if shared["ok"] != wantOK {
		t.Fatalf("ok = %v, want %v (result %s)", shared["ok"], wantOK, want)
	}
	if wantOK {
		return shared
	}
	if _, exists := shared["event"]; exists {
		t.Fatalf("failed line must never carry an event: %s", want)
	}
	msg, _ := shared["error"].(string)
	for _, sub := range wantSubs {
		if !strings.Contains(msg, sub) {
			t.Fatalf("error %q must contain %q (full result %s)", msg, sub, want)
		}
	}
	return shared
}

func mappedChoices(tsVal, ipVal, actVal string) []fieldChoice {
	return []fieldChoice{
		{names: []string{FieldTimestamp, "time"}, val: tsVal},
		{names: []string{FieldSourceIP, "src_ip"}, val: ipVal},
		{names: []string{FieldAction, "event_type"}, val: actVal},
	}
}

// TestNormalizeFieldOrderInvalidPrecedence locks the fixed validation
// order timestamp -> source_ip -> action: the first reported failure is
// chosen by canonical-field meaning, independent of input position and
// independent of canonical/alias spelling.
func TestNormalizeFieldOrderInvalidPrecedence(t *testing.T) {
	cases := []struct {
		name     string
		tsVal    string
		ipVal    string
		actVal   string
		wantSubs []string
	}{
		{
			name:     "all three invalid reports timestamp",
			tsVal:    badTSLiteral,
			ipVal:    badIPLiteral,
			actVal:   badActLiteral,
			wantSubs: []string{FieldTimestamp, "invalid RFC3339 timestamp"},
		},
		{
			name:     "timestamp valid, ip and action invalid reports source_ip",
			tsVal:    validTSLiteral,
			ipVal:    badIPLiteral,
			actVal:   badActLiteral,
			wantSubs: []string{FieldSourceIP, "invalid IP address"},
		},
		{
			name:     "timestamp and ip valid, action invalid reports action",
			tsVal:    validTSLiteral,
			ipVal:    validIPLiteral,
			actVal:   badActLiteral,
			wantSubs: []string{FieldAction, "action must not be empty"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputs := expandOrderings(mappedChoices(tc.tsVal, tc.ipVal, tc.actVal))
			if len(inputs) != 48 {
				t.Fatalf("expected 48 arrangements, got %d", len(inputs))
			}
			assertOrderInvariant(t, inputs, false, tc.wantSubs)
		})
	}
}

// TestNormalizeFieldOrderInvariantInStream checks the same guarantee
// through the streaming API: each arrangement occupies its own line
// position, results stay in order with physical line numbers, and every
// failure result is identical apart from that number.
func TestNormalizeFieldOrderInvariantInStream(t *testing.T) {
	lines := permuteKV([]kv{
		{key: FieldTimestamp, val: badTSLiteral},
		{key: FieldSourceIP, val: badIPLiteral},
		{key: FieldAction, val: badActLiteral},
	})
	results := runNormalize(t, strings.Join(lines, "\n"))
	if len(results) != len(lines) {
		t.Fatalf("expected %d results, got %d", len(lines), len(results))
	}
	var want string
	for i, r := range results {
		if r["line"] != float64(i+1) || r["ok"] != false {
			t.Fatalf("line %d mismatch: %#v", i+1, r)
		}
		if _, exists := r["event"]; exists {
			t.Fatalf("line %d must not emit an event", i+1)
		}
		delete(r, "line")
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			want = string(b)
			if !strings.Contains(want, FieldTimestamp) {
				t.Fatalf("first error must name %q: %s", FieldTimestamp, want)
			}
			continue
		}
		if string(b) != want {
			t.Fatalf("line %d result %s differs from %s", i+1, b, want)
		}
	}
}

// dualOrderings emits every key ordering of the competing canonical/alias
// pair together with its companion fields. Permuting all keys covers both
// relative placements of the pair, so swapping the two competing entries'
// input positions is part of the asserted set.
func dualOrderings(a, b kv, companions ...kv) []string {
	specs := make([]kv, 0, 2+len(companions))
	specs = append(specs, a, b)
	specs = append(specs, companions...)
	return permuteKV(specs)
}

// TestNormalizeCanonicalAndAliasDualKeys locks the two existing failure
// outcomes when one canonical field and its alias appear together:
//
//   - both values legal but normalize differently -> value conflict;
//   - one value invalid, even if the other is legal -> that field's
//     invalid-value error, never a success that ignores the bad side;
//
// while values normalizing to the same thing still merge. Swapping the
// two entries' positions must not change the complete result.
func TestNormalizeCanonicalAndAliasDualKeys(t *testing.T) {
	validTSCompanion := kv{key: FieldAction, val: validActLiteral}
	ipCompanions := []kv{
		{key: FieldTimestamp, val: validTSLiteral},
		{key: FieldAction, val: validActLiteral},
	}
	actionCompanion := kv{key: FieldTimestamp, val: validTSLiteral}

	cases := []struct {
		name       string
		a, b       kv
		companions []kv
		wantOK     bool
		wantSubs   []string
		forbidSubs []string
		wantValue  string // canonical event value on success
	}{
		// --- timestamp ---
		{
			name:       "timestamp two legal distinct instants conflict",
			a:          kv{FieldTimestamp, `"2026-01-02T00:04:05Z"`},
			b:          kv{"time", `"2026-01-02T00:05:00Z"`},
			companions: []kv{validTSCompanion},
			wantSubs:   []string{FieldTimestamp, "conflicting values", "2026-01-02T00:04:05Z", "2026-01-02T00:05:00Z"},
		},
		{
			name:       "timestamp invalid under canonical name wins over legal alias",
			a:          kv{FieldTimestamp, badTSLiteral},
			b:          kv{"time", `"2026-01-02T00:00:00Z"`},
			companions: []kv{validTSCompanion},
			wantSubs:   []string{FieldTimestamp, "invalid RFC3339 timestamp"},
			forbidSubs: []string{"conflicting values"},
		},
		{
			name:       "timestamp invalid under alias wins over legal canonical",
			a:          kv{FieldTimestamp, `"2026-01-02T00:00:00Z"`},
			b:          kv{"time", badTSLiteral},
			companions: []kv{validTSCompanion},
			wantSubs:   []string{FieldTimestamp, "invalid RFC3339 timestamp"},
			forbidSubs: []string{"conflicting values"},
		},
		{
			name:       "timestamp same instant in two zones merges",
			a:          kv{FieldTimestamp, `"2026-01-02T00:04:05Z"`},
			b:          kv{"time", `" 2026-01-02T08:04:05+08:00 "`},
			companions: []kv{validTSCompanion},
			wantOK:     true,
			wantValue:  "2026-01-02T00:04:05Z",
		},
		// --- source_ip ---
		{
			name:       "source_ip two legal distinct addresses conflict",
			a:          kv{FieldSourceIP, `"1.2.3.4"`},
			b:          kv{"src_ip", `"5.6.7.8"`},
			companions: ipCompanions,
			wantSubs:   []string{FieldSourceIP, "conflicting values", "1.2.3.4", "5.6.7.8"},
		},
		{
			name:       "source_ip invalid under canonical name wins over legal alias",
			a:          kv{FieldSourceIP, badIPLiteral},
			b:          kv{"src_ip", validIPLiteral},
			companions: ipCompanions,
			wantSubs:   []string{FieldSourceIP, "invalid IP address"},
			forbidSubs: []string{"conflicting values"},
		},
		{
			name:       "source_ip invalid under alias wins over legal canonical",
			a:          kv{FieldSourceIP, validIPLiteral},
			b:          kv{"src_ip", badIPLiteral},
			companions: ipCompanions,
			wantSubs:   []string{FieldSourceIP, "invalid IP address"},
			forbidSubs: []string{"conflicting values"},
		},
		{
			name:       "source_ip equivalent spellings merge",
			a:          kv{FieldSourceIP, `"0:0:0:0:0:0:0:1"`},
			b:          kv{"src_ip", `"::1"`},
			companions: ipCompanions,
			wantOK:     true,
			wantValue:  "::1",
		},
		// --- action ---
		{
			name:       "action two legal distinct values conflict",
			a:          kv{FieldAction, `"login"`},
			b:          kv{"event_type", `"logout"`},
			companions: []kv{actionCompanion},
			wantSubs:   []string{FieldAction, "conflicting values", "login", "logout"},
		},
		{
			name:       "action invalid under canonical name wins over legal alias",
			a:          kv{FieldAction, badActLiteral},
			b:          kv{"event_type", `"login"`},
			companions: []kv{actionCompanion},
			wantSubs:   []string{FieldAction, "action must not be empty"},
			forbidSubs: []string{"conflicting values"},
		},
		{
			name:       "action invalid under alias wins over legal canonical",
			a:          kv{FieldAction, `"login"`},
			b:          kv{"event_type", badActLiteral},
			companions: []kv{actionCompanion},
			wantSubs:   []string{FieldAction, "action must not be empty"},
			forbidSubs: []string{"conflicting values"},
		},
		{
			name:       "action values differing only by surrounding space merge",
			a:          kv{FieldAction, `" login "`},
			b:          kv{"event_type", `"login"`},
			companions: []kv{actionCompanion},
			wantOK:     true,
			wantValue:  "login",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputs := dualOrderings(tc.a, tc.b, tc.companions...)
			shared := assertOrderInvariant(t, inputs, tc.wantOK, tc.wantSubs)
			if len(tc.forbidSubs) > 0 {
				msg, _ := shared["error"].(string)
				for _, sub := range tc.forbidSubs {
					if strings.Contains(msg, sub) {
						t.Fatalf("error %q must not report %q", msg, sub)
					}
				}
			}
			if tc.wantOK {
				event := eventOf(t, shared)
				var got string
				switch tc.a.key {
				case FieldTimestamp, "time":
					got, _ = event[FieldTimestamp].(string)
				case FieldSourceIP, "src_ip":
					got, _ = event[FieldSourceIP].(string)
				default:
					got, _ = event[FieldAction].(string)
				}
				if got != tc.wantValue {
					t.Fatalf("merged value = %q, want %q", got, tc.wantValue)
				}
			}
		})
	}
}

// TestNormalizeMissingRequiredYieldsToProvidedErrors locks the rule that
// a missing required field is reported only after every provided field
// validates; when both required fields are absent the timestamp is
// reported first. Rearranging fields or swapping in alias names must not
// change the result.
func TestNormalizeMissingRequiredYieldsToProvidedErrors(t *testing.T) {
	cases := []struct {
		name     string
		variants []string
		wantSubs []string
		forbid   []string
	}{
		{
			name: "invalid provided timestamp beats missing action",
			variants: []string{
				`{"timestamp":"not-a-time"}`,
				`{"time":"not-a-time"}`,
				`{"user":"x","timestamp":"not-a-time"}`,
				`{"timestamp":"not-a-time","user":"x"}`,
				`{"user":"x","time":"not-a-time"}`,
				`{"time":"not-a-time","user":"x"}`,
			},
			wantSubs: []string{FieldTimestamp, "invalid RFC3339 timestamp"},
			forbid:   []string{"missing"},
		},
		{
			name: "invalid provided source_ip beats missing action",
			variants: permuteKV([]kv{
				{key: FieldTimestamp, val: validTSLiteral},
				{key: FieldSourceIP, val: badIPLiteral},
			}),
			wantSubs: []string{FieldSourceIP, "invalid IP address"},
			forbid:   []string{"missing"},
		},
		{
			name: "invalid provided source_ip beats missing timestamp",
			variants: permuteKV([]kv{
				{key: "src_ip", val: badIPLiteral},
				{key: FieldAction, val: validActLiteral},
			}),
			wantSubs: []string{FieldSourceIP, "invalid IP address"},
			forbid:   []string{"missing"},
		},
		{
			name: "invalid provided action beats missing timestamp",
			variants: []string{
				`{"action":"   "}`,
				`{"event_type":"   "}`,
				`{"user":"x","action":"   "}`,
				`{"action":"   ","user":"x"}`,
				`{"user":"x","event_type":"   "}`,
				`{"event_type":"   ","user":"x"}`,
			},
			wantSubs: []string{FieldAction, "action must not be empty"},
			forbid:   []string{"missing"},
		},
		{
			name: "valid timestamp then missing action",
			variants: []string{
				`{"timestamp":"2026-01-02T00:00:00Z"}`,
				`{"time":"2026-01-02T00:00:00Z"}`,
				`{"user":"x","timestamp":"2026-01-02T00:00:00Z"}`,
				`{"timestamp":"2026-01-02T00:00:00Z","user":"x"}`,
			},
			wantSubs: []string{`missing required field "action"`},
		},
		{
			name: "both required missing reports timestamp first",
			variants: []string{
				`{}`,
				`{"user":"x"}`,
			},
			wantSubs: []string{`missing required field "timestamp"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shared := assertOrderInvariant(t, tc.variants, false, tc.wantSubs)
			msg, _ := shared["error"].(string)
			for _, sub := range tc.forbid {
				if strings.Contains(msg, sub) {
					t.Fatalf("error %q must not mention %q", msg, sub)
				}
			}
		})
	}
}

// TestNormalizeExplicitNullIsProvidedTypeError pins the distinction
// between omission and explicit null: null is a provided field with a
// type error, joins the same fixed validation order, and is reported
// ahead of any missing-required error — always under the canonical field
// name, regardless of alias spelling or position.
func TestNormalizeExplicitNullIsProvidedTypeError(t *testing.T) {
	cases := []struct {
		name     string
		variants []string
		wantSubs []string
		forbid   []string
	}{
		{
			name: "null timestamp reported as type error before missing action",
			variants: []string{
				`{"timestamp":null}`,
				`{"time":null}`,
				`{"user":"x","timestamp":null}`,
				`{"timestamp":null,"user":"x"}`,
				`{"user":"x","time":null}`,
				`{"time":null,"user":"x"}`,
			},
			wantSubs: []string{FieldTimestamp, "value must be a string, got null"},
			forbid:   []string{"missing"},
		},
		{
			name: "null action with valid timestamp is a type error",
			variants: append(
				permuteKV([]kv{{FieldTimestamp, validTSLiteral}, {FieldAction, "null"}}),
				permuteKV([]kv{{"time", validTSLiteral}, {"event_type", "null"}})...,
			),
			wantSubs: []string{FieldAction, "value must be a string, got null"},
			forbid:   []string{"missing"},
		},
		{
			name: "null action beats missing timestamp",
			variants: []string{
				`{"action":null}`,
				`{"event_type":null}`,
				`{"user":"x","action":null}`,
				`{"action":null,"user":"x"}`,
			},
			wantSubs: []string{FieldAction, "value must be a string, got null"},
			forbid:   []string{"missing"},
		},
		{
			name: "null source_ip beats missing action",
			variants: permuteKV([]kv{
				{FieldTimestamp, validTSLiteral},
				{"src_ip", "null"},
			}),
			wantSubs: []string{FieldSourceIP, "value must be a string, got null"},
			forbid:   []string{"missing"},
		},
		{
			name: "timestamp and action both null reports timestamp first",
			variants: append(
				permuteKV([]kv{{FieldTimestamp, "null"}, {FieldAction, "null"}}),
				permuteKV([]kv{{"time", "null"}, {"event_type", "null"}})...,
			),
			wantSubs: []string{FieldTimestamp, "value must be a string, got null"},
			forbid:   []string{"missing"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shared := assertOrderInvariant(t, tc.variants, false, tc.wantSubs)
			msg, _ := shared["error"].(string)
			for _, sub := range tc.forbid {
				if strings.Contains(msg, sub) {
					t.Fatalf("error %q must not mention %q", msg, sub)
				}
			}
		})
	}
}

// TestNormalizeReorderingPreservesSuccessEvent confirms the success path
// is equally insensitive to arrangement: reordered fields and mixed
// canonical/alias names yield one event with identical content.
func TestNormalizeReorderingPreservesSuccessEvent(t *testing.T) {
	choices := []fieldChoice{
		{names: []string{FieldTimestamp, "time"}, val: `"2026-01-02T08:04:05+08:00"`},
		{names: []string{FieldSourceIP, "src_ip"}, val: `"0:0:0:0:0:0:0:1"`},
		{names: []string{FieldAction, "event_type"}, val: `" login "`},
	}
	inputs := expandOrderings(choices)
	shared := assertOrderInvariant(t, inputs, true, nil)
	event := eventOf(t, shared)
	if event[FieldTimestamp] != "2026-01-02T00:04:05Z" {
		t.Fatalf("timestamp mismatch: %v", event[FieldTimestamp])
	}
	if event[FieldSourceIP] != "::1" {
		t.Fatalf("source_ip mismatch: %v", event[FieldSourceIP])
	}
	if event[FieldAction] != "login" {
		t.Fatalf("action mismatch: %v", event[FieldAction])
	}
}

// TestNormalizeExistingSyntaxAndDuplicateBehaviorAnchors the scope of the
// ordering guarantees: malformed JSON and duplicate top-level keys keep
// their existing handling and never reach field validation.
func TestNormalizeExistingSyntaxAndDuplicateBehaviorAnchors(t *testing.T) {
	t.Run("syntax error", func(t *testing.T) {
		results := runNormalize(t, `{not json`)
		if len(results) != 1 || results[0]["ok"] != false {
			t.Fatalf("syntax error must fail: %#v", results)
		}
		if _, exists := results[0]["event"]; exists {
			t.Fatalf("syntax error must not emit an event")
		}
		if msg, _ := results[0]["error"].(string); !strings.Contains(msg, "invalid JSON") {
			t.Fatalf("syntax error must keep its error, got %q", msg)
		}
	})
	t.Run("duplicate top-level key", func(t *testing.T) {
		// Equal values do not save a repeated key; this is independent of
		// the canonical/alias coexistence covered above.
		results := runNormalize(t, `{"action":"a","action":"a"}`)
		if len(results) != 1 || results[0]["ok"] != false {
			t.Fatalf("duplicate key must fail: %#v", results)
		}
		if _, exists := results[0]["event"]; exists {
			t.Fatalf("duplicate key must not emit an event")
		}
		msg, _ := results[0]["error"].(string)
		if !strings.Contains(strings.ToLower(msg), "duplicate") {
			t.Fatalf("duplicate key must keep its error, got %q", msg)
		}
	})
	t.Run("normal event", func(t *testing.T) {
		results := runNormalize(t, `{"timestamp":"2026-01-02T00:00:00Z","source_ip":"1.2.3.4","action":"login"}`)
		if len(results) != 1 || results[0]["ok"] != true {
			t.Fatalf("normal line must succeed: %#v", results)
		}
		event := eventOf(t, results[0])
		if event[FieldAction] != "login" || event[FieldSourceIP] != "1.2.3.4" {
			t.Fatalf("event mismatch: %#v", event)
		}
	})
}
