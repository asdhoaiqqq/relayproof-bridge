package relayproof

import (
	"bytes"
	"strings"
	"testing"
)

// Regression coverage for multi-field lines: when a single log line carries
// several mapped fields at once, reordering the top-level fields must never
// change which failure is reported first. Scope is parseable JSON objects
// without duplicate top-level keys (syntax errors and duplicate keys keep
// their own existing handling, covered at the end of this file).
//
// The contracts pinned here:
//   - Validation priority follows the standard-field meanings in the fixed
//     order timestamp, source_ip, action; using the alias names time, src_ip,
//     event_type (or swapping alias and canonical positions) must not change
//     either the ok outcome or the complete error text.
//   - A canonical name and its alias are two candidates for one field: valid
//     values that normalize differently conflict, one invalid candidate fails
//     the field even when the other is valid, and values normalizing equal
//     still merge. Swapping the two members changes none of that.
//   - Errors in provided fields outrank missing-required errors; only after
//     every provided field is valid may "missing required field" appear, with
//     timestamp reported before action. An explicit null is a provided value
//     (a type error), never an omission.
//   - Failures carry no event.
//
// Everything runs in-process, so the coverage is fully deterministic offline.

// Exact failure texts pinned by these tests. Field validation errors always
// name the canonical field even when the value arrived under an alias.
const (
	orderErrBadTimestamp = `field "timestamp": invalid RFC3339 timestamp: not an RFC3339 timestamp (need YYYY-MM-DDTHH:MM:SS with two-digit fields, a dot fraction of 1-9 digits, and Z or ±HH:MM offset)`
	orderErrBadIP        = `field "source_ip": invalid IP address "not-an-ip" (no port allowed)`
	orderErrEmptyAction  = `field "action": action must not be empty`

	orderErrNullTimestamp = `field "timestamp": value must be a string, got null`
	orderErrNullSourceIP  = `field "source_ip": value must be a string, got null`
	orderErrNullAction    = `field "action": value must be a string, got null`

	orderErrMissingTimestamp = `missing required field "timestamp"`
	orderErrMissingAction    = `missing required field "action"`
)

func orderValidTS() string     { return `"timestamp":"2026-01-02T00:00:00Z"` }
func orderValidIP() string     { return `"source_ip":"1.2.3.4"` }
func orderValidAction() string { return `"action":"a"` }

// permuteStrings returns every ordering of items (items may repeat).
func permuteStrings(items []string) [][]string {
	var out [][]string
	cur := make([]string, 0, len(items))
	used := make([]bool, len(items))
	var walk func(int)
	walk = func(n int) {
		if n == len(items) {
			perm := make([]string, len(cur))
			copy(perm, cur)
			out = append(out, perm)
			return
		}
		for i := range items {
			if used[i] {
				continue
			}
			used[i] = true
			cur = append(cur, items[i])
			walk(n + 1)
			cur = cur[:len(cur)-1]
			used[i] = false
		}
	}
	walk(0)
	return out
}

// joinObject builds one JSON object line from "key":value member snippets.
func joinObject(members []string) string {
	return "{" + strings.Join(members, ",") + "}"
}

// normalizeRawLine runs a single line through the streaming entry point and
// returns the exact serialized result bytes with the failure count.
func normalizeRawLine(t *testing.T, line string) (string, int) {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(line+"\n"), &out)
	if err != nil {
		t.Fatalf("NormalizeReader returned stream error for %s: %v", line, err)
	}
	return out.String(), failures
}

// assertMemberOrderInvariant normalizes every permutation of the given object
// members and asserts byte-identical output (line number, ok, full error text
// or complete event) and an identical failure count: reordering top-level
// fields and values kept verbatim must be unobservable. It returns the shared
// raw result for further content assertions.
func assertMemberOrderInvariant(t *testing.T, members []string) string {
	t.Helper()
	var want string
	wantFailures := -1
	for i, perm := range permuteStrings(members) {
		line := joinObject(perm)
		got, failures := normalizeRawLine(t, line)
		if i == 0 {
			want, wantFailures = got, failures
			continue
		}
		if got != want {
			t.Fatalf("reordering members changed the result\nmembers: %s\nbase:    %sreorder: %s",
				strings.Join(perm, ", "), want, got)
		}
		if failures != wantFailures {
			t.Fatalf("reordering members changed the failure count: got %d, want %d (%s)",
				failures, wantFailures, line)
		}
	}
	return want
}

// requireRawFailure decodes a one-line raw result and pins the exact failure:
// ok=false, the complete error text, and no event.
func requireRawFailure(t *testing.T, raw, wantErr string) {
	t.Helper()
	results := decodeResults(t, []byte(raw))
	if len(results) != 1 {
		t.Fatalf("expected exactly one result, got %#v (raw %q)", results, raw)
	}
	r := results[0]
	if r["ok"] != false {
		t.Fatalf("expected failure, got %#v (raw %q)", r, raw)
	}
	if got, _ := r["error"].(string); got != wantErr {
		t.Fatalf("error text mismatch\n got %q\nwant %q", got, wantErr)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("failure must not carry an event: %#v", r)
	}
}

// mustFailExactly is the single-line form for inputs checked without
// permutation: same ok/error/no-event contract as requireRawFailure.
func mustFailExactly(t *testing.T, line, wantErr string) {
	t.Helper()
	results := runNormalize(t, line)
	if len(results) != 1 {
		t.Fatalf("expected one result for %s, got %#v", line, results)
	}
	r := results[0]
	if r["ok"] != false {
		t.Fatalf("expected failure for %s, got %#v", line, r)
	}
	if got, _ := r["error"].(string); got != wantErr {
		t.Fatalf("error text mismatch for %s\n got %q\nwant %q", line, got, wantErr)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("failure must not carry an event for %s: %#v", line, r)
	}
}

// With several invalid provided fields at once, the first reported failure is
// chosen by canonical-field meaning (timestamp, then source_ip, then action)
// and never by key order or by whether the value used an alias. Every member
// ordering must produce the same complete error, and failures carry no event.
func TestNormalizeFieldValidationOrderIndependentOfArrangement(t *testing.T) {
	cases := []struct {
		name    string
		members []string
		wantErr string
	}{
		{
			name: "all three invalid under canonical names reports timestamp",
			members: []string{
				`"timestamp":"not-a-time"`,
				`"source_ip":"not-an-ip"`,
				`"action":"   "`,
			},
			wantErr: orderErrBadTimestamp,
		},
		{
			name: "all three invalid under alias names reports timestamp",
			members: []string{
				`"time":"not-a-time"`,
				`"src_ip":"not-an-ip"`,
				`"event_type":"   "`,
			},
			wantErr: orderErrBadTimestamp,
		},
		{
			name: "timestamp valid, ip and action invalid reports source_ip",
			members: []string{
				orderValidTS(),
				`"source_ip":"not-an-ip"`,
				`"action":"   "`,
			},
			wantErr: orderErrBadIP,
		},
		{
			name: "same via aliases reports source_ip",
			members: []string{
				`"time":"2026-01-02T00:00:00Z"`,
				`"src_ip":"not-an-ip"`,
				`"event_type":"   "`,
			},
			wantErr: orderErrBadIP,
		},
		{
			name: "alias timestamp, canonical source_ip and event action",
			members: []string{
				`"time":"2026-01-02T00:00:00Z"`,
				`"source_ip":"not-an-ip"`,
				`"event_type":"   "`,
			},
			wantErr: orderErrBadIP,
		},
		{
			name: "canonical timestamp, alias ip and canonical action",
			members: []string{
				orderValidTS(),
				`"src_ip":"not-an-ip"`,
				`"action":"   "`,
			},
			wantErr: orderErrBadIP,
		},
		{
			name: "timestamp and ip valid, action invalid reports action",
			members: []string{
				orderValidTS(),
				orderValidIP(),
				`"action":"   "`,
			},
			wantErr: orderErrEmptyAction,
		},
		{
			name: "same via alias action reports action",
			members: []string{
				`"time":"2026-01-02T00:00:00Z"`,
				`"src_ip":"1.2.3.4"`,
				`"event_type":"   "`,
			},
			wantErr: orderErrEmptyAction,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := assertMemberOrderInvariant(t, tc.members)
			requireRawFailure(t, raw, tc.wantErr)
		})
	}
}

// A canonical field and its alias coexisting must keep the two existing
// failure outcomes regardless of which member appears first: valid values
// normalizing to different strings are a value conflict naming the canonical
// field, and one invalid value fails the field with its invalid-value error
// even when the other candidate is legal. Values normalizing equal still
// merge into one success event.
func TestNormalizeCanonicalAliasPairSwap(t *testing.T) {
	t.Run("valid values normalizing differently conflict", func(t *testing.T) {
		cases := []struct {
			name    string
			members []string
			wantErr string
		}{
			{
				name: "timestamp pair",
				members: []string{
					orderValidAction(),
					`"timestamp":"2026-01-02T00:00:00Z"`,
					`"time":"2026-01-02T00:05:00Z"`,
				},
				wantErr: `field "timestamp" has conflicting values: "2026-01-02T00:05:00Z" and "2026-01-02T00:00:00Z"`,
			},
			{
				name: "source_ip pair",
				members: []string{
					orderValidTS(),
					orderValidAction(),
					`"source_ip":"1.2.3.4"`,
					`"src_ip":"5.6.7.8"`,
				},
				wantErr: `field "source_ip" has conflicting values: "1.2.3.4" and "5.6.7.8"`,
			},
			{
				name: "action pair",
				members: []string{
					orderValidTS(),
					`"action":"login"`,
					`"event_type":"logout"`,
				},
				wantErr: `field "action" has conflicting values: "login" and "logout"`,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				raw := assertMemberOrderInvariant(t, tc.members)
				requireRawFailure(t, raw, tc.wantErr)
			})
		}
	})

	t.Run("invalid candidate fails even when the other is legal", func(t *testing.T) {
		// For each field the invalid value is placed once under the canonical
		// name and once under the alias; a legal partner is present in both
		// variants. Neither pairing may collapse into a success event, and
		// swapping the two members must leave the complete error unchanged.
		cases := []struct {
			name         string
			canonicalBad []string
			aliasBad     []string
			wantErr      string
		}{
			{
				name: "timestamp pair",
				canonicalBad: []string{
					orderValidAction(),
					`"timestamp":"not-a-time"`,
					`"time":"2026-01-02T00:00:00Z"`,
				},
				aliasBad: []string{
					orderValidAction(),
					orderValidTS(),
					`"time":"not-a-time"`,
				},
				wantErr: orderErrBadTimestamp,
			},
			{
				name: "source_ip pair",
				canonicalBad: []string{
					orderValidTS(),
					orderValidAction(),
					`"source_ip":"not-an-ip"`,
					`"src_ip":"1.2.3.4"`,
				},
				aliasBad: []string{
					orderValidTS(),
					orderValidAction(),
					orderValidIP(),
					`"src_ip":"not-an-ip"`,
				},
				wantErr: orderErrBadIP,
			},
			{
				name: "action pair",
				canonicalBad: []string{
					orderValidTS(),
					`"action":"   "`,
					`"event_type":"login"`,
				},
				aliasBad: []string{
					orderValidTS(),
					`"action":"login"`,
					`"event_type":"   "`,
				},
				wantErr: orderErrEmptyAction,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				badCanonical := assertMemberOrderInvariant(t, tc.canonicalBad)
				requireRawFailure(t, badCanonical, tc.wantErr)
				badAlias := assertMemberOrderInvariant(t, tc.aliasBad)
				requireRawFailure(t, badAlias, tc.wantErr)
				// The reported reason must be identical no matter which side
				// carried the invalid value.
				if badCanonical != badAlias {
					t.Fatalf("invalid-value placement changed the result\ncanonical-bad: %salias-bad:     %s",
						badCanonical, badAlias)
				}
			})
		}
	})

	t.Run("values normalizing equal still merge after a swap", func(t *testing.T) {
		// Two different legal timestamp spellings of the same instant must
		// not be mistaken for a conflict.
		cases := []struct {
			name    string
			members []string
			check   func(t *testing.T, event map[string]any)
		}{
			{
				name: "same instant in different zones",
				members: []string{
					orderValidAction(),
					`"timestamp":"2026-01-02T08:00:00+08:00"`,
					`"time":"2026-01-02T00:00:00Z"`,
				},
				check: func(t *testing.T, e map[string]any) {
					if e["timestamp"] != "2026-01-02T00:00:00Z" {
						t.Fatalf("merged timestamp mismatch: %v", e["timestamp"])
					}
				},
			},
			{
				name: "same instant with surrounding whitespace on one spelling",
				members: []string{
					orderValidAction(),
					`"timestamp":"  2026-01-02T08:00:00+08:00  "`,
					`"time":"2026-01-02T00:00:00Z"`,
				},
				check: func(t *testing.T, e map[string]any) {
					if e["timestamp"] != "2026-01-02T00:00:00Z" {
						t.Fatalf("merged timestamp mismatch: %v", e["timestamp"])
					}
				},
			},
			{
				name: "equivalent IPv6 spellings",
				members: []string{
					orderValidTS(),
					orderValidAction(),
					`"source_ip":"::1"`,
					`"src_ip":"0:0:0:0:0:0:0:1"`,
				},
				check: func(t *testing.T, e map[string]any) {
					if e["source_ip"] != "::1" {
						t.Fatalf("merged source_ip mismatch: %v", e["source_ip"])
					}
				},
			},
			{
				name: "same action with surrounding whitespace",
				members: []string{
					orderValidTS(),
					`"action":"login"`,
					`"event_type":" login "`,
				},
				check: func(t *testing.T, e map[string]any) {
					if e["action"] != "login" {
						t.Fatalf("merged action mismatch: %v", e["action"])
					}
				},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				raw := assertMemberOrderInvariant(t, tc.members)
				results := decodeResults(t, []byte(raw))
				if len(results) != 1 || results[0]["ok"] != true {
					t.Fatalf("equal candidates must merge successfully under every ordering: %#v", results)
				}
				tc.check(t, eventOf(t, results[0]))
			})
		}
	})
}

// An error in a provided field outranks every missing-required error: only
// after all provided fields validate may the line report the absent timestamp
// or action (timestamp first when both are absent). The chosen error is again
// independent of member order.
func TestNormalizeProvidedFieldErrorsBeatMissingRequired(t *testing.T) {
	cases := []struct {
		name    string
		members []string // single-line members; permuted when there is >1
		wantErr string
	}{
		{
			name:    "invalid provided source_ip beats missing timestamp",
			members: []string{`"source_ip":"not-an-ip"`, `"action":"a"`},
			wantErr: orderErrBadIP,
		},
		{
			name:    "invalid provided timestamp beats missing action",
			members: []string{`"timestamp":"not-a-time"`},
			wantErr: orderErrBadTimestamp,
		},
		{
			name:    "invalid provided source_ip beats missing action",
			members: []string{orderValidTS(), `"source_ip":"not-an-ip"`},
			wantErr: orderErrBadIP,
		},
		{
			name:    "invalid provided action beats missing timestamp",
			members: []string{`"action":"   "`},
			wantErr: orderErrEmptyAction,
		},
		{
			name:    "invalid provided source_ip beats both missing required fields",
			members: []string{`"source_ip":"not-an-ip"`},
			wantErr: orderErrBadIP,
		},
		{
			name:    "both required fields absent reports timestamp first",
			members: nil,
			wantErr: orderErrMissingTimestamp,
		},
		{
			name:    "only an optional field present reports missing timestamp",
			members: []string{`"source_ip":"1.2.3.4"`},
			wantErr: orderErrMissingTimestamp,
		},
		{
			name:    "timestamp present and valid reports missing action",
			members: []string{orderValidTS()},
			wantErr: orderErrMissingAction,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.members) <= 1 {
				mustFailExactly(t, joinObject(tc.members), tc.wantErr)
				return
			}
			raw := assertMemberOrderInvariant(t, tc.members)
			requireRawFailure(t, raw, tc.wantErr)
		})
	}
}

// An explicit null is a provided value whose type is wrong, not an omitted
// field: it participates in the same timestamp -> source_ip -> action error
// selection, beats missing-required errors, and reports under the canonical
// field name even when spelled with the alias key.
func TestNormalizeExplicitNullParticipatesInErrorSelection(t *testing.T) {
	cases := []struct {
		name    string
		members []string // permuted when there is >1
		wantErr string
	}{
		{
			name:    "null timestamp under canonical name is a type error",
			members: []string{`"timestamp":null`, `"action":"a"`},
			wantErr: orderErrNullTimestamp,
		},
		{
			name:    "null timestamp under alias still names the canonical field",
			members: []string{`"time":null`, `"action":"a"`},
			wantErr: orderErrNullTimestamp,
		},
		{
			name:    "null timestamp outranks missing action",
			members: []string{`"timestamp":null`},
			wantErr: orderErrNullTimestamp,
		},
		{
			name:    "null action outranks missing timestamp",
			members: []string{`"action":null`},
			wantErr: orderErrNullAction,
		},
		{
			name:    "both required values null reports timestamp first",
			members: []string{`"timestamp":null`, `"action":null`},
			wantErr: orderErrNullTimestamp,
		},
		{
			name:    "valid timestamp then null action",
			members: []string{orderValidTS(), `"action":null`},
			wantErr: orderErrNullAction,
		},
		{
			name:    "null action under alias still names the canonical field",
			members: []string{orderValidTS(), `"event_type":null`},
			wantErr: orderErrNullAction,
		},
		{
			name:    "null source_ip beats both missing required fields",
			members: []string{`"source_ip":null`},
			wantErr: orderErrNullSourceIP,
		},
		{
			name: "null timestamp beats invalid source_ip",
			members: []string{
				`"timestamp":null`,
				`"source_ip":"not-an-ip"`,
				`"action":"a"`,
			},
			wantErr: orderErrNullTimestamp,
		},
		{
			name: "null source_ip beats an invalid later action",
			members: []string{
				orderValidTS(),
				`"source_ip":null`,
				`"action":"   "`,
			},
			wantErr: orderErrNullSourceIP,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.members) <= 1 {
				mustFailExactly(t, joinObject(tc.members), tc.wantErr)
				return
			}
			raw := assertMemberOrderInvariant(t, tc.members)
			requireRawFailure(t, raw, tc.wantErr)
		})
	}
}

// Successful lines stay successful and identical under every field
// arrangement: consistent canonical/alias pairs for all three mapped fields
// merge, unknown fields are preserved, and the emitted event bytes are the
// same no matter how the input members were ordered.
func TestNormalizeSuccessUnchangedByArrangement(t *testing.T) {
	members := []string{
		`"timestamp":"2026-01-02T00:00:00Z"`,
		`"time":" 2026-01-02T08:00:00+08:00 "`,
		`"source_ip":"::1"`,
		`"src_ip":"0:0:0:0:0:0:0:1"`,
		`"action":"login"`,
		`"event_type":" login "`,
		`"user":"alice"`,
	}
	raw := assertMemberOrderInvariant(t, members)
	results := decodeResults(t, []byte(raw))
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("fully valid line must succeed under every ordering: %#v", results)
	}
	event := eventOf(t, results[0])
	if event["timestamp"] != "2026-01-02T00:00:00Z" {
		t.Fatalf("timestamp mismatch: %v", event["timestamp"])
	}
	if event["source_ip"] != "::1" {
		t.Fatalf("source_ip mismatch: %v", event["source_ip"])
	}
	if event["action"] != "login" {
		t.Fatalf("action mismatch: %v", event["action"])
	}
	if extraOf(t, results[0])["user"] != "alice" {
		t.Fatalf("unknown field must be preserved: %#v", event["extra"])
	}
}

// Existing handling outside the arrangement scope must be preserved: syntax
// errors and non-object inputs fail with no event, and duplicate top-level
// keys fail with the duplicate error (never a value conflict) regardless of
// where the repeated member sits.
func TestNormalizeSyntaxAndDuplicateHandlingPositionIndependent(t *testing.T) {
	for _, in := range []string{`{not json`, `[1,2,3]`, `"hello"`, `123`} {
		results := runNormalize(t, in)
		if len(results) != 1 || results[0]["ok"] != false {
			t.Fatalf("syntax/non-object input must yield one failure: %s -> %#v", in, results)
		}
		if _, exists := results[0]["event"]; exists {
			t.Fatalf("syntax failure must not carry an event: %s -> %#v", in, results[0])
		}
		if results[0]["error"] == "" {
			t.Fatalf("syntax failure must explain itself: %s", in)
		}
	}

	dupCases := []struct {
		name    string
		members []string
		field   string
	}{
		{
			name: "duplicate canonical action in either position",
			members: []string{
				orderValidTS(),
				`"action":"a"`,
				`"action":"b"`,
			},
			field: FieldAction,
		},
		{
			name: "duplicate alias timestamp in either position",
			members: []string{
				`"time":"2026-01-02T00:00:00Z"`,
				`"time":"2026-01-02T00:00:00Z"`,
				`"action":"a"`,
			},
			field: "time",
		},
	}
	for _, tc := range dupCases {
		t.Run(tc.name, func(t *testing.T) {
			raw := assertMemberOrderInvariant(t, tc.members)
			requireRawFailure(t, raw, `duplicate field "`+tc.field+`"`)
			if strings.Contains(raw, "conflict") {
				t.Fatalf("duplicate keys must never degrade into a value conflict: %s", raw)
			}
		})
	}
}
