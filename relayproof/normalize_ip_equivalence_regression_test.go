package relayproof

// Regression coverage for source-address equivalence: an IPv4 address and
// its IPv4-mapped IPv6 spellings denote one source and must normalize and
// merge identically, while other IPv4-embedded IPv6 forms (the deprecated
// "IPv4-compatible" range) are distinct addresses that merge only with
// themselves and conflict with the mapped family. A value that merely
// resembles an address (e.g. carries a port) is invalid input and fails
// the whole line; it is never repaired and merged.

import (
	"strings"
	"testing"
)

// ipv4MappedSpellings are the accepted spellings of one and the same
// source: the plain IPv4 form, the dotted IPv4-mapped IPv6 form, and the
// hexadecimal IPv4-mapped form. All normalize to "192.0.2.1".
var ipv4MappedSpellings = []string{"192.0.2.1", "::ffff:192.0.2.1", "::FFFF:C000:0201"}

// ipv4CompatibleSpellings are two spellings of the IPv4-compatible address
// ::c000:201. It embeds the same 32 bits as 192.0.2.1 but is a distinct
// IPv6 address, so it must never merge with the mapped family above.
var ipv4CompatibleSpellings = []string{"::192.0.2.1", "0:0:0:0:0:0:c000:201"}

const (
	validTS     = `"2026-01-02T00:00:00Z"`
	validAction = `"login"`
)

// TestNormalizeIPv4MappedSpellingsAlone pins the canonical form of the
// mapped family: provided on its own, under either the canonical name or
// the alias, every spelling yields source_ip 192.0.2.1.
func TestNormalizeIPv4MappedSpellingsAlone(t *testing.T) {
	for _, field := range []string{FieldSourceIP, "src_ip"} {
		for _, ip := range ipv4MappedSpellings {
			input := `{"timestamp":` + validTS + `,"action":` + validAction + `,"` + field + `":"` + ip + `"}`
			results := runNormalize(t, input)
			if len(results) != 1 || results[0]["ok"] != true {
				t.Fatalf("%s %q must succeed on its own: %#v", field, ip, results)
			}
			if results[0]["line"] != float64(1) {
				t.Fatalf("result must carry the physical line number: %#v", results[0])
			}
			event := eventOf(t, results[0])
			if event["source_ip"] != "192.0.2.1" {
				t.Fatalf("%s %q normalized to %v, want 192.0.2.1", field, ip, event["source_ip"])
			}
			if _, exists := event["extra"]; exists {
				t.Fatalf("no unmapped fields were given, extra must be absent: %#v", event)
			}
		}
	}
}

// TestNormalizeIPv4MappedMergeAcrossAliases requires every pairing of the
// mapped spellings across source_ip and src_ip to merge into one source
// field. Swapping which spelling sits under which field name, or
// rearranging the object members, must not change the result byte for
// byte. The consumed alias must not reappear in extra; unknown fields are
// preserved.
func TestNormalizeIPv4MappedMergeAcrossAliases(t *testing.T) {
	var inputs []string
	for _, a := range ipv4MappedSpellings {
		for _, b := range ipv4MappedSpellings {
			inputs = append(inputs, permuteKV([]kv{
				{key: FieldTimestamp, val: validTS},
				{key: FieldSourceIP, val: `"` + a + `"`},
				{key: "src_ip", val: `"` + b + `"`},
				{key: FieldAction, val: validAction},
				{key: "user", val: `"alice"`},
			})...)
		}
	}
	shared := assertOrderInvariant(t, inputs, true, nil)
	event := eventOf(t, shared)
	if event["source_ip"] != "192.0.2.1" {
		t.Fatalf("merged source_ip = %v, want 192.0.2.1", event["source_ip"])
	}
	if event["timestamp"] != "2026-01-02T00:00:00Z" || event["action"] != "login" {
		t.Fatalf("timestamp/action must follow the existing rules: %#v", event)
	}
	extra := extraOf(t, shared)
	if len(extra) != 1 || extra["user"] != "alice" {
		t.Fatalf("extra must hold only the unknown field, got %#v", extra)
	}
}

// TestNormalizeIPv4CompatibleAlone pins the canonical form of the
// IPv4-compatible address: it stays an IPv6 address and normalizes to
// ::c000:201, never to the dotted IPv4 form.
func TestNormalizeIPv4CompatibleAlone(t *testing.T) {
	for _, field := range []string{FieldSourceIP, "src_ip"} {
		for _, ip := range ipv4CompatibleSpellings {
			input := `{"timestamp":` + validTS + `,"action":` + validAction + `,"` + field + `":"` + ip + `"}`
			results := runNormalize(t, input)
			if len(results) != 1 || results[0]["ok"] != true {
				t.Fatalf("%s %q must succeed on its own: %#v", field, ip, results)
			}
			if got := eventOf(t, results[0])["source_ip"]; got != "::c000:201" {
				t.Fatalf("%s %q normalized to %v, want ::c000:201", field, ip, got)
			}
		}
	}
}

// TestNormalizeIPv4CompatibleMerge requires the two spellings of
// ::c000:201 to merge with each other across source_ip and src_ip, in any
// member order.
func TestNormalizeIPv4CompatibleMerge(t *testing.T) {
	var inputs []string
	for _, a := range ipv4CompatibleSpellings {
		for _, b := range ipv4CompatibleSpellings {
			inputs = append(inputs, permuteKV([]kv{
				{key: FieldTimestamp, val: validTS},
				{key: FieldSourceIP, val: `"` + a + `"`},
				{key: "src_ip", val: `"` + b + `"`},
				{key: FieldAction, val: validAction},
			})...)
		}
	}
	shared := assertOrderInvariant(t, inputs, true, nil)
	if got := eventOf(t, shared)["source_ip"]; got != "::c000:201" {
		t.Fatalf("merged source_ip = %v, want ::c000:201", got)
	}
}

// TestNormalizeIPv4CompatibleConflictsWithMapped requires a compatible
// address paired with any mapped-family spelling to fail the whole line.
// Both values are legal addresses, so the error must report a value
// conflict on source_ip — not an invalid address.
func TestNormalizeIPv4CompatibleConflictsWithMapped(t *testing.T) {
	for _, compat := range ipv4CompatibleSpellings {
		for _, mapped := range ipv4MappedSpellings {
			pairs := [][2]kv{
				{{key: FieldSourceIP, val: `"` + compat + `"`}, {key: "src_ip", val: `"` + mapped + `"`}},
				{{key: FieldSourceIP, val: `"` + mapped + `"`}, {key: "src_ip", val: `"` + compat + `"`}},
			}
			for _, pair := range pairs {
				input := joinObject([]kv{
					{key: FieldTimestamp, val: validTS},
					pair[0],
					pair[1],
					{key: FieldAction, val: validAction},
				})
				results := runNormalize(t, input)
				if len(results) != 1 || results[0]["ok"] != false {
					t.Fatalf("distinct addresses must not merge: %s -> %#v", input, results)
				}
				if _, exists := results[0]["event"]; exists {
					t.Fatalf("conflicting line must not emit an event: %s", input)
				}
				msg, _ := results[0]["error"].(string)
				if !strings.Contains(msg, FieldSourceIP) || !strings.Contains(msg, "conflicting values") {
					t.Fatalf("error must report a source_ip value conflict, got %q", msg)
				}
				if strings.Contains(msg, "invalid IP address") {
					t.Fatalf("two legal addresses must not be reported as invalid: %q", msg)
				}
			}
		}
	}
}

// TestNormalizeMappedIPWithPortFailsWholeLine requires a port-carrying
// value to fail as an invalid address even when the other side is a legal
// spelling of the same address after the port is stripped. The bad value
// is never dropped to let the good one win.
func TestNormalizeMappedIPWithPortFailsWholeLine(t *testing.T) {
	const withPort = "[::ffff:192.0.2.1]:443"
	for _, good := range ipv4MappedSpellings {
		pairs := [][2]kv{
			{{key: FieldSourceIP, val: `"` + good + `"`}, {key: "src_ip", val: `"` + withPort + `"`}},
			{{key: FieldSourceIP, val: `"` + withPort + `"`}, {key: "src_ip", val: `"` + good + `"`}},
		}
		for _, pair := range pairs {
			input := joinObject([]kv{
				{key: FieldTimestamp, val: validTS},
				pair[0],
				pair[1],
				{key: FieldAction, val: validAction},
			})
			results := runNormalize(t, input)
			if len(results) != 1 || results[0]["ok"] != false {
				t.Fatalf("port-carrying value must fail the whole line: %s -> %#v", input, results)
			}
			if _, exists := results[0]["event"]; exists {
				t.Fatalf("invalid address must not emit an event: %s", input)
			}
			msg, _ := results[0]["error"].(string)
			if !strings.Contains(msg, FieldSourceIP) || !strings.Contains(msg, "invalid IP address") {
				t.Fatalf("error must report an invalid source_ip address, got %q", msg)
			}
			if strings.Contains(msg, "conflicting values") {
				t.Fatalf("an invalid value is not a conflict between legal addresses: %q", msg)
			}
		}
	}
}

// TestNormalizeIPSourcePublicResultShape locks the public result shape for
// the equivalence scenarios in one stream: successes carry their physical
// line number and the normalized event with no error key; failures carry
// their line number, ok:false and an error, and never an event. Blank
// lines only advance the counter and later lines are still processed.
func TestNormalizeIPSourcePublicResultShape(t *testing.T) {
	input := `{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"::FFFF:C000:0201","src_ip":"192.0.2.1","user":"alice"}` + "\n" +
		"\n" +
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"::192.0.2.1","src_ip":"192.0.2.1"}` + "\n" +
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"[::ffff:192.0.2.1]:443","src_ip":"192.0.2.1"}` + "\n" +
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"src_ip":"0:0:0:0:0:0:c000:201"}` + "\n"
	results := runNormalize(t, input)
	if len(results) != 4 {
		t.Fatalf("expected 4 results for 5 physical lines, got %d: %#v", len(results), results)
	}

	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must succeed with its line number: %#v", results[0])
	}
	if _, exists := results[0]["error"]; exists {
		t.Fatalf("success must not carry an error key: %#v", results[0])
	}
	event := eventOf(t, results[0])
	if event["source_ip"] != "192.0.2.1" {
		t.Fatalf("line 1 source_ip = %v, want 192.0.2.1", event["source_ip"])
	}
	if extra := event["extra"].(map[string]any); len(extra) != 1 || extra["user"] != "alice" {
		t.Fatalf("line 1 extra must hold only the unknown field: %#v", event["extra"])
	}

	if results[1]["line"] != float64(3) || results[1]["ok"] != false {
		t.Fatalf("line 3 must fail with its line number: %#v", results[1])
	}
	if _, exists := results[1]["event"]; exists {
		t.Fatalf("line 3 conflict must not emit an event: %#v", results[1])
	}
	if msg, _ := results[1]["error"].(string); !strings.Contains(msg, "conflicting values") {
		t.Fatalf("line 3 must report a value conflict, got %q", msg)
	}

	if results[2]["line"] != float64(4) || results[2]["ok"] != false {
		t.Fatalf("line 4 must fail with its line number: %#v", results[2])
	}
	if _, exists := results[2]["event"]; exists {
		t.Fatalf("line 4 invalid address must not emit an event: %#v", results[2])
	}
	if msg, _ := results[2]["error"].(string); !strings.Contains(msg, "invalid IP address") {
		t.Fatalf("line 4 must report an invalid address, got %q", msg)
	}

	if results[3]["line"] != float64(5) || results[3]["ok"] != true {
		t.Fatalf("line 5 must still be processed after the failures: %#v", results[3])
	}
	if got := eventOf(t, results[3])["source_ip"]; got != "::c000:201" {
		t.Fatalf("line 5 source_ip = %v, want ::c000:201", got)
	}
}
