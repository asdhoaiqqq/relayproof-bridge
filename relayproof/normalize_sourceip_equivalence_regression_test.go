package relayproof

// Regression coverage for source-address equivalence when source_ip and
// src_ip are normalized separately and then merged. IPv4-mapped IPv6
// spellings (::ffff:a.b.c.d, including the all-hex form ::FFFF:...) denote
// the same source as the plain IPv4 literal and must merge with it in every
// key/order arrangement; other IPv6 addresses that merely embed an IPv4-looking
// tail (::a.b.c.d) are distinct addresses and conflict rather than merge.
// A bracketed host:port is an invalid address, not an equivalent spelling
// with a port to strip.

import (
	"strings"
	"testing"
)

// The three input spellings of one IPv4-mapped source, and the one canonical
// form every success must carry.
const (
	plainIPv4Source    = "192.0.2.1"
	mappedDottedSource = "::ffff:192.0.2.1"
	mappedHexSource    = "::FFFF:C000:0201"
	canonicalIPv4Field = "192.0.2.1"
)

// An embedded-IPv4 address that is NOT a mapped address: it stays IPv6.
const (
	embeddedDottedSource = "::192.0.2.1"
	embeddedFullSource   = "0:0:0:0:0:0:c000:201"
	canonicalIPv6Field   = "::c000:201"
)

// Bracketed host:port: ParseIP rejects it; the brackets and port must not be
// stripped to recover the mapped address underneath.
const bracketedMappedWithPort = "[::ffff:192.0.2.1]:443"

var mappedSourceSpellings = []string{plainIPv4Source, mappedDottedSource, mappedHexSource}

var sourceIPCompanions = []kv{
	{key: FieldTimestamp, val: `"2026-01-02T00:00:00Z"`},
	{key: FieldAction, val: `"login"`},
}

// TestNormalizeIPv4MappedAddressSpellingsAreOneSource pins single-field
// behavior under either the canonical name or its alias: each of the three
// spellings alone normalizes to source_ip "192.0.2.1".
func TestNormalizeIPv4MappedAddressSpellingsAreOneSource(t *testing.T) {
	for _, spelling := range mappedSourceSpellings {
		for _, name := range []string{FieldSourceIP, "src_ip"} {
			input := `{"timestamp":"2026-01-02T00:00:00Z","` + name + `":"` + spelling + `","action":"login"}`
			results := runNormalize(t, input)
			if len(results) != 1 || results[0]["line"] != float64(1) || results[0]["ok"] != true {
				t.Fatalf("%s under %q must succeed on line 1: %s -> %#v", spelling, name, input, results)
			}
			event := eventOf(t, results[0])
			if event[FieldSourceIP] != canonicalIPv4Field {
				t.Fatalf("%s under %q normalized to %v, want %q", spelling, name, event[FieldSourceIP], canonicalIPv4Field)
			}
			if _, exists := event["extra"]; exists {
				t.Fatalf("a consumed %q must not reappear in extra: %#v", name, event["extra"])
			}
		}
	}
}

// TestNormalizeIPv4MappedDualKeysMergeInAnyArrangement: one line supplying
// both source_ip and src_ip merges as long as both spellings denote the
// mapped address. Swapping which spelling sits under which key name, and
// permuting member order, must yield the byte-identical success result. The
// consumed alias must not land in extra; unrelated unknown fields survive.
func TestNormalizeIPv4MappedDualKeysMergeInAnyArrangement(t *testing.T) {
	pairs := [][2]string{
		{plainIPv4Source, mappedDottedSource},
		{plainIPv4Source, mappedHexSource},
		{mappedDottedSource, mappedHexSource},
		// The same spelling given under both key names must merge too.
		{mappedDottedSource, mappedDottedSource},
	}
	for _, pair := range pairs {
		var inputs []string
		for _, assignment := range [][2]string{
			{pair[0], pair[1]},
			{pair[1], pair[0]}, // swap which spelling uses which key name
		} {
			a := kv{key: FieldSourceIP, val: `"` + assignment[0] + `"`}
			b := kv{key: "src_ip", val: `"` + assignment[1] + `"`}
			companions := append(append([]kv{}, sourceIPCompanions...), kv{key: "user", val: `"alice"`})
			inputs = append(inputs, dualOrderings(a, b, companions...)...)
		}
		shared := assertOrderInvariant(t, inputs, true, nil)
		event := eventOf(t, shared)
		if event[FieldSourceIP] != canonicalIPv4Field {
			t.Fatalf("pair %v must merge to %q, got %v", pair, canonicalIPv4Field, event[FieldSourceIP])
		}
		extra, ok := event["extra"].(map[string]any)
		if !ok {
			t.Fatalf("unrelated unknown field must be preserved for pair %v: %#v", pair, event)
		}
		if extra["user"] != "alice" {
			t.Fatalf("unknown field value mismatch: %#v", extra["user"])
		}
		if _, leaked := extra["src_ip"]; leaked {
			t.Fatalf("consumed alias src_ip must not be copied into extra: %#v", extra)
		}
		if len(extra) != 1 {
			t.Fatalf("only the unrelated field may appear in extra: %#v", extra)
		}
	}
}

// TestNormalizeEmbeddedIPv4WithoutMappedPrefixStaysIPv6 separates mapped
// addresses (::ffff:0:0/96) from other IPv6 addresses whose last 32 bits are
// written in dotted form. ::192.0.2.1 is ::c000:201, a different host from
// 192.0.2.1: it normalizes as IPv6 alone, merges with its own full spelling,
// and conflicts with both the IPv4 literal and the mapped spelling.
func TestNormalizeEmbeddedIPv4WithoutMappedPrefixStaysIPv6(t *testing.T) {
	t.Run("single spellings normalize as IPv6", func(t *testing.T) {
		for _, name := range []string{FieldSourceIP, "src_ip"} {
			input := `{"timestamp":"2026-01-02T00:00:00Z","` + name + `":"` + embeddedDottedSource + `","action":"login"}`
			results := runNormalize(t, input)
			if results[0]["ok"] != true {
				t.Fatalf("%s under %q must be a legal IPv6 address: %#v", embeddedDottedSource, name, results[0])
			}
			if got := eventOf(t, results[0])[FieldSourceIP]; got != canonicalIPv6Field {
				t.Fatalf("%s under %q -> %v, want %q", embeddedDottedSource, name, got, canonicalIPv6Field)
			}
		}
	})

	t.Run("merges with its own full spelling in any arrangement", func(t *testing.T) {
		var inputs []string
		for _, assignment := range [][2]string{
			{embeddedDottedSource, embeddedFullSource},
			{embeddedFullSource, embeddedDottedSource},
		} {
			a := kv{key: FieldSourceIP, val: `"` + assignment[0] + `"`}
			b := kv{key: "src_ip", val: `"` + assignment[1] + `"`}
			inputs = append(inputs, dualOrderings(a, b, sourceIPCompanions...)...)
		}
		shared := assertOrderInvariant(t, inputs, true, nil)
		if got := eventOf(t, shared)[FieldSourceIP]; got != canonicalIPv6Field {
			t.Fatalf("embedded and full spelling must merge to %q, got %v", canonicalIPv6Field, got)
		}
	})

	t.Run("conflicts with plain IPv4 and with the mapped spelling", func(t *testing.T) {
		// The conflict message quotes the values in canonical-key order, so
		// the two key assignments are compared separately; within each
		// assignment every member position must be byte-identical.
		others := []string{plainIPv4Source, mappedDottedSource, mappedHexSource}
		for _, other := range others {
			for _, assignment := range [][2]string{
				{embeddedDottedSource, other},
				{other, embeddedDottedSource}, // swap key names
			} {
				a := kv{key: FieldSourceIP, val: `"` + assignment[0] + `"`}
				b := kv{key: "src_ip", val: `"` + assignment[1] + `"`}
				inputs := dualOrderings(a, b, sourceIPCompanions...)
				shared := assertOrderInvariant(t, inputs, false, []string{
					FieldSourceIP, "conflicting values", canonicalIPv4Field, canonicalIPv6Field,
				})
				msg, _ := shared["error"].(string)
				if strings.Contains(msg, "invalid IP address") {
					t.Fatalf("two legal but distinct addresses must be a conflict, not an invalid address: %q", msg)
				}
			}
		}
	})
}

// TestNormalizeBracketedMappedAddressWithPortIsInvalidNotEquivalent: a legal
// IPv4 on one side and "[::ffff:192.0.2.1]:443" on the other must fail the
// whole line as an invalid source_ip even though stripping the brackets and
// port would reveal an equivalent address. The bad value is never dropped to
// let the merge succeed, and the failure must not masquerade as a conflict.
func TestNormalizeBracketedMappedAddressWithPortIsInvalidNotEquivalent(t *testing.T) {
	wantSubs := []string{FieldSourceIP, "invalid IP address", bracketedMappedWithPort}

	// Alone, under either key name, the result is already the same
	// invalid-address error naming the canonical field.
	var inputs []string
	for _, name := range []string{FieldSourceIP, "src_ip"} {
		inputs = append(inputs,
			`{"timestamp":"2026-01-02T00:00:00Z","`+name+`":"`+bracketedMappedWithPort+`","action":"login"}`,
		)
	}

	// Paired with a legal IPv4 literal, under both key assignments and in
	// every member position.
	for _, assignment := range [][2]string{
		{plainIPv4Source, bracketedMappedWithPort},
		{bracketedMappedWithPort, plainIPv4Source},
	} {
		a := kv{key: FieldSourceIP, val: `"` + assignment[0] + `"`}
		b := kv{key: "src_ip", val: `"` + assignment[1] + `"`}
		inputs = append(inputs, dualOrderings(a, b, sourceIPCompanions...)...)
	}

	shared := assertOrderInvariant(t, inputs, false, wantSubs)
	msg, _ := shared["error"].(string)
	if strings.Contains(msg, "conflicting values") {
		t.Fatalf("the bracketed value is invalid, not a conflicting-but-legal address: %q", msg)
	}
}

// TestNormalizeSourceIPEquivalenceMixedStream checks the public result shape
// across one stream: successes keep their physical line numbers and the
// normalized event (timestamp/action rules and unknown-field preservation
// included), failures keep their line numbers with ok:false and error and no
// event, and blank lines only advance the counter.
func TestNormalizeSourceIPEquivalenceMixedStream(t *testing.T) {
	input := "" +
		`{"timestamp":"2026-01-02T08:04:05+08:00","src_ip":"` + mappedDottedSource + `","event_type":" login ","user":"alice"}` + "\n" +
		"\n" +
		`{"source_ip":"` + embeddedDottedSource + `","src_ip":"` + plainIPv4Source + `","timestamp":"2026-01-02T00:00:00Z","action":"a"}` + "\n" +
		`{"source_ip":"` + plainIPv4Source + `","src_ip":"` + bracketedMappedWithPort + `","timestamp":"2026-01-02T00:00:00Z","action":"a"}` + "\n" +
		`{"source_ip":"` + embeddedDottedSource + `","src_ip":"` + embeddedFullSource + `","timestamp":"2026-01-02T00:00:00Z","action":"a","device":"gw-7"}` + "\n"
	results := runNormalize(t, input)
	if len(results) != 4 {
		t.Fatalf("expected 4 results for 5 physical lines, got %d: %#v", len(results), results)
	}

	first := results[0]
	if first["line"] != float64(1) || first["ok"] != true {
		t.Fatalf("mapped-address line must succeed on line 1: %#v", first)
	}
	event := eventOf(t, first)
	if event[FieldTimestamp] != "2026-01-02T00:04:05Z" {
		t.Fatalf("timestamp must still convert to UTC: %v", event[FieldTimestamp])
	}
	if event[FieldSourceIP] != canonicalIPv4Field {
		t.Fatalf("mapped spelling must canonicalize to %q, got %v", canonicalIPv4Field, event[FieldSourceIP])
	}
	if event[FieldAction] != "login" {
		t.Fatalf("action alias must still trim and map: %v", event[FieldAction])
	}
	if extra := event["extra"].(map[string]any); extra["user"] != "alice" {
		t.Fatalf("unknown field must survive on success: %#v", event["extra"])
	}

	for i, wantSubs := range [][]string{
		{"conflicting values", FieldSourceIP, canonicalIPv4Field, canonicalIPv6Field},
		{"invalid IP address", FieldSourceIP, bracketedMappedWithPort},
	} {
		bad := results[i+1]
		if bad["line"] != float64(i+3) || bad["ok"] != false {
			t.Fatalf("line %d must fail preserving its physical line number: %#v", i+3, bad)
		}
		if _, exists := bad["event"]; exists {
			t.Fatalf("line %d failure must not carry an event: %#v", i+3, bad)
		}
		msg, _ := bad["error"].(string)
		for _, sub := range wantSubs {
			if !strings.Contains(msg, sub) {
				t.Fatalf("line %d error %q must contain %q", i+3, msg, sub)
			}
		}
	}
	conflictMsg, _ := results[1]["error"].(string)
	if strings.Contains(conflictMsg, "invalid IP address") {
		t.Fatalf("line 3 must be a conflict of two legal addresses: %q", conflictMsg)
	}
	invalidMsg, _ := results[2]["error"].(string)
	if strings.Contains(invalidMsg, "conflicting values") {
		t.Fatalf("line 4 must be an invalid-address error: %q", invalidMsg)
	}

	last := results[3]
	if last["line"] != float64(5) || last["ok"] != true {
		t.Fatalf("embedded-IPv6 merge line must succeed on line 5: %#v", last)
	}
	lastEvent := eventOf(t, last)
	if lastEvent[FieldSourceIP] != canonicalIPv6Field {
		t.Fatalf("line 5 source_ip = %v, want %q", lastEvent[FieldSourceIP], canonicalIPv6Field)
	}
	if extra := lastEvent["extra"].(map[string]any); extra["device"] != "gw-7" {
		t.Fatalf("unknown field on line 5 must survive: %#v", lastEvent["extra"])
	}
}
