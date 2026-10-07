package relayproof

// These tests pin the single shared plain/base64 recovery rule behind
// splitFieldSpec.decode — the inverse of every raw-bytes log field's encoding
// (header root, message payload, submit source and destination, source/header
// chain name, consumed source and destination, and the value-based pairs
// message id / reason / consuming id). Each field pair must keep exactly one
// behavior matrix, while keeping its own business value and its own corruption
// wording. The end-to-end open/compaction semantics are covered by the
// per-field tests; this table guards the shared rule itself so the rule cannot
// silently drift per field again.

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// decodeEntry unmarshals one synthetic record body so key presence is recorded
// exactly as it is on replay, then runs the field's shared decoder.
func decodeEntry(t *testing.T, body map[string]any, spec splitFieldSpec) (string, error) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var e logEntry
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	return spec.decode(&e)
}

// rawRoundTrip mixes Chinese text, a colon, a NUL and invalid UTF-8 bytes: all
// four must come back from the base64 form exactly, with no replacement.
var rawRoundTrip = "链:\x00" + string([]byte{0xFF, 0xFE})

// TestSplitFieldSharedDecoderMatrix drives every field pair through the same
// shapes and asserts the single rule set: plain face value, sole base64
// (including empty) restored to exact bytes, dual representations corrupt by
// presence, undecodable base64 corrupt with the field's own wording.
func TestSplitFieldSharedDecoderMatrix(t *testing.T) {
	rawB64 := base64.StdEncoding.EncodeToString([]byte(rawRoundTrip))
	ffB64 := base64.StdEncoding.EncodeToString([]byte{0xFF})

	type field struct {
		name     string
		spec     splitFieldSpec
		plainKey string // real JSON plain key, even for value-based pairs
		presence bool   // presence-tracked pair (root/payload/to/from/chain/consumeTo/consumeFrom)
	}
	fields := []field{
		{"id", splitFields.id, "id", false},
		{"reason", splitFields.reason, "reason", false},
		{"consumeBy", splitFields.consumeBy, "consumeBy", false},
		{"root", splitFields.root, "root", true},
		{"payload", splitFields.payload, "payload", true},
		{"to", splitFields.to, "to", true},
		{"from", splitFields.from, "from", true},
		{"chain", splitFields.chain, "chain", true},
		{"consumeTo", splitFields.consumeTo, "consumeTo", true},
		{"consumeFrom", splitFields.consumeFrom, "consumeFrom", true},
	}

	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			b64Key := f.spec.b64Key

			// No base64: the plain value is taken at face value, including an
			// omitted plain key (the historical empty root/payload) and bytes a
			// legacy build had rewritten to U+FFFD.
			for _, plain := range []string{"", "legacy-" + replacementCharRoot, "链:a\x00b"} {
				got, err := decodeEntry(t, map[string]any{f.plainKey: plain}, f.spec)
				if err != nil || got != plain {
					t.Fatalf("plain-only %q: got %q err=%v", plain, got, err)
				}
			}
			if got, err := decodeEntry(t, map[string]any{}, f.spec); err != nil || got != "" {
				t.Fatalf("both keys omitted: got %q err=%v, want empty", got, err)
			}

			// A sole base64 form restores the exact bytes; an empty sole base64
			// restores the empty value.
			if got, err := decodeEntry(t, map[string]any{b64Key: rawB64}, f.spec); err != nil || got != rawRoundTrip {
				t.Fatalf("sole b64 raw bytes: got % x err=%v", got, err)
			}
			if got, err := decodeEntry(t, map[string]any{b64Key: ""}, f.spec); err != nil || got != "" {
				t.Fatalf("sole empty b64: got %q err=%v, want empty", got, err)
			}

			// An undecodable sole base64 is corruption named after this field.
			_, err := decodeEntry(t, map[string]any{b64Key: "!!!not-base64!!!"}, f.spec)
			if err == nil || !strings.HasPrefix(err.Error(), f.spec.undecodableErr+":") {
				t.Fatalf("undecodable b64: want %q, got %v", f.spec.undecodableErr, err)
			}

			// Two non-empty representations always clash with this field's
			// wording, whether or not they decode to the same bytes.
			dual := map[string]any{f.plainKey: "x", b64Key: "eA=="}
			if _, err := decodeEntry(t, dual, f.spec); err == nil || err.Error() != f.spec.bothErr {
				t.Fatalf("dual non-empty: want %q, got %v", f.spec.bothErr, err)
			}

			if f.presence {
				// Presence-tracked pairs: an empty-but-present plain value still
				// clashes with any base64 key, including an empty one and one
				// that decodes to the same/empty bytes.
				for _, b64 := range []string{ffB64, ""} {
					if _, err := decodeEntry(t, map[string]any{f.plainKey: "", b64Key: b64}, f.spec); err == nil ||
						err.Error() != f.spec.bothErr {
						t.Fatalf("empty plain + b64 %q must clash: want %q, got %v", b64, f.spec.bothErr, err)
					}
				}
				// Field order never changes the verdict: the base64 key first
				// must be rejected identically.
				ordered := `{"` + b64Key + `":"eA==","` + f.plainKey + `":"x"}`
				var e logEntry
				if err := json.Unmarshal([]byte(ordered), &e); err != nil {
					t.Fatal(err)
				}
				if _, err := f.spec.decode(&e); err == nil || err.Error() != f.spec.bothErr {
					t.Fatalf("base64-key-first dual record: want %q, got %v", f.spec.bothErr, err)
				}
			} else {
				// Value-based pairs keep their historical edge: a non-empty plain
				// value with an empty base64 string is just the plain value
				// (empty base64 means the form is absent).
				if got, err := decodeEntry(t, map[string]any{f.plainKey: "x", b64Key: ""}, f.spec); err != nil || got != "x" {
					t.Fatalf("plain + empty b64 legacy edge: got %q err=%v", got, err)
				}
			}
		})
	}
}

// TestSplitFieldDescriptorWordingIsFieldSpecific guards that the shared rule
// preserves distinguishable corruption diagnostics per field: no two fields
// share the same wording, and every wording names its own JSON keys.
func TestSplitFieldDescriptorWordingIsFieldSpecific(t *testing.T) {
	specs := []struct {
		key string
		s   splitFieldSpec
	}{
		{"idB64", splitFields.id},
		{"reasonB64", splitFields.reason},
		{"consumeByB64", splitFields.consumeBy},
		{"rootB64", splitFields.root},
		{"payloadB64", splitFields.payload},
		{"toB64", splitFields.to},
		{"fromB64", splitFields.from},
		{"chainB64", splitFields.chain},
		{"consumeToB64", splitFields.consumeTo},
		{"consumeFromB64", splitFields.consumeFrom},
	}
	seenBoth := map[string]string{}
	seenUndec := map[string]string{}
	for _, c := range specs {
		if c.s.b64Key != c.key {
			t.Fatalf("descriptor b64Key = %q, want %q", c.s.b64Key, c.key)
		}
		if !strings.Contains(c.s.undecodableErr, c.key) {
			t.Fatalf("%s wording must name its field: %q", c.key, c.s.undecodableErr)
		}
		if prev, dup := seenBoth[c.s.bothErr]; dup {
			t.Fatalf("both-representation wording shared by %s and %s: %q", prev, c.key, c.s.bothErr)
		}
		seenBoth[c.s.bothErr] = c.key
		if prev, dup := seenUndec[c.s.undecodableErr]; dup {
			t.Fatalf("undecodable wording shared by %s and %s: %q", prev, c.key, c.s.undecodableErr)
		}
		seenUndec[c.s.undecodableErr] = c.key
	}
}
