package main

// End-to-end CLI behaviour when an existing state directory's queue.log
// carries a complete, checksummed submit record whose payload field is
// spelled with an upper or mixed case. encoding/json matches struct fields
// case-insensitively, so re-casing a JSON key never makes the record a
// different shape: both payload representations present in ANY casing — one
// empty, both empty, or decoding to the same bytes — is on-disk corruption,
// and a sole undecodable base64 field under a re-cased key is invalid
// encoding rather than a silent empty payload. Opening the directory (a query
// listing, a single-id lookup, or a fresh submit that would otherwise append)
// must fail with the corrupt exit code 12, print no query records, return no
// usable queue and leave queue.log byte-for-byte untouched — even when the
// offending frame is the last one (a complete record is never a torn tail)
// and even when normal records precede it. The two verdicts stay
// distinguishable in stderr.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cliCasedPayloadLog frames the leading version record plus one literal submit
// body, so the payload field-name casing is exactly what sits on disk.
func cliCasedPayloadLog(body string) []byte {
	var raw []byte
	raw = append(raw, cliLogMagic...)
	raw = append(raw, cliFrame([]byte(`{"t":"version","v":1}`))...)
	raw = append(raw, cliFrame([]byte(body))...)
	return raw
}

func cliCasedSubmitBody(payloadMembers string) string {
	return `{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10,` + payloadMembers + `}`
}

// assertPayloadEncodingCorruptExit12 pins the invalid-encoding surface: exit
// 12, no stdout, a stderr naming an undecodable payloadB64 (and never the
// both-representations wording), and an untouched queue.log.
func assertPayloadEncodingCorruptExit12(t *testing.T, r cliResult, state string, wantLog []byte) {
	t.Helper()
	if r.code != 12 {
		t.Fatalf("want corrupt exit code 12, got %d (stdout=%q stderr=%q)", r.code, r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a corrupt directory must print no query results: %q", r.stdout)
	}
	if !strings.Contains(r.stderr, "corrupt") || !strings.Contains(r.stderr, "undecodable payloadB64") {
		t.Fatalf("stderr must name corrupt + undecodable payloadB64:\n%s", r.stderr)
	}
	if strings.Contains(r.stderr, "both payload and payloadB64") {
		t.Fatalf("invalid encoding must not be reported as a representation conflict:\n%s", r.stderr)
	}
	got, err := os.ReadFile(filepath.Join(state, "queue.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wantLog) {
		t.Fatalf("queue.log changed on rejected open: want %d bytes, got %d bytes", len(wantLog), len(got))
	}
}

// TestCLIPayloadDualRepresentationAnyCasingCorrupt drives every casing
// combination of the two field names, each in a shape that must never let one
// representation be picked (one empty, both empty, equal bytes). Every log
// must be refused with exit 12 and left untouched.
func TestCLIPayloadDualRepresentationAnyCasingCorrupt(t *testing.T) {
	plainKeys := []string{"payload", "PAYLOAD", "Payload", "pAyLoAd"}
	b64Keys := []string{"payloadB64", "PAYLOADB64", "PayloadB64", "pAyLoAdb64"}
	shapes := []struct {
		name     string
		plainVal string
		b64Val   string
	}{
		{"empty plain plus 0xff base64", "", "/w=="},
		{"non-empty plain plus empty base64", "x", ""},
		{"both empty", "", ""},
		{"equal bytes", "x", "eA=="},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			for _, pk := range plainKeys {
				for _, bk := range b64Keys {
					members := `"` + pk + `":"` + shape.plainVal + `","` + bk + `":"` + shape.b64Val + `"`
					state := t.TempDir()
					raw := cliCasedPayloadLog(cliCasedSubmitBody(members))
					writeCLIStateLog(t, state, raw)
					assertPayloadCorruptExit12(t, queueCLI(t, state, "query"), state, raw)
				}
			}
		})
	}
}

// A re-cased plain key with a canonical base64 key, and the reverse, were the
// exact bypasses: with literal key matching the two looked like one
// representation. As the final complete frame the directory must still be
// refused for query, single-id lookup and a fresh submit (which must not
// append), repeatedly.
func TestCLIPayloadReCasedDualKeysRefusedEverywhere(t *testing.T) {
	bodies := map[string]string{
		"upper plain, canonical b64": cliCasedSubmitBody(`"PAYLOAD":"","payloadB64":"/w=="`),
		"canonical plain, upper b64": cliCasedSubmitBody(`"payload":"","PAYLOADB64":"/w=="`),
		"both upper, base64 first":   `{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10,"PAYLOADB64":"/w==","PAYLOAD":""}`,
		"mixed case pair":            cliCasedSubmitBody(`"PaYlOaD":"x","pAyLoAdb64":"eA=="`),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			raw := cliCasedPayloadLog(body)
			writeCLIStateLog(t, state, raw)

			assertPayloadCorruptExit12(t, queueCLI(t, state, "query"), state, raw)
			assertPayloadCorruptExit12(t, queueCLI(t, state, "query", "--id", "m"), state, raw)

			r := queueCLI(t, state, "submit",
				"--id", "other", "--from", "a", "--to", "b",
				"--nonce", "2", "--proof-at", "10", "--payload", "fresh")
			assertPayloadCorruptExit12(t, r, state, raw)

			// Stays unopenable and byte-identical.
			assertPayloadCorruptExit12(t, queueCLI(t, state, "query"), state, raw)
		})
	}
}

// A sole base64 field under a re-cased key whose value cannot decode used to
// look like an omitted base64 key and was silently restored as an empty
// payload. It must instead refuse the directory as invalid encoding with exit
// 12, an error distinct from the both-representations verdict, leaving the
// file untouched — even when a normal record precedes the corrupt one.
func TestCLIPayloadUndecodableReCasedB64Corrupt(t *testing.T) {
	for _, key := range []string{"PAYLOADB64", "PayloadB64", "pAyLoAdb64"} {
		t.Run(key, func(t *testing.T) {
			state := t.TempDir()
			raw := cliCasedPayloadLog(cliCasedSubmitBody(`"` + key + `":"!!!not-base64!!!"`))
			writeCLIStateLog(t, state, raw)

			assertPayloadEncodingCorruptExit12(t, queueCLI(t, state, "query"), state, raw)
			assertPayloadEncodingCorruptExit12(t, queueCLI(t, state, "query", "--id", "m"), state, raw)

			r := queueCLI(t, state, "submit",
				"--id", "other", "--from", "a", "--to", "b",
				"--nonce", "2", "--proof-at", "10", "--payload", "fresh")
			assertPayloadEncodingCorruptExit12(t, r, state, raw)
		})
	}
}

// Re-cased corruption after a normal record hides the earlier record too: the
// whole open is refused, not partially served.
func TestCLIPayloadReCasedCorruptionHidesNormalResults(t *testing.T) {
	state := t.TempDir()

	// One normal, accepted message through the real CLI.
	submitMsg(t, state, "m1", "x", "y", 1, 90)

	path := filepath.Join(state, "queue.log")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("dual representation", func(t *testing.T) {
		log := append(append([]byte(nil), raw...), cliFrame([]byte(
			`{"t":"submit","seq":1,"id":"bad","from":"x","to":"y","nonce":2,"proofAt":90,"PAYLOAD":"","payloadB64":"/w=="}`))...)
		writeCLIStateLog(t, state, log)
		r := queueCLI(t, state, "query")
		assertPayloadCorruptExit12(t, r, state, log)
		if strings.Contains(r.stdout, "m1") {
			t.Fatalf("normal message must not be served from a corrupt directory: %q", r.stdout)
		}
	})

	t.Run("undecodable base64", func(t *testing.T) {
		log := append(append([]byte(nil), raw...), cliFrame([]byte(
			`{"t":"submit","seq":1,"id":"bad","from":"x","to":"y","nonce":2,"proofAt":90,"PAYLOADB64":"%not-base64%"}`))...)
		writeCLIStateLog(t, state, log)
		r := queueCLI(t, state, "query")
		assertPayloadEncodingCorruptExit12(t, r, state, log)
		if strings.Contains(r.stdout, "m1") {
			t.Fatalf("normal message must not be served from a corrupt directory: %q", r.stdout)
		}
	})
}
