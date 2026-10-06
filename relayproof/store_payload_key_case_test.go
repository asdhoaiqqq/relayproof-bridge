package relayproof

// Recovery of a submit record's payload must not depend on the casing of its
// JSON field name. encoding/json matches struct fields case-insensitively, so a
// checksum-valid record that spells the field PAYLOAD, Payload or a mixed case
// still populates the same struct value as one using the conventional spelling;
// the plain/base64 presence split that protects message content must apply the
// same folding. These tests pin:
//
//   - a record carrying exactly one payload representation restores the same
//     bytes under every casing — plain text is read as saved text and a sole
//     base64 field restores its original bytes byte-for-byte (never the U+FFFD
//     replacement rune for invalid UTF-8);
//   - the restored bytes then take part in ordinary same-id comparison: an
//     identical resubmit of an unterminated message returns its record, while a
//     one-byte payload change is ErrConflict and keeps the original;
//   - both representations present in ANY casing combination — one empty, both
//     empty, or decoding to identical bytes — is corruption, as is a sole
//     undecodable base64 field under a re-cased key; the two verdicts keep
//     distinct wording, the open returns ErrCorrupt with no usable queue, and a
//     complete offending frame is never dropped as a torn tail even when normal
//     records precede it;
//   - the legal empty-payload shapes (both keys omitted, sole empty plain, sole
//     empty base64), re-cased keys included, still mean the empty payload.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// casedSubmitLog frames the leading version record plus one synthetic submit
// body whose payload member is spelled by the caller, so the field-name casing
// is exactly what is on disk.
func casedSubmitLog(t *testing.T, body string) []byte {
	t.Helper()
	var raw []byte
	raw = append(raw, logMagic...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
	raw = append(raw, encodeFrame([]byte(body))...)
	return raw
}

// casedSubmitBody wraps a literal payload JSON member in an otherwise normal
// seq-0 submit record.
func casedSubmitBody(payloadMember string) string {
	return `{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10,` + payloadMember + `}`
}

// flipOneByte returns a payload differing from want in exactly one byte.
func flipOneByte(want string) string {
	if len(want) == 0 {
		return "x"
	}
	b := []byte(want)
	b[len(b)-1] ^= 1
	return string(b)
}

// TestPayloadSoleRepresentationRestoresSameBytesAcrossCasings drives a record
// carrying exactly one payload representation through conventional, upper and
// mixed-case field names and requires identical restored content.
func TestPayloadSoleRepresentationRestoresSameBytesAcrossCasings(t *testing.T) {
	const helloB64 = "aGVsbG8=" // "hello"
	const ffB64 = "/w=="        // single byte 0xFF

	cases := []struct {
		name   string
		member string // literal payload JSON member
		want   string
	}{
		// Plain text is read as the saved text, regardless of field casing.
		{"plain conventional", `"payload":"hello"`, "hello"},
		{"plain upper", `"PAYLOAD":"hello"`, "hello"},
		{"plain capitalized", `"Payload":"hello"`, "hello"},
		{"plain mixed", `"pAyLoAd":"hello"`, "hello"},

		// A sole base64 representation restores its original bytes, including
		// invalid UTF-8 and ordinary text, under every casing.
		{"base64 conventional raw byte", `"payloadB64":"` + ffB64 + `"`, "\xff"},
		{"base64 upper raw byte", `"PAYLOADB64":"` + ffB64 + `"`, "\xff"},
		{"base64 capitalized raw byte", `"PayloadB64":"` + ffB64 + `"`, "\xff"},
		{"base64 mixed raw byte", `"pAyLoAdb64":"` + ffB64 + `"`, "\xff"},
		{"base64 upper text bytes", `"PAYLOADB64":"` + helloB64 + `"`, "hello"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			raw := casedSubmitLog(t, casedSubmitBody(tc.member))
			writeRawLog(t, dir, raw)

			q := reopen(t, dir)
			defer q.Close()

			got, ok := q.Query("m")
			if !ok {
				t.Fatal("restored message missing")
			}
			// Byte-exact: a re-cased sole base64 field must never come back as a
			// U+FFFD replacement rune or an empty payload.
			if got.Payload != tc.want {
				t.Fatalf("restored payload mismatch:\nwant % x\ngot  % x", tc.want, got.Payload)
			}

			// An identical resubmit of the unterminated message returns the
			// existing record and adds nothing. The envelope mirrors the
			// synthetic record's routing fields (from/to/nonce/proofAt).
			env := Envelope{Message: Message{
				ID: "m", From: "a", To: "b", Nonce: 1,
				Payload: tc.want, ProofAt: 10,
			}}
			echo, err := q.Submit(env)
			if err != nil {
				t.Fatalf("identical resubmit must return the existing record: %v", err)
			}
			if echo.Msg.Message.Payload != tc.want {
				t.Fatalf("resubmit echo payload = % x, want % x", echo.Msg.Message.Payload, tc.want)
			}
			if len(q.Queries()) != 1 {
				t.Fatalf("identical resubmit added a record: %d rows", len(q.Queries()))
			}

			// A one-byte payload change is a content conflict and keeps the
			// original message and its bytes.
			bad := env
			bad.Message.Payload = flipOneByte(tc.want)
			if _, err := q.Submit(bad); !errors.Is(err, ErrConflict) {
				t.Fatalf("one-byte payload change must be ErrConflict, got %v", err)
			}
			after, ok := q.Query("m")
			if !ok || after.Payload != tc.want {
				t.Fatalf("original payload not preserved after conflict: ok=%v % x", ok, after.Payload)
			}
			if len(q.Queries()) != 1 {
				t.Fatalf("conflicting resubmit added a record: %d rows", len(q.Queries()))
			}
		})
	}
}

// TestPayloadEmptyShapesStayEmptyAcrossCasings keeps the legal empty payloads
// empty: both keys omitted, a sole empty plain field (any casing) and a sole
// empty base64 field (any casing).
func TestPayloadEmptyShapesStayEmptyAcrossCasings(t *testing.T) {
	bodies := map[string]string{
		"both keys omitted":       `{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10}`,
		"sole empty plain":        casedSubmitBody(`"payload":""`),
		"sole empty plain upper":  casedSubmitBody(`"PAYLOAD":""`),
		"sole empty base64":       casedSubmitBody(`"payloadB64":""`),
		"sole empty base64 upper": casedSubmitBody(`"PAYLOADB64":""`),
		"sole empty base64 mixed": casedSubmitBody(`"PaYlOaDb64":""`),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeRawLog(t, dir, casedSubmitLog(t, body))

			q := reopen(t, dir)
			defer q.Close()
			got, ok := q.Query("m")
			if !ok || got.Payload != "" {
				t.Fatalf("want empty payload, got ok=%v % x", ok, got.Payload)
			}
			// Empty content resubmits as the same record; non-empty conflicts.
			env := Envelope{Message: Message{
				ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10,
			}}
			envEmpty := env
			envEmpty.Message.Payload = ""
			if _, err := q.Submit(envEmpty); err != nil {
				t.Fatalf("identical empty resubmit: %v", err)
			}
			envBad := env
			envBad.Message.Payload = "x"
			if _, err := q.Submit(envBad); !errors.Is(err, ErrConflict) {
				t.Fatalf("non-empty payload must conflict with the empty record: %v", err)
			}
		})
	}
}

// assertCorruptUntouched opens dir, requires ErrCorrupt with no usable queue
// and an error message naming wantMsg, and requires queue.log to stay
// byte-for-byte as written.
func assertCorruptUntouched(t *testing.T, dir string, wantLog []byte, wantMsg string) {
	t.Helper()
	q, err := Open(dir)
	if !errors.Is(err, ErrCorrupt) {
		if q != nil {
			q.Close()
		}
		t.Fatalf("want ErrCorrupt, got %v (queue=%v)", err, q != nil)
	}
	if q != nil {
		q.Close()
		t.Fatal("corrupt open must not return a usable queue")
	}
	if wantMsg != "" && !strings.Contains(err.Error(), wantMsg) {
		t.Fatalf("corrupt error %q does not name %q", err.Error(), wantMsg)
	}
	got, rerr := os.ReadFile(filepath.Join(dir, logName))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != string(wantLog) {
		t.Fatalf("corrupt log was modified: want %d bytes, got %d bytes", len(wantLog), len(got))
	}
}

// TestPayloadDualRepresentationAnyCasingRejected requires both representations
// present under every casing combination to be rejected as a representation
// conflict — including one or both values empty or the two forms decoding to
// the same bytes, and regardless of key order.
func TestPayloadDualRepresentationAnyCasingRejected(t *testing.T) {
	plainKeys := []string{"payload", "PAYLOAD", "Payload", "pAyLoAd"}
	b64Keys := []string{"payloadB64", "PAYLOADB64", "PayloadB64", "pAyLoAdb64"}

	// value shapes that must never allow one representation to be picked: each
	// is (plain value literal, base64 value literal).
	shapes := []struct {
		name     string
		plainVal string
		b64Val   string
	}{
		{"empty plain plus 0xff base64", ``, `/w==`},
		{"non-empty plain plus empty base64", `x`, ``},
		{"both empty", ``, ``},
		{"both decode to the same bytes", `x`, `eA==`},
	}

	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			for _, pk := range plainKeys {
				for _, bk := range b64Keys {
					plainMember := `"` + pk + `":"` + shape.plainVal + `"`
					b64Member := `"` + bk + `":"` + shape.b64Val + `"`
					t.Run(pk+"+"+bk, func(t *testing.T) {
						dir := t.TempDir()
						raw := casedSubmitLog(t, casedSubmitBody(plainMember+","+b64Member))
						writeRawLog(t, dir, raw)
						assertCorruptUntouched(t, dir, raw, "both payload and payloadB64")
					})
				}
			}
		})
	}

	// Key order never changes the verdict: the re-cased base64 key first, then
	// a conventional plain key.
	t.Run("base64 key first", func(t *testing.T) {
		dir := t.TempDir()
		member := `"PAYLOADB64":"/w==","payload":""`
		raw := casedSubmitLog(t, casedSubmitBody(member))
		writeRawLog(t, dir, raw)
		assertCorruptUntouched(t, dir, raw, "both payload and payloadB64")
	})
}

// TestPayloadUndecodableReCasedB64Rejected requires a sole re-cased base64
// field whose value cannot decode to be rejected as invalid encoding (distinct
// from the representation-conflict verdict), never silently restored as an
// empty payload.
func TestPayloadUndecodableReCasedB64Rejected(t *testing.T) {
	for _, key := range []string{"payloadB64", "PAYLOADB64", "PayloadB64", "pAyLoAdb64"} {
		t.Run(key, func(t *testing.T) {
			dir := t.TempDir()
			raw := casedSubmitLog(t, casedSubmitBody(`"`+key+`":"!!!not-base64!!!"`))
			writeRawLog(t, dir, raw)
			q, err := Open(dir)
			if !errors.Is(err, ErrCorrupt) {
				if q != nil {
					q.Close()
				}
				t.Fatalf("want ErrCorrupt, got %v", err)
			}
			if q != nil {
				q.Close()
				t.Fatal("corrupt open must not return a usable queue")
			}
			msg := err.Error()
			if !strings.Contains(msg, "undecodable payloadB64") {
				t.Fatalf("want an invalid-encoding verdict, got %q", msg)
			}
			if strings.Contains(msg, "both payload and payloadB64") {
				t.Fatalf("encoding failure must not be reported as a representation conflict: %q", msg)
			}
			got, rerr := os.ReadFile(filepath.Join(dir, logName))
			if rerr != nil {
				t.Fatal(rerr)
			}
			if string(got) != string(raw) {
				t.Fatalf("corrupt log was modified: want %d bytes, got %d bytes", len(raw), len(got))
			}
		})
	}
}

// TestPayloadReCasedCorruptionAfterNormalRecords verifies a complete offending
// frame is never treated as an unwritten torn tail: placed after normal
// records, the whole directory is refused and every log byte — including the
// good leading message — is preserved, so none of the earlier records can be
// queried.
func TestPayloadReCasedCorruptionAfterNormalRecords(t *testing.T) {
	dir := t.TempDir()
	var raw []byte
	raw = append(raw, logMagic...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
	// One good, ordinary message at seq 0.
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 0, ID: "ok", From: "a", To: "b", Nonce: 1,
		Payload: "normal", ProofAt: 10,
	}))...)

	t.Run("dual representation", func(t *testing.T) {
		log := append(append([]byte(nil), raw...), encodeFrame([]byte(
			`{"t":"submit","seq":1,"id":"bad","from":"a","to":"b","nonce":2,"proofAt":10,"PAYLOAD":"","payloadB64":"/w=="}`))...)
		writeRawLog(t, dir, log)
		assertCorruptUntouched(t, dir, log, "both payload and payloadB64")
	})

	t.Run("undecodable base64", func(t *testing.T) {
		log := append(append([]byte(nil), raw...), encodeFrame([]byte(
			`{"t":"submit","seq":1,"id":"bad","from":"a","to":"b","nonce":2,"proofAt":10,"PAYLOADB64":"%not-base64%"}`))...)
		writeRawLog(t, dir, log)
		assertCorruptUntouched(t, dir, log, "undecodable payloadB64")
	})
}

// TestSplitKeyPresenceIsCaseInsensitive guards the shared presence layer
// directly: every presence-tracked plain/base64 pair must recognize its keys
// under re-cased spellings, so a re-cased sole base64 key is present (and
// decodes) while a re-cased plain key next to a canonical base64 key reads as
// two representations.
func TestSplitKeyPresenceIsCaseInsensitive(t *testing.T) {
	pairs := []struct {
		name     string
		plainKey string
		b64Key   string
		spec     splitFieldSpec
		rawB64   string // decodes to a single valid byte 0x78 ("x")
	}{
		{"root", "root", "rootB64", splitFields.root, "eA=="},
		{"payload", "payload", "payloadB64", splitFields.payload, "eA=="},
		{"to", "to", "toB64", splitFields.to, "eA=="},
		{"consumeTo", "consumeTo", "consumeToB64", splitFields.consumeTo, "eA=="},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			upper := func(k string) string { return strings.ToUpper(k) }

			// A sole upper-case base64 key is present and decodes to its bytes.
			sole := `{"` + upper(p.b64Key) + `":"` + p.rawB64 + `"}`
			var e logEntry
			if err := json.Unmarshal([]byte(sole), &e); err != nil {
				t.Fatal(err)
			}
			if !e.present[p.b64Key] || e.present[p.plainKey] {
				t.Fatalf("sole %s presence wrong: %+v", upper(p.b64Key), e.present)
			}
			if got, err := p.spec.decode(&e); err != nil || got != "x" {
				t.Fatalf("sole re-cased base64 decode: got %q err=%v", got, err)
			}

			// A re-cased plain key next to the canonical base64 key is the clash.
			both := `{"` + upper(p.plainKey) + `":"x","` + p.b64Key + `":"` + p.rawB64 + `"}`
			var e2 logEntry
			if err := json.Unmarshal([]byte(both), &e2); err != nil {
				t.Fatal(err)
			}
			if !e2.present[p.plainKey] || !e2.present[p.b64Key] {
				t.Fatalf("dual-key presence wrong: %+v", e2.present)
			}
			if _, err := p.spec.decode(&e2); err == nil || err.Error() != p.spec.bothErr {
				t.Fatalf("re-cased dual keys: want %q, got %v", p.spec.bothErr, err)
			}
		})
	}
}
