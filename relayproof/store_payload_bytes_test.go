package relayproof

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Message payloads are arbitrary byte strings compared byte for byte. A
// payload holding invalid UTF-8 bytes must survive saving, reopening and log
// compaction exactly: JSON string encoding would otherwise silently rewrite
// such bytes to U+FFFD, making the resubmitted original payload conflict
// with its own saved value while the replacement character is wrongly
// accepted.

// requirePayloadRecord requires the record for id to carry exactly want as
// its payload in the single-message view, the all-messages listing and the
// resubmit echo.
func requirePayloadRecord(t *testing.T, q *Queue, id, want string) {
	t.Helper()
	qy, ok := q.Query(id)
	if !ok {
		t.Fatalf("missing %s", id)
	}
	if qy.Payload != want {
		t.Fatalf("query payload wrong:\nwant %q\ngot  %q", want, qy.Payload)
	}
	all := q.Queries()
	if len(all) != 1 || all[0].ID != id || all[0].Payload != want {
		t.Fatalf("listing payload wrong: %+v", all)
	}
}

// An invalid-UTF-8 payload is preserved byte-for-byte through save, close,
// reopen and compaction: the identical byte sequence resubmits idempotently,
// while a payload differing in any byte — and the legal character U+FFFD,
// which must never be merged with invalid bytes — conflicts, before and
// after every persistence boundary.
func TestPayloadInvalidUTF8PreservedAcrossReopenAndCompaction(t *testing.T) {
	payloadFF := string([]byte{0xFF})
	payloadFE := string([]byte{0xFE})
	mixed := "pre" + string([]byte{0xFF, 0x00, 0xFE}) + "post"

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	envFF := Envelope{Message: Message{ID: "m", From: "a", To: "b", Nonce: 1, Payload: payloadFF, ProofAt: 10}}
	if _, err := q.Submit(envFF); err != nil {
		t.Fatalf("submit invalid-UTF-8 payload: %v", err)
	}

	check := func(t *testing.T, q *Queue) {
		t.Helper()
		// The exact same bytes resubmit idempotently: the existing record is
		// returned and nothing is added or rescheduled.
		again, err := q.Submit(envFF)
		if err != nil {
			t.Fatalf("identical resubmit must be accepted: %v", err)
		}
		if again.Msg != envFF || again.Status != StatusPending {
			t.Fatalf("resubmit echo wrong: %+v", again)
		}
		if len(q.records) != 1 || len(q.order) != 1 || q.nextSeq != 1 {
			t.Fatalf("identical resubmit added state: records=%d order=%v nextSeq=%d",
				len(q.records), q.order, q.nextSeq)
		}
		requirePayloadRecord(t, q, "m", payloadFF)

		// Any single-byte difference is a conflict, and U+FFFD is a distinct
		// payload, never the canonical form of invalid bytes.
		for _, other := range []string{payloadFE, replacementCharRoot, mixed} {
			changed := envFF
			changed.Message.Payload = other
			if _, err := q.Submit(changed); !errors.Is(err, ErrConflict) {
				t.Fatalf("payload %q: want ErrConflict, got %v", other, err)
			}
			requirePayloadRecord(t, q, "m", payloadFF)
		}
	}
	t.Run("same instance", func(t *testing.T) { check(t, q) })
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	t.Run("after reopen", func(t *testing.T) { check(t, q) })

	// Force a compaction cycle; the snapshot must carry the exact bytes too.
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	t.Run("after compaction and reopen", func(t *testing.T) { check(t, q) })
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// The persisted log holds the raw bytes base64-encoded and never the
	// replacement character.
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"payloadB64":"`)) {
		t.Fatalf("invalid-UTF-8 payload not stored byte-exactly: %s", raw)
	}
	if bytes.Contains(raw, []byte(replacementCharRoot)) {
		t.Fatalf("log contains U+FFFD: a payload was silently rewritten: %s", raw)
	}
}

// Byte-distinct invalid payloads — 0xFF, 0xFE and the genuine character
// U+FFFD — are three different contents that coexist as separate messages
// and never substitute for one another, across reopen and compaction.
func TestPayloadInvalidBytesDistinctFromReplacementChar(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	payloads := map[string]string{
		"ff":  string([]byte{0xFF}),
		"fe":  string([]byte{0xFE}),
		"rep": replacementCharRoot,
		"nul": "a\x00b",
	}
	for id, p := range payloads {
		if _, err := q.Submit(Envelope{Message: Message{ID: id, From: "a", To: "b", Nonce: 1, Payload: p}}); err != nil {
			t.Fatalf("submit %q: %v", p, err)
		}
	}
	check := func(t *testing.T, q *Queue) {
		t.Helper()
		all := q.Queries()
		if len(all) != len(payloads) {
			t.Fatalf("want %d records, got %+v", len(payloads), all)
		}
		for id, want := range payloads {
			qy, ok := q.Query(id)
			if !ok || qy.Payload != want {
				t.Fatalf("record %s: want payload %q, got %+v", id, want, qy)
			}
		}
	}
	check(t, q)
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q = reopen(t, dir)
	check(t, q)
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q = reopen(t, dir)
	check(t, q)
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
}

// Valid-UTF-8 payloads — plain text, empty, whitespace, U+FFFD itself — keep
// the historical plain "payload" field, so logs written by older builds and
// this build remain byte-identical and existing state directories keep
// working.
func TestPayloadValidUTF8KeepsHistoricalEncoding(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	payloads := []string{"hello world", "", " spaced ", replacementCharRoot}
	for i, p := range payloads {
		id := string(rune('m' + i))
		if _, err := q.Submit(Envelope{Message: Message{ID: id, From: "a", To: "b", Nonce: 1, Payload: p}}); err != nil {
			t.Fatalf("submit payload %q: %v", p, err)
		}
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("payloadB64")) {
		t.Fatalf("valid-UTF-8 payloads must keep the plain payload field: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"payload":"hello world"`)) {
		t.Fatalf("plain payload missing from log: %s", raw)
	}

	// Reopen: every payload means exactly what it meant before, including the
	// empty payload and U+FFFD as an ordinary legal character.
	q = reopen(t, dir)
	defer q.Close()
	for i, want := range payloads {
		id := string(rune('m' + i))
		qy, ok := q.Query(id)
		if !ok || qy.Payload != want {
			t.Fatalf("record %s: want payload %q, got %+v", id, want, qy)
		}
	}
}

// A state directory written by an older build may already hold a payload
// that was silently rewritten to U+FFFD. Replay takes the saved characters
// at face value — the lost bytes are never guessed — so the replacement
// character is the stored payload and the original invalid bytes conflict
// with it.
func TestPayloadLegacyReplacementCharTakenAtFaceValue(t *testing.T) {
	dir := t.TempDir()
	var raw []byte
	raw = append(raw, logMagic...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1,
		Payload: replacementCharRoot, ProofAt: 10,
	}))...)
	writeRawLog(t, dir, raw)

	q := reopen(t, dir)
	defer q.Close()
	qy, ok := q.Query("m")
	if !ok || qy.Payload != replacementCharRoot {
		t.Fatalf("legacy payload must be taken at face value: %+v", qy)
	}
	same := Envelope{Message: Message{ID: "m", From: "a", To: "b", Nonce: 1, Payload: replacementCharRoot, ProofAt: 10}}
	if _, err := q.Submit(same); err != nil {
		t.Fatalf("identical resubmit of legacy payload: %v", err)
	}
	changed := same
	changed.Message.Payload = string([]byte{0xFF})
	if _, err := q.Submit(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("original invalid bytes must conflict with the saved U+FFFD: %v", err)
	}
}

// A payloadB64 entry must decode unambiguously: an entry carrying both
// payload and payloadB64, or an undecodable payloadB64, is an inconsistent
// record no build writes and rejects the directory as corrupt, leaving every
// byte untouched — the payload is never treated as empty or substituted.
func TestPayloadB64InconsistentRecordsRejected(t *testing.T) {
	for name, e := range map[string]*logEntry{
		"both payload and payloadB64": {T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, Payload: "x", PayloadB64: "eA=="},
		"undecodable payloadB64":      {T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, PayloadB64: "!!!not-base64!!!"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var raw []byte
			raw = append(raw, logMagic...)
			raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
			raw = append(raw, encodeFrame(mustMarshal(e))...)
			writeRawLog(t, dir, raw)
			assertCorruptAndUntouched(t, dir, raw)
		})
	}
}

// A message with an invalid-UTF-8 payload that has already been processed —
// successfully delivered or terminally rejected — keeps its exact payload
// through compaction and reopen, and its terminal id still refuses
// resubmission.
func TestPayloadInvalidUTF8SurvivesCompactionOfTerminalRecords(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	payload := "bin" + string([]byte{0xFF, 0xFE}) + "ary"
	delivered := Envelope{Message: Message{ID: "ok", From: "a", To: "b", Nonce: 1, Payload: payload, ProofAt: 10}}
	rejected := Envelope{Message: Message{ID: "no", From: "ghost", To: "b", Nonce: 2, Payload: string([]byte{0xFF}), ProofAt: 10}}
	for _, e := range []Envelope{delivered, rejected} {
		if _, err := q.Submit(e); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := q.Advance(1_700_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 2 || rep.Results[0].Status != StatusSuccess || rep.Results[1].Status != StatusUnknownSrc {
		t.Fatalf("setup: want success and unknown-source, got %+v", rep.Results)
	}

	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	defer q.Close()
	for id, want := range map[string]string{"ok": payload, "no": string([]byte{0xFF})} {
		qy, ok := q.Query(id)
		if !ok || qy.Payload != want {
			t.Fatalf("terminal record %s lost its payload: %+v", id, qy)
		}
	}
	if _, err := q.Submit(delivered); !errors.Is(err, ErrTerminal) {
		t.Fatalf("terminal id must refuse resubmission: %v", err)
	}
}
