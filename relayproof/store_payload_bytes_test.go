package relayproof

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Message payloads are arbitrary byte strings compared byte for byte in the
// same-id content check. The Go submit interface never requires a payload to
// be valid UTF-8: it may be empty, plain text, hold NUL bytes or stray
// 0xFF/0xFE bytes, or mix text with them. Such a payload must survive the
// submit echo, single and full queries, an identical resubmit, reopen and log
// compaction exactly — JSON string encoding would otherwise silently rewrite
// the invalid bytes to U+FFFD, so a byte-identical resubmit of an
// unterminated message would wrongly conflict after a reopen.

const replacementCharPayload = "�"

// payloadEnvelope builds a non-terminal envelope carrying payload; each call
// site supplies a distinct nonce so processing one message can never replay
// another.
func payloadEnvelope(id string, nonce uint64, payload string) Envelope {
	return Envelope{
		Message: Message{
			ID:      id,
			From:    "chain-a",
			To:      "chain-b",
			Nonce:   nonce,
			Payload: payload,
			ProofAt: 90,
		},
	}
}

// Every payload shape must come back byte-identical from the submit echo, a
// single Query and the full Queries listing.
func TestPayloadArbitraryBytesPreservedInInstance(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()

	names := []string{"empty", "plain", "nul", "ff", "fe", "fffe", "mixed", "replacement"}
	payloads := map[string]string{
		"empty":       "",
		"plain":       "hello",
		"nul":         "a\x00b\x00",
		"ff":          string([]byte{0xFF}),
		"fe":          string([]byte{0xFE}),
		"fffe":        string([]byte{0xFF, 0xFE}),
		"mixed":       "pre\x00mid" + string([]byte{0xFF, 0xFE}) + "post",
		"replacement": replacementCharPayload,
	}
	for i, name := range names {
		if _, err := q.Submit(payloadEnvelope(name, uint64(i+1), payloads[name])); err != nil {
			t.Fatalf("submit %s: %v", name, err)
		}
	}

	for i, name := range names {
		want := payloads[name]
		qy, ok := q.Query(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if !bytes.Equal([]byte(qy.Payload), []byte(want)) {
			t.Fatalf("Query payload for %s changed:\nwant % x\ngot  % x", name, want, qy.Payload)
		}
		// An identical resubmit of an unterminated message returns the existing
		// record byte-for-byte and adds nothing.
		echo, err := q.Submit(payloadEnvelope(name, uint64(i+1), want))
		if err != nil {
			t.Fatalf("identical resubmit %s: %v", name, err)
		}
		if echo.Msg.Message.Payload != want {
			t.Fatalf("resubmit echo payload for %s changed", name)
		}
	}
	all := q.Queries()
	if len(all) != len(names) {
		t.Fatalf("identical resubmits must not add records: got %d rows", len(all))
	}
	for i, qy := range all {
		if qy.ID != names[i] || qy.Payload != payloads[names[i]] {
			t.Fatalf("Queries[%d] = (%s, % x), want (%s, % x)",
				i, qy.ID, qy.Payload, names[i], payloads[names[i]])
		}
	}
}

// 0xFF, 0xFE and the legal character U+FFFD are three different payloads: an
// identical-byte resubmit is the existing record, while changing any single
// byte — or submitting the visually similar replacement character — is a
// content conflict that leaves the original record untouched. The same holds
// after close/reopen and after a forced compaction (with a terminal record in
// the snapshot) plus reopen.
func TestPayloadInvalidBytesDistinctAcrossPersistenceBoundaries(t *testing.T) {
	payFF := string([]byte{0xFF})
	payFE := string([]byte{0xFE})
	payMixed := "pre" + string([]byte{0xFF}) + "post"

	originals := map[string]string{
		"ff":    payFF,
		"fe":    payFE,
		"mixed": payMixed,
		"ufffd": replacementCharPayload,
	}
	nonces := map[string]uint64{"ff": 1, "fe": 2, "mixed": 3, "ufffd": 4}

	check := func(t *testing.T, q *Queue) {
		t.Helper()
		before := len(q.Queries())
		for id, want := range originals {
			echo, err := q.Submit(payloadEnvelope(id, nonces[id], want))
			if err != nil {
				t.Fatalf("identical resubmit %s: %v", id, err)
			}
			if echo.Msg.Message.Payload != want {
				t.Fatalf("resubmit %s changed payload: % x", id, echo.Msg.Message.Payload)
			}
		}
		if len(q.Queries()) != before {
			t.Fatalf("identical resubmits must not add records: %d -> %d", before, len(q.Queries()))
		}

		// One-byte changes and the look-alike legal character all conflict, no
		// matter which live status (pending or waiting) the record is in.
		for _, c := range []struct {
			id  string
			bad string
		}{
			{"ff", payFE},
			{"ff", replacementCharPayload},
			{"fe", payFF},
			{"fe", replacementCharPayload},
			{"mixed", replacementCharPayload},
			{"ufffd", payFF},
			{"ufffd", payFE},
		} {
			if _, err := q.Submit(payloadEnvelope(c.id, nonces[c.id], c.bad)); !errors.Is(err, ErrConflict) {
				t.Fatalf("id %s resubmitted with payload % x must conflict: %v", c.id, c.bad, err)
			}
		}

		// Originals are untouched.
		for id, p := range originals {
			qy, ok := q.Query(id)
			if !ok || qy.Payload != p {
				t.Fatalf("original payload for %s changed after conflicts: ok=%v got % x want % x",
					id, ok, qy.Payload, p)
			}
		}
	}

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for id, p := range originals {
		if _, err := q.Submit(payloadEnvelope(id, nonces[id], p)); err != nil {
			t.Fatalf("submit %s: %v", id, err)
		}
	}
	t.Run("same instance", func(t *testing.T) { check(t, q) })
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	t.Run("after reopen", func(t *testing.T) { check(t, q) })

	// Drive the records to waiting and one to success so the forced snapshot
	// carries post-processing state entries as well as submit entries.
	q.RegisterSource("chain-a")
	q.UpsertHeader(Header{Chain: "chain-a", Height: 1, Root: "r", Trusted: true})
	term := Envelope{
		Message: Message{
			ID: "term", From: "chain-a", To: "chain-b", Nonce: 99,
			Payload: "done" + string([]byte{0xFF}), ProofAt: 1,
		},
	}
	if _, err := q.Submit(term); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	if st, _ := q.Query("term"); st.Status != StatusSuccess || st.Payload != term.Message.Payload {
		t.Fatalf("term not delivered with payload intact: %+v", st)
	}
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	t.Run("after compaction and reopen", func(t *testing.T) { check(t, q) })
	if st, ok := q.Query("term"); !ok || st.Payload != term.Message.Payload || st.Status != StatusSuccess {
		t.Fatalf("terminal payload lost in compaction: ok=%v %+v", ok, st)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// The on-disk log stores invalid bytes base64-encoded and never the
	// replacement character.
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"payloadB64":"`)) {
		t.Fatalf("invalid-UTF-8 payload not stored byte-exactly: %s", raw)
	}
	// "ufffd" legitimately serializes its U+FFFD payload as plain JSON, so
	// assert only that the all-invalid-byte payloads left no replacement runs:
	// the base64 encodings of 0xFF and 0xFE must be present.
	if !bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte{0xFF}))) ||
		!bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte{0xFE}))) {
		t.Fatalf("log is missing the base64 payload bytes: %s", raw)
	}
}

// Valid-UTF-8 payloads — plain text, empty, NUL bytes, U+FFFD itself — keep
// the historical plain "payload" field, so existing state directories, the
// CLI text interface and the README examples stay byte-compatible on disk.
func TestPayloadValidUTF8KeepsHistoricalEncoding(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id string
		p  string
	}{
		{"plain", "hello"},
		{"empty", ""},
		{"nul", "a\x00b"},
		{"ufffd", replacementCharPayload},
	}
	for i, c := range cases {
		if _, err := q.Submit(payloadEnvelope(c.id, uint64(i+1), c.p)); err != nil {
			t.Fatalf("submit %q: %v", c.p, err)
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
	if !bytes.Contains(raw, []byte(`"payload":"hello"`)) {
		t.Fatalf("plain payload missing from log: %s", raw)
	}

	q = reopen(t, dir)
	defer q.Close()
	echo, err := q.Submit(payloadEnvelope("plain", 1, "hello"))
	if err != nil || echo.Msg.Message.Payload != "hello" {
		t.Fatalf("plain payload resubmit after reopen: rec=%+v err=%v", echo, err)
	}
	if _, err := q.Submit(payloadEnvelope("plain", 1, string([]byte{0xFF}))); !errors.Is(err, ErrConflict) {
		t.Fatalf("invalid byte 0xFF must differ from every text payload: %v", err)
	}
}

// An unterminated waiting message whose identical resubmit happens after a
// reopen must return the existing waiting record — schedule unchanged —
// rather than a content conflict, because the saved payload bytes equal the
// submitted bytes. Changing one byte conflicts and leaves the schedule alone.
func TestPayloadInvalidBytesWaitingResubmitAfterReopenKeepsSchedule(t *testing.T) {
	pay := "w" + string([]byte{0x00, 0xFF, 0xFE})
	env := payloadEnvelope("w", 7, pay)
	env.Message.ProofAt = 100 // no trusted header covers it -> waiting

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("chain-a")
	if _, err := q.Submit(env); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	st, _ := q.Query("w")
	if st.Status != StatusWaiting || st.Attempts != 1 || st.NextRetry != 2000 {
		t.Fatalf("unexpected pre-reopen state: %+v", st)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	defer q.Close()
	echo, err := q.Submit(env)
	if err != nil {
		t.Fatalf("byte-identical resubmit after reopen must return existing record: %v", err)
	}
	if echo.Msg.Message.Payload != pay || echo.Status != StatusWaiting ||
		echo.Attempts != 1 || echo.NextRetry != 2000 {
		t.Fatalf("resubmit must not reschedule or rewrite payload: %+v", echo)
	}
	if len(q.Queries()) != 1 {
		t.Fatal("resubmit must not add a record")
	}
	bad := env
	bad.Message.Payload = "w" + string([]byte{0x00, 0xFF, 0x00})
	if _, err := q.Submit(bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("one-byte payload change must conflict: %v", err)
	}
	st2, _ := q.Query("w")
	if st2.Payload != pay || st2.Attempts != 1 || st2.NextRetry != 2000 {
		t.Fatalf("conflicting resubmit changed the record: %+v", st2)
	}
}

// invalidPayloadFrameSize returns the real framed size of a submit entry
// carrying tmpl's exact fields with an invalid-UTF-8 payload of n bytes; the
// seq-0 omit behavior matches the real queue's first submit.
func invalidPayloadFrameSize(t *testing.T, tmpl Envelope, n int) int64 {
	t.Helper()
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("chain-a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "chain-a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	tmpl.Message.Payload = strings.Repeat("\xff", n)
	before := q.store.size
	if _, err := q.Submit(tmpl); err != nil {
		t.Fatal(err)
	}
	return q.store.size - before
}

// Automatic threshold compaction, triggered by an ordinary Submit, must carry
// invalid-UTF-8 payloads byte-exactly into the snapshot, including the
// oversized payload that supplies the bulk and the small submit that crosses
// the threshold; both read identically after reopen.
func TestPayloadInvalidBytesSurviveAutomaticCompaction(t *testing.T) {
	const margin int64 = 4096

	// Measure the real framed sizes in a gauge queue: size after
	// source+header+one checkpoint (gaugeBase), the checkpoint frame, the
	// crossing small submit frame, and the invalid-payload frame math at seq 0.
	gq, _ := openTempQueue(t)
	if err := gq.RegisterSource("chain-a"); err != nil {
		t.Fatal(err)
	}
	if err := gq.UpsertHeader(Header{Chain: "chain-a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	gaugeBase := gq.store.size
	if _, err := gq.Advance(1000); err != nil {
		t.Fatal(err)
	}
	checkpoint := gq.store.size - gaugeBase
	gq.Close()

	cross := payloadEnvelope("cross", 2, "x"+string([]byte{0xFF}))
	filler := payloadEnvelope("filler", 1, "") // payload length is filled in below

	// Measure the crossing frame at seq 1 (a placeholder occupies seq 0, as the
	// filler does in the real queue) in a setup identical to the real one.
	gq2, _ := openTempQueue(t)
	if err := gq2.RegisterSource("chain-a"); err != nil {
		t.Fatal(err)
	}
	if err := gq2.UpsertHeader(Header{Chain: "chain-a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := gq2.Advance(1000); err != nil {
		t.Fatal(err)
	}
	if _, err := gq2.Submit(Envelope{Message: Message{
		ID: "gauge-seq0", From: "chain-a", To: "chain-b", Nonce: 998,
		Payload: "placeholder", ProofAt: 1,
	}}); err != nil {
		t.Fatal(err)
	}
	beforeCross := gq2.store.size
	if _, err := gq2.Submit(cross); err != nil {
		t.Fatal(err)
	}
	crossFrame := gq2.store.size - beforeCross
	gq2.Close()

	// Invalid payloads serialize as base64: frame(n) = overhead + EncodedLen(n),
	// measured for the seq-0 filler (whose seq is JSON-omitted).
	const probeLen = 4096
	probeFrame := invalidPayloadFrameSize(t, filler, probeLen)
	overhead := probeFrame - int64(base64.StdEncoding.EncodedLen(probeLen))
	targetFillerFrame := compactThreshold - margin - gaugeBase - checkpoint - crossFrame
	if targetFillerFrame <= overhead {
		t.Fatalf("setup arithmetic leaves no room for filler: target=%d overhead=%d", targetFillerFrame, overhead)
	}
	// Largest invalid byte count whose framed submit stays at the target size.
	var fillerLen int
	for lo, hi := 0, int(targetFillerFrame); ; {
		mid := (lo + hi + 1) / 2
		if overhead+int64(base64.StdEncoding.EncodedLen(mid)) <= targetFillerFrame {
			lo = mid
		} else {
			hi = mid - 1
		}
		if lo == hi {
			fillerLen = lo
			break
		}
	}
	filler.Message.Payload = strings.Repeat("\xff", fillerLen)

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.RegisterSource("chain-a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "chain-a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if q.store.size != gaugeBase {
		t.Fatalf("base mismatch: gauge %d real %d", gaugeBase, q.store.size)
	}

	// Equal-time checkpoint padding (legal with no messages yet) so the small
	// crossing submit is exactly what crosses 4 MiB; every checkpoint but one
	// is dropped by the snapshot, which therefore lands margin below.
	nCheckpoints := int(margin/checkpoint) + 2
	for i := 0; i < nCheckpoints; i++ {
		if _, err := q.Advance(1000); err != nil {
			t.Fatal(err)
		}
	}
	if q.store.size > compactThreshold {
		t.Fatalf("padding crossed the threshold early: size=%d", q.store.size)
	}
	if _, err := q.Submit(filler); err != nil {
		t.Fatalf("filler submit: %v", err)
	}
	if q.store.size > compactThreshold {
		t.Fatalf("filler crossed the threshold before the crossing submit: size=%d", q.store.size)
	}
	if _, err := q.Submit(cross); err != nil {
		t.Fatalf("crossing submit: %v", err)
	}
	if q.store.size > compactThreshold {
		t.Fatalf("auto-compaction did not shrink the log below the threshold: size=%d", q.store.size)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	defer q.Close()
	got, ok := q.Query("filler")
	if !ok {
		t.Fatal("filler missing after auto compaction and reopen")
	}
	if got.Payload != filler.Message.Payload {
		t.Fatalf("filler payload changed across auto compaction:\nwant len=%d\ngot  len=%d",
			len(filler.Message.Payload), len(got.Payload))
	}
	if got, ok := q.Query("cross"); !ok || got.Payload != cross.Message.Payload {
		t.Fatalf("crossing payload lost across auto compaction: ok=%v % x", ok, got.Payload)
	}
	// Byte-identical resubmits stay idempotent against the compacted records.
	if _, err := q.Submit(filler); err != nil {
		t.Fatalf("filler identical resubmit after compaction: %v", err)
	}
	if _, err := q.Submit(cross); err != nil {
		t.Fatalf("cross identical resubmit after compaction: %v", err)
	}
	if len(q.Queries()) != 2 {
		t.Fatalf("identical resubmits added records: %+v", q.Queries())
	}
}

// Existing state directories keep working: payloads an older build saved as
// plain JSON — ordinary text, empty and payloads already rewritten to U+FFFD —
// are read at face value. The lost bytes are never guessed: the replacement
// character stays that payload, and resubmitting the original invalid bytes
// conflicts with it.
func TestPayloadLegacyRecordsReadAtFaceValue(t *testing.T) {
	dir := t.TempDir()
	var raw []byte
	raw = append(raw, logMagic...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 0, ID: "txt", From: "a", To: "b", Nonce: 1,
		Payload: "legacy text", ProofAt: 10,
	}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 1, ID: "empty", From: "a", To: "b", Nonce: 2, ProofAt: 10,
	}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 2, ID: "lost", From: "a", To: "b", Nonce: 3,
		Payload: replacementCharPayload, ProofAt: 10,
	}))...)
	writeRawLog(t, dir, raw)

	q := reopen(t, dir)
	defer q.Close()
	if got, ok := q.Query("txt"); !ok || got.Payload != "legacy text" {
		t.Fatalf("legacy text payload: ok=%v %q", ok, got.Payload)
	}
	if got, ok := q.Query("empty"); !ok || got.Payload != "" {
		t.Fatalf("legacy empty payload: ok=%v %q", ok, got.Payload)
	}
	if got, ok := q.Query("lost"); !ok || got.Payload != replacementCharPayload {
		t.Fatalf("legacy replacement payload must be taken at face value: ok=%v %x", ok, got.Payload)
	}
	lost := Envelope{Message: Message{ID: "lost", From: "a", To: "b", Nonce: 3,
		Payload: replacementCharPayload, ProofAt: 10}}
	if _, err := q.Submit(lost); err != nil {
		t.Fatalf("saved replacement character must resubmit as itself: %v", err)
	}
	lost.Message.Payload = string([]byte{0xFF})
	if _, err := q.Submit(lost); !errors.Is(err, ErrConflict) {
		t.Fatalf("original invalid bytes must not be guessed back: %v", err)
	}
}

// A checksum-valid record carrying both payload fields, or an undecodable
// payloadB64, is an inconsistent record no build writes: opening returns
// ErrCorrupt and leaves the file byte-for-byte untouched — the payload is
// never treated as empty or as replacement-filled text.
//
// Presence is judged by key, not by value: "payload":"" is a legal empty
// payload on its own, but together with any payloadB64 it is two
// representations of the message content at once — no matter which side is
// empty, and even when the two decode to the same bytes. Field order in the
// JSON object is irrelevant. Every such record below is complete and
// checksum-valid and sits at the end of the log, so it must be rejected as
// corruption, never dropped as a torn tail.
func TestPayloadB64InconsistentRecordsRejected(t *testing.T) {
	// Struct-built cases: omitempty drops an empty Payload, so the non-empty
	// plain clash and the undecodable base64 can use the typed entry.
	structEntries := map[string]*logEntry{
		"both payload and payloadB64": {
			T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1,
			Payload: "x", PayloadB64: "eA==", ProofAt: 10,
		},
		"undecodable payloadB64": {
			T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1,
			PayloadB64: "!!!not-base64!!!", ProofAt: 10,
		},
	}
	// Raw-JSON cases: the "payload":"" key must literally be present, which
	// the omitempty struct tag would erase on marshal.
	rawPayloads := map[string]string{
		"empty payload plus payloadB64 of 0xff":     `{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10,"payload":"","payloadB64":"/w=="}`,
		"empty payload plus empty payloadB64":       `{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10,"payload":"","payloadB64":""}`,
		"plain and payloadB64 decode to same bytes": `{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10,"payloadB64":"eA==","payload":"x"}`,
		"payloadB64 first, plain payload second":    `{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10,"payloadB64":"/w==","payload":""}`,
	}
	for name, e := range structEntries {
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
	for name, payload := range rawPayloads {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var raw []byte
			raw = append(raw, logMagic...)
			raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
			raw = append(raw, encodeFrame([]byte(payload))...)
			writeRawLog(t, dir, raw)
			assertCorruptAndUntouched(t, dir, raw)
		})
	}
}

// A dual-payload record rejects the whole directory even when intact,
// acknowledged messages precede it — whether it sits at the end of a live log
// or among the submit records of a compacted one. No usable queue comes back
// and no partial state is recovered; the log keeps every byte.
func TestPayloadB64ClashAfterValidRecordsRejected(t *testing.T) {
	clash := `{"t":"submit","seq":1,"id":"bad","from":"a","to":"b","nonce":2,"proofAt":10,"payload":"","payloadB64":"/w=="}`
	for name, mid := range map[string][]*logEntry{
		// Live-log shape: a plain pending submit precedes the clashing record.
		"after plain submit": {},
		// Compacted-log shape: a processed message (submit plus its snapshot)
		// precedes the clashing record.
		"after compacted submit and state": {
			{T: kindState, ID: "ok", Now: 100, Status: StatusSuccess, Attempts: 1,
				ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "ok"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var raw []byte
			raw = append(raw, logMagic...)
			raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
			raw = append(raw, encodeFrame(mustMarshal(&logEntry{
				T: kindSubmit, Seq: 0, ID: "ok", From: "a", To: "b", Nonce: 1,
				Payload: "fine", ProofAt: 10,
			}))...)
			for _, e := range mid {
				raw = append(raw, encodeFrame(mustMarshal(e))...)
			}
			raw = append(raw, encodeFrame([]byte(clash))...)
			writeRawLog(t, dir, raw)
			assertCorruptAndUntouched(t, dir, raw)
		})
	}
}

// The empty payload keeps its long-standing meaning through every legal
// on-disk shape, and a sole payloadB64 still restores its bytes: the
// presence-based clash check must never mistake an omitted key for an
// empty-but-present one.
func TestPayloadEmptyOmittedAndSoleB64StillAccepted(t *testing.T) {
	payloadFF := string([]byte{0xFF})
	cases := map[string]struct {
		payload string
		want    string
	}{
		"explicit empty payload": {
			payload: `{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10,"payload":""}`,
			want:    "",
		},
		"both payload keys omitted (historical empty payload)": {
			payload: `{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10}`,
			want:    "",
		},
		"sole empty payloadB64": {
			payload: `{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10,"payloadB64":""}`,
			want:    "",
		},
		"sole payloadB64 restores its bytes": {
			payload: `{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10,"payloadB64":"/w=="}`,
			want:    payloadFF,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var raw []byte
			raw = append(raw, logMagic...)
			raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
			raw = append(raw, encodeFrame([]byte(tc.payload))...)
			writeRawLog(t, dir, raw)

			q := reopen(t, dir)
			defer q.Close()
			got, ok := q.Query("m")
			if !ok {
				t.Fatalf("message lost on replay")
			}
			if got.Payload != tc.want {
				t.Fatalf("payload restored as % x, want % x", got.Payload, tc.want)
			}
			// A byte-identical resubmit is the existing record, proving the
			// restored bytes are the real payload, not a conflated empty one.
			same := Envelope{Message: Message{ID: "m", From: "a", To: "b", Nonce: 1,
				Payload: tc.want, ProofAt: 10}}
			if _, err := q.Submit(same); err != nil {
				t.Fatalf("identical resubmit of restored payload: %v", err)
			}
		})
	}
}
