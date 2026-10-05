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

// Message ids are arbitrary byte strings distinguished byte for byte. The Go
// submit interface never requires an id to be valid UTF-8: a non-empty id may
// be ordinary text, hold whitespace, colons or NUL bytes, stray 0xFF/0xFE
// bytes, or mix text with them. Such an id must survive the submit echo,
// single and full queries, advance results, an identical resubmit, a reopen
// and log compaction exactly — JSON string encoding would otherwise silently
// rewrite the invalid bytes to U+FFFD, so a reopened directory would merge
// originally-distinct ids into an unopenable duplicate record and a
// byte-identical resubmit would become unfindable.

const replacementCharID = "�"

// idEnvelope builds an envelope carrying id with a plain-text payload, so
// assertions over the id bytes are not confused with payload encoding.
func idEnvelope(id string, nonce uint64, proofAt int64) Envelope {
	return Envelope{
		Message: Message{
			ID:      id,
			From:    "chain-a",
			To:      "chain-b",
			Nonce:   nonce,
			Payload: "p",
			ProofAt: proofAt,
		},
	}
}

// Every id shape must come back byte-identical from the submit echo, a single
// Query and the full Queries listing, and a byte-identical resubmit must
// return the existing record without adding one.
func TestIDArbitraryBytesPreservedInInstance(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()

	names := []string{"plain", "spaced", "colon", "nul", "ff", "fe", "fffe", "mixed", "replacement"}
	ids := map[string]string{
		"plain":       "hello",
		"spaced":      " a b\tc ",
		"colon":       "a:b:c",
		"nul":         "a\x00b\x00",
		"ff":          string([]byte{0xFF}),
		"fe":          string([]byte{0xFE}),
		"fffe":        string([]byte{0xFF, 0xFE}),
		"mixed":       "pre\x00mid" + string([]byte{0xFF, 0xFE}) + "post",
		"replacement": replacementCharID,
	}
	for i, name := range names {
		if _, err := q.Submit(idEnvelope(ids[name], uint64(i+1), 90)); err != nil {
			t.Fatalf("submit %s: %v", name, err)
		}
	}

	for i, name := range names {
		want := ids[name]
		echo, err := q.Submit(idEnvelope(want, uint64(i+1), 90))
		if err != nil {
			t.Fatalf("identical resubmit %s: %v", name, err)
		}
		if !bytes.Equal([]byte(echo.Msg.Message.ID), []byte(want)) {
			t.Fatalf("resubmit echo id for %s changed: % x", name, echo.Msg.Message.ID)
		}
		qy, ok := q.Query(want)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if !bytes.Equal([]byte(qy.ID), []byte(want)) {
			t.Fatalf("Query id for %s changed:\nwant % x\ngot  % x", name, want, qy.ID)
		}
	}
	all := q.Queries()
	if len(all) != len(names) {
		t.Fatalf("identical resubmits must not add records: got %d rows", len(all))
	}
	for i, qy := range all {
		if !bytes.Equal([]byte(qy.ID), []byte(ids[names[i]])) {
			t.Fatalf("Queries[%d] id = % x, want % x", i, qy.ID, ids[names[i]])
		}
	}
}

// 0xFF, 0xFE and the legal character U+FFFD are three different ids. Each
// must remain independently queryable in first-submission order across a
// reopen and across a forced compaction, never collapsing into another on
// the listing or the on-disk record set (a collapsed submit pair is a
// duplicate id the directory can no longer open).
func TestIDInvalidBytesDistinctAcrossPersistenceBoundaries(t *testing.T) {
	idFF := string([]byte{0xFF})
	idFE := string([]byte{0xFE})
	idRep := replacementCharID
	idMixed := "x" + string([]byte{0xFF, 0x00, 0xFE}) + "y"
	ordered := []string{idFF, idFE, idRep, idMixed}
	nonce := map[string]uint64{idFF: 1, idFE: 2, idRep: 3, idMixed: 4}

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range ordered {
		if _, err := q.Submit(idEnvelope(id, nonce[id], 90)); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}

	// assertDistinct is read-only and is valid before processing and after the
	// records have become terminal: every id still queries independently, in
	// order, with its exact bytes.
	assertDistinct := func(t *testing.T, q *Queue) {
		t.Helper()
		all := q.Queries()
		if len(all) != len(ordered) {
			t.Fatalf("distinct ids merged: got %d rows, want %d", len(all), len(ordered))
		}
		for i, want := range ordered {
			if !bytes.Equal([]byte(all[i].ID), []byte(want)) {
				t.Fatalf("Queries[%d] id changed:\nwant % x\ngot  % x", i, want, all[i].ID)
			}
			qy, ok := q.Query(want)
			if !ok {
				t.Fatalf("id % x not independently queryable", want)
			}
			if qy.ID != want {
				t.Fatalf("single Query id % x came back % x", want, qy.ID)
			}
		}
	}

	// assertResubmit adds the live-record rule: a byte-identical resubmit
	// returns this exact record without adding one. Valid only while the
	// records are still non-terminal.
	assertResubmit := func(t *testing.T, q *Queue) {
		t.Helper()
		for _, want := range ordered {
			echo, err := q.Submit(idEnvelope(want, nonce[want], 90))
			if err != nil {
				t.Fatalf("identical resubmit of % x: %v", want, err)
			}
			if echo.Msg.Message.ID != want {
				t.Fatalf("resubmit echo for % x came back % x", want, echo.Msg.Message.ID)
			}
		}
		if len(q.Queries()) != len(ordered) {
			t.Fatalf("identical resubmits added records: %d", len(q.Queries()))
		}
	}

	t.Run("same instance", func(t *testing.T) {
		assertDistinct(t, q)
		assertResubmit(t, q)
	})
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q = reopen(t, dir)
	t.Run("after reopen", func(t *testing.T) {
		assertDistinct(t, q)
		assertResubmit(t, q)
	})

	// Deliver all four and add one waiting invalid-byte id, so the forced
	// snapshot carries submit, success and waiting state entries.
	if err := q.RegisterSource("chain-a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "chain-a", Height: 100, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	idWait := "w" + string([]byte{0xFF})
	if _, err := q.Submit(idEnvelope(idWait, 50, 5000)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	for _, id := range ordered {
		if st, _ := q.Query(id); st.Status != StatusSuccess {
			t.Fatalf("% x must succeed, got %+v", id, st)
		}
	}
	if st, _ := q.Query(idWait); st.Status != StatusWaiting ||
		st.Attempts != 1 || st.NextRetry != 2000 {
		t.Fatalf("waiting record wrong: %+v", st)
	}

	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q = reopen(t, dir)
	t.Run("after compaction and reopen", func(t *testing.T) {
		t.Helper()
		all := q.Queries()
		wantOrder := append(append([]string{}, ordered...), idWait)
		if len(all) != len(wantOrder) {
			t.Fatalf("distinct ids merged or lost: got %d rows, want %d", len(all), len(wantOrder))
		}
		for i, want := range wantOrder {
			if !bytes.Equal([]byte(all[i].ID), []byte(want)) {
				t.Fatalf("Queries[%d] id changed:\nwant % x\ngot  % x", i, want, all[i].ID)
			}
			if _, ok := q.Query(want); !ok {
				t.Fatalf("id % x not independently queryable", want)
			}
		}
	})
	for _, id := range ordered {
		if st, ok := q.Query(id); !ok || st.Status != StatusSuccess {
			t.Fatalf("% x lost success across compaction: ok=%v %+v", id, ok, st)
		}
	}
	if st, ok := q.Query(idWait); !ok || st.Status != StatusWaiting ||
		st.Attempts != 1 || st.NextRetry != 2000 {
		t.Fatalf("waiting state lost across compaction: ok=%v %+v", ok, st)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// The persisted log stores invalid id bytes base64-encoded, never as a
	// run of replacement characters: the encodings of 0xFF and 0xFE must
	// both appear (in id fields and, once delivered, in consumeBy fields).
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"idB64":"`)) {
		t.Fatalf("invalid-UTF-8 ids not stored byte-exactly: %s", raw)
	}
	if !bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte{0xFF}))) ||
		!bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte{0xFE}))) {
		t.Fatalf("log is missing the base64 id bytes: %s", raw)
	}
}

// Identical content resubmitted for a non-terminal invalid-byte id returns
// the existing record without adding an entry or reordering; changing any
// content byte is ErrConflict leaving the original and its retry schedule;
// a terminal invalid-byte id rejects the resubmit with ErrTerminal.
func TestIDInvalidBytesResubmitRules(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("chain-a"); err != nil {
		t.Fatal(err)
	}

	id := "\xff id \x00"
	env := idEnvelope(id, 7, 100)
	if _, err := q.Submit(env); err != nil {
		t.Fatal(err)
	}
	// Pending: identical resubmit is a no-op echo.
	echo, err := q.Submit(env)
	if err != nil || echo.Msg.Message.ID != id || echo.Status != StatusPending {
		t.Fatalf("pending identical resubmit: rec=%+v err=%v", echo, err)
	}
	if len(q.Queries()) != 1 {
		t.Fatal("identical resubmit added a record")
	}
	// One-byte content change conflicts and leaves the record.
	bad := env
	bad.Message.Payload = "changed"
	if _, err := q.Submit(bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("different content must conflict: %v", err)
	}
	// The visually similar legal character is a different, new id, not this
	// one, so it submits fine as its own pending message.
	lookalike := env
	lookalike.Message.ID = replacementCharID
	if _, err := q.Submit(lookalike); err != nil {
		t.Fatalf("U+FFFD must be a distinct id, not a conflict: %v", err)
	}
	if len(q.Queries()) != 2 {
		t.Fatalf("look-alike legal id must be its own record: %d", len(q.Queries()))
	}

	// Waiting: identical content returns the waiting record and keeps the
	// schedule; a content change still conflicts and leaves the schedule.
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	st, _ := q.Query(id)
	if st.Status != StatusWaiting || st.Attempts != 1 || st.NextRetry != 2000 {
		t.Fatalf("want waiting, got %+v", st)
	}
	echo, err = q.Submit(env)
	if err != nil || echo.Status != StatusWaiting || echo.Attempts != 1 || echo.NextRetry != 2000 {
		t.Fatalf("waiting identical resubmit must keep the record: %+v %v", echo, err)
	}
	bad2 := env
	bad2.Message.Nonce = 8
	if _, err := q.Submit(bad2); !errors.Is(err, ErrConflict) {
		t.Fatalf("different nonce resubmit must conflict while waiting: %v", err)
	}
	st2, _ := q.Query(id)
	if st2.Attempts != 1 || st2.NextRetry != 2000 {
		t.Fatalf("conflict changed the waiting schedule: %+v", st2)
	}

	// Deliver, then terminal resubmits are ErrTerminal (identical and not).
	if err := q.UpsertHeader(Header{Chain: "chain-a", Height: 100, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(2000); err != nil {
		t.Fatal(err)
	}
	if st, _ := q.Query(id); st.Status != StatusSuccess {
		t.Fatalf("want success, got %+v", st)
	}
	if _, err := q.Submit(env); !errors.Is(err, ErrTerminal) {
		t.Fatalf("terminal identical resubmit must be ErrTerminal: %v", err)
	}
	if _, err := q.Submit(bad); !errors.Is(err, ErrTerminal) {
		t.Fatalf("terminal different-content resubmit must still be ErrTerminal: %v", err)
	}
}

// The consumed nonce stays attributed to the successful message's exact id.
// After a reopen, submitting a NEW id with the same (from,to,nonce) must be
// judged replay and the reason must name the original id byte-for-byte; the
// original success must not redeliver even though its saved id carried
// invalid bytes and its consumption attribution used consumeByB64.
func TestIDInvalidBytesNonceAttributionSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("chain-a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "chain-a", Height: 100, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	winnerID := "win" + string([]byte{0xFF, 0xFE})
	if _, err := q.Submit(idEnvelope(winnerID, 42, 90)); err != nil {
		t.Fatal(err)
	}
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	r0, ok := resultFor(rep, winnerID)
	if !ok || r0.Status != StatusSuccess || r0.ID != winnerID {
		t.Fatalf("winner must succeed under its exact id: ok=%v %+v", ok, r0)
	}
	if winner := q.consumed[newConsumeToken("chain-a", "chain-b", 42)]; winner != winnerID {
		t.Fatalf("nonce attributed to % x, want % x", winner, winnerID)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	defer q.Close()
	if winner := q.consumed[newConsumeToken("chain-a", "chain-b", 42)]; winner != winnerID {
		t.Fatalf("nonce attribution changed across reopen: % x", winner)
	}
	// A new id on the same triple must replay, named with the exact winner id.
	if _, err := q.Submit(idEnvelope("newcomer", 42, 90)); err != nil {
		t.Fatal(err)
	}
	rep, err = q.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	r1, ok := resultFor(rep, "newcomer")
	if !ok || r1.Status != StatusReplay {
		t.Fatalf("newcomer must replay: ok=%v %+v", ok, r1)
	}
	if !bytes.Contains([]byte(r1.Reason), []byte(winnerID)) {
		t.Fatalf("replay reason must name winner byte-for-byte:\nreason % x\nwinner % x", r1.Reason, winnerID)
	}
	// The winner stays terminal success and is not redelivered.
	if st, _ := q.Query(winnerID); st.Status != StatusSuccess {
		t.Fatalf("winner must remain success: %+v", st)
	}
	rep2, err := q.Advance(3000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep2.Results {
		if r.ID == winnerID {
			t.Fatalf("winner redelivered: %+v", r)
		}
	}
}

// An invalid-byte id that loses a replay records the replay reason naming
// the (also invalid-byte) winner, and that reason survives a reopen
// byte-for-byte.
func TestIDInvalidBytesReplayReasonSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("chain-a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "chain-a", Height: 100, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	winner := "w\xfe"
	loser := "l\xff"
	if _, err := q.Submit(idEnvelope(winner, 9, 90)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(idEnvelope(loser, 9, 90)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	wantReason := "nonce combination already consumed by message " + winner
	st, _ := q.Query(loser)
	if st.Status != StatusReplay || st.Reason != wantReason {
		t.Fatalf("loser replay state wrong: %+v", st)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	defer q.Close()
	st, _ = q.Query(loser)
	if st.Status != StatusReplay || st.ID != loser || st.Reason != wantReason {
		t.Fatalf("replay reason/id changed across reopen: %+v", st)
	}
}

// A waiting message with an invalid-byte id keeps its status, attempt count
// and scheduled retry across a reopen and across a compaction.
func TestIDInvalidBytesWaitingScheduleSurvives(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("chain-a"); err != nil {
		t.Fatal(err)
	}
	id := "wait" + string([]byte{0x00, 0xFF})
	if _, err := q.Submit(idEnvelope(id, 3, 5000)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	st, _ := q.Query(id)
	if st.ID != id || st.Status != StatusWaiting || st.Attempts != 1 || st.NextRetry != 2000 {
		t.Fatalf("waiting state lost across reopen: %+v", st)
	}
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q = reopen(t, dir)
	defer q.Close()
	st, _ = q.Query(id)
	if st.ID != id || st.Status != StatusWaiting || st.Attempts != 1 || st.NextRetry != 2000 {
		t.Fatalf("waiting state lost across compaction: %+v", st)
	}
	if len(q.order) != 1 || q.order[0] != id {
		t.Fatalf("processing order lost: %v", q.order)
	}
}

// Valid-UTF-8 ids — plain text, whitespace, colons, NUL bytes, U+FFFD itself
// — keep the historical plain "id" field on disk, so existing state
// directories and the CLI stay byte-compatible.
func TestIDValidUTF8KeepsHistoricalEncoding(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"m1", " spaced ", "a:b", "n\x00l", replacementCharID} {
		if _, err := q.Submit(idEnvelope(id, uint64(i+1), 1)); err != nil {
			t.Fatalf("submit %q: %v", id, err)
		}
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("idB64")) {
		t.Fatalf("valid-UTF-8 ids must keep the plain id field: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"id":"m1"`)) {
		t.Fatalf("plain id missing from log: %s", raw)
	}

	q = reopen(t, dir)
	defer q.Close()
	echo, err := q.Submit(idEnvelope("a:b", 3, 1))
	if err != nil || echo.Msg.Message.ID != "a:b" {
		t.Fatalf("plain id resubmit after reopen: %+v %v", echo, err)
	}
	if _, err := q.Submit(idEnvelope(string([]byte{0xFF}), 99, 1)); err != nil {
		t.Fatalf("invalid byte id must be a distinct new record, not a conflict: %v", err)
	}
}

// Existing state directories keep working: ids an older build saved as plain
// JSON — ordinary text and ids already rewritten to U+FFFD — are read at
// face value. The lost bytes are never guessed: the replacement character
// stays that id, and submitting the original invalid bytes creates a
// distinct record rather than finding the old one.
func TestIDLegacyRecordsReadAtFaceValue(t *testing.T) {
	dir := t.TempDir()
	var raw []byte
	raw = append(raw, logMagic...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 0, ID: "text-id", From: "a", To: "b", Nonce: 1, ProofAt: 10,
	}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 1, ID: replacementCharID, From: "a", To: "b", Nonce: 2, ProofAt: 10,
	}))...)
	writeRawLog(t, dir, raw)

	q := reopen(t, dir)
	defer q.Close()
	if got, ok := q.Query("text-id"); !ok || got.ID != "text-id" {
		t.Fatalf("legacy text id: ok=%v %q", ok, got.ID)
	}
	if got, ok := q.Query(replacementCharID); !ok || got.ID != replacementCharID {
		t.Fatalf("legacy replacement id must be taken at face value: ok=%v %x", ok, got.ID)
	}
	// A resubmit with the saved characters (and the saved empty payload)
	// returns the same record.
	saved := Envelope{Message: Message{
		ID: replacementCharID, From: "a", To: "b", Nonce: 2, Payload: "", ProofAt: 10,
	}}
	if _, err := q.Submit(saved); err != nil {
		t.Fatalf("saved replacement id must resubmit as itself: %v", err)
	}
	// The original invalid bytes are a different id: a new record, not the
	// old one and not a conflict.
	original := saved
	original.Message.ID = string([]byte{0xFF})
	original.Message.Nonce = 3
	before := len(q.Queries())
	if _, err := q.Submit(original); err != nil {
		t.Fatalf("original invalid bytes must not be guessed back: %v", err)
	}
	if len(q.Queries()) != before+1 {
		t.Fatalf("invalid-byte id must be its own record")
	}
}

// resultIDFixture builds a well-formed successful result for message "m"
// consuming its own triple; callers mutate one field to make it inconsistent.
func resultIDFixture() *logEntry {
	return &logEntry{
		T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess,
		Reason:      "delivered; proof verified by trusted header at height 100",
		Attempts:    1,
		ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m",
	}
}

// assertIDCorruptWithSubmit writes a complete, checksum-valid log containing
// source, trusted header, the "m" submit and the given result, and requires
// Open to reject it with ErrCorrupt while leaving every byte untouched.
func assertIDCorruptWithSubmit(t *testing.T, badResult *logEntry) {
	t.Helper()
	dir := t.TempDir()
	var raw []byte
	raw = append(raw, logMagic...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindSource, Chain: "a"}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true,
	}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 100,
	}))...)
	raw = append(raw, encodeFrame(mustMarshal(badResult))...)
	writeRawLog(t, dir, raw)
	assertCorruptAndUntouched(t, dir, raw)
}

// A checksum-valid entry carrying both id and idB64, an undecodable idB64,
// both reason and reasonB64, an undecodable reasonB64, or a dual/undecodable
// consumeByB64 is an inconsistent record no build writes: opening returns
// ErrCorrupt and leaves the file byte-for-byte untouched.
func TestIDB64InconsistentRecordsRejected(t *testing.T) {
	t.Run("both id and idB64 on submit", func(t *testing.T) {
		dir := t.TempDir()
		e := &logEntry{
			T: kindSubmit, Seq: 0, ID: "m", IDB64: "bQ==",
			From: "a", To: "b", Nonce: 1, ProofAt: 10,
		}
		var raw []byte
		raw = append(raw, logMagic...)
		raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
		raw = append(raw, encodeFrame(mustMarshal(e))...)
		writeRawLog(t, dir, raw)
		assertCorruptAndUntouched(t, dir, raw)
	})
	t.Run("undecodable idB64 on submit", func(t *testing.T) {
		dir := t.TempDir()
		e := &logEntry{
			T: kindSubmit, Seq: 0, IDB64: "!!!not-base64!!!",
			From: "a", To: "b", Nonce: 1, ProofAt: 10,
		}
		var raw []byte
		raw = append(raw, logMagic...)
		raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
		raw = append(raw, encodeFrame(mustMarshal(e))...)
		writeRawLog(t, dir, raw)
		assertCorruptAndUntouched(t, dir, raw)
	})
	t.Run("both reason and reasonB64 on result", func(t *testing.T) {
		e := resultIDFixture()
		e.Reason = "x"
		e.ReasonB64 = base64.StdEncoding.EncodeToString([]byte("y"))
		assertIDCorruptWithSubmit(t, e)
	})
	t.Run("undecodable reasonB64 on result", func(t *testing.T) {
		e := resultIDFixture()
		e.Reason = ""
		e.ReasonB64 = "!!!not-base64!!!"
		assertIDCorruptWithSubmit(t, e)
	})
	t.Run("both consumeBy and consumeByB64", func(t *testing.T) {
		e := resultIDFixture()
		e.ConsumeByB64 = base64.StdEncoding.EncodeToString([]byte("m"))
		assertIDCorruptWithSubmit(t, e)
	})
	t.Run("undecodable consumeByB64", func(t *testing.T) {
		e := resultIDFixture()
		e.ConsumeBy = ""
		e.ConsumeByB64 = "!!!not-base64!!!"
		assertIDCorruptWithSubmit(t, e)
	})
	t.Run("both id and idB64 on result", func(t *testing.T) {
		e := resultIDFixture()
		e.IDB64 = base64.StdEncoding.EncodeToString([]byte("m"))
		assertIDCorruptWithSubmit(t, e)
	})
}

// A success entry whose consumeBy names a different id than the record it is
// attached to was already corrupt before; with byte ids the mismatch must be
// detected against the decoded idB64/consumeByB64 pair as well.
func TestIDConsumeByMismatchWithB64Rejected(t *testing.T) {
	dir := t.TempDir()
	submit := &logEntry{
		T: kindSubmit, Seq: 0, From: "a", To: "b", Nonce: 1, ProofAt: 100,
	}
	submit.setID(string([]byte{0xFF}))
	result := &logEntry{
		T: kindResult, Now: 1000, Status: StatusSuccess,
		Reason: "ok", Attempts: 1,
		ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1,
	}
	result.setID(string([]byte{0xFF}))
	result.setConsumeBy(string([]byte{0xFE})) // attributes success to another id

	var raw []byte
	raw = append(raw, logMagic...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindSource, Chain: "a"}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindHeader, Chain: "a", Height: 100, Root: "r", Trusted: true,
	}))...)
	raw = append(raw, encodeFrame(mustMarshal(submit))...)
	raw = append(raw, encodeFrame(mustMarshal(result))...)
	writeRawLog(t, dir, raw)
	assertCorruptAndUntouched(t, dir, raw)
}

// invalidIDFrameSize returns the real framed size of a submit entry carrying
// tmpl's exact fields with an invalid-UTF-8 id of n bytes.
func invalidIDFrameSize(t *testing.T, tmpl Envelope, n int) int64 {
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
	tmpl.Message.ID = strings.Repeat("\xff", n)
	before := q.store.size
	if _, err := q.Submit(tmpl); err != nil {
		t.Fatal(err)
	}
	return q.store.size - before
}

// Automatic threshold compaction, triggered by an ordinary Submit, must carry
// invalid-UTF-8 ids byte-exactly into the snapshot: the oversized filler and
// the small crossing submit both read identically after reopen, and a
// byte-identical resubmit stays idempotent against the compacted records.
func TestIDInvalidBytesSurviveAutomaticCompaction(t *testing.T) {
	const margin int64 = 4096

	// Gauge the fixed prefix and one equal-time checkpoint frame.
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

	cross := idEnvelope("cross"+string([]byte{0xFF}), 2, 1)
	cross.Message.Payload = "x"
	tmpl := idEnvelope("", 1, 1)

	// Measure the crossing frame at seq 1 (a placeholder occupies seq 0).
	gq2, _ := openTempQueue(t)
	gq2.RegisterSource("chain-a")
	gq2.UpsertHeader(Header{Chain: "chain-a", Height: 100, Root: "0x100", Trusted: true})
	gq2.Advance(1000)
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

	// Invalid ids serialize as base64: frame(n) = overhead + EncodedLen(n).
	const probeLen = 4096
	probeFrame := invalidIDFrameSize(t, tmpl, probeLen)
	overhead := probeFrame - int64(base64.StdEncoding.EncodedLen(probeLen))
	targetFillerFrame := compactThreshold - margin - gaugeBase - checkpoint - crossFrame
	if targetFillerFrame <= overhead {
		t.Fatalf("setup arithmetic leaves no room for filler: target=%d overhead=%d", targetFillerFrame, overhead)
	}
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
	filler := idEnvelope(strings.Repeat("\xff", fillerLen), 1, 1)
	filler.Message.Payload = ""

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
	got, ok := q.Query(filler.Message.ID)
	if !ok {
		t.Fatal("filler missing after auto compaction and reopen")
	}
	if got.ID != filler.Message.ID {
		t.Fatalf("filler id changed across auto compaction:\nwant len=%d\ngot  len=%d",
			len(filler.Message.ID), len(got.ID))
	}
	if got, ok := q.Query(cross.Message.ID); !ok || got.ID != cross.Message.ID {
		t.Fatalf("crossing id lost across auto compaction: ok=%v % x", ok, got.ID)
	}
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
