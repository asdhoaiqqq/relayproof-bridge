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

// Destination chain names are arbitrary non-empty byte strings: they are part
// of the same-id content comparison and of the consumed (from,to,nonce)
// triple. The Go submit interface never requires a destination to be valid
// UTF-8 — plain text, colons, NUL bytes, stray 0xFF/0xFE bytes or text mixed
// with them are all accepted — and such a destination must survive the submit
// echo, queries, an identical resubmit, reopen and log compaction exactly.
// JSON string encoding would otherwise silently rewrite the invalid bytes to
// U+FFFD, merging distinct destinations into one consumption identity and
// making a byte-identical resubmit conflict with its own record.

const replacementCharTo = "�"

// toEnvelope builds a non-terminal envelope destined for chain to; each call
// site supplies a distinct nonce so processing one message can never replay
// another.
func toEnvelope(id string, nonce uint64, to string) Envelope {
	return Envelope{
		Message: Message{
			ID:      id,
			From:    "chain-a",
			To:      to,
			Nonce:   nonce,
			Payload: "p-" + id,
			ProofAt: 90,
		},
	}
}

// Every destination shape must come back byte-identical from the submit echo,
// a single Query and the full Queries listing.
func TestToArbitraryBytesPreservedInInstance(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()

	names := []string{"plain", "colon", "nul", "ff", "fe", "fffe", "mixed", "replacement"}
	dests := map[string]string{
		"plain":       "chain-b",
		"colon":       "zone:chain-b",
		"nul":         "a\x00b\x00",
		"ff":          string([]byte{0xFF}),
		"fe":          string([]byte{0xFE}),
		"fffe":        string([]byte{0xFF, 0xFE}),
		"mixed":       "pre\x00mid" + string([]byte{0xFF, 0xFE}) + "post",
		"replacement": replacementCharTo,
	}
	for i, name := range names {
		echo, err := q.Submit(toEnvelope(name, uint64(i+1), dests[name]))
		if err != nil {
			t.Fatalf("submit %s: %v", name, err)
		}
		if echo.Msg.Message.To != dests[name] {
			t.Fatalf("submit echo destination for %s changed:\nwant % x\ngot  % x",
				name, dests[name], echo.Msg.Message.To)
		}
	}

	for i, name := range names {
		want := dests[name]
		qy, ok := q.Query(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if !bytes.Equal([]byte(qy.To), []byte(want)) {
			t.Fatalf("Query destination for %s changed:\nwant % x\ngot  % x", name, want, qy.To)
		}
		// An identical resubmit of an unterminated message returns the existing
		// record byte-for-byte and adds nothing.
		echo, err := q.Submit(toEnvelope(name, uint64(i+1), want))
		if err != nil {
			t.Fatalf("identical resubmit %s: %v", name, err)
		}
		if echo.Msg.Message.To != want {
			t.Fatalf("resubmit echo destination for %s changed", name)
		}
	}
	all := q.Queries()
	if len(all) != len(names) {
		t.Fatalf("identical resubmits must not add records: got %d rows", len(all))
	}
	for i, qy := range all {
		if qy.ID != names[i] || qy.To != dests[names[i]] {
			t.Fatalf("Queries[%d] = (%s, % x), want (%s, % x)",
				i, qy.ID, qy.To, names[i], dests[names[i]])
		}
	}
}

// 0xFF, 0xFE and the legal character U+FFFD are three different destinations:
// an identical-byte resubmit is the existing record, while changing any
// single byte — or submitting the visually similar replacement character — is
// a content conflict that leaves the original record untouched. The same
// holds after close/reopen and after a forced compaction (with a terminal
// record in the snapshot) plus reopen.
func TestToInvalidBytesDistinctAcrossPersistenceBoundaries(t *testing.T) {
	toFF := string([]byte{0xFF})
	toFE := string([]byte{0xFE})
	toMixed := "pre" + string([]byte{0xFF}) + "post"

	originals := map[string]string{
		"ff":    toFF,
		"fe":    toFE,
		"mixed": toMixed,
		"ufffd": replacementCharTo,
	}
	nonces := map[string]uint64{"ff": 1, "fe": 2, "mixed": 3, "ufffd": 4}

	check := func(t *testing.T, q *Queue) {
		t.Helper()
		before := len(q.Queries())
		for id, want := range originals {
			echo, err := q.Submit(toEnvelope(id, nonces[id], want))
			if err != nil {
				t.Fatalf("identical resubmit %s: %v", id, err)
			}
			if echo.Msg.Message.To != want {
				t.Fatalf("resubmit %s changed destination: % x", id, echo.Msg.Message.To)
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
			{"ff", toFE},
			{"ff", replacementCharTo},
			{"fe", toFF},
			{"fe", replacementCharTo},
			{"mixed", replacementCharTo},
			{"ufffd", toFF},
			{"ufffd", toFE},
		} {
			if _, err := q.Submit(toEnvelope(c.id, nonces[c.id], c.bad)); !errors.Is(err, ErrConflict) {
				t.Fatalf("id %s resubmitted with destination % x must conflict: %v", c.id, c.bad, err)
			}
		}

		// Originals are untouched.
		for id, to := range originals {
			qy, ok := q.Query(id)
			if !ok || qy.To != to {
				t.Fatalf("original destination for %s changed after conflicts: ok=%v got % x want % x",
					id, ok, qy.To, to)
			}
		}
	}

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for id, to := range originals {
		if _, err := q.Submit(toEnvelope(id, nonces[id], to)); err != nil {
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
			ID: "term", From: "chain-a", To: "done" + string([]byte{0xFF}), Nonce: 99,
			Payload: "done", ProofAt: 1,
		},
	}
	if _, err := q.Submit(term); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	if st, _ := q.Query("term"); st.Status != StatusSuccess || st.To != term.Message.To {
		t.Fatalf("term not delivered with destination intact: %+v", st)
	}
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	t.Run("after compaction and reopen", func(t *testing.T) { check(t, q) })
	if st, ok := q.Query("term"); !ok || st.To != term.Message.To || st.Status != StatusSuccess {
		t.Fatalf("terminal destination lost in compaction: ok=%v %+v", ok, st)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// The on-disk log stores invalid destination bytes base64-encoded and
	// never as the replacement character.
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"toB64":"`)) {
		t.Fatalf("invalid-UTF-8 destination not stored byte-exactly: %s", raw)
	}
	// "ufffd" legitimately serializes its U+FFFD destination as plain JSON, so
	// assert only that the all-invalid-byte destinations left no replacement
	// runs: the base64 encodings of 0xFF and 0xFE must be present.
	if !bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte{0xFF}))) ||
		!bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte{0xFE}))) {
		t.Fatalf("log is missing the base64 destination bytes: %s", raw)
	}
}

// Valid-UTF-8 destinations — plain text, colons, NUL bytes, U+FFFD itself —
// keep the historical plain "to" field, so existing state directories, the
// CLI text interface and the README examples stay byte-compatible on disk.
func TestToValidUTF8KeepsHistoricalEncoding(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id string
		to string
	}{
		{"plain", "chain-b"},
		{"colon", "zone:chain-b"},
		{"nul", "a\x00b"},
		{"ufffd", replacementCharTo},
	}
	for i, c := range cases {
		if _, err := q.Submit(toEnvelope(c.id, uint64(i+1), c.to)); err != nil {
			t.Fatalf("submit %q: %v", c.to, err)
		}
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("toB64")) {
		t.Fatalf("valid-UTF-8 destinations must keep the plain to field: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"to":"chain-b"`)) {
		t.Fatalf("plain destination missing from log: %s", raw)
	}

	q = reopen(t, dir)
	defer q.Close()
	echo, err := q.Submit(toEnvelope("plain", 1, "chain-b"))
	if err != nil || echo.Msg.Message.To != "chain-b" {
		t.Fatalf("plain destination resubmit after reopen: rec=%+v err=%v", echo, err)
	}
	if _, err := q.Submit(toEnvelope("plain", 1, string([]byte{0xFF}))); !errors.Is(err, ErrConflict) {
		t.Fatalf("invalid byte 0xFF must differ from every text destination: %v", err)
	}
}

// An unterminated waiting message whose identical resubmit happens after a
// reopen must return the existing waiting record — status, attempt count and
// retry schedule unchanged — rather than a content conflict, because the
// saved destination bytes equal the submitted bytes. Changing one destination
// byte conflicts and leaves the record alone.
func TestToInvalidBytesWaitingResubmitAfterReopenKeepsSchedule(t *testing.T) {
	to := "w" + string([]byte{0x00, 0xFF, 0xFE})
	env := toEnvelope("w", 7, to)
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
	if echo.Msg.Message.To != to || echo.Status != StatusWaiting ||
		echo.Attempts != 1 || echo.NextRetry != 2000 {
		t.Fatalf("resubmit must not reschedule or rewrite destination: %+v", echo)
	}
	if len(q.Queries()) != 1 {
		t.Fatal("resubmit must not add a record")
	}
	bad := env
	bad.Message.To = "w" + string([]byte{0x00, 0xFF, 0x00})
	if _, err := q.Submit(bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("one-byte destination change must conflict: %v", err)
	}
	st2, _ := q.Query("w")
	if st2.To != to || st2.Attempts != 1 || st2.NextRetry != 2000 {
		t.Fatalf("conflicting resubmit changed the record: %+v", st2)
	}
}

// Replay protection judges the consumed (from,to,nonce) triple by exact
// destination bytes: 0xFF, 0xFE and U+FFFD are three different destinations,
// so the same nonce can be delivered once to each of them. Across a reopen —
// and across a compaction that snapshots the success records — a new message
// reusing a consumed nonce on one of those destinations terminalizes as
// replay, with the reason naming the message that truly succeeded, while the
// same nonce on a fourth destination is still deliverable. The distinct
// success records must never merge, and the directory must never be judged
// corrupt for holding them.
func TestToInvalidBytesReplayIdentityAcrossReopenAndCompaction(t *testing.T) {
	toFF := string([]byte{0xFF})
	toFE := string([]byte{0xFE})
	toUFFFD := replacementCharTo
	toOther := "chain-b"

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
	// The same nonce 5 is delivered once to each of the three look-alike
	// destinations; each must succeed on its own.
	for id, to := range map[string]string{"w-ff": toFF, "w-fe": toFE, "w-ufffd": toUFFFD} {
		env := toEnvelope(id, 5, to)
		env.Message.ProofAt = 90
		if _, err := q.Submit(env); err != nil {
			t.Fatalf("submit %s: %v", id, err)
		}
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"w-ff", "w-fe", "w-ufffd"} {
		if st, _ := q.Query(id); st.Status != StatusSuccess {
			t.Fatalf("%s must succeed on its own destination: %+v", id, st)
		}
	}
	// Snapshot the three success records (with their consumeTo fields) and
	// reopen, so replay identity is judged from restored state.
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	defer q.Close()
	for id, to := range map[string]string{"w-ff": toFF, "w-fe": toFE, "w-ufffd": toUFFFD} {
		st, ok := q.Query(id)
		if !ok || st.Status != StatusSuccess || st.To != to {
			t.Fatalf("restored winner %s changed: ok=%v %+v", id, ok, st)
		}
	}

	// A new id reusing nonce 5 on the 0xFF destination terminalizes as
	// replay, and the reason names the message that truly succeeded there.
	replayEnv := toEnvelope("late-ff", 5, toFF)
	replayEnv.Message.ProofAt = 90
	if _, err := q.Submit(replayEnv); err != nil {
		t.Fatal(err)
	}
	// The same nonce on a destination that never consumed it is not a replay.
	freshEnv := toEnvelope("late-other", 5, toOther)
	freshEnv.Message.ProofAt = 90
	if _, err := q.Submit(freshEnv); err != nil {
		t.Fatal(err)
	}
	report, err := q.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[string]Result{}
	for _, r := range report.Results {
		statuses[r.ID] = r
	}
	got, ok := statuses["late-ff"]
	if !ok || got.Status != StatusReplay {
		t.Fatalf("late-ff must terminalize as replay: %+v", got)
	}
	if !strings.Contains(got.Reason, "w-ff") {
		t.Fatalf("replay reason must name the true winner w-ff: %q", got.Reason)
	}
	if got, ok := statuses["late-other"]; !ok || got.Status != StatusSuccess {
		t.Fatalf("late-other on an unconsumed destination must succeed: %+v", got)
	}
	st, _ := q.Query("late-ff")
	if st.Status != StatusReplay || !strings.Contains(st.Reason, "w-ff") {
		t.Fatalf("persisted replay outcome wrong: %+v", st)
	}
	// The original winners are untouched by the replay verdicts.
	for id, to := range map[string]string{"w-ff": toFF, "w-fe": toFE, "w-ufffd": toUFFFD} {
		if st, _ := q.Query(id); st.Status != StatusSuccess || st.To != to {
			t.Fatalf("winner %s changed after replay: %+v", id, st)
		}
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// The replay outcome itself survives one more reopen, and the directory
	// with three same-nonce successes is never judged corrupt.
	q = reopen(t, dir)
	defer q.Close()
	if st, ok := q.Query("late-ff"); !ok || st.Status != StatusReplay {
		t.Fatalf("replay outcome lost across reopen: ok=%v %+v", ok, st)
	}
	if st, ok := q.Query("late-other"); !ok || st.Status != StatusSuccess {
		t.Fatalf("fresh-destination success lost across reopen: ok=%v %+v", ok, st)
	}
}

// Automatic threshold compaction, triggered by ordinary queue operations,
// must carry invalid-UTF-8 destinations byte-exactly into the snapshot; both
// the message whose destination supplies the bulk and the small submit after
// the compaction read identically after reopen. The log is pushed past 4 MiB
// with superseded large-root header updates, which the snapshot drops.
func TestToInvalidBytesSurviveAutomaticCompaction(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.RegisterSource("chain-a"); err != nil {
		t.Fatal(err)
	}

	// A 2 MiB invalid-UTF-8 destination base64-encodes to ~2.8 MB; two 600 KiB
	// invalid-UTF-8 header roots (~800 KB each encoded) push the log past the
	// 4 MiB threshold, while the snapshot keeps only the latest header.
	bigTo := strings.Repeat("\xff", 2<<20)
	big := toEnvelope("big", 1, bigTo)
	if _, err := q.Submit(big); err != nil {
		t.Fatalf("big submit: %v", err)
	}
	if q.store.size > compactThreshold {
		t.Fatalf("big submit crossed the threshold early: size=%d", q.store.size)
	}
	padRoot1 := strings.Repeat("\xfe", 600<<10)
	padRoot2 := strings.Repeat("\xfe", 600<<10) + "x"
	for i, root := range []string{padRoot1, padRoot2} {
		if err := q.UpsertHeader(Header{Chain: "chain-a", Height: int64(i + 1), Root: root}); err != nil {
			t.Fatalf("padding header %d: %v", i, err)
		}
	}
	if q.store.size > compactThreshold {
		t.Fatalf("auto-compaction did not shrink the log below the threshold: size=%d", q.store.size)
	}
	cross := toEnvelope("cross", 2, "x"+string([]byte{0xFF}))
	if _, err := q.Submit(cross); err != nil {
		t.Fatalf("crossing submit: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	defer q.Close()
	got, ok := q.Query("big")
	if !ok {
		t.Fatal("big missing after auto compaction and reopen")
	}
	if got.To != bigTo {
		t.Fatalf("big destination changed across auto compaction:\nwant len=%d\ngot  len=%d",
			len(bigTo), len(got.To))
	}
	if got, ok := q.Query("cross"); !ok || got.To != cross.Message.To {
		t.Fatalf("crossing destination lost across auto compaction: ok=%v % x", ok, got.To)
	}
	// Byte-identical resubmits stay idempotent against the compacted records.
	if _, err := q.Submit(big); err != nil {
		t.Fatalf("big identical resubmit after compaction: %v", err)
	}
	if _, err := q.Submit(cross); err != nil {
		t.Fatalf("cross identical resubmit after compaction: %v", err)
	}
	if len(q.Queries()) != 2 {
		t.Fatalf("identical resubmits added records: %+v", q.Queries())
	}
}

// Existing state directories keep working: destinations an older build saved
// as plain JSON — ordinary text and destinations already rewritten to U+FFFD —
// are read at face value. The lost bytes are never guessed: the replacement
// character stays that destination, and resubmitting the original invalid
// bytes conflicts with it.
func TestToLegacyRecordsReadAtFaceValue(t *testing.T) {
	dir := t.TempDir()
	var raw []byte
	raw = append(raw, logMagic...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 0, ID: "txt", From: "a", To: "chain-b", Nonce: 1,
		Payload: "p", ProofAt: 10,
	}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 1, ID: "lost", From: "a", To: replacementCharTo,
		Nonce: 2, Payload: "p", ProofAt: 10,
	}))...)
	writeRawLog(t, dir, raw)

	q := reopen(t, dir)
	defer q.Close()
	if got, ok := q.Query("txt"); !ok || got.To != "chain-b" {
		t.Fatalf("legacy text destination: ok=%v %q", ok, got.To)
	}
	if got, ok := q.Query("lost"); !ok || got.To != replacementCharTo {
		t.Fatalf("legacy replacement destination must be taken at face value: ok=%v % x", ok, got.To)
	}
	lost := Envelope{Message: Message{ID: "lost", From: "a", To: replacementCharTo,
		Nonce: 2, Payload: "p", ProofAt: 10}}
	if _, err := q.Submit(lost); err != nil {
		t.Fatalf("saved replacement character must resubmit as itself: %v", err)
	}
	lost.Message.To = string([]byte{0xFF})
	if _, err := q.Submit(lost); !errors.Is(err, ErrConflict) {
		t.Fatalf("original invalid bytes must not be guessed back: %v", err)
	}
}

// A checksum-valid record that carries both a plain destination field and its
// base64 form, or an undecodable base64 destination field, is an inconsistent
// record no build writes: opening returns ErrCorrupt and leaves the file
// byte-for-byte untouched. This holds for the submit entry's to/toB64 and for
// a success entry's consumeTo/consumeToB64 alike.
func TestToB64InconsistentRecordsRejected(t *testing.T) {
	submitBoth := &logEntry{
		T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", ToB64: "Yg==",
		Nonce: 1, Payload: "p", ProofAt: 10,
	}
	submitBad := &logEntry{
		T: kindSubmit, Seq: 0, ID: "m", From: "a", ToB64: "!!!not-base64!!!",
		Nonce: 1, Payload: "p", ProofAt: 10,
	}
	successBoth := func() []*logEntry {
		return []*logEntry{
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, Payload: "p", ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeToB64: "Yg==",
				ConsumeNonce: 1, ConsumeBy: "m"},
		}
	}
	successBadTo := func() []*logEntry {
		return []*logEntry{
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, Payload: "p", ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok",
				Attempts: 1, ConsumeFrom: "a", ConsumeToB64: "!!!not-base64!!!",
				ConsumeNonce: 1, ConsumeBy: "m"},
		}
	}

	cases := map[string][]*logEntry{
		"submit with both to and toB64":         {submitBoth},
		"submit with undecodable toB64":         {submitBad},
		"success with both consumeTo forms":     successBoth(),
		"success with undecodable consumeToB64": successBadTo(),
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var data []byte
			data = append(data, logMagic...)
			data = append(data, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
			for _, e := range entries {
				data = append(data, encodeFrame(mustMarshal(e))...)
			}
			writeRawLog(t, dir, data)
			assertCorruptAndUntouched(t, dir, data)
		})
	}
}

// The empty destination stays rejected by the Go API as an invalid argument.
func TestToEmptyStillRejected(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	_, err := q.Submit(Envelope{Message: Message{ID: "m", From: "a", To: "", Nonce: 1, ProofAt: 1}})
	if !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("empty destination: want ErrInvalidArg, got %v", err)
	}
}
