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

// Message ids are arbitrary byte strings: the Go submit interface accepts any
// non-empty id without requiring valid UTF-8 — Chinese text, whitespace,
// colons, NUL bytes, stray 0xFF/0xFE bytes, or text mixed with them. Identity
// is judged by the exact bytes: the single bytes 0xFF and 0xFE and the legal
// character U+FFFD are three different ids. JSON string encoding silently
// rewrites invalid UTF-8 to U+FFFD, so without byte-exact persistence the
// original id would lose its message after a reopen and two distinct ids
// could replay as duplicate submits, making the directory unopenable.

const replacementCharID = "�"

// idEnvelope builds a pending envelope keyed by id; callers supply distinct
// nonces so processing one message can never replay another.
func idEnvelope(id string, nonce uint64, proofAt int64) Envelope {
	return Envelope{
		Message: Message{
			ID: id, From: "chain-a", To: "chain-b", Nonce: nonce,
			Payload: "payload-" + id, ProofAt: proofAt,
		},
	}
}

// Every id shape must come back byte-identical from the submit echo, a single
// Query and the full Queries listing, in first-submission order.
func TestIDArbitraryBytesPreservedInInstance(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()

	ids := []string{
		"plain",
		"消息-壹",        // Chinese
		"  id : 9 ",   // whitespace and colon
		"a:b",         // colon
		"a\x00b\x00c", // NUL bytes (Go API only)
		string([]byte{0xFF}),
		string([]byte{0xFE}),
		"mid" + string([]byte{0x00, 0xFF, 0xFE}) + "尾",
		replacementCharID,
	}
	for i, id := range ids {
		if _, err := q.Submit(idEnvelope(id, uint64(i+1), 90)); err != nil {
			t.Fatalf("submit % x: %v", id, err)
		}
	}

	for i, want := range ids {
		// Submit echo.
		echo, err := q.Submit(idEnvelope(want, uint64(i+1), 90))
		if err != nil {
			t.Fatalf("identical resubmit % x: %v", want, err)
		}
		if !bytes.Equal([]byte(echo.Msg.Message.ID), []byte(want)) {
			t.Fatalf("resubmit echo id changed: want % x got % x", want, echo.Msg.Message.ID)
		}
		// Single lookup by the exact original bytes.
		qy, ok := q.Query(want)
		if !ok {
			t.Fatalf("Query missing id % x", want)
		}
		if !bytes.Equal([]byte(qy.ID), []byte(want)) {
			t.Fatalf("Query id changed: want % x got % x", want, qy.ID)
		}
	}

	all := q.Queries()
	if len(all) != len(ids) {
		t.Fatalf("identical resubmits must not add records: got %d rows", len(all))
	}
	for i, qy := range all {
		if !bytes.Equal([]byte(qy.ID), []byte(ids[i])) {
			t.Fatalf("Queries order/content at %d: want % x got % x", i, ids[i], qy.ID)
		}
	}
}

// 0xFF, 0xFE and U+FFFD are three different ids: all three submitted with
// distinct nonces must each be queryable by their own bytes, listed once in
// first-submission order, and never merged on visual similarity. An identical
// resubmit returns the existing record; a content change conflicts; a
// terminal id cannot be re-submitted. Advance result ids are byte-identical
// too, including the replay reason that names a raw-bytes winner.
func TestIDInvalidBytesDistinctProcessingAndResults(t *testing.T) {
	idFF := string([]byte{0xFF})
	idFE := string([]byte{0xFE})
	idFD := replacementCharID

	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("chain-a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "chain-a", Height: 100, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	// ff and ufffd deliver; fe waits (proof height beyond coverage); loser
	// shares ff's exact triple and must replay with ff's raw id in the reason.
	envFF := idEnvelope(idFF, 50, 100)
	envFE := idEnvelope(idFE, 60, 101)
	envFD := idEnvelope(idFD, 70, 100)
	envLoser := idEnvelope("loser", 50, 100)
	for _, e := range []Envelope{envFF, envFE, envFD, envLoser} {
		if _, err := q.Submit(e); err != nil {
			t.Fatalf("submit % x: %v", e.Message.ID, err)
		}
	}

	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	wantResults := []struct {
		id     string
		status string
	}{
		{idFF, StatusSuccess},
		{idFE, StatusWaiting},
		{idFD, StatusSuccess},
		{"loser", StatusReplay},
	}
	if len(rep.Results) != len(wantResults) {
		t.Fatalf("results = %+v", rep.Results)
	}
	for i, want := range wantResults {
		got := rep.Results[i]
		if !bytes.Equal([]byte(got.ID), []byte(want.id)) || got.Status != want.status {
			t.Fatalf("result %d = (% x, %s), want (% x, %s)", i, got.ID, got.Status, want.id, want.status)
		}
	}
	loserReason := "nonce combination already consumed by message " + idFF
	if got, _ := q.Query("loser"); !bytes.Equal([]byte(got.Reason), []byte(loserReason)) {
		t.Fatalf("replay reason changed: want % x got % x", loserReason, got.Reason)
	}

	// fe waits: attempts and retry schedule are attached to the raw-bytes id.
	if got, _ := q.Query(idFE); got.Status != StatusWaiting || got.Attempts != 1 || got.NextRetry != 2000 {
		t.Fatalf("waiting state for % x: %+v", idFE, got)
	}

	// Same-id rules survive the raw-bytes keys.
	if _, err := q.Submit(envFE); err != nil { // identical, still waiting
		t.Fatalf("identical resubmit of waiting id: %v", err)
	}
	bad := envFE
	bad.Message.Payload = "changed"
	if _, err := q.Submit(bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("different content under same raw id must conflict: %v", err)
	}
	if _, err := q.Submit(envFF); !errors.Is(err, ErrTerminal) {
		t.Fatalf("terminal raw-bytes id resubmit must return ErrTerminal: %v", err)
	}
	if len(q.Queries()) != 4 {
		t.Fatal("conflict/duplicate resubmits changed record count")
	}

	// Full listing keeps the exact bytes and first-submission order.
	all := q.Queries()
	for i, want := range []string{idFF, idFE, idFD, "loser"} {
		if !bytes.Equal([]byte(all[i].ID), []byte(want)) {
			t.Fatalf("Queries[%d] = % x, want % x", i, all[i].ID, want)
		}
	}
}

// Across close/reopen every raw-bytes id keeps its exact message: the three
// look-alike ids stay distinct, the consumed nonce stays attributed to its
// raw-bytes winner (a new id on the same triple still replays; the winner
// stays success and is never redelivered), and waiting status/attempts/retry
// survive with the id. Forcing a compaction in between must change nothing.
func TestIDInvalidBytesSurviveReopenAndCompaction(t *testing.T) {
	idFF := string([]byte{0xFF})
	idFE := string([]byte{0xFE})
	idFD := replacementCharID

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
	envFF := idEnvelope(idFF, 50, 100)
	envFE := idEnvelope(idFE, 60, 101)
	envFD := idEnvelope(idFD, 70, 100)
	envLoser := idEnvelope("loser", 50, 100)
	for _, e := range []Envelope{envFF, envFE, envFD, envLoser} {
		if _, err := q.Submit(e); err != nil {
			t.Fatalf("submit % x: %v", e.Message.ID, err)
		}
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}

	// A message from an unregistered, exotic-but-valid chain name (NUL bytes
	// and Chinese are valid UTF-8) terminalizes unknown-source; its reason
	// embeds the chain name verbatim and must survive the same boundaries.
	rawChain := "ghost\x00链"
	alien := Envelope{Message: Message{
		ID: "alien", From: rawChain, To: "chain-b", Nonce: 1, ProofAt: 1,
	}}
	if _, err := q.Submit(alien); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(2000); err != nil {
		t.Fatal(err)
	}
	alienReason := "unknown source chain " + rawChain
	if got, _ := q.Query("alien"); got.From != rawChain ||
		!bytes.Equal([]byte(got.Reason), []byte(alienReason)) {
		t.Fatalf("unknown-source record = from %q reason % x, want %q / % x",
			got.From, got.Reason, rawChain, alienReason)
	}

	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	defer q.Close()

	// verifyState asserts the restored records; it is read-only and safe to
	// run after every reopen.
	verifyState := func(t *testing.T) {
		t.Helper()
		// The three look-alikes resolve to their own distinct messages.
		for want, env := range map[string]Envelope{idFF: envFF, idFE: envFE, idFD: envFD} {
			qy, ok := q.Query(want)
			if !ok {
				t.Fatalf("id % x vanished after reopen/compaction", want)
			}
			if !bytes.Equal([]byte(qy.ID), []byte(want)) || qy.Payload != env.Message.Payload {
				t.Fatalf("record for % x changed: %+v", want, qy)
			}
		}
		if got, _ := q.Query(idFF); got.Status != StatusSuccess || got.Attempts != 1 {
			t.Fatalf("winner % x not restored as success: %+v", idFF, got)
		}
		if got, _ := q.Query(idFE); got.Status != StatusWaiting || got.Attempts != 2 || got.NextRetry != 4000 {
			t.Fatalf("waiting % x not restored with schedule: %+v", idFE, got)
		}
		if got, _ := q.Query("loser"); got.Status != StatusReplay ||
			got.Reason != "nonce combination already consumed by message "+idFF {
			t.Fatalf("replay attribution for loser changed: %+v", got)
		}
		if got, _ := q.Query("alien"); got.Status != StatusUnknownSrc || got.Reason != alienReason {
			t.Fatalf("unknown-source record changed: %+v", got)
		}
	}

	// exerciseResubmits uses the live raw-bytes id and the consumed triple;
	// it mutates state and runs once per session.
	exerciseResubmits := func(t *testing.T, againID string) {
		t.Helper()
		// Identical resubmit of the live raw-bytes id is idempotent and keeps
		// whatever schedule the record currently has; a one-byte content change
		// still conflicts.
		before, _ := q.Query(idFE)
		echo, err := q.Submit(envFE)
		if err != nil || echo.Status != StatusWaiting ||
			echo.Attempts != before.Attempts || echo.NextRetry != before.NextRetry {
			t.Fatalf("identical resubmit after reopen changed the record: rec=%+v err=%v", echo, err)
		}
		bad := envFE
		bad.Message.Payload = "changed"
		if _, err := q.Submit(bad); !errors.Is(err, ErrConflict) {
			t.Fatalf("content conflict lost after reopen: %v", err)
		}

		// New id, same consumed triple: replay, winner stays success and is not
		// delivered again.
		if _, err := q.Submit(idEnvelope(againID, 50, 100)); err != nil {
			t.Fatal(err)
		}
		rep, err := q.Advance(3000)
		if err != nil {
			t.Fatal(err)
		}
		var sawAgain bool
		for _, r := range rep.Results {
			if r.ID == idFF {
				t.Fatalf("successful raw-bytes winner redelivered: %+v", r)
			}
			if r.ID == againID {
				sawAgain = true
				if r.Status != StatusReplay || r.Reason != "nonce combination already consumed by message "+idFF {
					t.Fatalf("new id on consumed triple: %+v", r)
				}
			}
		}
		if !sawAgain {
			t.Fatalf("new id on the winner's triple was not judged replay: %+v", rep.Results)
		}
		if got, _ := q.Query(idFF); got.Status != StatusSuccess {
			t.Fatalf("winner status changed: %+v", got)
		}
		if got, ok := q.Query(againID); !ok || got.Status != StatusReplay ||
			got.Reason != "nonce combination already consumed by message "+idFF {
			t.Fatalf("replay record for new id not preserved: ok=%v %+v", ok, got)
		}
	}

	assertOrder := func(t *testing.T, want ...string) {
		t.Helper()
		all := q.Queries()
		if len(all) != len(want) {
			t.Fatalf("Queries rows = %d, want %d: %+v", len(all), len(want), all)
		}
		for i, w := range want {
			if !bytes.Equal([]byte(all[i].ID), []byte(w)) {
				t.Fatalf("Queries[%d] = % x, want % x", i, all[i].ID, w)
			}
		}
	}

	baseOrder := []string{idFF, idFE, idFD, "loser", "alien"}
	verifyState(t)
	exerciseResubmits(t, "again-1")
	assertOrder(t, append(append([]string{}, baseOrder...), "again-1")...)
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	verifyState(t)
	if got, ok := q.Query("again-1"); !ok || got.Status != StatusReplay {
		t.Fatalf("again-1 replay lost across reopen: ok=%v %+v", ok, got)
	}
	assertOrder(t, append(append([]string{}, baseOrder...), "again-1")...)
	// A further new id on the same triple still replays after the restart.
	exerciseResubmits(t, "again-2")
	assertOrder(t, append(append([]string{}, baseOrder...), "again-1", "again-2")...)
}

// Automatic threshold compaction, triggered by an ordinary Submit, must carry
// invalid-UTF-8 ids byte-exactly into the snapshot: an oversized raw-bytes id
// supplies the bulk, the small crossing submit pushes past 4 MiB, and both
// read identically, in order, after reopen.
func TestIDInvalidBytesSurviveAutomaticCompaction(t *testing.T) {
	const margin int64 = 4096

	versionFrame := int64(len(encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))))
	baseSize := int64(len(logMagic)) + versionFrame
	checkpointFrame := int64(len(encodeFrame(mustMarshal(&logEntry{T: kindAdvance, Now: 1000}))))

	crossID := "cross" + string([]byte{0xFF})
	crossEntry := &logEntry{T: kindSubmit, Seq: 1, From: "chain-a", To: "chain-b", Nonce: 2, ProofAt: 1}
	crossEntry.setID(crossID)
	crossFrame := int64(len(encodeFrame(mustMarshal(crossEntry))))

	// The filler is the seq-0 submit: its seq zero-value is JSON-omitted, so
	// the framed size measured here is exactly what the real queue writes.
	fillerFrame := func(idLen int) int64 {
		e := &logEntry{T: kindSubmit, From: "chain-a", To: "chain-b", Nonce: 1, ProofAt: 1}
		e.setID(strings.Repeat("\xff", idLen))
		return int64(len(encodeFrame(mustMarshal(e))))
	}
	overhead := fillerFrame(1) - int64(base64.StdEncoding.EncodedLen(1))

	nCheckpoints := int(margin/checkpointFrame) + 2
	targetFillerFrame := compactThreshold - margin - baseSize -
		int64(nCheckpoints)*checkpointFrame - crossFrame
	if targetFillerFrame <= overhead {
		t.Fatalf("setup arithmetic leaves no room: target=%d overhead=%d", targetFillerFrame, overhead)
	}
	var fillerLen int
	for lo, hi := 0, int(targetFillerFrame); ; {
		mid := (lo + hi + 1) / 2
		if fillerFrame(mid) <= targetFillerFrame {
			lo = mid
		} else {
			hi = mid - 1
		}
		if lo == hi {
			fillerLen = lo
			break
		}
	}
	if fillerLen == 0 {
		t.Fatal("filler id length resolved to zero")
	}
	fillerID := strings.Repeat("\xff", fillerLen)
	filler := idEnvelope(fillerID, 1, 1)
	filler.Message.Payload = ""
	cross := idEnvelope(crossID, 2, 1)
	cross.Message.Payload = ""

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if q.store.size != baseSize {
		t.Fatalf("base size mismatch: want %d got %d", baseSize, q.store.size)
	}
	// Equal-time checkpoint padding (legal with no messages yet) so the
	// crossing submit is exactly what trips 4 MiB; snapshots drop the
	// checkpoints, so the compacted log lands margin below the threshold.
	for i := 0; i < nCheckpoints; i++ {
		if _, err := q.Advance(1000); err != nil {
			t.Fatal(err)
		}
	}
	if q.store.size > compactThreshold {
		t.Fatalf("padding crossed the threshold early: %d", q.store.size)
	}
	if _, err := q.Submit(filler); err != nil {
		t.Fatalf("filler submit: %v", err)
	}
	if q.store.size > compactThreshold {
		t.Fatalf("filler crossed before the crossing submit: %d", q.store.size)
	}
	if _, err := q.Submit(cross); err != nil {
		t.Fatalf("crossing submit: %v", err)
	}
	if q.store.size > compactThreshold {
		t.Fatalf("auto-compaction did not shrink the log: %d", q.store.size)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	defer q.Close()
	got, ok := q.Query(fillerID)
	if !ok || got.ID != fillerID {
		t.Fatalf("filler id changed across auto compaction: ok=%v idlen=%d gotlen=%d",
			ok, len(fillerID), len(got.ID))
	}
	if got, ok := q.Query(crossID); !ok || got.ID != crossID {
		t.Fatalf("crossing id lost across auto compaction: ok=%v % x", ok, got.ID)
	}
	all := q.Queries()
	if len(all) != 2 || all[0].ID != fillerID || all[1].ID != crossID {
		t.Fatalf("order after auto compaction: %d rows % x / % x", len(all), all[0].ID, all[1].ID)
	}

	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"idB64":"`)) {
		t.Fatalf("invalid-UTF-8 ids not stored byte-exactly: %s", raw[:200])
	}
	if bytes.Contains(raw, []byte(replacementCharID)) {
		t.Fatalf("compacted log contains replacement characters for raw-byte ids")
	}
}

// Existing state directories keep their meaning: ids an older build saved as
// plain JSON are read at face value. A saved U+FFFD is that character, not the
// 0xFF an old build may have lost — resubmitting the character idempotently
// returns the record, while resubmitting the original invalid bytes conflicts
// rather than resurrecting or merging.
func TestIDLegacyRecordsReadAtFaceValue(t *testing.T) {
	dir := t.TempDir()
	var raw []byte
	raw = append(raw, logMagic...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 0, ID: "txt", From: "a", To: "b", Nonce: 1,
		Payload: "legacy text", ProofAt: 10,
	}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 1, ID: replacementCharID, From: "a", To: "b",
		Nonce: 2, Payload: "p", ProofAt: 10,
	}))...)
	writeRawLog(t, dir, raw)

	q := reopen(t, dir)
	defer q.Close()
	if got, ok := q.Query("txt"); !ok || got.ID != "txt" {
		t.Fatalf("legacy text id: ok=%v %q", ok, got.ID)
	}
	got, ok := q.Query(replacementCharID)
	if !ok || got.ID != replacementCharID {
		t.Fatalf("legacy replacement id must be read at face value: ok=%v % x", ok, got.ID)
	}
	saved := Envelope{Message: Message{
		ID: replacementCharID, From: "a", To: "b", Nonce: 2, Payload: "p", ProofAt: 10,
	}}
	if _, err := q.Submit(saved); err != nil {
		t.Fatalf("saved replacement character id must resubmit as itself: %v", err)
	}
	// The invalid bytes the old build lost are not guessed back: 0xFF is a
	// different id from the saved U+FFFD, so it enqueues a distinct record and
	// neither id finds the other's message.
	original := saved
	original.Message.ID = string([]byte{0xFF})
	if _, err := q.Submit(original); err != nil {
		t.Fatalf("original invalid bytes are a distinct id, not a conflict with saved U+FFFD: %v", err)
	}
	if got, ok := q.Query(replacementCharID); !ok || got.ID != replacementCharID {
		t.Fatalf("saved U+FFFD record changed: ok=%v % x", ok, got.ID)
	}
	if got, ok := q.Query(string([]byte{0xFF})); !ok || got.ID != string([]byte{0xFF}) {
		t.Fatalf("raw 0xFF id must keep its own new record: ok=%v % x", ok, got.ID)
	}
	if len(q.Queries()) != 3 {
		t.Fatalf("raw 0xFF and saved U+FFFD must not merge: %+v", q.Queries())
	}
}

// A checksum-valid record that carries both a plain field and its base64 form,
// or an undecodable base64 field, is an inconsistent record no build writes:
// opening returns ErrCorrupt and leaves the file byte-for-byte untouched.
func TestIDB64InconsistentRecordsRejected(t *testing.T) {
	submitBoth := &logEntry{
		T: kindSubmit, Seq: 0, ID: "m", IDB64: "bQ==", From: "a", To: "b",
		Nonce: 1, Payload: "p", ProofAt: 10,
	}
	submitBad := &logEntry{
		T: kindSubmit, Seq: 0, IDB64: "!!!not-base64!!!", From: "a", To: "b",
		Nonce: 1, Payload: "p", ProofAt: 10,
	}
	successBoth := func() []*logEntry {
		return []*logEntry{
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, Payload: "p", ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1,
				ConsumeBy: "m", ConsumeByB64: "bQ=="},
		}
	}
	successBadBy := func() []*logEntry {
		return []*logEntry{
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, Payload: "p", ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok",
				Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1,
				ConsumeByB64: "!!!not-base64!!!"},
		}
	}
	waitingBadReason := func() []*logEntry {
		return []*logEntry{
			{T: kindSubmit, Seq: 0, ID: "w", From: "a", To: "b", Nonce: 1, Payload: "p", ProofAt: 100},
			{T: kindResult, Now: 1000, ID: "w", Status: StatusWaiting, ReasonB64: "!!!not-base64!!!",
				Attempts: 1, NextRetry: 2000},
		}
	}

	cases := map[string][]*logEntry{
		"submit with both id and idB64":         {submitBoth},
		"submit with undecodable idB64":         {submitBad},
		"success with both consumeBy forms":     successBoth(),
		"success with undecodable consumeByB64": successBadBy(),
		"waiting with undecodable reasonB64":    waitingBadReason(),
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

// The empty id stays rejected by the Go API as an invalid argument.
func TestIDEmptyStillRejected(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	_, err := q.Submit(Envelope{Message: Message{ID: "", From: "a", To: "b", Nonce: 1, ProofAt: 1}})
	if !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("empty id: want ErrInvalidArg, got %v", err)
	}
}
