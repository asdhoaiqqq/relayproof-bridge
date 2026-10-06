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

// Destination chains are arbitrary byte strings: the Go submit interface only
// requires a non-empty destination, never valid UTF-8 — text, colons, NUL
// bytes, stray 0xFF/0xFE bytes, or text mixed with them. The destination is
// half of the replay identity (source, destination, nonce), so it must survive
// save, reopen and compaction byte for byte; JSON string encoding would
// otherwise silently rewrite invalid bytes to U+FFFD, merging distinct
// destinations and misattributing consumed nonces after a restart.

const replacementCharTo = "�"

// toEnvelope builds an envelope addressed to destination to, source chain-a,
// with caller-chosen id/nonce/proof height.
func toEnvelope(id, to string, nonce uint64, proofAt int64) Envelope {
	return Envelope{
		Message: Message{
			ID: id, From: "chain-a", To: to, Nonce: nonce,
			Payload: "payload-" + id, ProofAt: proofAt,
		},
	}
}

// Every destination shape must come back byte-identical from the submit echo,
// a single Query and the full Queries listing, in first-submission order.
func TestDestinationArbitraryBytesPreservedInInstance(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()

	names := []string{"plain", "colon", "nul", "ff", "fe", "mixed", "replacement"}
	tos := map[string]string{
		"plain":       "chain-b",
		"colon":       "b:c",
		"nul":         "b\x00c",
		"ff":          string([]byte{0xFF}),
		"fe":          string([]byte{0xFE}),
		"mixed":       "pre\x00mid" + string([]byte{0xFF, 0xFE}) + "post",
		"replacement": replacementCharTo,
	}
	for i, name := range names {
		if _, err := q.Submit(toEnvelope(name, tos[name], uint64(i+1), 90)); err != nil {
			t.Fatalf("submit %s: %v", name, err)
		}
	}

	for i, name := range names {
		want := tos[name]
		echo, err := q.Submit(toEnvelope(name, want, uint64(i+1), 90))
		if err != nil {
			t.Fatalf("identical resubmit %s: %v", name, err)
		}
		if !bytes.Equal([]byte(echo.Msg.Message.To), []byte(want)) {
			t.Fatalf("resubmit echo to for %s changed: want % x got % x", name, want, echo.Msg.Message.To)
		}
		qy, ok := q.Query(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if !bytes.Equal([]byte(qy.To), []byte(want)) {
			t.Fatalf("Query to for %s changed: want % x got % x", name, want, qy.To)
		}
	}
	all := q.Queries()
	if len(all) != len(names) {
		t.Fatalf("identical resubmits must not add records: got %d rows", len(all))
	}
	for i, qy := range all {
		if !bytes.Equal([]byte(qy.To), []byte(tos[names[i]])) {
			t.Fatalf("Queries[%d] to = % x, want % x", i, qy.To, tos[names[i]])
		}
	}
}

// 0xFF, 0xFE and the legal character U+FFFD are three different destinations:
// with the same source and nonce, all three messages succeed independently and
// consume three distinct triples. They must stay distinct across a plain
// reopen, further processing, and a forced compaction plus reopen; saved and
// recovered successes must never merge.
func TestDestinationInvalidBytesDistinctConsumptionAcrossReopens(t *testing.T) {
	toFF := string([]byte{0xFF})
	toFE := string([]byte{0xFE})
	toFD := replacementCharTo

	setup := func(t *testing.T, dir string) *Queue {
		t.Helper()
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
		// Same source and nonce 7; only the destination distinguishes them.
		for _, e := range []Envelope{
			toEnvelope("ff", toFF, 7, 100),
			toEnvelope("fe", toFE, 7, 100),
			toEnvelope("fd", toFD, 7, 100),
		} {
			if _, err := q.Submit(e); err != nil {
				t.Fatalf("submit to % x: %v", e.Message.To, err)
			}
		}
		rep, err := q.Advance(1000)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 3 {
			t.Fatalf("three distinct destinations must each succeed: %+v", rep.Results)
		}
		for _, r := range rep.Results {
			if r.Status != StatusSuccess {
				t.Fatalf("message %s to a distinct destination must succeed, got %s (%s)", r.ID, r.Status, r.Reason)
			}
		}
		if len(q.consumed) != 3 {
			t.Fatalf("want three distinct consumed triples, got %d: %v", len(q.consumed), q.consumed)
		}
		return q
	}

	// assertRestored verifies the three winners after every reopen boundary.
	assertRestored := func(t *testing.T, q *Queue) {
		t.Helper()
		for id, to := range map[string]string{"ff": toFF, "fe": toFE, "fd": toFD} {
			qy, ok := q.Query(id)
			if !ok {
				t.Fatalf("winner %s vanished", id)
			}
			if !bytes.Equal([]byte(qy.To), []byte(to)) {
				t.Fatalf("destination of %s changed: want % x got % x", id, to, qy.To)
			}
			if qy.Status != StatusSuccess || qy.Attempts != 1 {
				t.Fatalf("winner %s not restored as success: %+v", id, qy)
			}
			if winner := q.consumed[newConsumeToken("chain-a", to, 7)]; winner != id {
				t.Fatalf("consumption of destination % x misattributed to %q", to, winner)
			}
		}
	}

	dir := t.TempDir()
	q := setup(t, dir)
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// Plain reopen: the three consumed triples stay distinct and byte-exact.
	q = reopen(t, dir)
	assertRestored(t, q)

	// New ids on the already-consumed destinations replay, each attributed to
	// the real winner; a new destination that never consumed nonce 7 delivers
	// instead of being misjudged as a replay.
	for _, c := range []struct {
		id, to, winner string
	}{
		{"again-ff", toFF, "ff"},
		{"again-fe", toFE, "fe"},
		{"again-fd", toFD, "fd"},
	} {
		if _, err := q.Submit(toEnvelope(c.id, c.to, 7, 100)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := q.Submit(toEnvelope("again-other", "chain-other", 7, 100)); err != nil {
		t.Fatal(err)
	}
	rep, err := q.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Result{}
	for _, r := range rep.Results {
		got[r.ID] = r
	}
	for _, c := range []struct {
		id, to, winner string
	}{
		{"again-ff", toFF, "ff"},
		{"again-fe", toFE, "fe"},
		{"again-fd", toFD, "fd"},
	} {
		r := got[c.id]
		wantReason := "nonce combination already consumed by message " + c.winner
		if r.Status != StatusReplay || r.Reason != wantReason {
			t.Fatalf("%s (to % x) must replay at %s: %+v", c.id, c.to, c.winner, r)
		}
	}
	if r := got["again-other"]; r.Status != StatusSuccess {
		t.Fatalf("a destination that never consumed nonce 7 must deliver, not replay: %+v", r)
	}
	if len(q.consumed) != 4 {
		t.Fatalf("want four consumed triples after the fresh delivery: %v", q.consumed)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen after the replay/success processing: attributions survive.
	q = reopen(t, dir)
	assertRestored(t, q)
	for _, c := range []struct{ id, winner string }{
		{"again-ff", "ff"}, {"again-fe", "fe"}, {"again-fd", "fd"},
	} {
		if qy, ok := q.Query(c.id); !ok || qy.Status != StatusReplay ||
			qy.Reason != "nonce combination already consumed by message "+c.winner {
			t.Fatalf("%s replay record lost/misattributed: ok=%v %+v", c.id, ok, qy)
		}
	}
	if qy, ok := q.Query("again-other"); !ok || qy.Status != StatusSuccess {
		t.Fatalf("fresh-destination delivery lost: ok=%v %+v", ok, qy)
	}

	// Forced compaction plus another reopen must merge nothing.
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q = reopen(t, dir)
	defer q.Close()
	assertRestored(t, q)
	if len(q.consumed) != 4 {
		t.Fatalf("compaction merged consumed triples: %v", q.consumed)
	}
	// Post-compaction the replay rules still hold by exact destination bytes.
	if _, err := q.Submit(toEnvelope("post-ff", toFF, 7, 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(toEnvelope("post-other", "chain-other-2", 7, 100)); err != nil {
		t.Fatal(err)
	}
	rep, err = q.Advance(3000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		switch r.ID {
		case "post-ff":
			if r.Status != StatusReplay || r.Reason != "nonce combination already consumed by message ff" {
				t.Fatalf("post-compaction replay misattributed: %+v", r)
			}
		case "post-other":
			if r.Status != StatusSuccess {
				t.Fatalf("fresh destination post-compaction must deliver: %+v", r)
			}
		}
	}
}

// An unterminated (waiting) message keeps its exact destination across a
// reopen: an identical-byte resubmit returns the existing record with its
// status, attempts and retry schedule, while changing one destination byte —
// or submitting the visually similar U+FFFD — is a content conflict that
// leaves the original record untouched.
func TestDestinationInvalidBytesWaitingResubmitAfterReopen(t *testing.T) {
	toRaw := "w" + string([]byte{0x00, 0xFF, 0xFE})
	env := toEnvelope("w", toRaw, 7, 100) // trusted coverage stops at 100 below

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
	if st, _ := q.Query("w"); st.Status != StatusWaiting || st.Attempts != 1 || st.NextRetry != 2000 {
		t.Fatalf("setup: unexpected state %+v", st)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	defer q.Close()
	echo, err := q.Submit(env)
	if err != nil {
		t.Fatalf("byte-identical resubmit after reopen must return the existing record: %v", err)
	}
	if !bytes.Equal([]byte(echo.Msg.Message.To), []byte(toRaw)) ||
		echo.Status != StatusWaiting || echo.Attempts != 1 || echo.NextRetry != 2000 {
		t.Fatalf("resubmit must not reschedule or rewrite destination: %+v", echo)
	}
	if len(q.Queries()) != 1 {
		t.Fatal("identical resubmit must not add a record")
	}

	for name, bad := range map[string]string{
		"one byte changed":    "w" + string([]byte{0x00, 0xFF, 0x00}),
		"single invalid byte": string([]byte{0xFE}),
		"look-alike U+FFFD":   replacementCharTo,
		"mixed but replaced":  "w" + string([]byte{0x00, 0xEF, 0xBF, 0xBD}) + string([]byte{0xFE}),
	} {
		if _, err := q.Submit(toEnvelope("w", bad, 7, 100)); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s: destination % x must conflict, got %v", name, bad, err)
		}
	}
	st, _ := q.Query("w")
	if !bytes.Equal([]byte(st.To), []byte(toRaw)) ||
		st.Attempts != 1 || st.NextRetry != 2000 || st.Status != StatusWaiting {
		t.Fatalf("conflicting resubmits changed the original record: %+v", st)
	}
}

// The compacted snapshot stores invalid destination bytes base64-encoded in
// both the submit entry ("toB64") and the success state entry
// ("consumeToB64"), never as replacement characters, and reads them back
// byte-identical after reopen.
func TestDestinationInvalidBytesOnDiskEncoding(t *testing.T) {
	toFF := string([]byte{0xFF})
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("chain-a")
	if err := q.UpsertHeader(Header{Chain: "chain-a", Height: 100, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(toEnvelope("ff", toFF, 3, 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"toB64":"`)) {
		t.Fatalf("invalid destination not stored byte-exactly in submit entry: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"consumeToB64":"`)) {
		t.Fatalf("invalid destination not stored byte-exactly in success entry: %s", raw)
	}
	enc := base64.StdEncoding.EncodeToString([]byte{0xFF})
	if !bytes.Contains(raw, []byte(enc)) {
		t.Fatalf("log missing base64 destination bytes %q: %s", enc, raw)
	}
	if bytes.Contains(raw, []byte(replacementCharTo)) {
		t.Fatalf("compacted log must not contain replacement characters for raw-byte destinations")
	}

	q = reopen(t, dir)
	defer q.Close()
	if st, ok := q.Query("ff"); !ok || !bytes.Equal([]byte(st.To), []byte(toFF)) || st.Status != StatusSuccess {
		t.Fatalf("destination not restored byte-exactly: ok=%v %+v", ok, st)
	}
}

// Existing state directories keep their meaning: destinations an older build
// saved as plain JSON are read at face value. A saved U+FFFD is that
// character, not the 0xFF the old build may have lost — resubmitting the
// character is idempotent, while the original invalid bytes are a different
// destination that neither conflicts with nor merges into the saved record.
func TestDestinationLegacyRecordsReadAtFaceValue(t *testing.T) {
	dir := t.TempDir()
	var raw []byte
	raw = append(raw, logMagic...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 0, ID: "txt", From: "a", To: "b", Nonce: 1,
		Payload: "p", ProofAt: 10,
	}))...)
	// An old build that lost the invalid bytes saved the destination as U+FFFD.
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 1, ID: "lost", From: "a", To: replacementCharTo, Nonce: 2,
		Payload: "p", ProofAt: 10,
	}))...)
	writeRawLog(t, dir, raw)

	q := reopen(t, dir)
	defer q.Close()
	if got, ok := q.Query("txt"); !ok || got.To != "b" {
		t.Fatalf("legacy text destination: ok=%v %q", ok, got.To)
	}
	got, ok := q.Query("lost")
	if !ok || !bytes.Equal([]byte(got.To), []byte(replacementCharTo)) {
		t.Fatalf("legacy replacement destination must be read at face value: ok=%v % x", ok, got.To)
	}
	saved := Envelope{Message: Message{
		ID: "lost", From: "a", To: replacementCharTo, Nonce: 2, Payload: "p", ProofAt: 10,
	}}
	if _, err := q.Submit(saved); err != nil {
		t.Fatalf("saved replacement character destination must resubmit as itself: %v", err)
	}
	// The invalid bytes the old build lost are not guessed back: the same id
	// with 0xFF is different content and conflicts, never merges.
	original := saved
	original.Message.To = string([]byte{0xFF})
	if _, err := q.Submit(original); !errors.Is(err, ErrConflict) {
		t.Fatalf("original invalid bytes differ from saved U+FFFD, must conflict: %v", err)
	}
	if st, _ := q.Query("lost"); !bytes.Equal([]byte(st.To), []byte(replacementCharTo)) {
		t.Fatalf("saved U+FFFD destination changed: % x", st.To)
	}
	if len(q.Queries()) != 2 {
		t.Fatal("conflicting resubmit must not add a record")
	}
}

// A legacy success whose destination an old build saved as a plain U+FFFD
// consumes only (source, U+FFFD, nonce): after reopen a new id addressed to
// the genuine invalid-byte destination 0xFF delivers, while one addressed to
// U+FFFD still replays at the historical winner. Save/restore must not merge
// the two success records nor declare the usable directory corrupt.
func TestDestinationLegacyConsumptionReadAtFaceValue(t *testing.T) {
	dir := t.TempDir()
	entries := []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindHeader, Chain: "a", Height: 100, Root: "r", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "won", From: "a", To: replacementCharTo, Nonce: 7, Payload: "p", ProofAt: 100},
		{T: kindResult, Now: 1000, ID: "won", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeFrom: "a", ConsumeTo: replacementCharTo, ConsumeNonce: 7, ConsumeBy: "won"},
		{T: kindAdvance, Now: 1000},
	}
	writeLegacyLog(t, dir, entries...)

	q, err := Open(dir)
	if err != nil {
		t.Fatalf("directory with a legacy replacement destination must open directly: %v", err)
	}
	defer q.Close()
	if winner := q.consumed[newConsumeToken("a", replacementCharTo, 7)]; winner != "won" {
		t.Fatalf("legacy consumption not restored at U+FFFD: %q", winner)
	}
	if _, taken := q.consumed[newConsumeToken("a", string([]byte{0xFF}), 7)]; taken {
		t.Fatal("the invalid-byte destination must not be considered consumed by a legacy U+FFFD record")
	}
	if _, err := q.Submit(Envelope{Message: Message{
		ID: "raw-byte-dest", From: "a", To: string([]byte{0xFF}), Nonce: 7, Payload: "p", ProofAt: 100,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(Envelope{Message: Message{
		ID: "replacement-dest", From: "a", To: replacementCharTo, Nonce: 7, Payload: "p", ProofAt: 100,
	}}); err != nil {
		t.Fatal(err)
	}
	rep, err := q.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]Result{}
	for _, r := range rep.Results {
		seen[r.ID] = r
	}
	if r := seen["raw-byte-dest"]; r.Status != StatusSuccess {
		t.Fatalf("a different destination must not be misjudged as replay: %+v", r)
	}
	if r := seen["replacement-dest"]; r.Status != StatusReplay ||
		r.Reason != "nonce combination already consumed by message won" {
		t.Fatalf("the saved U+FFFD destination must still replay at won: %+v", r)
	}
}

// A checksum-valid record that carries both a plain destination and its base64
// form, or an undecodable base64 value — in either a submit entry's "to" or a
// success entry's "consumeTo" — is an inconsistent record no build writes:
// opening returns ErrCorrupt, no usable queue, and the file stays untouched.
// A success triple whose consumeTo decodes to something other than the
// message's own destination is likewise corrupt.
func TestDestinationB64InconsistentRecordsRejected(t *testing.T) {
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
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok", Attempts: 1,
				ConsumeFrom: "a", ConsumeTo: "b", ConsumeToB64: "Yg==", ConsumeNonce: 1, ConsumeBy: "m"},
		}
	}
	successBadTo := func() []*logEntry {
		return []*logEntry{
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, Payload: "p", ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok", Attempts: 1,
				ConsumeFrom: "a", ConsumeToB64: "!!!not-base64!!!", ConsumeNonce: 1, ConsumeBy: "m"},
		}
	}
	// Submit goes to "b"; the success claims consumption of raw 0xFF: a
	// mismatched triple that must be rejected rather than silently accepted.
	successMismatch := func() []*logEntry {
		return []*logEntry{
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, Payload: "p", ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok", Attempts: 1,
				ConsumeFrom: "a", ConsumeToB64: "/w==", ConsumeNonce: 1, ConsumeBy: "m"},
		}
	}
	rawCases := map[string]string{
		"empty to plus toB64":                      `{"t":"submit","seq":0,"id":"m","from":"a","to":"","nonce":1,"proofAt":10,"toB64":"/w=="}`,
		"plain and toB64 decode to the same bytes": `{"t":"submit","seq":0,"id":"m","from":"a","nonce":1,"proofAt":10,"toB64":"Yg==","to":"b"}`,
	}

	for name, e := range map[string]*logEntry{
		"submit with both to and toB64": submitBoth,
		"submit with undecodable toB64": submitBad,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var data []byte
			data = append(data, logMagic...)
			data = append(data, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
			data = append(data, encodeFrame(mustMarshal(e))...)
			writeRawLog(t, dir, data)
			assertCorruptAndUntouched(t, dir, data)
		})
	}
	for name, build := range map[string]func() []*logEntry{
		"success with both consumeTo forms":     successBoth,
		"success with undecodable consumeToB64": successBadTo,
		"success whose consumeTo mismatches to": successMismatch,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var data []byte
			data = append(data, logMagic...)
			data = append(data, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
			for _, e := range build() {
				data = append(data, encodeFrame(mustMarshal(e))...)
			}
			writeRawLog(t, dir, data)
			assertCorruptAndUntouched(t, dir, data)
		})
	}
	for name, jsonBody := range rawCases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var data []byte
			data = append(data, logMagic...)
			data = append(data, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
			data = append(data, encodeFrame([]byte(jsonBody))...)
			writeRawLog(t, dir, data)
			assertCorruptAndUntouched(t, dir, data)
		})
	}
}

// The empty destination stays rejected by the Go API as an invalid argument.
func TestDestinationEmptyStillRejected(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	_, err := q.Submit(Envelope{Message: Message{ID: "m", From: "a", To: "", Nonce: 1, ProofAt: 1}})
	if !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("empty destination: want ErrInvalidArg, got %v", err)
	}
}

// Automatic threshold compaction, triggered by an ordinary Submit, must carry
// invalid-UTF-8 destinations byte-exactly into the snapshot: an oversized
// raw-bytes destination supplies the bulk, the small crossing submit pushes
// past 4 MiB, and both read identically, in order, after reopen.
func TestDestinationInvalidBytesSurviveAutomaticCompaction(t *testing.T) {
	const margin int64 = 4096

	versionFrame := int64(len(encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))))
	baseSize := int64(len(logMagic)) + versionFrame
	checkpointFrame := int64(len(encodeFrame(mustMarshal(&logEntry{T: kindAdvance, Now: 1000}))))

	crossTo := "cross" + string([]byte{0xFF})
	crossEntry := &logEntry{T: kindSubmit, Seq: 1, ID: "cross", From: "chain-a", Nonce: 2, ProofAt: 1}
	crossEntry.setTo(crossTo)
	crossFrame := int64(len(encodeFrame(mustMarshal(crossEntry))))

	// The filler is the seq-0 submit: its seq zero-value is JSON-omitted. The
	// gauge entry mirrors the real write field-for-field (id included), so its
	// framed size is exactly what the real queue appends; only the destination
	// length varies.
	fillerFrame := func(toLen int) int64 {
		e := &logEntry{T: kindSubmit, ID: "filler", From: "chain-a", Nonce: 1, ProofAt: 1}
		e.setTo(strings.Repeat("\xff", toLen))
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
		t.Fatal("filler destination length resolved to zero")
	}
	fillerTo := strings.Repeat("\xff", fillerLen)
	filler := Envelope{Message: Message{ID: "filler", From: "chain-a", To: fillerTo, Nonce: 1, ProofAt: 1}}
	cross := Envelope{Message: Message{ID: "cross", From: "chain-a", To: crossTo, Nonce: 2, ProofAt: 1}}

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
	got, ok := q.Query("filler")
	if !ok || !bytes.Equal([]byte(got.To), []byte(fillerTo)) {
		t.Fatalf("filler destination changed across auto compaction: ok=%v len(want)=%d len(got)=%d",
			ok, len(fillerTo), len(got.To))
	}
	if got, ok := q.Query("cross"); !ok || !bytes.Equal([]byte(got.To), []byte(crossTo)) {
		t.Fatalf("crossing destination lost across auto compaction: ok=%v % x", ok, got.To)
	}
	all := q.Queries()
	if len(all) != 2 || all[0].ID != "filler" || all[1].ID != "cross" {
		t.Fatalf("order after auto compaction: %+v", all)
	}
	// Byte-identical resubmits stay idempotent against the compacted records,
	// and the visually similar replacement character still conflicts.
	if _, err := q.Submit(filler); err != nil {
		t.Fatalf("filler identical resubmit after compaction: %v", err)
	}
	bad := cross
	bad.Message.To = replacementCharTo
	if _, err := q.Submit(bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("U+FFFD must differ from the invalid-byte destination after compaction: %v", err)
	}
	if len(q.Queries()) != 2 {
		t.Fatal("idempotent/conflicting resubmits changed record count")
	}

	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"toB64":"`)) {
		t.Fatalf("invalid destinations not stored byte-exactly: %s", raw[:200])
	}
}
