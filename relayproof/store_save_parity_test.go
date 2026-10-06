package relayproof

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// readLogEntries frames the on-disk log apart from its magic and leading
// version record and returns the remaining records in file order as their raw
// JSON payloads. It is read-only test support for comparing the ordinary
// append path against the compaction path.
func readLogEntries(t *testing.T, dir string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	pos := len(logMagic)
	for pos < len(raw) {
		f, torn, err := scanFrame(raw, pos)
		if err != nil || torn {
			t.Fatalf("unexpected torn/error frame at %d: %v", pos, err)
		}
		body, ok := f.payload(raw)
		if !ok {
			t.Fatalf("bad checksum at %d", pos)
		}
		var e logEntry
		if err := json.Unmarshal(body, &e); err != nil {
			t.Fatal(err)
		}
		if e.T != kindVersion {
			out = append(out, body)
		}
		pos = f.end
	}
	return out
}

// decodedID returns an entry's id as exact bytes, applying the plain/base64
// split the same way replay does.
func decodedID(t *testing.T, body []byte) string {
	t.Helper()
	var e logEntry
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatal(err)
	}
	id, err := e.entryID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// canonicalJSON re-encodes a record's JSON with its "t" kind tag neutralized,
// so a "result" and a "state" entry can be compared field for field. Key order
// is irrelevant to the comparison; key presence (e.g. an omitted nextRetry) and
// every value still count, so a field set in only one path fails the match.
func canonicalJSON(t *testing.T, body []byte) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	m["t"] = "<kind>"
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestSavePathParityNormalVsCompaction pins the consolidation: the ordinary
// incremental save path and the automatic-compaction snapshot path must encode
// the same message record identically. For every message the two paths' submit
// entries are byte-identical, and the snapshot's status entry matches the
// ordinary path's last result entry for that message field for field (only the
// record kind tag differs), across success, a three-attempt waiting record with
// its retry schedule, replay attributed to a raw-bytes winner, expiry and
// unknown-source — and across invalid-UTF-8 id, destination, payload and reason
// bytes, plus an empty payload.
func TestSavePathParityNormalVsCompaction(t *testing.T) {
	idFF := string([]byte{0xFF})
	idFE := string([]byte{0xFE})
	rawTo := "t\xffo"

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	// Deliberately leave "mystery\x00链" unregistered for an unknown-source.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}

	submit := func(e Envelope) {
		t.Helper()
		if _, err := q.Submit(e); err != nil {
			t.Fatal(err)
		}
	}
	// success with raw-bytes id/destination/payload
	submit(Envelope{Message: Message{ID: idFF, From: "a", To: rawTo, Nonce: 50,
		Payload: "p\xff", ProofAt: 100}})
	// waiting record driven to three attempts
	submit(Envelope{Message: Message{ID: idFE, From: "a", To: "b", Nonce: 60,
		Payload: "", ProofAt: 500}})
	// replay naming the raw-bytes winner idFF
	submit(Envelope{Message: Message{ID: "loser", From: "a", To: rawTo, Nonce: 50,
		Payload: "plain", ProofAt: 100}})
	// unknown-source: reason embeds the unregistered chain name
	submit(Envelope{Message: Message{ID: "alien", From: "mystery\x00链", To: "b", Nonce: 1,
		Payload: "a", ProofAt: 1}})
	// expired: waits once at 1000, expires at exactly 1500 during phase 2
	submit(Envelope{Message: Message{ID: "exp", From: "a", To: "b", Nonce: 70,
		Payload: "e", ProofAt: 9999}, ExpiresAt: 1500})
	// success with an empty payload kept as the historical plain field
	submit(Envelope{Message: Message{ID: "empt", From: "a", To: "b", Nonce: 80,
		Payload: "", ProofAt: 10}})

	for _, now := range []int64{1000, 1500, 2000, 4000} {
		if _, err := q.Advance(now); err != nil {
			t.Fatal(err)
		}
	}
	// pending message submitted after processing: zero attempts, no state entry.
	submit(Envelope{Message: Message{ID: "pend", From: "a", To: "b", Nonce: 90,
		Payload: "later", ProofAt: 10}})

	// Sanity: the runtime states the comparison below relies on.
	if r := statusOf(t, q, idFF); r.Status != StatusSuccess || r.Attempts != 1 || r.NextRetry != 0 {
		t.Fatalf("idFF setup wrong: %+v", r)
	}
	if r := statusOf(t, q, idFE); r.Status != StatusWaiting || r.Attempts != 3 || r.NextRetry != 8000 {
		t.Fatalf("idFE must be waiting with three attempts and retry 8000: %+v", r)
	}
	if r := statusOf(t, q, "loser"); r.Status != StatusReplay ||
		r.Reason != "nonce combination already consumed by message "+idFF {
		t.Fatalf("loser replay attribution wrong: %+v", r)
	}
	if r := statusOf(t, q, "exp"); r.Status != StatusExpired || r.Attempts != 2 {
		t.Fatalf("exp setup wrong: %+v", r)
	}
	if r := statusOf(t, q, "alien"); r.Status != StatusUnknownSrc {
		t.Fatalf("alien setup wrong: %+v", r)
	}
	if r := statusOf(t, q, "pend"); r.Status != StatusPending || r.Attempts != 0 {
		t.Fatalf("pend setup wrong: %+v", r)
	}

	normalEntries := readLogEntries(t, dir)

	// Force the compaction snapshot through the same live queue, then read it.
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatal(err)
	}
	compactedEntries := readLogEntries(t, dir)
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// Group each path's submit entries and post-processing entries by id.
	submitByID := func(entries [][]byte) map[string][]byte {
		m := map[string][]byte{}
		for _, body := range entries {
			var e logEntry
			if err := json.Unmarshal(body, &e); err != nil {
				t.Fatal(err)
			}
			if e.T == kindSubmit {
				m[decodedID(t, body)] = body
			}
		}
		return m
	}
	lastStatusByID := func(entries [][]byte, wantKind string) map[string][]byte {
		m := map[string][]byte{}
		for _, body := range entries {
			var e logEntry
			if err := json.Unmarshal(body, &e); err != nil {
				t.Fatal(err)
			}
			if e.T == wantKind {
				m[decodedID(t, body)] = body
			}
		}
		return m
	}

	normalSubmits := submitByID(normalEntries)
	compactedSubmits := submitByID(compactedEntries)
	normalResults := lastStatusByID(normalEntries, kindResult)
	compactedStates := lastStatusByID(compactedEntries, kindState)

	wantIDs := []string{idFF, idFE, "loser", "alien", "exp", "empt", "pend"}
	if len(normalSubmits) != len(wantIDs) || len(compactedSubmits) != len(wantIDs) {
		t.Fatalf("submit entry count: normal=%d compact=%d want=%d",
			len(normalSubmits), len(compactedSubmits), len(wantIDs))
	}
	for _, id := range wantIDs {
		ns, okN := normalSubmits[id]
		cs, okC := compactedSubmits[id]
		if !okN || !okC {
			t.Fatalf("submit entry missing for id % x: normal=%v compact=%v", id, okN, okC)
		}
		// The submit frame restores original content and submission order; the
		// two paths must write it byte for byte.
		if !bytes.Equal(ns, cs) {
			t.Fatalf("submit entry differs by path for id % x:\nnormal   %s\ncompact  %s", id, ns, cs)
		}
	}

	// Every processed message has a last result on the normal path and exactly
	// one state in the snapshot; the pending message has neither.
	processed := []string{idFF, idFE, "loser", "alien", "exp", "empt"}
	if len(normalResults) != len(processed) {
		t.Fatalf("want %d last-result entries, got %d", len(processed), len(normalResults))
	}
	if len(compactedStates) != len(processed) {
		t.Fatalf("want %d compacted state entries, got %d", len(processed), len(compactedStates))
	}
	for _, id := range processed {
		nr, okN := normalResults[id]
		cs, okC := compactedStates[id]
		if !okN || !okC {
			t.Fatalf("status entry missing for id % x: result=%v state=%v", id, okN, okC)
		}
		if got, want := canonicalJSON(t, nr), canonicalJSON(t, cs); got != want {
			t.Fatalf("status entry differs by path for id % x:\nresult %s\nstate  %s", id, got, want)
		}
	}
	if _, pending := normalResults["pend"]; pending {
		t.Fatal("pending message must have no result entry")
	}
	if _, pending := compactedStates["pend"]; pending {
		t.Fatal("compaction must not manufacture an attempt for a pending message")
	}

	// The snapshot still carries invalid bytes base64-encoded, never as the
	// Unicode replacement character, and keeps the empty payload plain.
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{`"idB64":"`, `"toB64":"`, `"payloadB64":"`, `"reasonB64":"`, `"consumeToB64":"`} {
		if !bytes.Contains(raw, []byte(marker)) {
			t.Fatalf("compacted log missing raw-bytes marker %s", marker)
		}
	}
	if bytes.Contains(raw, []byte(replacementCharID)) {
		// Only a genuinely invalid-byte value would surface here; none of the
		// content uses the legal U+FFFD, so its presence means a rewrite.
		t.Fatalf("compacted log rewrote invalid bytes to U+FFFD")
	}
}
