package relayproof

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Source chains are arbitrary byte strings: the Go interface only requires a
// non-empty source name, never valid UTF-8 — for RegisterSource, for a
// header's chain and for a submitted message's "from". The source keys
// registration and trusted-header lookups and is half of the replay identity
// (source, destination, nonce), so it must survive save, reopen and
// compaction byte for byte; JSON string encoding would otherwise silently
// rewrite invalid bytes to U+FFFD, merging distinct chains' trusted coverage
// and consumed nonces after a restart.

const replacementCharFrom = "�"

// fromEnvelope builds an envelope from source chain from, addressed to
// chain-b, with caller-chosen id/nonce/proof height.
func fromEnvelope(id, from string, nonce uint64, proofAt int64) Envelope {
	return Envelope{
		Message: Message{
			ID: id, From: from, To: "chain-b", Nonce: nonce,
			Payload: "payload-" + id, ProofAt: proofAt,
		},
	}
}

// Every source shape must come back byte-identical from the submit echo, a
// single Query and the full Queries listing, in first-submission order.
func TestSourceArbitraryBytesPreservedInInstance(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()

	names := []string{"plain", "colon", "nul", "ff", "fe", "mixed", "replacement"}
	froms := map[string]string{
		"plain":       "chain-a",
		"colon":       "a:b",
		"nul":         "a\x00b",
		"ff":          string([]byte{0xFF}),
		"fe":          string([]byte{0xFE}),
		"mixed":       "pre\x00mid" + string([]byte{0xFF, 0xFE}) + "post",
		"replacement": replacementCharFrom,
	}
	for i, name := range names {
		if _, err := q.Submit(fromEnvelope(name, froms[name], uint64(i+1), 90)); err != nil {
			t.Fatalf("submit %s: %v", name, err)
		}
	}

	for i, name := range names {
		want := froms[name]
		echo, err := q.Submit(fromEnvelope(name, want, uint64(i+1), 90))
		if err != nil {
			t.Fatalf("identical resubmit %s: %v", name, err)
		}
		if !bytes.Equal([]byte(echo.Msg.Message.From), []byte(want)) {
			t.Fatalf("resubmit echo from for %s changed: want % x got % x", name, want, echo.Msg.Message.From)
		}
		qy, ok := q.Query(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if !bytes.Equal([]byte(qy.From), []byte(want)) {
			t.Fatalf("Query from for %s changed: want % x got % x", name, want, qy.From)
		}
	}
	all := q.Queries()
	if len(all) != len(names) {
		t.Fatalf("identical resubmits must not add records: got %d rows", len(all))
	}
	for i, qy := range all {
		if !bytes.Equal([]byte(qy.From), []byte(froms[names[i]])) {
			t.Fatalf("Queries[%d] from = % x, want % x", i, qy.From, froms[names[i]])
		}
	}
}

// 0xFF, 0xFE and the legal character U+FFFD are three different source chains.
// Registering and trusting only one of them never qualifies a visually similar
// chain for delivery: the unregistered one terminates as unknown-source, the
// registered-but-uncovered one waits. Once every chain has its own
// registration and covering trusted header, messages to the same destination
// with the same nonce succeed independently and consume three distinct
// triples — across a plain reopen and a forced compaction plus reopen, and a
// later replay is attributed to its own chain's winner.
func TestSourceInvalidBytesDistinctChainsAcrossReopens(t *testing.T) {
	fromFF := string([]byte{0xFF})
	fromFE := string([]byte{0xFE})
	fromFD := replacementCharFrom

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Register 0xFF (with covering trusted header) and U+FFFD (registered but
	// with no sufficient trusted height); 0xFE stays unregistered.
	if err := q.RegisterSource(fromFF); err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource(fromFD); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: fromFF, Height: 100, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	// Same destination and nonce 7; only the source chain distinguishes them.
	for _, e := range []Envelope{
		fromEnvelope("ff", fromFF, 7, 100),
		fromEnvelope("fe", fromFE, 7, 100),
		fromEnvelope("fd", fromFD, 7, 100),
	} {
		if _, err := q.Submit(e); err != nil {
			t.Fatalf("submit from % x: %v", e.Message.From, err)
		}
	}
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Result{}
	for _, r := range rep.Results {
		got[r.ID] = r
	}
	if r := got["ff"]; r.Status != StatusSuccess {
		t.Fatalf("registered and covered chain must deliver: %+v", r)
	}
	if r := got["fe"]; r.Status != StatusUnknownSrc {
		t.Fatalf("unregistered look-alike chain must terminate unknown-source, not borrow coverage: %+v", r)
	}
	if r := got["fd"]; r.Status != StatusWaiting {
		t.Fatalf("registered but uncovered chain must wait, not borrow coverage: %+v", r)
	}
	if len(q.consumed) != 1 {
		t.Fatalf("only the covered chain may consume: %v", q.consumed)
	}

	// Give every chain its own registration and covering trusted header. The
	// unknown-source message stays terminal (never reactivated); new messages
	// from each chain to the same destination with the same nonce succeed
	// independently.
	if err := q.RegisterSource(fromFE); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{fromFE, fromFD} {
		if err := q.UpsertHeader(Header{Chain: c, Height: 100, Root: "r", Trusted: true}); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []Envelope{
		fromEnvelope("ff8", fromFF, 8, 100),
		fromEnvelope("fe8", fromFE, 8, 100),
		fromEnvelope("fd8", fromFD, 8, 100),
	} {
		if _, err := q.Submit(e); err != nil {
			t.Fatalf("submit from % x: %v", e.Message.From, err)
		}
	}
	rep, err = q.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	got = map[string]Result{}
	for _, r := range rep.Results {
		got[r.ID] = r
	}
	for _, id := range []string{"ff8", "fe8", "fd8"} {
		if r := got[id]; r.Status != StatusSuccess {
			t.Fatalf("%s: each registered, covered chain must deliver: %+v", id, r)
		}
	}
	// The waiting message from the first round is now covered and delivers too.
	if r := got["fd"]; r.Status != StatusSuccess {
		t.Fatalf("previously waiting message must deliver once covered: %+v", r)
	}
	if len(q.consumed) != 5 {
		t.Fatalf("want five distinct consumed triples, got %d: %v", len(q.consumed), q.consumed)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// assertRestored verifies the nonce-8 winners and their attributions after
	// every reopen boundary.
	assertRestored := func(t *testing.T, q *Queue) {
		t.Helper()
		for id, from := range map[string]string{"ff8": fromFF, "fe8": fromFE, "fd8": fromFD} {
			qy, ok := q.Query(id)
			if !ok {
				t.Fatalf("winner %s vanished", id)
			}
			if !bytes.Equal([]byte(qy.From), []byte(from)) {
				t.Fatalf("source of %s changed: want % x got % x", id, from, qy.From)
			}
			if qy.Status != StatusSuccess || qy.Attempts != 1 {
				t.Fatalf("winner %s not restored as success: %+v", id, qy)
			}
			if winner := q.consumed[newConsumeToken(from, "chain-b", 8)]; winner != id {
				t.Fatalf("consumption of source % x misattributed to %q", from, winner)
			}
		}
		if st, _ := q.Query("fe"); st.Status != StatusUnknownSrc {
			t.Fatalf("terminal unknown-source record changed across reopen: %+v", st)
		}
	}

	// Plain reopen: the chains, their coverage and the consumed triples stay
	// distinct and byte-exact.
	q = reopen(t, dir)
	assertRestored(t, q)
	if !q.sources[fromFF] || !q.sources[fromFE] || !q.sources[fromFD] {
		t.Fatalf("registrations merged across reopen: %v", q.sources)
	}

	// A new id from the chain that already consumed nonce 8 replays at its own
	// chain's winner — never at another chain's consumption record.
	if _, err := q.Submit(fromEnvelope("again-ff", fromFF, 8, 100)); err != nil {
		t.Fatal(err)
	}
	rep, err = q.Advance(3000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		if r.ID == "again-ff" &&
			(r.Status != StatusReplay || r.Reason != "nonce combination already consumed by message ff8") {
			t.Fatalf("replay must be judged by the chain's own consumption: %+v", r)
		}
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// Forced compaction plus another reopen must merge nothing.
	q = reopen(t, dir)
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q = reopen(t, dir)
	defer q.Close()
	assertRestored(t, q)
	if len(q.consumed) != 5 {
		t.Fatalf("compaction merged consumed triples: %v", q.consumed)
	}
	if qy, ok := q.Query("again-ff"); !ok || qy.Status != StatusReplay ||
		qy.Reason != "nonce combination already consumed by message ff8" {
		t.Fatalf("replay record lost/misattributed across compaction: ok=%v %+v", ok, qy)
	}
}

// An unterminated (waiting) message keeps its exact source chain across a
// reopen: an identical-byte resubmit returns the existing record with its
// status, attempts and retry schedule, while changing one source byte — or
// submitting the visually similar U+FFFD — is a content conflict that leaves
// the original record untouched.
func TestSourceInvalidBytesWaitingResubmitAfterReopen(t *testing.T) {
	fromRaw := "w" + string([]byte{0x00, 0xFF, 0xFE})
	env := fromEnvelope("w", fromRaw, 7, 100) // no trusted coverage at all below

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource(fromRaw)
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
	if !bytes.Equal([]byte(echo.Msg.Message.From), []byte(fromRaw)) ||
		echo.Status != StatusWaiting || echo.Attempts != 1 || echo.NextRetry != 2000 {
		t.Fatalf("resubmit must not reschedule or rewrite source: %+v", echo)
	}
	if len(q.Queries()) != 1 {
		t.Fatal("identical resubmit must not add a record")
	}

	for name, bad := range map[string]string{
		"one byte changed":    "w" + string([]byte{0x00, 0xFF, 0x00}),
		"single invalid byte": string([]byte{0xFE}),
		"look-alike U+FFFD":   replacementCharFrom,
		"mixed but replaced":  "w" + string([]byte{0x00, 0xEF, 0xBF, 0xBD}) + string([]byte{0xFE}),
	} {
		c := env
		c.Message.From = bad
		if _, err := q.Submit(c); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s: source % x must conflict, got %v", name, bad, err)
		}
	}
	st, _ := q.Query("w")
	if !bytes.Equal([]byte(st.From), []byte(fromRaw)) ||
		st.Attempts != 1 || st.NextRetry != 2000 || st.Status != StatusWaiting {
		t.Fatalf("conflicting resubmits changed the original record: %+v", st)
	}
}

// The compacted snapshot stores invalid source bytes base64-encoded in the
// source entry ("chainB64"), the header entry, the submit entry ("fromB64")
// and the success state entry ("consumeFromB64"), never as replacement
// characters, and reads them back byte-identical after reopen.
func TestSourceInvalidBytesOnDiskEncoding(t *testing.T) {
	fromFF := string([]byte{0xFF})
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource(fromFF); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: fromFF, Height: 100, Root: "r", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(fromEnvelope("ff", fromFF, 3, 100)); err != nil {
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
	for _, key := range []string{`"chainB64":"`, `"fromB64":"`, `"consumeFromB64":"`} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Fatalf("invalid source not stored byte-exactly (%s): %s", key, raw)
		}
	}
	enc := base64.StdEncoding.EncodeToString([]byte{0xFF})
	if !bytes.Contains(raw, []byte(enc)) {
		t.Fatalf("log missing base64 source bytes %q: %s", enc, raw)
	}
	if bytes.Contains(raw, []byte(replacementCharFrom)) {
		t.Fatalf("compacted log must not contain replacement characters for raw-byte sources")
	}

	q = reopen(t, dir)
	defer q.Close()
	if !q.sources[fromFF] {
		t.Fatalf("registration of % x lost across compaction", fromFF)
	}
	st, ok := q.Query("ff")
	if !ok || !bytes.Equal([]byte(st.From), []byte(fromFF)) || st.Status != StatusSuccess {
		t.Fatalf("source not restored byte-exactly: ok=%v %+v", ok, st)
	}
	if winner := q.consumed[newConsumeToken(fromFF, "chain-b", 3)]; winner != "ff" {
		t.Fatalf("consumption of source % x misattributed to %q", fromFF, winner)
	}
}

// Existing state directories keep their meaning: source names an older build
// saved as plain JSON are read at face value. A saved U+FFFD is that
// character, not the 0xFF the old build may have lost — the U+FFFD chain is
// the registered, covered one, while a message from the invalid-byte chain is
// a different, unregistered source that terminates as unknown-source.
func TestSourceLegacyRecordsReadAtFaceValue(t *testing.T) {
	dir := t.TempDir()
	entries := []*logEntry{
		{T: kindSource, Chain: replacementCharFrom},
		{T: kindHeader, Chain: replacementCharFrom, Height: 100, Root: "r", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "won", From: replacementCharFrom, To: "b", Nonce: 7, Payload: "p", ProofAt: 100},
		{T: kindResult, Now: 1000, ID: "won", Status: StatusSuccess,
			Reason:   "delivered; proof verified by trusted header at height 100",
			Attempts: 1, ConsumeFrom: replacementCharFrom, ConsumeTo: "b", ConsumeNonce: 7, ConsumeBy: "won"},
		{T: kindAdvance, Now: 1000},
	}
	writeLegacyLog(t, dir, entries...)

	q, err := Open(dir)
	if err != nil {
		t.Fatalf("directory with a legacy replacement source must open directly: %v", err)
	}
	defer q.Close()
	if !q.sources[replacementCharFrom] {
		t.Fatal("legacy U+FFFD registration not restored at face value")
	}
	if q.sources[string([]byte{0xFF})] {
		t.Fatal("the invalid-byte chain must not be considered registered by a legacy U+FFFD record")
	}
	if winner := q.consumed[newConsumeToken(replacementCharFrom, "b", 7)]; winner != "won" {
		t.Fatalf("legacy consumption not restored at U+FFFD: %q", winner)
	}
	if _, taken := q.consumed[newConsumeToken(string([]byte{0xFF}), "b", 7)]; taken {
		t.Fatal("the invalid-byte chain must not be considered consumed by a legacy U+FFFD record")
	}
	// A message from the genuine invalid-byte chain is unregistered and
	// terminates unknown-source; one from U+FFFD replays at the saved winner.
	if _, err := q.Submit(fromEnvelope("raw-byte-src", string([]byte{0xFF}), 7, 100)); err != nil {
		t.Fatal(err)
	}
	repl := fromEnvelope("replacement-src", replacementCharFrom, 7, 100)
	repl.Message.To = "b" // the legacy winner's destination
	if _, err := q.Submit(repl); err != nil {
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
	if r := seen["raw-byte-src"]; r.Status != StatusUnknownSrc {
		t.Fatalf("the invalid-byte chain must not borrow the U+FFFD chain's registration: %+v", r)
	}
	if r := seen["replacement-src"]; r.Status != StatusReplay ||
		r.Reason != "nonce combination already consumed by message won" {
		t.Fatalf("the saved U+FFFD chain must still replay at won: %+v", r)
	}
}

// A checksum-valid record that carries both a plain source name and its
// base64 form, or an undecodable base64 value — in a source or header entry's
// "chain", a submit entry's "from" or a success entry's "consumeFrom" — is an
// inconsistent record no build writes: opening returns ErrCorrupt, no usable
// queue, and the file stays untouched. A success triple whose consumeFrom
// decodes to something other than the message's own source is likewise
// corrupt.
func TestSourceB64InconsistentRecordsRejected(t *testing.T) {
	sourceBoth := &logEntry{T: kindSource, Chain: "a", ChainB64: "YQ=="}
	headerBoth := &logEntry{T: kindHeader, Chain: "a", ChainB64: "YQ==", Height: 1, Root: "r"}
	submitBoth := &logEntry{
		T: kindSubmit, Seq: 0, ID: "m", From: "a", FromB64: "YQ==", To: "b",
		Nonce: 1, Payload: "p", ProofAt: 10,
	}
	submitBad := &logEntry{
		T: kindSubmit, Seq: 0, ID: "m", FromB64: "!!!not-base64!!!", To: "b",
		Nonce: 1, Payload: "p", ProofAt: 10,
	}
	successBoth := func() []*logEntry {
		return []*logEntry{
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, Payload: "p", ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok", Attempts: 1,
				ConsumeFrom: "a", ConsumeFromB64: "YQ==", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		}
	}
	successBadFrom := func() []*logEntry {
		return []*logEntry{
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, Payload: "p", ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok", Attempts: 1,
				ConsumeFromB64: "!!!not-base64!!!", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		}
	}
	// Submit comes from "a"; the success claims consumption of raw 0xFF: a
	// mismatched triple that must be rejected rather than silently accepted.
	successMismatch := func() []*logEntry {
		return []*logEntry{
			{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, Payload: "p", ProofAt: 10},
			{T: kindResult, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok", Attempts: 1,
				ConsumeFromB64: "/w==", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m"},
		}
	}
	rawCases := map[string]string{
		"empty from plus fromB64":   `{"t":"submit","seq":0,"id":"m","from":"","to":"b","nonce":1,"proofAt":10,"fromB64":"/w=="}`,
		"empty chain plus chainB64": `{"t":"source","chain":"","chainB64":"/w=="}`,
	}

	for name, e := range map[string]*logEntry{
		"source with both chain and chainB64": sourceBoth,
		"header with both chain and chainB64": headerBoth,
		"submit with both from and fromB64":   submitBoth,
		"submit with undecodable fromB64":     submitBad,
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
		"success with both consumeFrom forms":       successBoth,
		"success with undecodable consumeFromB64":   successBadFrom,
		"success whose consumeFrom mismatches from": successMismatch,
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

// The empty source stays rejected by the Go API as an invalid argument, for
// registration, headers and submission alike.
func TestSourceEmptyStillRejected(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource(""); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("empty source registration: want ErrInvalidArg, got %v", err)
	}
	if err := q.UpsertHeader(Header{Chain: "", Height: 1, Root: "r", Trusted: true}); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("empty header chain: want ErrInvalidArg, got %v", err)
	}
	_, err := q.Submit(Envelope{Message: Message{ID: "m", From: "", To: "b", Nonce: 1, ProofAt: 1}})
	if !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("empty message source: want ErrInvalidArg, got %v", err)
	}
}
