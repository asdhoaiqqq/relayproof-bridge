package relayproof

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests pin the effect of AUTOMATIC log compaction on already-accepted
// messages when a normal, successful Submit is the operation that pushes the
// append-only log past its 4 MiB threshold. Submit reports success only after
// the new message's own frame is fsynced, and maybeCompact then rewrites the
// log as a snapshot of live state; the regression these guard against is the
// triggering message (or anything submitted before it) being lost, reordered,
// processed early or having its status changed by that rewrite. Every
// scenario crosses the real compactThreshold with real bytes — no compaction
// is invoked by hand — and is observed again after closing and reopening the
// same state directory, so the compacted log itself must carry the data.

// submitFrameSize is the exact on-disk size of the submit frame that
// appendSubmit would write for env at seq.
func submitFrameSize(env Envelope, seq int64) int {
	m := env.Message
	e := &logEntry{
		T: kindSubmit, Seq: seq, ID: m.ID, From: m.From, To: m.To,
		Nonce: m.Nonce, Payload: m.Payload, ProofAt: m.ProofAt, ExpiresAt: env.ExpiresAt,
	}
	b, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}
	return frameHeaderSize + len(b) + frameCRCsSize
}

// compactionMargin keeps the compacted snapshot itself past the threshold
// after a fat crossing message is rewritten: compacted submit+state frames are
// shaped slightly differently from the append-only frames the payload was
// sized against, so landing the pre-compaction log exactly at threshold+1 can
// leave the rewritten snapshot a few frames under. 256 KiB dwarfs that reshape
// delta without making the tests meaningfully slower (each snapshot rewrite is
// one non-fsyncing write of ~4.2 MiB).
const compactionMargin = 256 << 10

// crossingSubmit returns a pending-destined envelope whose single submit frame
// takes the active log from at/below the threshold to threshold+margin bytes,
// so its append is the first one that crosses (needsCompaction is a strict >)
// and the resulting snapshot, which keeps the fat record verbatim, stays over
// the threshold as well — letting a normal-sized follow-up submit compact too.
// Payload bytes are single-byte JSON characters; the size is measured against
// the real framed record, so the JSON field overhead is accounted for.
func crossingSubmit(q *Queue, id, from, to string, nonce uint64, proofAt, expiresAt int64) Envelope {
	target := compactThreshold + compactionMargin
	e := Envelope{Message: Message{ID: id, From: from, To: to, Nonce: nonce, ProofAt: proofAt}, ExpiresAt: expiresAt}
	need := target - int(q.store.size) - submitFrameSize(e, q.nextSeq)
	if need < 1 {
		need = 1
	}
	// Frame size is linear in payload length once the field is present; the
	// first bytes also pay the JSON field wrapper, so converge in a few steps.
	for range 5 {
		e.Message.Payload = strings.Repeat("A", need)
		total := int(q.store.size) + submitFrameSize(e, q.nextSeq)
		if total == target {
			return e
		}
		need += target - total
		if need < 1 {
			need = 1
		}
	}
	panic("crossingSubmit failed to land at the target size")
}

// assertCompactedLogCarries fails unless the active queue.log is a replayable
// snapshot that both carries id's bytes (id payloads use plain characters) and
// contains at least one compacted state entry.
func assertCompactedLogCarries(t *testing.T, dir, id string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatalf("read compacted log: %v", err)
	}
	if len(raw) <= compactThreshold {
		t.Fatalf("log did not stay past the %d-byte threshold: %d bytes", compactThreshold, len(raw))
	}
	if !strings.Contains(string(raw), `"t":"state"`) {
		t.Fatalf("active log is not a compacted snapshot (no state entry)")
	}
	if !strings.Contains(string(raw), `"id":"`+id+`"`) {
		t.Fatalf("compacted log does not carry triggering message %q", id)
	}
}

// content is the immutable message identity checked across compaction.
type msgContent struct {
	id, from, to, payload string
	nonce                 uint64
	proofAt, expiresAt    int64
}

func contentOf(q Query) msgContent {
	return msgContent{id: q.ID, from: q.From, to: q.To, payload: q.Payload, nonce: q.Nonce, proofAt: q.ProofAt, expiresAt: q.ExpiresAt}
}

func envContent(e Envelope) msgContent {
	m := e.Message
	return msgContent{id: m.ID, from: m.From, to: m.To, payload: m.Payload, nonce: m.Nonce, proofAt: m.ProofAt, expiresAt: e.ExpiresAt}
}

// Scenario 1: the message whose submit crosses the threshold is itself saved
// durably together with everything submitted earlier — delivered successes
// and still-pending records alike. All keep their original id, routing,
// nonce, payload, proof height, expiry, status, reason and attempt counts;
// the triggering message stays pending with zero attempts and no retry, and
// the first-submission order (each id once) survives a directory reopen.
func TestAutoCompactionOnSubmitPreservesTriggerAndPriorMessages(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}

	// Two previously submitted, already delivered messages, and one pending
	// message that has never been processed.
	old1 := Envelope{Message: Message{ID: "old1", From: "a", To: "b", Nonce: 10, Payload: "one", ProofAt: 80}, ExpiresAt: 9_000_000_000_000}
	old2 := Envelope{Message: Message{ID: "old2", From: "a", To: "b", Nonce: 11, Payload: "two", ProofAt: 100}, ExpiresAt: 9_000_000_000_000}
	pend1 := Envelope{Message: Message{ID: "pend1", From: "a", To: "b", Nonce: 20, Payload: "pending-body", ProofAt: 50}, ExpiresAt: 8_000_000_000_000}
	for _, e := range []Envelope{old1, old2} {
		if _, err := q.Submit(e); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := q.Advance(1000)
	if err != nil || len(rep.Results) != 2 {
		t.Fatalf("setup advance: %+v err=%v", rep.Results, err)
	}
	if _, err := q.Submit(pend1); err != nil {
		t.Fatal(err)
	}

	before := q.store.compactions
	if q.store.size > compactThreshold {
		t.Fatalf("setup must stay under the threshold, got %d", q.store.size)
	}

	// The fat pending message is the first crossing; its own success triggers
	// the first automatic compaction.
	fill := crossingSubmit(q, "fill", "a", "b", 900, 100, 0)
	rec, err := q.Submit(fill)
	if err != nil {
		t.Fatalf("crossing submit: %v", err)
	}
	if q.store.compactions != before+1 {
		t.Fatalf("the fat submit must compact once, compactions=%d", q.store.compactions-before)
	}
	if rec.Status != StatusPending || rec.Attempts != 0 || rec.NextRetry != 0 {
		t.Fatalf("crossing message must be pending/0/no-retry: %+v", rec)
	}
	if q.store.size <= compactThreshold {
		t.Fatalf("snapshot must still hold the fat pending record above threshold")
	}

	// The normal-sized new message is the user-visible triggering submission:
	// state is already over threshold, so its submit also compacts, and its
	// success result must mean this exact message is already saved.
	trigger := Envelope{Message: Message{ID: "trigger", From: "a", To: "b", Nonce: 777, Payload: "trigger-body", ProofAt: 90}, ExpiresAt: 9_000_000_000_000}
	trigRec, err := q.Submit(trigger)
	if err != nil {
		t.Fatalf("triggering submit: %v", err)
	}
	if q.store.compactions != before+2 {
		t.Fatalf("the triggering submit must compact once more, compactions=%d", q.store.compactions-before)
	}
	if trigRec.Status != StatusPending || trigRec.Reason != "awaiting first processing" ||
		trigRec.Attempts != 0 || trigRec.NextRetry != 0 {
		t.Fatalf("triggering message must be returned pending with zero attempts: %+v", trigRec)
	}

	wantContent := map[string]msgContent{
		"old1":    envContent(old1),
		"old2":    envContent(old2),
		"pend1":   envContent(pend1),
		"fill":    envContent(fill),
		"trigger": envContent(trigger),
	}
	wantStatus := map[string]struct {
		status   string
		reason   string
		attempts int
	}{
		"old1":    {StatusSuccess, "delivered; proof verified by trusted header at height 100", 1},
		"old2":    {StatusSuccess, "delivered; proof verified by trusted header at height 100", 1},
		"pend1":   {StatusPending, "awaiting first processing", 0},
		"fill":    {StatusPending, "awaiting first processing", 0},
		"trigger": {StatusPending, "awaiting first processing", 0},
	}

	all := q.Queries()
	if len(all) != 5 {
		t.Fatalf("want 5 records each appearing once, got %d: %+v", len(all), all)
	}
	wantOrder := []string{"old1", "old2", "pend1", "fill", "trigger"}
	for i, qr := range all {
		if qr.ID != wantOrder[i] {
			t.Fatalf("position %d: want %s, got %s (full order %v)", i, wantOrder[i], qr.ID, idsOf(all))
		}
		if got := contentOf(qr); got != wantContent[qr.ID] {
			t.Fatalf("%s content changed by compaction:\nwant %+v\ngot  %+v", qr.ID, wantContent[qr.ID], got)
		}
		ws := wantStatus[qr.ID]
		if qr.Status != ws.status || qr.Reason != ws.reason || qr.Attempts != ws.attempts || qr.NextRetry != 0 {
			t.Fatalf("%s state wrong after compaction: %+v", qr.ID, qr)
		}
	}
	if q.nextSeq != 5 || len(q.order) != 3 {
		t.Fatalf("seq/order wrong: nextSeq=%d live order=%v", q.nextSeq, q.order)
	}
	// Neither still-pending message consumed a nonce.
	for _, nonce := range []uint64{20, 900, 777} {
		if _, taken := q.consumed[newConsumeToken("a", "b", nonce)]; taken {
			t.Fatalf("nonce %d consumed before first processing", nonce)
		}
	}
	if got := q.consumed[newConsumeToken("a", "b", 10)]; got != "old1" {
		t.Fatalf("old1 consumption lost: %q", got)
	}
	if got := q.consumed[newConsumeToken("a", "b", 11)]; got != "old2" {
		t.Fatalf("old2 consumption lost: %q", got)
	}

	// The rewrite on disk is a snapshot, and the triggering message is in it.
	assertCompactedLogCarries(t, dir, "trigger")

	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen the SAME directory: the triggering submission must not exist only
	// before close; every confirmed submission, its content, order and state
	// must come back from the compacted log.
	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen compacted directory: %v", err)
	}
	defer q2.Close()
	if q2.nextSeq != 5 || len(q2.records) != 5 {
		t.Fatalf("reopen lost records: nextSeq=%d records=%d", q2.nextSeq, len(q2.records))
	}
	reopened := q2.Queries()
	if len(reopened) != 5 {
		t.Fatalf("want 5 records after reopen, got %d", len(reopened))
	}
	for i, qr := range reopened {
		if qr.ID != wantOrder[i] {
			t.Fatalf("after reopen position %d: want %s got %s (%v)", i, wantOrder[i], qr.ID, idsOf(reopened))
		}
		if got := contentOf(qr); got != wantContent[qr.ID] {
			t.Fatalf("after reopen %s content changed:\nwant %+v\ngot  %+v", qr.ID, wantContent[qr.ID], got)
		}
		ws := wantStatus[qr.ID]
		if qr.Status != ws.status || qr.Reason != ws.reason || qr.Attempts != ws.attempts || qr.NextRetry != 0 {
			t.Fatalf("after reopen %s state wrong: %+v", qr.ID, qr)
		}
	}
	if got := q2.consumed[newConsumeToken("a", "b", 777)]; got != "" {
		t.Fatalf("trigger must be pending after reopen, nonce held by %q", got)
	}
}

// Scenario 2: two messages with different ids but the SAME registered source,
// same destination and same nonce both sit through the automatic compaction
// BEFORE either is first processed; both proofs are already covered by a
// trusted header and neither has expired. When the queue is advanced
// afterwards, submission order alone decides delivery: the first submitted
// succeeds, the second ends replay with a reason naming the winner. The
// compaction-triggering submit earns no priority. Both records end with one
// attempt, no retry schedule and their original payloads still readable, also
// across a reopen and further (no-op) advances.
func TestAutoCompactionBeforeFirstProcessingKeepsDeliveryOrder(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true})

	// A fat message crosses the threshold and is itself delivered, so once the
	// pair arrives the log is already compacting on every append.
	fill := crossingSubmit(q, "fill", "a", "b", 9000, 100, 0)
	if _, err := q.Submit(fill); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	if r := statusOf(t, q, "fill"); r.Status != StatusSuccess {
		t.Fatalf("setup: fill must deliver, got %+v", r)
	}

	first := Envelope{Message: Message{ID: "first", From: "a", To: "b", Nonce: 42, Payload: "first-payload", ProofAt: 100}, ExpiresAt: 9_000_000_000_000}
	second := Envelope{Message: Message{ID: "second", From: "a", To: "b", Nonce: 42, Payload: "second-payload", ProofAt: 100}, ExpiresAt: 9_000_000_000_000}

	c0 := q.store.compactions
	r1, err := q.Submit(first)
	if err != nil {
		t.Fatal(err)
	}
	if q.store.compactions <= c0 {
		t.Fatal("submitting first must compact the over-threshold log")
	}
	if r1.Status != StatusPending || r1.Attempts != 0 || r1.NextRetry != 0 {
		t.Fatalf("first must be untouched before first processing: %+v", r1)
	}
	c1 := q.store.compactions
	r2, err := q.Submit(second)
	if err != nil {
		t.Fatal(err)
	}
	if q.store.compactions <= c1 {
		t.Fatal("submitting second must compact the over-threshold log")
	}
	if r2.Status != StatusPending || r2.Attempts != 0 || r2.NextRetry != 0 {
		t.Fatalf("second must be untouched before first processing: %+v", r2)
	}
	// Neither processing nor compaction consumed the shared nonce yet.
	if _, taken := q.consumed[newConsumeToken("a", "b", 42)]; taken {
		t.Fatal("nonce must not be consumed before the advance")
	}
	if ids := idsOf(q.Queries()); len(ids) != 3 || ids[0] != "fill" || ids[1] != "first" || ids[2] != "second" {
		t.Fatalf("pre-advance order wrong: %v", ids)
	}

	rep, err := q.Advance(1_700_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	// fill is already terminal, so exactly the pair is processed, in order.
	if len(rep.Results) != 2 {
		t.Fatalf("want exactly first/second results, got %+v", rep.Results)
	}
	win := rep.Results[0]
	lose := rep.Results[1]
	if win.ID != "first" || win.Status != StatusSuccess ||
		win.Reason != "delivered; proof verified by trusted header at height 100" {
		t.Fatalf("first-submitted message must win delivery, got %+v", win)
	}
	if lose.ID != "second" || lose.Status != StatusReplay ||
		lose.Reason != "nonce combination already consumed by message first" {
		t.Fatalf("second-submitted message must be replay attributed to first, got %+v", lose)
	}

	qFirst := statusOf(t, q, "first")
	if qFirst.Status != StatusSuccess || qFirst.Attempts != 1 || qFirst.NextRetry != 0 ||
		qFirst.Msg.Message.Payload != "first-payload" {
		t.Fatalf("first final state wrong: %+v", qFirst)
	}
	qSecond := statusOf(t, q, "second")
	if qSecond.Status != StatusReplay || qSecond.Attempts != 1 || qSecond.NextRetry != 0 ||
		qSecond.Msg.Message.Payload != "second-payload" {
		t.Fatalf("second final state wrong: %+v", qSecond)
	}
	if got := q.consumed[newConsumeToken("a", "b", 42)]; got != "first" {
		t.Fatalf("nonce must be consumed by first only, got %q", got)
	}
	// Every id still appears exactly once, in first-submission order.
	if ids := idsOf(q.Queries()); len(ids) != 3 || ids[0] != "fill" || ids[1] != "first" || ids[2] != "second" {
		t.Fatalf("post-advance order/uniqueness wrong: %v", ids)
	}

	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer q2.Close()
	if r := statusOf(t, q2, "first"); r.Status != StatusSuccess || r.Attempts != 1 ||
		r.Msg.Message.Payload != "first-payload" {
		t.Fatalf("first must survive reopen: %+v", r)
	}
	if r := statusOf(t, q2, "second"); r.Status != StatusReplay || r.Attempts != 1 ||
		r.Reason != "nonce combination already consumed by message first" ||
		r.Msg.Message.Payload != "second-payload" {
		t.Fatalf("second must survive reopen with replay reason: %+v", r)
	}
	if got := q2.consumed[newConsumeToken("a", "b", 42)]; got != "first" {
		t.Fatalf("after reopen nonce owner wrong: %q", got)
	}
	// Terminal records are never reprocessed: equal-time and later advances
	// both produce nothing for the pair.
	for _, now := range []int64{1_700_000_000_000, 1_700_000_100_000} {
		rep, err := q2.Advance(now)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 0 {
			t.Fatalf("terminal pair must not reappear at %d: %+v", now, rep.Results)
		}
	}
	if r := statusOf(t, q2, "second"); r.Status != StatusReplay || r.Attempts != 1 {
		t.Fatalf("second must not gain attempts after reopen: %+v", r)
	}
}

// Scenario 3: the submit-time conflict rules are unchanged for a message that
// is still pending after automatic compaction. An identical resubmit returns
// the existing record and appends/orders nothing; a resubmit with different
// payload is ErrConflict with the original record fully intact; later
// processing order is unaffected and the original payload is the one
// delivered. The conclusions match the non-compacted rules exactly.
func TestAutoCompactionSubmitConflictsKeepRecordAndOrder(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true})

	fill := crossingSubmit(q, "fill", "a", "b", 9000, 100, 0)
	if _, err := q.Submit(fill); err != nil {
		t.Fatal(err)
	}

	dup := Envelope{Message: Message{ID: "dup", From: "a", To: "b", Nonce: 50, Payload: "orig-payload", ProofAt: 100}, ExpiresAt: 9_000_000_000_000}
	if _, err := q.Submit(dup); err != nil {
		t.Fatal(err)
	}
	if q.store.compactions == 0 {
		t.Fatal("setup must have crossed into automatic compaction")
	}
	compactionsAfterDup := q.store.compactions

	// Identical content: existing record, no new message, no append (hence no
	// additional compaction), same submission position.
	echo, err := q.Submit(dup)
	if err != nil {
		t.Fatalf("identical resubmit after compaction: %v", err)
	}
	if echo.Status != StatusPending || echo.Attempts != 0 || echo.NextRetry != 0 || echo.Msg != dup {
		t.Fatalf("identical resubmit must echo the stored pending record: %+v", echo)
	}
	if q.store.compactions != compactionsAfterDup {
		t.Fatal("idempotent resubmit must append nothing")
	}
	if q.nextSeq != 2 || len(q.records) != 2 || len(q.order) != 2 {
		t.Fatalf("identical resubmit added state: nextSeq=%d records=%d order=%v", q.nextSeq, len(q.records), q.order)
	}

	// Different payload with the same id is the existing content-conflict
	// error; nothing is persisted or reordered.
	bad := dup
	bad.Message.Payload = "changed-payload"
	if _, err := q.Submit(bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("different payload after compaction must be ErrConflict, got %v", err)
	}
	if q.store.compactions != compactionsAfterDup {
		t.Fatal("rejected resubmit must append nothing")
	}
	if q.nextSeq != 2 || len(q.records) != 2 || len(q.order) != 2 {
		t.Fatalf("rejected resubmit added state: nextSeq=%d records=%d order=%v", q.nextSeq, len(q.records), q.order)
	}
	got := statusOf(t, q, "dup")
	if got.Msg != dup || got.Status != StatusPending || got.Attempts != 0 || got.NextRetry != 0 {
		t.Fatalf("original record must survive the rejected resubmit intact: %+v", got)
	}

	// A sibling submitted afterwards pins dup's position; the conflict must
	// not have moved it.
	after := Envelope{Message: Message{ID: "after", From: "a", To: "b", Nonce: 51, Payload: "after-body", ProofAt: 100}, ExpiresAt: 9_000_000_000_000}
	if _, err := q.Submit(after); err != nil {
		t.Fatal(err)
	}
	if ids := idsOf(q.Queries()); len(ids) != 3 || ids[0] != "fill" || ids[1] != "dup" || ids[2] != "after" {
		t.Fatalf("order wrong after conflict and sibling submit: %v", ids)
	}

	// Processing proceeds in first-submission order using the ORIGINAL content.
	rep, err := q.Advance(1_700_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 3 {
		t.Fatalf("want fill/dup/after processed once each, got %+v", rep.Results)
	}
	for i, want := range []string{"fill", "dup", "after"} {
		if rep.Results[i].ID != want || rep.Results[i].Status != StatusSuccess {
			t.Fatalf("position %d: want %s success, got %+v", i, want, rep.Results[i])
		}
	}
	if r := statusOf(t, q, "dup"); r.Status != StatusSuccess ||
		r.Msg.Message.Payload != "orig-payload" || r.Attempts != 1 {
		t.Fatalf("dup must deliver exactly once with its original payload: %+v", r)
	}

	// The rejected content stays rejected on the compacted, reopened log too.
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer q2.Close()
	if r := statusOf(t, q2, "dup"); r.Status != StatusSuccess || r.Msg != dup {
		t.Fatalf("after reopen dup differs from the original record: %+v", r)
	}
}

func idsOf(qs []Query) []string {
	out := make([]string, len(qs))
	for i, qr := range qs {
		out[i] = qr.ID
	}
	return out
}
