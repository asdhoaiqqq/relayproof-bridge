package relayproof

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Regression coverage for AUTOMATIC log compaction triggered by an ordinary
// successful Submit crossing the 4 MiB threshold — not a manually invoked
// store.compact. When that submit returns success, the triggering message
// must already be part of the compacted state together with every earlier
// message, and compaction must have no business effect:
//
//   - earlier records stay individually queryable with every content field
//     (id, source chain, destination chain, nonce, payload, proof height and
//     expiry) at its original value, and the listing appends the new record
//     at the end in first-submission order, each id appearing exactly once;
//   - the triggering message stays pending with zero attempts and no retry
//     time: compaction itself never processes it and never changes earlier
//     statuses or reasons;
//   - close/reopen of the same state directory restores the same content and
//     order — the last submit must not exist only before closing;
//   - continued delivery keeps first-submission order for two messages
//     sharing one (source, destination, nonce): the first succeeds, the
//     second ends replay whose reason names the first; the submit that
//     triggered compaction gets no extra priority;
//   - the post-compaction submission boundary is unchanged: an identical
//     resubmit returns the existing record without adding an entry, while a
//     resubmit with different content is ErrConflict and leaves the original
//     record, the seq assignment and the processing order untouched.
//
// Crossing the threshold honestly but cheaply: equal-time advance
// checkpoints are small frames that are legal to repeat while no message
// exists yet, and every checkpoint but the last is excluded from a compaction
// snapshot, so a few hundred of them pad the active log up to the boundary
// with a handful of fsyncs. A large PRIOR filler supplies the retained bulk,
// and the ordinary small submit at the end crosses by a few dozen bytes; the
// snapshot then genuinely shrinks well below 4 MiB. All frame sizes are
// measured against real framed records rather than hard-coded.

// gaugeFrames opens a throwaway queue with the same source/header setup and
// returns: the log size right after the source+header pair, the framed size
// of one equal-time advance checkpoint, and the framed submit size of each
// envelope in order. A throwaway record occupies seq 0 first, so the gauged
// envelopes carry seqs 1..N exactly as they do in the real queue (a seq-0
// submit is JSON-omitted and would otherwise be measured 8 bytes short).
// Envelopes must be ASCII-payload.
func gaugeFrames(t *testing.T, envs []Envelope) (base, checkpoint int64, frames []int64) {
	t.Helper()
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	base = q.store.size
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	checkpoint = q.store.size - base
	if _, err := q.Submit(Envelope{Message: Message{
		ID: "gauge-seq0", From: "a", To: "b", Nonce: 999_999,
		Payload: "seq-zero-placeholder", ProofAt: 1,
	}}); err != nil {
		t.Fatal(err)
	}
	for _, e := range envs {
		before := q.store.size
		if _, err := q.Submit(e); err != nil {
			t.Fatal(err)
		}
		frames = append(frames, q.store.size-before)
	}
	return base, checkpoint, frames
}

// submitOverhead measures the non-payload framed size of a submit for the
// template's exact fields when it lands at submission position seq (JSON seq
// encoding differs at seq 0, which is omitted), using an all-ASCII probe
// payload (one JSON byte per character).
func submitOverhead(t *testing.T, template Envelope, seq int64, probeLen int) int64 {
	t.Helper()
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource(template.Message.From); err != nil {
		t.Fatal(err)
	}
	for i := int64(0); i < seq; i++ {
		if _, err := q.Submit(Envelope{Message: Message{
			ID: "gauge-dummy-" + strconv.FormatInt(i, 10), From: template.Message.From, To: "b",
			Nonce: 8_000_000 + uint64(i), Payload: "d", ProofAt: 1,
		}}); err != nil {
			t.Fatal(err)
		}
	}
	before := q.store.size
	template.Message.Payload = strings.Repeat("Z", probeLen)
	if _, err := q.Submit(template); err != nil {
		t.Fatal(err)
	}
	return q.store.size - before - int64(probeLen)
}

// assertRecordExact fails unless the query view equals e in every content
// field and carries exactly the given processing state.
func assertRecordExact(t *testing.T, q *Queue, e Envelope, status, reason string, attempts int, nextRetry int64) {
	t.Helper()
	got, ok := q.Query(e.Message.ID)
	if !ok {
		t.Fatalf("missing record %s", e.Message.ID)
	}
	m := e.Message
	if got.ID != m.ID || got.From != m.From || got.To != m.To || got.Nonce != m.Nonce ||
		got.Payload != m.Payload || got.ProofAt != m.ProofAt || got.ExpiresAt != e.ExpiresAt {
		t.Fatalf("%s content changed:\nwant id=%s from=%s to=%s nonce=%d payloadLen=%d proofAt=%d expiresAt=%d"+
			"\ngot  id=%s from=%s to=%s nonce=%d payloadLen=%d proofAt=%d expiresAt=%d",
			m.ID, m.ID, m.From, m.To, m.Nonce, len(m.Payload), m.ProofAt, e.ExpiresAt,
			got.ID, got.From, got.To, got.Nonce, len(got.Payload), got.ProofAt, got.ExpiresAt)
	}
	if got.Status != status || got.Reason != reason || got.Attempts != attempts || got.NextRetry != nextRetry {
		t.Fatalf("%s state changed: want status=%s reason=%q attempts=%d retry=%d; got status=%s reason=%q attempts=%d retry=%d",
			m.ID, status, reason, attempts, nextRetry, got.Status, got.Reason, got.Attempts, got.NextRetry)
	}
}

func listingIDs(qs []Query) []string {
	ids := make([]string, len(qs))
	for i, q := range qs {
		ids[i] = q.ID
	}
	return ids
}

// TestAutoCompactOnSubmitPersistsTriggerAndAllPrior is the core regression:
// the ordinary Submit that pushes the WAL past 4 MiB ("lose", the second
// message of a shared-nonce pair) returns success only after automatic
// compaction saved a state containing it and all earlier messages, with
// identical business conclusions before and after.
func TestAutoCompactOnSubmitPersistsTriggerAndAllPrior(t *testing.T) {
	const margin int64 = 4096 // compacted snapshot lands this far below 4 MiB

	// The five business messages in first-submission order. The first three
	// are prior bystanders with distinct field values; win/lose share the
	// (source, destination, nonce) triplet, both covered and unexpired.
	fillerTmpl := Envelope{Message: Message{ID: "filler", From: "a", To: "b", Nonce: 99, ProofAt: 10}}
	keep1 := Envelope{
		Message:   Message{ID: "keep1", From: "a", To: "b", Nonce: 10, Payload: "body-keep1", ProofAt: 20},
		ExpiresAt: 9_000_000_000_000,
	}
	keep2 := Envelope{
		Message:   Message{ID: "keep2", From: "a", To: "c", Nonce: 11, Payload: "body-keep2", ProofAt: 30},
		ExpiresAt: 9_000_000_000_001,
	}
	win := Envelope{
		Message:   Message{ID: "win", From: "a", To: "shared-dest", Nonce: 77, Payload: "body-win", ProofAt: 50},
		ExpiresAt: 9_000_000_000_000,
	}
	lose := Envelope{
		Message:   Message{ID: "lose", From: "a", To: "shared-dest", Nonce: 77, Payload: "body-lose", ProofAt: 60},
		ExpiresAt: 9_000_000_000_000,
	}

	// Measure the real framed sizes. The filler's payload length is chosen
	// below so that the post-compaction snapshot equals threshold-margin:
	// snapshot = base + one checkpoint + filler frame + the four small frames.
	gaugeBase, cp, smallFrames := gaugeFrames(t, []Envelope{keep1, keep2, win, lose})
	var smallTotal int64
	for _, f := range smallFrames {
		smallTotal += f
	}
	fillerOverhead := submitOverhead(t, fillerTmpl, 0, 4096)
	fillerPayloadLen := compactThreshold - margin - gaugeBase - cp - smallTotal - fillerOverhead
	if fillerPayloadLen <= 0 {
		t.Fatalf("setup arithmetic leaves no filler payload: %d", fillerPayloadLen)
	}
	filler := fillerTmpl
	filler.Message.Payload = strings.Repeat("Z", int(fillerPayloadLen))
	fillerFrame := fillerOverhead + fillerPayloadLen

	// Number of equal-time checkpoints with which to pad the empty log so
	// that lose's frame is exactly the one that crosses:
	//
	//	base + n*cp + fillerFrame + smallTotal > threshold   (lose crosses)
	//	base + n*cp + fillerFrame + smallTotal <= threshold + loseFrame
	//	                                                     (nothing crosses early)
	//
	// i.e. margin+cp < n*cp <= margin+cp+loseFrame. The smallest strict n
	// lands inside the window (which is one loseFrame wide). The runtime
	// boundary checks after the submits verify both sides with real sizes.
	nCheckpoints := int((margin+cp)/cp) + 1
	if int64(nCheckpoints)*cp <= margin+cp {
		t.Fatalf("padding arithmetic: %d checkpoints * %d must exceed %d", nCheckpoints, cp, margin+cp)
	}

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	base := q.store.size
	if base != gaugeBase {
		t.Fatalf("setup base mismatch: gauge %d real %d", gaugeBase, base)
	}

	// Padding: no messages exist yet, so the repeated equal-time advances
	// append checkpoint frames and nothing else.
	for i := 0; i < nCheckpoints; i++ {
		rep, err := q.Advance(1000)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 0 {
			t.Fatalf("padding advances must process nothing: %+v", rep.Results)
		}
	}
	wantSize := base + int64(nCheckpoints)*cp
	if q.store.size != wantSize {
		t.Fatalf("padding size: want %d got %d", wantSize, q.store.size)
	}

	// Prior messages, none of which may cross the line on its own.
	for _, e := range []Envelope{filler, keep1, keep2, win} {
		if _, err := q.Submit(e); err != nil {
			t.Fatal(err)
		}
		if q.store.size > compactThreshold {
			t.Fatalf("submit %s crossed the threshold early at %d", e.Message.ID, q.store.size)
		}
	}
	preLose := q.store.size
	if preLose+smallFrames[3] <= compactThreshold {
		t.Fatalf("setup arithmetic: lose would not cross: pre=%d frame=%d", preLose, smallFrames[3])
	}

	// THE crossing submit: ordinary Submit success must include lose in the
	// automatically compacted log.
	rec, err := q.Submit(lose)
	if err != nil {
		t.Fatalf("the threshold-crossing submit must succeed: %v", err)
	}
	predictedPost := base + cp + fillerFrame + smallTotal
	if q.store.size != predictedPost {
		t.Fatalf("automatic compaction must leave exactly the snapshot size: got %d want %d",
			q.store.size, predictedPost)
	}
	if q.store.size >= compactThreshold {
		t.Fatalf("snapshot must shrink below the threshold: %d >= %d", q.store.size, compactThreshold)
	}
	if info, err := os.Stat(filepath.Join(dir, logName)); err != nil || info.Size() != q.store.size {
		t.Fatalf("on-disk log size %v disagrees with compacted size %d: %v", info, q.store.size, err)
	}
	// The trigger echo is its untouched pending record: compaction never
	// processed it or advanced its seq.
	if rec.Status != StatusPending || rec.Reason != "awaiting first processing" ||
		rec.Attempts != 0 || rec.NextRetry != 0 || rec.Seq != 4 {
		t.Fatalf("triggering submit echo must be a fresh pending record: %+v", rec)
	}

	// All five records are queryable with original content and pending state;
	// the trigger is appended at the end, each id exactly once.
	wantIDs := []string{"filler", "keep1", "keep2", "win", "lose"}
	pendingReason := "awaiting first processing"
	for _, e := range []Envelope{filler, keep1, keep2, win, lose} {
		assertRecordExact(t, q, e, StatusPending, pendingReason, 0, 0)
	}
	all := q.Queries()
	if len(all) != 5 {
		t.Fatalf("want 5 records, got %d: %v", len(all), listingIDs(all))
	}
	for i, want := range wantIDs {
		if all[i].ID != want {
			t.Fatalf("listing must be in first-submission order: want %v got %v", wantIDs, listingIDs(all))
		}
	}
	counts := map[string]int{}
	for _, r := range all {
		counts[r.ID]++
	}
	for id, n := range counts {
		if n != 1 {
			t.Fatalf("record %s appears %d times", id, n)
		}
	}

	// Submission boundary while records are still pending: identical
	// resubmit returns the existing record, different content conflicts,
	// with no new entry, no seq consumed and no reordering.
	echo, err := q.Submit(keep1)
	if err != nil {
		t.Fatalf("identical resubmit after compaction must return the record: %v", err)
	}
	if echo.Seq != 1 || echo.Status != StatusPending || echo.Attempts != 0 || echo.NextRetry != 0 {
		t.Fatalf("identical resubmit must echo the existing pending record: %+v", echo)
	}
	if len(q.records) != 5 || len(q.order) != 5 || q.nextSeq != 5 {
		t.Fatalf("identical resubmit added an entry: records=%d order=%v nextSeq=%d",
			len(q.records), q.order, q.nextSeq)
	}
	bad := keep1
	bad.Message.Payload = "body-keep1-CHANGED"
	if _, err := q.Submit(bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("same id with different content after compaction must be ErrConflict, got %v", err)
	}
	assertRecordExact(t, q, keep1, StatusPending, pendingReason, 0, 0)
	if len(q.records) != 5 || q.nextSeq != 5 {
		t.Fatalf("rejected submit must add no record and consume no seq: records=%d nextSeq=%d",
			len(q.records), q.nextSeq)
	}
	for i, want := range wantIDs {
		if q.order[i] != want {
			t.Fatalf("processing order changed after the rejected submit: want %v got %v", wantIDs, q.order)
		}
	}

	// Close and reopen the same state directory: the triggering submit must
	// not exist only before closing.
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen the compacted directory: %v", err)
	}
	defer q2.Close()
	if q2.Now() != 1000 {
		t.Fatalf("processing time lost across compaction/reopen: want 1000 got %d", q2.Now())
	}
	all = q2.Queries()
	if len(all) != 5 {
		t.Fatalf("after reopen want 5 records, got %d: %v", len(all), listingIDs(all))
	}
	for i, want := range wantIDs {
		if all[i].ID != want {
			t.Fatalf("order lost across reopen: want %v got %v", wantIDs, listingIDs(all))
		}
	}
	for _, e := range []Envelope{filler, keep1, keep2, win, lose} {
		assertRecordExact(t, q2, e, StatusPending, pendingReason, 0, 0)
	}
	// The same submission boundary holds against the compacted bytes, before
	// anything is processed.
	if _, err := q2.Submit(win); err != nil {
		t.Fatalf("identical resubmit after reopen must still be idempotent: %v", err)
	}
	bad2 := lose
	bad2.Message.ProofAt = 61
	if _, err := q2.Submit(bad2); !errors.Is(err, ErrConflict) {
		t.Fatalf("content conflict after reopen must stay ErrConflict, got %v", err)
	}
	assertRecordExact(t, q2, lose, StatusPending, pendingReason, 0, 0)
	if len(q2.records) != 5 {
		t.Fatalf("post-reopen rejected submit added a record: %d", len(q2.records))
	}

	// Continue delivery after the compaction both messages lived through:
	// processing follows first-submission order. The bystanders and filler
	// deliver; win (first of the shared-nonce pair) succeeds and lose ends
	// replay naming win; the triggering submit gets no priority.
	rep, err := q2.Advance(2000)
	if err != nil {
		t.Fatalf("advance after compaction: %v", err)
	}
	wantResults := []Result{
		{ID: "filler", Status: StatusSuccess, Reason: "delivered; proof verified by trusted header at height 100"},
		{ID: "keep1", Status: StatusSuccess, Reason: "delivered; proof verified by trusted header at height 100"},
		{ID: "keep2", Status: StatusSuccess, Reason: "delivered; proof verified by trusted header at height 100"},
		{ID: "win", Status: StatusSuccess, Reason: "delivered; proof verified by trusted header at height 100"},
		{ID: "lose", Status: StatusReplay, Reason: "nonce combination already consumed by message win"},
	}
	if len(rep.Results) != len(wantResults) {
		t.Fatalf("want %d ordered results, got %+v", len(wantResults), rep.Results)
	}
	for i, w := range wantResults {
		if rep.Results[i] != w {
			t.Fatalf("result %d: want %+v got %+v", i, w, rep.Results[i])
		}
	}

	// The shared-nonce pair: one attempt each, no retry scheduled, original
	// payloads still viewable — the trigger's body included.
	assertRecordExact(t, q2, win, StatusSuccess,
		"delivered; proof verified by trusted header at height 100", 1, 0)
	assertRecordExact(t, q2, lose, StatusReplay,
		"nonce combination already consumed by message win", 1, 0)
	if winner := q2.consumed[newConsumeToken("a", "shared-dest", 77)]; winner != "win" {
		t.Fatalf("nonce consumption must belong to the first-submitted win, got %q", winner)
	}
	// The prior messages and the large filler keep their exact content.
	assertRecordExact(t, q2, filler, StatusSuccess,
		"delivered; proof verified by trusted header at height 100", 1, 0)
	assertRecordExact(t, q2, keep1, StatusSuccess,
		"delivered; proof verified by trusted header at height 100", 1, 0)
	assertRecordExact(t, q2, keep2, StatusSuccess,
		"delivered; proof verified by trusted header at height 100", 1, 0)

	// Terminal ordering is stable across yet another reopen, and a later
	// advance reprocesses nothing.
	if err := q2.Close(); err != nil {
		t.Fatal(err)
	}
	q3, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q3.Close()
	all = q3.Queries()
	if len(all) != 5 {
		t.Fatalf("final reopen: want 5 records, got %v", listingIDs(all))
	}
	for i, want := range wantIDs {
		if all[i].ID != want {
			t.Fatalf("final order changed: want %v got %v", wantIDs, listingIDs(all))
		}
	}
	assertRecordExact(t, q3, lose, StatusReplay,
		"nonce combination already consumed by message win", 1, 0)
	if winner := q3.consumed[newConsumeToken("a", "shared-dest", 77)]; winner != "win" {
		t.Fatalf("consumption lost after final reopen: %q", winner)
	}
	again, err := q3.Advance(3000)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Results) != 0 {
		t.Fatalf("terminal records must not be reprocessed: %+v", again.Results)
	}
}

// TestAutoCompactDuringSubmissionLeavesPriorStatusesUntouched crosses the
// threshold with already-PROCESSED records of different kinds: a success and
// a waiting record mid-backoff. The submit-triggered compaction must preserve
// their statuses, reasons, attempt counts and retry schedules exactly, and
// the waiting backoff must continue on its canonical schedule afterwards.
func TestAutoCompactDuringSubmissionLeavesPriorStatusesUntouched(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	// Trusted height 50: done (proof 10) delivers; waiting (proof 90) parks.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 50, Root: "0x50", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("done", "a", "b", 1, 10, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("waiting", "a", "b", 2, 90, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	wantDone := statusOf(t, q, "done")
	wantWaiting := statusOf(t, q, "waiting")
	if wantDone.Status != StatusSuccess || wantDone.Attempts != 1 || wantDone.NextRetry != 0 {
		t.Fatalf("setup done wrong: %+v", wantDone)
	}
	if wantWaiting.Status != StatusWaiting || wantWaiting.Attempts != 1 || wantWaiting.NextRetry != 2000 {
		t.Fatalf("setup waiting wrong: %+v", wantWaiting)
	}

	// Normalize to the snapshot floor with both processed records present:
	// one checkpoint (now=1000) is carried, so later padding checkpoints are
	// exactly the bytes a fresh snapshot drops.
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatal(err)
	}
	snapshotFloor := q.store.size
	if snapshotFloor >= compactThreshold {
		t.Fatalf("setup snapshot already at threshold: %d", snapshotFloor)
	}

	// Filler is itself the crossing submit; its retained payload sizes the
	// next snapshot to 4 KiB below the threshold.
	fillerTmpl := Envelope{Message: Message{ID: "filler2", From: "a", To: "b", Nonce: 9, ProofAt: 10}}
	overhead := submitOverhead(t, fillerTmpl, 2, 4096)
	payloadLen := compactThreshold - 4096 - snapshotFloor - overhead
	if payloadLen <= 0 {
		t.Fatalf("setup arithmetic leaves no payload: %d", payloadLen)
	}
	frame := overhead + payloadLen

	// Pad with equal-time checkpoints: at 1000 the waiting record is not
	// reprocessed (its last processing was that same instant) and done is
	// terminal. Stop at the first count where appending the filler crosses.
	for q.store.size+frame <= compactThreshold {
		rep, err := q.Advance(1000)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 0 {
			t.Fatalf("padding advances must not reprocess waiting/done: %+v", rep.Results)
		}
	}
	if q.store.size > compactThreshold {
		t.Fatalf("padding crossed without the filler: %d", q.store.size)
	}
	before := q.store.size

	filler := fillerTmpl
	filler.Message.Payload = strings.Repeat("Z", int(payloadLen))
	rec, err := q.Submit(filler)
	if err != nil {
		t.Fatalf("the threshold-crossing submit must succeed: %v", err)
	}
	if q.store.size != snapshotFloor+frame {
		t.Fatalf("compacted size: want %d got %d", snapshotFloor+frame, q.store.size)
	}
	if q.store.size >= compactThreshold || before+frame <= compactThreshold {
		t.Fatalf("filler must be the genuine crossing submit: before=%d frame=%d after=%d threshold=%d",
			before, frame, q.store.size, compactThreshold)
	}
	if rec.Status != StatusPending || rec.Attempts != 0 || rec.NextRetry != 0 {
		t.Fatalf("triggering filler must stay pending: %+v", rec)
	}

	// Prior statuses, reasons, attempts, schedules and content are unchanged.
	if got := statusOf(t, q, "done"); got != wantDone {
		t.Fatalf("success record changed across submit-triggered compaction:\nbefore=%+v\nafter =%+v", wantDone, got)
	}
	if got := statusOf(t, q, "waiting"); got != wantWaiting {
		t.Fatalf("waiting record changed across submit-triggered compaction:\nbefore=%+v\nafter =%+v", wantWaiting, got)
	}
	assertRecordExact(t, q, filler, StatusPending, "awaiting first processing", 0, 0)

	// Reopen from the compacted bytes: the processed states are still exact.
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	if got := statusOf(t, q2, "done"); got != wantDone {
		t.Fatalf("success record lost across reopen:\nbefore=%+v\nafter =%+v", wantDone, got)
	}
	if got := statusOf(t, q2, "waiting"); got != wantWaiting {
		t.Fatalf("waiting record lost across reopen:\nbefore=%+v\nafter =%+v", wantWaiting, got)
	}
	assertRecordExact(t, q2, filler, StatusPending, "awaiting first processing", 0, 0)

	// The preserved backoff continues on its canonical 1s/2s schedule.
	if _, err := q2.Advance(2000); err != nil {
		t.Fatal(err)
	}
	r := statusOf(t, q2, "waiting")
	if r.Status != StatusWaiting || r.Attempts != 2 || r.NextRetry != 4000 {
		t.Fatalf("waiting backoff must continue on the canonical schedule after compaction: %+v", r)
	}
}
