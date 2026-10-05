package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Black-box regression tests for AUTOMATIC log compaction triggered by the
// normal `queue submit` success path. The queue rewrites its append-only log
// once it grows past 4 MiB; these tests cross the real threshold with real
// user commands against the real binary, observe that the submit which crosses
// the threshold is itself already saved (and still pending), then continue to
// use the queue exactly as the documented rules promise — order, delivery,
// replay attribution and submit-time id/conflict boundaries must all match the
// behaviour of a log that never compacted. Every `relayproof` invocation is a
// fresh process over the SAME state directory, so reopening the compacted
// directory is exercised on every assertion.

// autoCompactThreshold mirrors relayproof.compactThreshold, which is not
// exported: the active queue.log compacts once it is strictly larger than
// 4 MiB.
const autoCompactThreshold = 4 << 20

// fatPayloadBytes keeps every filler message well under any argv limit while
// crossing the threshold in a few dozen submissions (~0.7s of process
// spawns); filler payloads are one repeated single-byte character.
const fatPayloadBytes = 100_000

func logPath(state string) string { return filepath.Join(state, "queue.log") }

func logStat(t *testing.T, state string) (inode uint64, size int64) {
	t.Helper()
	st, err := os.Stat(logPath(state))
	if err != nil {
		t.Fatalf("stat queue.log: %v", err)
	}
	return st.Sys().(*syscall.Stat_t).Ino, st.Size()
}

func logSize(t *testing.T, state string) int64 {
	t.Helper()
	_, size := logStat(t, state)
	return size
}

// fatSubmitSpec builds one filler submission with a 100 KiB single-character
// payload, a distinct nonce and proof height covered by the test's trusted
// header at 100.
func fatSubmitSpec(id string, n int) cliSubmitSpec {
	return cliSubmitSpec{
		id:        id,
		from:      "chain-a",
		to:        "chain-b",
		nonce:     uint64(100 + n),
		payload:   strings.Repeat("z", fatPayloadBytes),
		proofAt:   100,
		expiresAt: 0,
	}
}

// crossThresholdWithFatSubmits submits covered filler messages until the live
// queue.log is strictly larger than the 4 MiB threshold. It returns the number
// of filler messages submitted and the id of the last one.
func crossThresholdWithFatSubmits(t *testing.T, state string) (int, string) {
	t.Helper()
	n := 0
	for logSize(t, state) <= autoCompactThreshold {
		n++
		id := fmt.Sprintf("fat-%02d", n)
		mustSubmit(t, state, fatSubmitSpec(id, n))
	}
	return n, fmt.Sprintf("fat-%02d", n)
}

// The submission whose success follows crossing the 4 MiB threshold triggers a
// snapshot rewrite, and that triggering message must already be saved: after
// the command returns it is queryable, still pending with zero attempts and no
// retry, together with every earlier (filler) message — each appearing once,
// in first-submission order, with the original payload. Reopening the same
// state directory (which every query does) shows the same content; the last
// submission must not exist only before close.
func TestCLIAutoCompactionTriggeringSubmitSavedAndReopens(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0x100", true); r.code != 0 {
		t.Fatalf("store header: %v", r)
	}

	n, lastFat := crossThresholdWithFatSubmits(t, state)
	if logSize(t, state) <= autoCompactThreshold {
		t.Fatalf("setup did not cross the threshold: %d", logSize(t, state))
	}

	// The log is over threshold but the fillers are pending, so the next normal
	// submit is the documented "user keeps submitting after 4 MiB" case: its
	// append forces the snapshot rewrite. The inode changes when compact()
	// atomically renames the new log over the old one.
	inoBefore, _ := logStat(t, state)
	trigger := cliSubmitSpec{
		id: "trigger", from: "chain-a", to: "chain-b", nonce: 999,
		payload: "trigger-body", proofAt: 90, expiresAt: 9_000_000_000_000,
	}
	echo, rawEcho := mustSubmit(t, state, trigger)
	wantEcho := cliSubmitRecord{
		ID: "trigger", Status: "pending", Reason: "awaiting first processing",
		Attempts: 0, ExpiresAt: 9_000_000_000_000,
	}
	if echo != wantEcho {
		t.Fatalf("triggering submit echo wrong: %+v\n%s", echo, rawEcho)
	}
	if inoAfter, size := logStat(t, state); inoAfter == inoBefore {
		t.Fatal("the triggering submit must have rewritten (compacted) the log; inode unchanged")
	} else if size <= autoCompactThreshold {
		t.Fatalf("compacted log must retain the fat pending records past the threshold: %d", size)
	}

	all := queryAll(t, state)
	if len(all) != n+1 {
		t.Fatalf("want %d records each once, got %d", n+1, len(all))
	}
	for i := 0; i < n; i++ {
		wantID := fmt.Sprintf("fat-%02d", i+1)
		if all[i].ID != wantID {
			t.Fatalf("filler position %d: want %s got %s (order head %v)", i, wantID, all[i].ID, recordIDs(all)[:5])
		}
		if all[i].Status != "pending" || all[i].Attempts != 0 || all[i].NextRetry != 0 ||
			len(all[i].Payload) != fatPayloadBytes {
			t.Fatalf("filler %s changed by compaction: %+v payloadLen=%d", wantID, all[i].Status, len(all[i].Payload))
		}
	}
	if all[n].ID != "trigger" {
		t.Fatalf("trigger must be last in submission order, got %s", all[n].ID)
	}
	trig := all[n]
	if trig.From != "chain-a" || trig.To != "chain-b" || trig.Nonce != 999 ||
		trig.Payload != "trigger-body" || trig.ProofAt != 90 ||
		trig.ExpiresAt != 9_000_000_000_000 || trig.Status != "pending" ||
		trig.Attempts != 0 || trig.NextRetry != 0 {
		t.Fatalf("triggering record wrong after compaction: %+v", trig)
	}

	// Single-id query through another fresh process: the last submission is not
	// allowed to exist only in the process that performed the compaction.
	one := queryFull(t, state, "trigger")
	if one.ID != "trigger" || one.Payload != "trigger-body" || one.Status != "pending" || one.Attempts != 0 {
		t.Fatalf("single query after reopen disagrees: %+v", one)
	}
	first := queryFull(t, state, "fat-01")
	last := queryFull(t, state, lastFat)
	if len(first.Payload) != fatPayloadBytes || len(last.Payload) != fatPayloadBytes {
		t.Fatalf("filler payloads must reopen byte-for-byte: %d/%d", len(first.Payload), len(last.Payload))
	}

	// Nothing was processed by the rewrite: an advance afterwards delivers all
	// n+1 covered messages once, in the same first-submission order.
	rep := advanceCLI(t, state, 1_700_000_000_000)
	if len(rep.Results) != n+1 {
		t.Fatalf("want %d deliveries, got %d: %+v", n+1, len(rep.Results), rep.Results)
	}
	if rep.Results[0].ID != "fat-01" || rep.Results[n].ID != "trigger" {
		t.Fatalf("delivery order wrong: head=%s tail=%s", rep.Results[0].ID, rep.Results[n].ID)
	}
	for _, r := range rep.Results {
		if r.Status != "success" {
			t.Fatalf("%s must deliver, got %+v", r.ID, r)
		}
	}
	if got := queryFull(t, state, "trigger"); got.Status != "success" || got.Attempts != 1 || got.NextRetry != 0 {
		t.Fatalf("trigger final state wrong: %+v", got)
	}
}

// Two different-id messages with the same registered source, destination and
// nonce, both already covered by a trusted header and unexpired, are each
// submitted only AFTER the log crossed the threshold and got compacted —
// before either is processed. Advancing the queue afterwards must keep pure
// first-submission order: the earlier one delivers, the later one ends as
// replay attributed to the winner. The compaction-triggering submit gets no
// priority. Both records show one attempt with no retry and their original
// payloads, also from a freshly reopened directory.
func TestCLIAutoCompactionSameNoncePairDeliversInSubmissionOrder(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0x100", true); r.code != 0 {
		t.Fatalf("store header: %v", r)
	}
	n, _ := crossThresholdWithFatSubmits(t, state)

	// Deliver all fillers first; the advance itself also compacts, so by the
	// time the pair arrives every append rewrites the snapshot.
	rep := advanceCLI(t, state, 1_700_000_000_000)
	if len(rep.Results) != n {
		t.Fatalf("setup: want %d filler successes, got %d", n, len(rep.Results))
	}

	first := cliSubmitSpec{
		id: "first", from: "chain-a", to: "chain-b", nonce: 7,
		payload: "first-body", proofAt: 100, expiresAt: 9_000_000_000_000,
	}
	second := cliSubmitSpec{
		id: "second", from: "chain-a", to: "chain-b", nonce: 7,
		payload: "second-body", proofAt: 100, expiresAt: 9_000_000_000_000,
	}

	ino, _ := logStat(t, state)
	echo1, _ := mustSubmit(t, state, first)
	if echo1.Status != "pending" || echo1.Attempts != 0 || echo1.NextRetry != 0 {
		t.Fatalf("first must be pending and unprocessed: %+v", echo1)
	}
	if ino1, _ := logStat(t, state); ino1 == ino {
		t.Fatal("submitting first must have compacted the over-threshold log")
	} else {
		ino = ino1
	}
	echo2, _ := mustSubmit(t, state, second)
	if echo2.Status != "pending" || echo2.Attempts != 0 || echo2.NextRetry != 0 {
		t.Fatalf("second must be pending and unprocessed: %+v", echo2)
	}
	if ino2, _ := logStat(t, state); ino2 == ino {
		t.Fatal("submitting second must have compacted the over-threshold log")
	}

	// Both experience compaction before first processing; now advance. The
	// fillers are terminal, so the report carries exactly the pair, in order.
	rep = advanceCLI(t, state, 1_700_000_001_000)
	if len(rep.Results) != 2 {
		t.Fatalf("want exactly the pair processed, got %+v", rep.Results)
	}
	if r := rep.Results[0]; r.ID != "first" || r.Status != "success" ||
		r.Reason != "delivered; proof verified by trusted header at height 100" {
		t.Fatalf("first-submitted message must win: %+v", r)
	}
	if r := rep.Results[1]; r.ID != "second" || r.Status != "replay" ||
		r.Reason != "nonce combination already consumed by message first" {
		t.Fatalf("second-submitted message must be replay pointing at first: %+v", r)
	}

	gotFirst := queryFull(t, state, "first")
	if gotFirst.Status != "success" || gotFirst.Attempts != 1 || gotFirst.NextRetry != 0 ||
		gotFirst.Payload != "first-body" {
		t.Fatalf("first stored state wrong: %+v", gotFirst)
	}
	gotSecond := queryFull(t, state, "second")
	if gotSecond.Status != "replay" || gotSecond.Attempts != 1 || gotSecond.NextRetry != 0 ||
		gotSecond.Payload != "second-body" ||
		gotSecond.Reason != "nonce combination already consumed by message first" {
		t.Fatalf("second stored state wrong: %+v", gotSecond)
	}

	// Full listing order and uniqueness, read from a freshly reopened compacted
	// directory: fillers, first, second, each exactly once.
	all := queryAll(t, state)
	if len(all) != n+2 {
		t.Fatalf("want %d unique records, got %d", n+2, len(all))
	}
	tailIDs := recordIDs(all)[n-1:]
	wantTail := []string{fmt.Sprintf("fat-%02d", n), "first", "second"}
	if all[0].ID != "fat-01" || fmt.Sprint(tailIDs) != fmt.Sprint(wantTail) {
		t.Fatalf("listing order wrong around the pair: %v", tailIDs)
	}

	// A later advance never reprocesses the terminal pair.
	again := advanceCLI(t, state, 1_700_000_100_000)
	if len(again.Results) != 0 {
		t.Fatalf("terminal records must not reappear: %+v", again.Results)
	}
	if got := queryFull(t, state, "second"); got.Attempts != 1 || got.Status != "replay" {
		t.Fatalf("second must keep one attempt and replay status: %+v", got)
	}
}

// Submit-time identity boundaries for a message still pending after automatic
// compaction: resubmitting the same id with identical content returns the
// existing record and adds nothing, while different content exits 13 as a
// content conflict with the original record fully intact and the submission
// order unchanged. A later advance processes everything in the original order
// using the original payload, identical to the non-compacted rules.
func TestCLIAutoCompactionSubmitConflictBoundaries(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0x100", true); r.code != 0 {
		t.Fatalf("store header: %v", r)
	}
	n, _ := crossThresholdWithFatSubmits(t, state)

	dup := cliSubmitSpec{
		id: "dup", from: "chain-a", to: "chain-b", nonce: 70,
		payload: "orig-body", proofAt: 100, expiresAt: 9_000_000_000_000,
	}
	ino, _ := logStat(t, state)
	firstEcho, rawFirst := mustSubmit(t, state, dup)
	if ino1, _ := logStat(t, state); ino1 == ino {
		t.Fatal("submitting dup must have compacted the over-threshold log")
	} else {
		ino = ino1
	}
	beforeIDs := recordIDs(queryAll(t, state))
	if len(beforeIDs) != n+1 || beforeIDs[n] != "dup" {
		t.Fatalf("setup listing wrong: %d entries, tail %v", len(beforeIDs), beforeIDs)
	}

	// Identical resubmit: same record, no append (inode unchanged), no extra
	// entry, same order.
	echo, rawEcho := mustSubmit(t, state, dup)
	if rawEcho != rawFirst || echo != firstEcho {
		t.Fatalf("identical resubmit must echo the existing record:\n%s\n%s", rawFirst, rawEcho)
	}
	if inoSame, _ := logStat(t, state); inoSame != ino {
		t.Fatal("an idempotent resubmit must append nothing and not recompact")
	}
	if ids := recordIDs(queryAll(t, state)); len(ids) != n+1 || ids[n] != "dup" {
		t.Fatalf("identical resubmit must add no record: %v", ids)
	}

	// Different content with the same id: exit 13, unchanged record and order.
	changed := dup
	changed.payload = "changed-body"
	assertContentConflict(t, submitRaw(t, state, changed), "dup")
	if inoSame, _ := logStat(t, state); inoSame != ino {
		t.Fatal("a rejected resubmit must append nothing and not recompact")
	}
	got := queryFull(t, state, "dup")
	if got.Payload != "orig-body" || got.Nonce != 70 || got.ProofAt != 100 ||
		got.ExpiresAt != 9_000_000_000_000 || got.Status != "pending" ||
		got.Attempts != 0 || got.NextRetry != 0 {
		t.Fatalf("original dup record must stay intact after conflict: %+v", got)
	}
	if ids := recordIDs(queryAll(t, state)); len(ids) != n+1 || ids[n] != "dup" {
		t.Fatalf("rejected resubmit must add no record and keep order: %v", ids)
	}
	// The original content still resubmits idempotently.
	if echo2, _ := mustSubmit(t, state, dup); echo2 != firstEcho {
		t.Fatalf("identical resubmit after rejected resubmit must still return the original: %+v", echo2)
	}

	// Processing order is unaffected: every filler then dup succeeds, once, in
	// first-submission order, using the original payload.
	rep := advanceCLI(t, state, 1_700_000_000_000)
	if len(rep.Results) != n+1 {
		t.Fatalf("want %d deliveries, got %d", n+1, len(rep.Results))
	}
	if rep.Results[n].ID != "dup" || rep.Results[n].Status != "success" {
		t.Fatalf("dup must deliver last in order, got %+v", rep.Results[n])
	}
	got = queryFull(t, state, "dup")
	if got.Status != "success" || got.Attempts != 1 || got.Payload != "orig-body" ||
		got.Reason != "delivered; proof verified by trusted header at height 100" {
		t.Fatalf("dup must deliver exactly once with its original body: %+v", got)
	}
	if ids := recordIDs(queryAll(t, state)); len(ids) != n+1 || ids[n] != "dup" {
		t.Fatalf("final listing must keep each record once in order: %v", ids)
	}
}
