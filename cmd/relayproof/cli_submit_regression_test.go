package main

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"testing"
)

// These tests pin the command-line observable behaviour of re-using a message
// id at submit time, end to end through the real binary and a fresh on-disk
// state directory per scenario:
//
//   - the same id with identical content returns the existing record (whether
//     it is still pending or already waiting), prints no second entry and keeps
//     the original submission position;
//   - the same id on a non-terminal record with ANY different content field
//     exits 13 as a message-content conflict, prints no success record and
//     changes neither the original record nor sibling messages;
//   - a terminal (delivered) id can never be submitted again: identical and
//     different content alike exit 14, never 13, and advancing time again must
//     not redeliver it.
//
// All processing time is supplied explicitly in Unix milliseconds, so every
// result is deterministic and reproducible offline with no chain or service.

// cliSubmitSpec is one `queue submit` invocation. Payload and expiry can be
// omitted from the argv entirely to exercise the CLI defaults (empty payload,
// expiry 0 = never), which must be equivalent to passing the same values.
type cliSubmitSpec struct {
	id          string
	from        string
	to          string
	payload     string
	nonce       uint64
	proofAt     int64
	expiresAt   int64
	omitPayload bool
	omitExpires bool
}

func submitRaw(t *testing.T, state string, s cliSubmitSpec) cliResult {
	t.Helper()
	args := []string{
		"--id", s.id, "--from", s.from, "--to", s.to,
		"--nonce", strconv.FormatUint(s.nonce, 10),
		"--proof-at", strconv.FormatInt(s.proofAt, 10),
	}
	if !s.omitPayload {
		args = append(args, "--payload", s.payload)
	}
	if !s.omitExpires {
		args = append(args, "--expires-at", strconv.FormatInt(s.expiresAt, 10))
	}
	return queueCLI(t, state, "submit", args...)
}

// cliSubmitRecord is the JSON object printed by a successful submit. Absent
// nextRetryMs/expiresAtMs fields decode as zero, matching the omitempty output
// of pending records and never-expiring messages.
type cliSubmitRecord struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Attempts  int    `json:"attempts"`
	NextRetry int64  `json:"nextRetryMs"`
	ExpiresAt int64  `json:"expiresAtMs"`
}

func mustSubmit(t *testing.T, state string, s cliSubmitSpec) (cliSubmitRecord, string) {
	t.Helper()
	r := submitRaw(t, state, s)
	if r.code != 0 {
		t.Fatalf("submit %s: exit=%d stderr=%q", s.id, r.code, r.stderr)
	}
	var rec cliSubmitRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(r.stdout)), &rec); err != nil {
		t.Fatalf("decode submit output %q: %v", r.stdout, err)
	}
	return rec, r.stdout
}

// cliFullRecord is the per-id query JSON view with every message-content field.
type cliFullRecord struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Nonce     uint64 `json:"nonce"`
	Payload   string `json:"payload"`
	ProofAt   int64  `json:"proofAtHeight"`
	ExpiresAt int64  `json:"expiresAtMs"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Attempts  int    `json:"attempts"`
	NextRetry int64  `json:"nextRetryMs"`
}

func queryFull(t *testing.T, state, id string) cliFullRecord {
	t.Helper()
	r := queueCLI(t, state, "query", "--id", id)
	if r.code != 0 {
		t.Fatalf("query %s: exit=%d stderr=%q", id, r.code, r.stderr)
	}
	var rec cliFullRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(r.stdout)), &rec); err != nil {
		t.Fatalf("decode query output %q: %v", r.stdout, err)
	}
	return rec
}

// queryAll reads the whole listing (one JSON object per line) in submission order.
func queryAll(t *testing.T, state string) []cliFullRecord {
	t.Helper()
	r := queueCLI(t, state, "query")
	if r.code != 0 {
		t.Fatalf("query listing: exit=%d stderr=%q", r.code, r.stderr)
	}
	var out []cliFullRecord
	dec := json.NewDecoder(strings.NewReader(r.stdout))
	for {
		var rec cliFullRecord
		switch err := dec.Decode(&rec); err {
		case nil:
			out = append(out, rec)
		case io.EOF:
			return out
		default:
			t.Fatalf("decode query listing %q: %v", r.stdout, err)
		}
	}
}

func recordIDs(recs []cliFullRecord) []string {
	ids := make([]string, len(recs))
	for i, r := range recs {
		ids[i] = r.ID
	}
	return ids
}

// assertSubmitMatchesQuery requires the submit echo and the single-record query
// to agree on every field both views expose.
func assertSubmitMatchesQuery(t *testing.T, sub cliSubmitRecord, q cliFullRecord) {
	t.Helper()
	if sub.ID != q.ID || sub.Status != q.Status || sub.Reason != q.Reason ||
		sub.Attempts != q.Attempts || sub.NextRetry != q.NextRetry ||
		sub.ExpiresAt != q.ExpiresAt {
		t.Fatalf("submit output %+v disagrees with stored record %+v", sub, q)
	}
}

// assertContentConflict requires the exact CLI surface of a message-content
// conflict: exit 13, a stderr line naming both the id-conflict category and
// the differing content, the message id, and nothing on stdout.
func assertContentConflict(t *testing.T, r cliResult, id string) {
	t.Helper()
	if r.code != 13 {
		t.Fatalf("want exit 13 for %s, got %d (stdout=%q stderr=%q)", id, r.code, r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a rejected submit must not print a success record: %q", r.stdout)
	}
	for _, want := range []string{"message id conflict", "different content", id} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("stderr for %s missing %q:\n%s", id, want, r.stderr)
		}
	}
}

// assertTerminalReject requires exit 14 naming the terminal category, the id
// and its current status; a terminal id must never be downgraded to a content
// conflict (13), even when the resubmitted content differs.
func assertTerminalReject(t *testing.T, r cliResult, id, status string) {
	t.Helper()
	if r.code != 14 {
		t.Fatalf("want exit 14 for terminal %s, got %d (stdout=%q stderr=%q)", id, r.code, r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a rejected submit must not print a success record: %q", r.stdout)
	}
	for _, want := range []string{"terminal", id, status} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("stderr for %s missing %q:\n%s", id, want, r.stderr)
		}
	}
	if strings.Contains(r.stderr, "different content") {
		t.Fatalf("terminal %s must be reported as terminal, not content conflict: %s", id, r.stderr)
	}
}

// First submission leaves the message pending; submitting byte-identical
// content again succeeds and echoes the same existing record, the listing still
// contains exactly one entry for that id, and the original submission position
// does not move relative to messages submitted around the duplicate.
func TestCLISubmitIdenticalPendingReturnsExistingRecord(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0x100", true); r.code != 0 {
		t.Fatalf("store header: %v", r)
	}

	spec := cliSubmitSpec{
		id: "m1", from: "chain-a", to: "chain-b", nonce: 7,
		proofAt: 90, payload: "hello", expiresAt: 9_000_000_000_000,
	}
	first, rawFirst := mustSubmit(t, state, spec)
	wantFirst := cliSubmitRecord{
		ID: "m1", Status: "pending", Reason: "awaiting first processing",
		Attempts: 0, ExpiresAt: 9_000_000_000_000,
	}
	if first != wantFirst {
		t.Fatalf("first submit output wrong: %+v", first)
	}

	// A sibling after m1 but before the duplicate pins m1's seq position.
	mustSubmit(t, state, cliSubmitSpec{
		id: "sib-before", from: "chain-a", to: "chain-b", nonce: 10,
		proofAt: 10, payload: "s1", expiresAt: 9_000_000_000_000,
	})

	second, rawSecond := mustSubmit(t, state, spec)
	if rawSecond != rawFirst || second != first {
		t.Fatalf("identical resubmit must echo the same record:\nfirst =%q\nsecond=%q", rawFirst, rawSecond)
	}

	mustSubmit(t, state, cliSubmitSpec{
		id: "sib-after", from: "chain-a", to: "chain-b", nonce: 11,
		proofAt: 10, payload: "s2", expiresAt: 9_000_000_000_000,
	})

	stored := queryFull(t, state, "m1")
	assertSubmitMatchesQuery(t, second, stored)
	if stored.From != spec.from || stored.To != spec.to || stored.Nonce != spec.nonce ||
		stored.Payload != spec.payload || stored.ProofAt != spec.proofAt ||
		stored.ExpiresAt != spec.expiresAt {
		t.Fatalf("stored content changed on identical resubmit: %+v", stored)
	}

	all := queryAll(t, state)
	if got := recordIDs(all); len(got) != 3 || got[0] != "m1" || got[1] != "sib-before" || got[2] != "sib-after" {
		t.Fatalf("duplicate submit must not add an entry or move the original seq: %v", got)
	}
}

// Omitting --payload and --expires-at is the same message as passing "" and 0
// explicitly; the duplicate returns the existing record, the listing has one
// entry, and expiry 0 still means never (the message delivers on advance).
func TestCLISubmitOmittedPayloadAndExpiryEqualExplicitZero(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0x100", true); r.code != 0 {
		t.Fatalf("store header: %v", r)
	}

	omitted := cliSubmitSpec{
		id: "d1", from: "chain-a", to: "chain-b", nonce: 1,
		proofAt: 10, omitPayload: true, omitExpires: true,
	}
	first, rawFirst := mustSubmit(t, state, omitted)
	if first.Status != "pending" || first.ExpiresAt != 0 || first.NextRetry != 0 || first.Attempts != 0 {
		t.Fatalf("default submit output wrong: %+v", first)
	}
	if strings.Contains(rawFirst, "expiresAtMs") || strings.Contains(rawFirst, "nextRetryMs") {
		t.Fatalf("zero expiry/no-retry fields must be omitted: %q", rawFirst)
	}

	explicit := omitted
	explicit.omitPayload, explicit.omitExpires = false, false
	explicit.payload, explicit.expiresAt = "", 0
	second, rawSecond := mustSubmit(t, state, explicit)
	if rawSecond != rawFirst || second != first {
		t.Fatalf("explicit empty payload/zero expiry must equal the defaults:\n%q\n%q", rawFirst, rawSecond)
	}

	all := queryAll(t, state)
	if len(all) != 1 || all[0].ID != "d1" || all[0].Payload != "" || all[0].ExpiresAt != 0 {
		t.Fatalf("duplicate default submit must not add an entry: %+v", all)
	}

	rep := advanceCLI(t, state, 1_700_000_000_000)
	if got := resultFor(t, rep, "d1"); got.Status != "success" {
		t.Fatalf("expiry 0 must mean never expire; message should deliver: %+v", got)
	}
}

// Once the first processing has parked a message in waiting (no trusted header
// at the proof height yet), an identical resubmit returns the CURRENT waiting
// record — status, reason, attempt count and next retry time — not a fresh
// pending echo. It must not process early, add an attempt or reschedule the
// retry, and the submit echo must match a single-id query exactly.
func TestCLISubmitIdenticalWaitingReturnsCurrentWaitingRecord(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0x100", true); r.code != 0 {
		t.Fatalf("store header: %v", r)
	}

	spec := cliSubmitSpec{
		id: "w1", from: "chain-a", to: "chain-b", nonce: 8,
		proofAt: 110, payload: "world", expiresAt: 9_000_000_000_000,
	}
	mustSubmit(t, state, spec)
	rep := advanceCLI(t, state, 1_700_000_000_000)
	if got := resultFor(t, rep, "w1"); got.Status != "waiting" {
		t.Fatalf("setup: want waiting, got %+v", got)
	}

	wantWaiting := cliSubmitRecord{
		ID: "w1", Status: "waiting",
		Reason:    "waiting for trusted header covering height 110 (current 100)",
		Attempts:  1,
		NextRetry: 1_700_000_001_000,
		ExpiresAt: 9_000_000_000_000,
	}
	echo, rawEcho := mustSubmit(t, state, spec)
	if echo != wantWaiting {
		t.Fatalf("identical resubmit must return the current waiting record: %+v\n%s", echo, rawEcho)
	}
	assertSubmitMatchesQuery(t, echo, queryFull(t, state, "w1"))
	if all := queryAll(t, state); len(all) != 1 || all[0].ID != "w1" {
		t.Fatalf("waiting duplicate must not add a queue entry: %+v", all)
	}

	// Advancing half a second early processes nothing; the duplicate submit
	// must neither have advanced the clock nor rescheduled the retry.
	early := advanceCLI(t, state, 1_700_000_000_500)
	if len(early.Results) != 0 {
		t.Fatalf("nothing is due before the retry instant: %+v", early.Results)
	}
	echo2, _ := mustSubmit(t, state, spec)
	if echo2 != wantWaiting {
		t.Fatalf("waiting record must keep status/reason/attempts/retry: %+v", echo2)
	}
	if got := queryFull(t, state, "w1"); got.Status != "waiting" ||
		got.Reason != wantWaiting.Reason || got.Attempts != 1 ||
		got.NextRetry != 1_700_000_001_000 {
		t.Fatalf("stored waiting record changed: %+v", got)
	}
}

// Identity of content covers every field: source chain, destination chain,
// nonce, payload, proof height and absolute expiry. Changing any single one of
// them on a pending id must exit 13 as a content conflict and leave the
// original content and pending state stored, with no second entry.
func TestCLISubmitContentConflictExit13ForEveryField(t *testing.T) {
	base := cliSubmitSpec{
		id: "m", from: "chain-a", to: "chain-b", nonce: 7,
		proofAt: 90, payload: "hello", expiresAt: 9_000_000_000_000,
	}
	cases := []struct {
		name   string
		mutate func(*cliSubmitSpec)
	}{
		{"source chain", func(s *cliSubmitSpec) { s.from = "chain-other" }},
		{"destination chain", func(s *cliSubmitSpec) { s.to = "chain-c" }},
		{"nonce", func(s *cliSubmitSpec) { s.nonce = 8 }},
		{"payload", func(s *cliSubmitSpec) { s.payload = "HELLO" }},
		{"proof height", func(s *cliSubmitSpec) { s.proofAt = 91 }},
		{"absolute expiry", func(s *cliSubmitSpec) { s.expiresAt = 9_000_000_000_001 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := t.TempDir()
			mustSubmit(t, state, base)

			changed := base
			tc.mutate(&changed)
			assertContentConflict(t, submitRaw(t, state, changed), "m")

			got := queryFull(t, state, "m")
			if got.From != base.from || got.To != base.to || got.Nonce != base.nonce ||
				got.Payload != base.payload || got.ProofAt != base.proofAt ||
				got.ExpiresAt != base.expiresAt {
				t.Fatalf("conflicting submit overwrote original content: %+v", got)
			}
			if got.Status != "pending" || got.Reason != "awaiting first processing" ||
				got.Attempts != 0 || got.NextRetry != 0 {
				t.Fatalf("conflicting submit changed pending state: %+v", got)
			}
			if all := queryAll(t, state); len(all) != 1 || all[0].ID != "m" {
				t.Fatalf("conflicting submit must not add an entry: %+v", all)
			}
		})
	}
}

// Changing just the proof height or just the expiry of a WAITING record is
// still a 13 conflict: the original content, status, reason, attempt count and
// scheduled retry all survive, an early advance still processes nothing, and
// the message later delivers against its ORIGINAL proof height (a trusted
// header at 110 covers the kept proof 110, not the rejected 111).
func TestCLISubmitWaitingConflictKeepsContentAndSchedule(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0x100", true); r.code != 0 {
		t.Fatalf("store header: %v", r)
	}
	spec := cliSubmitSpec{
		id: "w", from: "chain-a", to: "chain-b", nonce: 5,
		proofAt: 110, payload: "orig", expiresAt: 9_000_000_000_000,
	}
	mustSubmit(t, state, spec)
	advanceCLI(t, state, 1_700_000_000_000)
	before := queryFull(t, state, "w")
	if before.Status != "waiting" || before.Attempts != 1 || before.NextRetry != 1_700_000_001_000 {
		t.Fatalf("setup waiting record wrong: %+v", before)
	}

	mutations := []struct {
		name   string
		mutate func(*cliSubmitSpec)
	}{
		{"proof height only", func(s *cliSubmitSpec) { s.proofAt = 111 }},
		{"expiry only", func(s *cliSubmitSpec) { s.expiresAt = 9_000_000_000_001 }},
		{"payload only", func(s *cliSubmitSpec) { s.payload = "changed" }},
		{"nonce only", func(s *cliSubmitSpec) { s.nonce = 6 }},
		{"destination only", func(s *cliSubmitSpec) { s.to = "chain-c" }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			changed := spec
			tc.mutate(&changed)
			assertContentConflict(t, submitRaw(t, state, changed), "w")
			if got := queryFull(t, state, "w"); got != before {
				t.Fatalf("waiting record changed after rejected submit:\nbefore=%+v\nafter =%+v", before, got)
			}
		})
	}

	early := advanceCLI(t, state, 1_700_000_000_500)
	if len(early.Results) != 0 {
		t.Fatalf("rejected submits must not reschedule or trigger processing: %+v", early.Results)
	}
	if got := queryFull(t, state, "w"); got != before {
		t.Fatalf("waiting record changed on early advance: %+v", got)
	}

	// Trusted 110 covers the original proof height 110; the rejected 111 would
	// still wait. Success at the scheduled retry proves the original content
	// was kept and never processed early.
	if r := storeHeader(t, state, "chain-a", 110, "0x110", true); r.code != 0 {
		t.Fatalf("extend coverage: %v", r)
	}
	rep := advanceCLI(t, state, 1_700_000_001_000)
	got := resultFor(t, rep, "w")
	if got.Status != "success" ||
		got.Reason != "delivered; proof verified by trusted header at height 110" {
		t.Fatalf("message must deliver by its original proof height 110: %+v", got)
	}
}

// A rejected submit changes neither the target message nor any other message
// in the same directory: sibling content stays intact and the first-submission
// order of all three ids is unchanged when they are later processed.
func TestCLISubmitConflictLeavesSiblingsAndOrderUntouched(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 200, "0x200", true); r.code != 0 {
		t.Fatalf("store header: %v", r)
	}

	a := cliSubmitSpec{id: "a1", from: "chain-a", to: "chain-b", nonce: 1, proofAt: 10, payload: "pa", expiresAt: 9_000_000_000_000}
	m := cliSubmitSpec{id: "mid", from: "chain-a", to: "chain-b", nonce: 5, proofAt: 100, payload: "original", expiresAt: 9_000_000_000_000}
	b := cliSubmitSpec{id: "b1", from: "chain-a", to: "chain-b", nonce: 9, proofAt: 200, payload: "pb", expiresAt: 9_000_000_000_000}
	mustSubmit(t, state, a)
	mustSubmit(t, state, m)
	mustSubmit(t, state, b)

	badProof := m
	badProof.proofAt = 101
	assertContentConflict(t, submitRaw(t, state, badProof), "mid")
	badPayload := m
	badPayload.payload = "changed"
	assertContentConflict(t, submitRaw(t, state, badPayload), "mid")

	all := queryAll(t, state)
	if got := recordIDs(all); len(got) != 3 || got[0] != "a1" || got[1] != "mid" || got[2] != "b1" {
		t.Fatalf("order/content must survive rejected submits: %v", got)
	}
	got := map[string]cliFullRecord{}
	for _, r := range all {
		got[r.ID] = r
	}
	if got["mid"].ProofAt != 100 || got["mid"].Payload != "original" {
		t.Fatalf("target content overwritten: %+v", got["mid"])
	}
	if got["a1"].ProofAt != 10 || got["a1"].Payload != "pa" ||
		got["b1"].ProofAt != 200 || got["b1"].Payload != "pb" {
		t.Fatalf("sibling content changed: a1=%+v b1=%+v", got["a1"], got["b1"])
	}

	// All three process in original submission order using their original content.
	rep := advanceCLI(t, state, 1_700_000_000_000)
	if len(rep.Results) != 3 {
		t.Fatalf("want 3 delivery results, got %+v", rep.Results)
	}
	for i, wantID := range []string{"a1", "mid", "b1"} {
		if rep.Results[i].ID != wantID || rep.Results[i].Status != "success" {
			t.Fatalf("position %d: want %s success, got %+v", i, wantID, rep.Results[i])
		}
	}
}

// After a message is delivered its id is dead: resubmitting identical content
// or content differing in any single field both exit 14 (never 13), print no
// record, and the stored success with its reason is still queryable. Updating
// the trusted header and advancing again does not deliver the message a second
// time.
func TestCLISubmitDeliveredIDAlwaysRejectedWith14(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0x100", true); r.code != 0 {
		t.Fatalf("store header: %v", r)
	}
	spec := cliSubmitSpec{
		id: "s", from: "chain-a", to: "chain-b", nonce: 7,
		proofAt: 90, payload: "hello", expiresAt: 9_000_000_000_000,
	}
	mustSubmit(t, state, spec)
	rep := advanceCLI(t, state, 1_700_000_000_000)
	if got := resultFor(t, rep, "s"); got.Status != "success" ||
		got.Reason != "delivered; proof verified by trusted header at height 100" {
		t.Fatalf("setup delivery wrong: %+v", got)
	}
	before := queryFull(t, state, "s")

	// Identical content: terminal, not an idempotent success echo.
	assertTerminalReject(t, submitRaw(t, state, spec), "s", "success")

	// Different content in any field is still 14, never a 13 content conflict.
	for _, tc := range []struct {
		name   string
		mutate func(*cliSubmitSpec)
	}{
		{"proof height", func(s *cliSubmitSpec) { s.proofAt = 91 }},
		{"payload", func(s *cliSubmitSpec) { s.payload = "x" }},
		{"expiry", func(s *cliSubmitSpec) { s.expiresAt = 9_000_000_000_001 }},
		{"nonce", func(s *cliSubmitSpec) { s.nonce = 8 }},
		{"source", func(s *cliSubmitSpec) { s.from = "chain-a2" }},
		{"destination", func(s *cliSubmitSpec) { s.to = "chain-c" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := spec
			tc.mutate(&changed)
			assertTerminalReject(t, submitRaw(t, state, changed), "s", "success")
		})
	}

	if got := queryFull(t, state, "s"); got != before {
		t.Fatalf("success record changed after rejected resubmits:\nbefore=%+v\nafter =%+v", before, got)
	}
	if all := queryAll(t, state); len(all) != 1 || all[0].ID != "s" {
		t.Fatalf("rejected resubmit must not add an entry: %+v", all)
	}

	// A higher trusted header and another advance must not resurrect or
	// redeliver the terminal message.
	if r := storeHeader(t, state, "chain-a", 120, "0x120", true); r.code != 0 {
		t.Fatalf("extend coverage: %v", r)
	}
	again := advanceCLI(t, state, 1_700_000_100_000)
	if len(again.Results) != 0 {
		t.Fatalf("delivered message must not reappear on later advances: %+v", again.Results)
	}
	if got := queryFull(t, state, "s"); got != before {
		t.Fatalf("success record changed after re-advance:\nbefore=%+v\nafter =%+v", before, got)
	}
}

// Every terminal status, not just success, permanently rejects the id with 14
// for identical and differing content alike, while the stored status and reason
// stay queryable and unchanged.
func TestCLISubmitTerminalIDsRejectedWith14AcrossStatuses(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		state := t.TempDir()
		registerSource(t, state, "chain-a")
		spec := cliSubmitSpec{
			id: "e", from: "chain-a", to: "chain-b", nonce: 1,
			proofAt: 100, payload: "p", expiresAt: 1000,
		}
		mustSubmit(t, state, spec)
		rep := advanceCLI(t, state, 1000) // now == expiry counts as expired
		if got := resultFor(t, rep, "e"); got.Status != "expired" {
			t.Fatalf("setup: want expired, got %+v", got)
		}
		before := queryFull(t, state, "e")
		assertTerminalReject(t, submitRaw(t, state, spec), "e", "expired")
		changed := spec
		changed.proofAt = 101
		assertTerminalReject(t, submitRaw(t, state, changed), "e", "expired")
		if got := queryFull(t, state, "e"); got != before {
			t.Fatalf("expired record changed: %+v", got)
		}
	})

	t.Run("unknown-source", func(t *testing.T) {
		state := t.TempDir()
		spec := cliSubmitSpec{
			id: "u", from: "chain-ghost", to: "chain-b", nonce: 1,
			proofAt: 10, payload: "p", expiresAt: 9_000_000_000_000,
		}
		mustSubmit(t, state, spec)
		rep := advanceCLI(t, state, 1000)
		if got := resultFor(t, rep, "u"); got.Status != "unknown-source" {
			t.Fatalf("setup: want unknown-source, got %+v", got)
		}
		before := queryFull(t, state, "u")
		assertTerminalReject(t, submitRaw(t, state, spec), "u", "unknown-source")
		changed := spec
		changed.payload = "different"
		assertTerminalReject(t, submitRaw(t, state, changed), "u", "unknown-source")
		if got := queryFull(t, state, "u"); got != before {
			t.Fatalf("unknown-source record changed: %+v", got)
		}
	})

	t.Run("replay", func(t *testing.T) {
		state := t.TempDir()
		registerSource(t, state, "chain-a")
		if r := storeHeader(t, state, "chain-a", 100, "0x100", true); r.code != 0 {
			t.Fatalf("store header: %v", r)
		}
		winner := cliSubmitSpec{
			id: "win", from: "chain-a", to: "chain-b", nonce: 3,
			proofAt: 10, payload: "w", expiresAt: 9_000_000_000_000,
		}
		loser := cliSubmitSpec{
			id: "lose", from: "chain-a", to: "chain-b", nonce: 3,
			proofAt: 10, payload: "l", expiresAt: 9_000_000_000_000,
		}
		mustSubmit(t, state, winner)
		mustSubmit(t, state, loser)
		rep := advanceCLI(t, state, 1000)
		if got := resultFor(t, rep, "lose"); got.Status != "replay" {
			t.Fatalf("setup: want replay, got %+v", got)
		}
		before := queryFull(t, state, "lose")
		assertTerminalReject(t, submitRaw(t, state, loser), "lose", "replay")
		changed := loser
		changed.payload = "changed"
		assertTerminalReject(t, submitRaw(t, state, changed), "lose", "replay")
		if got := queryFull(t, state, "lose"); got != before {
			t.Fatalf("replay record changed: %+v", got)
		}
	})
}
