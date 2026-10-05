package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// These tests pin the command-line observable behaviour of re-submitting an
// existing message id: an identical re-submission of a non-terminal message
// returns the already-saved record (pending or waiting) without adding a
// queue entry or touching the schedule; any single-field content difference
// is rejected as a message content conflict with exit code 13; and a
// terminal id is rejected with exit code 14 no matter whether the content
// matches. The queue-level rules are covered in the relayproof package, but
// users go through the submit output, the stderr rendering and the exit-code
// mapping, so a regression there must never print a success record for a
// rejected submission or lose the error category. Every scenario runs
// against a local temp state directory and the real binary with explicit
// processing times; no chain or external service is involved.

// msgSpec describes one `queue submit` invocation. setPayload/setExpires
// control whether --payload/--expires-at are passed at all, so tests can
// cover the flag defaults (empty payload, expiry 0 = never expire).
type msgSpec struct {
	id         string
	from       string
	to         string
	nonce      uint64
	payload    string
	proofAt    int64
	expires    int64
	setPayload bool
	setExpires bool
}

// fullSpec returns a spec that passes every flag explicitly.
func fullSpec(id, from, to string, nonce uint64, proofAt int64, payload string, expires int64) msgSpec {
	return msgSpec{
		id: id, from: from, to: to, nonce: nonce, proofAt: proofAt,
		payload: payload, expires: expires, setPayload: true, setExpires: true,
	}
}

func submitSpec(t *testing.T, state string, m msgSpec) cliResult {
	t.Helper()
	args := []string{
		"--id", m.id,
		"--from", m.from,
		"--to", m.to,
		"--nonce", strconv.FormatUint(m.nonce, 10),
		"--proof-at", strconv.FormatInt(m.proofAt, 10),
	}
	if m.setPayload {
		args = append(args, "--payload", m.payload)
	}
	if m.setExpires {
		args = append(args, "--expires-at", strconv.FormatInt(m.expires, 10))
	}
	return queueCLI(t, state, "submit", args...)
}

func mustSubmit(t *testing.T, state string, m msgSpec) cliResult {
	t.Helper()
	r := submitSpec(t, state, m)
	if r.code != 0 {
		t.Fatalf("submit %s: code=%d stdout=%q stderr=%q", m.id, r.code, r.stdout, r.stderr)
	}
	return r
}

// cliSubmitRecord decodes the JSON printed by a successful `queue submit`.
type cliSubmitRecord struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Attempts  int    `json:"attempts"`
	NextRetry int64  `json:"nextRetryMs"`
	ExpiresAt int64  `json:"expiresAtMs"`
}

func decodeSubmit(t *testing.T, r cliResult) cliSubmitRecord {
	t.Helper()
	var got cliSubmitRecord
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("decode submit output %q: %v", r.stdout, err)
	}
	return got
}

// cliFullRecord decodes one `queue query` record including the message
// content fields, so tests can verify the saved content byte for byte.
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

func queryFullCLI(t *testing.T, state, id string) cliFullRecord {
	t.Helper()
	r := queueCLI(t, state, "query", "--id", id)
	if r.code != 0 {
		t.Fatalf("query %s: code=%d stderr=%q", id, r.code, r.stderr)
	}
	var got cliFullRecord
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("decode query output %q: %v", r.stdout, err)
	}
	return got
}

// queryListCLI returns every record in first-submission order.
func queryListCLI(t *testing.T, state string) []cliFullRecord {
	t.Helper()
	r := queueCLI(t, state, "query")
	if r.code != 0 {
		t.Fatalf("query list: code=%d stderr=%q", r.code, r.stderr)
	}
	var out []cliFullRecord
	for _, line := range strings.Split(strings.TrimRight(r.stdout, "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec cliFullRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode query list line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// assertContentConflict requires the exact CLI surface of a message content
// conflict: exit code 13, a stderr line naming the conflict category and the
// message id, and nothing on stdout (in particular no success record).
func assertContentConflict(t *testing.T, r cliResult, id string) {
	t.Helper()
	if r.code != 13 {
		t.Fatalf("want exit code 13, got %d (stdout=%q stderr=%q)", r.code, r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a rejected submission must not print a success record on stdout: %q", r.stdout)
	}
	for _, want := range []string{
		"message id conflict",
		"different content",
		"message " + id,
	} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("stderr missing %q:\n%s", want, r.stderr)
		}
	}
}

// assertTerminalReject requires the exact CLI surface of re-submitting a
// terminal id: exit code 14, a stderr line naming the terminal category and
// the message id, and nothing on stdout.
func assertTerminalReject(t *testing.T, r cliResult, id string) {
	t.Helper()
	if r.code != 14 {
		t.Fatalf("want exit code 14, got %d (stdout=%q stderr=%q)", r.code, r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a rejected submission must not print a success record on stdout: %q", r.stdout)
	}
	for _, want := range []string{
		"message is terminal",
		"message " + id,
	} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("stderr missing %q:\n%s", want, r.stderr)
		}
	}
}

// setupCoveredDir returns a fresh state directory with chain-a registered
// and a trusted header at height 100, so proof heights up to 100 are covered
// and higher ones wait.
func setupCoveredDir(t *testing.T) string {
	t.Helper()
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0x100", true); r.code != 0 {
		t.Fatalf("trusted header: code=%d stderr=%q", r.code, r.stderr)
	}
	return state
}

// Re-submitting a pending message with byte-identical content succeeds and
// returns the already-saved record: the output is identical to the first
// submission, the list still holds exactly one entry for the id, and the
// first-submission order is unchanged.
func TestCLISubmitIdenticalPendingIsIdempotent(t *testing.T) {
	state := setupCoveredDir(t)

	m1 := fullSpec("m1", "chain-a", "chain-b", 7, 90, "hello", 9_000_000_000_000)
	first := mustSubmit(t, state, m1)
	wantPending := cliSubmitRecord{
		ID: "m1", Status: "pending", Reason: "awaiting first processing",
		Attempts: 0, ExpiresAt: 9_000_000_000_000,
	}
	if got := decodeSubmit(t, first); got != wantPending {
		t.Fatalf("first submit output wrong: %+v", got)
	}

	m2 := fullSpec("m2", "chain-a", "chain-b", 8, 90, "world", 9_000_000_000_000)
	mustSubmit(t, state, m2)

	again := mustSubmit(t, state, m1)
	if again.stdout != first.stdout || again.stderr != "" {
		t.Fatalf("identical re-submit must print the saved record byte-for-byte:\nfirst=%q\nagain=%q\nstderr=%q",
			first.stdout, again.stdout, again.stderr)
	}

	rec := queryFullCLI(t, state, "m1")
	wantRec := cliFullRecord{
		ID: "m1", From: "chain-a", To: "chain-b", Nonce: 7, Payload: "hello",
		ProofAt: 90, ExpiresAt: 9_000_000_000_000,
		Status: "pending", Reason: "awaiting first processing",
	}
	if rec != wantRec {
		t.Fatalf("saved record wrong after idempotent re-submit:\ngot  %+v\nwant %+v", rec, wantRec)
	}

	list := queryListCLI(t, state)
	if len(list) != 2 || list[0].ID != "m1" || list[1].ID != "m2" {
		t.Fatalf("re-submit must not add an entry or reorder first submissions: %+v", list)
	}
}

// The flag defaults are content, not absence: omitting --payload and
// --expires-at is the same message as passing --payload "" and
// --expires-at 0 explicitly, in either submission order, and expiry 0 still
// means the message never expires.
func TestCLISubmitDefaultsEqualExplicitEmptyPayloadAndZeroExpiry(t *testing.T) {
	state := setupCoveredDir(t)

	implicit := msgSpec{id: "d1", from: "chain-a", to: "chain-b", nonce: 1, proofAt: 50}
	first := mustSubmit(t, state, implicit)
	wantPending := cliSubmitRecord{ID: "d1", Status: "pending", Reason: "awaiting first processing"}
	if got := decodeSubmit(t, first); got != wantPending {
		t.Fatalf("defaulted submit output wrong: %+v (raw %q)", got, first.stdout)
	}
	if strings.Contains(first.stdout, "expiresAtMs") {
		t.Fatalf("expiry 0 (never) must stay omitted from the output: %q", first.stdout)
	}

	explicit := fullSpec("d1", "chain-a", "chain-b", 1, 50, "", 0)
	again := mustSubmit(t, state, explicit)
	if again.stdout != first.stdout {
		t.Fatalf("explicit empty payload and zero expiry must equal the defaults:\nimplicit=%q\nexplicit=%q",
			first.stdout, again.stdout)
	}

	// Reverse order in the same directory: explicit first, defaults second.
	explicitFirst := fullSpec("d2", "chain-a", "chain-b", 2, 50, "", 0)
	first2 := mustSubmit(t, state, explicitFirst)
	implicitSecond := msgSpec{id: "d2", from: "chain-a", to: "chain-b", nonce: 2, proofAt: 50}
	again2 := mustSubmit(t, state, implicitSecond)
	if again2.stdout != first2.stdout {
		t.Fatalf("defaults must equal explicit empty payload and zero expiry:\nexplicit=%q\nimplicit=%q",
			first2.stdout, again2.stdout)
	}

	rec := queryFullCLI(t, state, "d1")
	if rec.Payload != "" || rec.ExpiresAt != 0 || rec.Status != "pending" {
		t.Fatalf("saved record must hold the defaulted content: %+v", rec)
	}
	if list := queryListCLI(t, state); len(list) != 2 {
		t.Fatalf("equivalent re-submits must not add entries: %+v", list)
	}

	// Expiry 0 means never expire: advancing far past any real clock still
	// delivers rather than expiring the message.
	rep := advanceCLI(t, state, 9_000_000_000_000)
	for _, id := range []string{"d1", "d2"} {
		got := resultFor(t, rep, id)
		if want := "delivered; proof verified by trusted header at height 100"; got.Status != "success" || got.Reason != want {
			t.Fatalf("expiry 0 must never expire: %+v", got)
		}
	}
}

// Re-submitting a waiting message with identical content returns the current
// waiting record as saved: status, reason, attempt count and next retry time
// keep their values, the output is not a fresh pending submission, and the
// wait is neither processed early nor rescheduled. The submitted output
// agrees with the single-record query.
func TestCLISubmitIdenticalWaitingReturnsCurrentRecord(t *testing.T) {
	state := setupCoveredDir(t)

	w := fullSpec("w1", "chain-a", "chain-b", 8, 110, "world", 9_000_000_000_000)
	mustSubmit(t, state, w)
	advanceCLI(t, state, 1_700_000_000_000)

	before := queryFullCLI(t, state, "w1")
	wantBefore := cliFullRecord{
		ID: "w1", From: "chain-a", To: "chain-b", Nonce: 8, Payload: "world",
		ProofAt: 110, ExpiresAt: 9_000_000_000_000,
		Status: "waiting", Reason: "waiting for trusted header covering height 110 (current 100)",
		Attempts: 1, NextRetry: 1_700_000_001_000,
	}
	if before != wantBefore {
		t.Fatalf("setup waiting record wrong:\ngot  %+v\nwant %+v", before, wantBefore)
	}

	r := mustSubmit(t, state, w)
	got := decodeSubmit(t, r)
	if got.Status == "pending" || got.Reason == "awaiting first processing" || got.Attempts == 0 {
		t.Fatalf("re-submit of a waiting message must not look like a new pending submission: %+v", got)
	}
	if got.Status != before.Status || got.Reason != before.Reason ||
		got.Attempts != before.Attempts || got.NextRetry != before.NextRetry ||
		got.ExpiresAt != before.ExpiresAt {
		t.Fatalf("submit output must carry the saved waiting record unchanged:\nsubmit=%+v\nquery =%+v", got, before)
	}

	// The re-submit did not process the message early or move the schedule:
	// advancing before the original retry time still finds nothing due.
	rep := advanceCLI(t, state, 1_700_000_000_500)
	if len(rep.Results) != 0 {
		t.Fatalf("no message is due before the original retry time: %+v", rep.Results)
	}
	if after := queryFullCLI(t, state, "w1"); after != before {
		t.Fatalf("waiting record changed after identical re-submit:\nbefore=%+v\nafter =%+v", before, after)
	}
	if list := queryListCLI(t, state); len(list) != 1 || list[0] != before {
		t.Fatalf("list must still hold exactly the original record: %+v", list)
	}

	// The original schedule is still in force: the retry happens at the
	// originally scheduled time, not one re-anchored to the re-submission.
	rep = advanceCLI(t, state, 1_700_000_001_000)
	entry := resultFor(t, rep, "w1")
	if entry.Status != "waiting" {
		t.Fatalf("retry at the original schedule must process once: %+v", entry)
	}
	rec := queryFullCLI(t, state, "w1")
	if rec.Attempts != 2 || rec.NextRetry != 1_700_000_003_000 {
		t.Fatalf("backoff must continue from the original schedule: %+v", rec)
	}
}

// For a non-terminal id, changing any single content field — source chain,
// destination chain, nonce, payload, proof height or expiry — is a message
// content conflict rejected with exit code 13. The rejected submissions save
// nothing: the original record, its content and the other messages in the
// same directory are all untouched, and the first-submission order holds.
func TestCLISubmitConflictingContentExit13PerField(t *testing.T) {
	state := setupCoveredDir(t)

	base := fullSpec("m1", "chain-a", "chain-b", 7, 90, "hello", 9_000_000_000_000)
	mustSubmit(t, state, base)
	other := fullSpec("m2", "chain-a", "chain-b", 8, 90, "world", 9_000_000_000_000)
	mustSubmit(t, state, other)

	variants := map[string]msgSpec{
		"source chain":      fullSpec("m1", "chain-c", "chain-b", 7, 90, "hello", 9_000_000_000_000),
		"destination chain": fullSpec("m1", "chain-a", "chain-c", 7, 90, "hello", 9_000_000_000_000),
		"nonce":             fullSpec("m1", "chain-a", "chain-b", 70, 90, "hello", 9_000_000_000_000),
		"payload":           fullSpec("m1", "chain-a", "chain-b", 7, 90, "CHANGED", 9_000_000_000_000),
		// A proof-height-only difference must not overwrite the original.
		"proof height": fullSpec("m1", "chain-a", "chain-b", 7, 101, "hello", 9_000_000_000_000),
		// An expiry-only difference must not overwrite the original either.
		"expiry": fullSpec("m1", "chain-a", "chain-b", 7, 90, "hello", 1),
	}
	for field, variant := range variants {
		assertContentConflict(t, submitSpec(t, state, variant), "m1")
		if got := queryFullCLI(t, state, "m1"); got.ProofAt != 90 || got.ExpiresAt != 9_000_000_000_000 ||
			got.Payload != "hello" || got.From != "chain-a" || got.To != "chain-b" || got.Nonce != 7 {
			t.Fatalf("conflicting %s must not overwrite the saved content: %+v", field, got)
		}
	}

	// The original record is still a first-submission-order pending entry and
	// the sibling message is untouched.
	list := queryListCLI(t, state)
	if len(list) != 2 || list[0].ID != "m1" || list[1].ID != "m2" {
		t.Fatalf("rejected submits must not add or reorder entries: %+v", list)
	}
	if list[1].Payload != "world" || list[1].Nonce != 8 || list[1].Status != "pending" {
		t.Fatalf("sibling message affected by rejected submits: %+v", list[1])
	}

	// Processing proves the saved content won: proof height 90 (not the
	// conflicting 101) is covered, and expiry 9000000000000 (not the
	// conflicting 1) is not reached, so both messages deliver in submission
	// order.
	rep := advanceCLI(t, state, 1_700_000_000_000)
	if len(rep.Results) != 2 || rep.Results[0].ID != "m1" || rep.Results[1].ID != "m2" {
		t.Fatalf("processing order must follow first submissions: %+v", rep.Results)
	}
	for _, id := range []string{"m1", "m2"} {
		got := resultFor(t, rep, id)
		if want := "delivered; proof verified by trusted header at height 100"; got.Status != "success" || got.Reason != want {
			t.Fatalf("original content must survive the conflicts: %+v", got)
		}
	}
}

// A content conflict against a waiting message is likewise rejected with
// exit code 13 and leaves the waiting record — status, reason, attempt count
// and scheduled retry — exactly as it was.
func TestCLISubmitConflictOnWaitingKeepsSchedule(t *testing.T) {
	state := setupCoveredDir(t)

	w := fullSpec("w1", "chain-a", "chain-b", 8, 110, "world", 9_000_000_000_000)
	mustSubmit(t, state, w)
	advanceCLI(t, state, 1_700_000_000_000)
	before := queryFullCLI(t, state, "w1")
	if before.Status != "waiting" || before.Attempts != 1 || before.NextRetry != 1_700_000_001_000 {
		t.Fatalf("setup waiting record wrong: %+v", before)
	}

	conflict := fullSpec("w1", "chain-a", "chain-b", 8, 110, "CHANGED", 9_000_000_000_000)
	assertContentConflict(t, submitSpec(t, state, conflict), "w1")

	if got := queryFullCLI(t, state, "w1"); got != before {
		t.Fatalf("waiting record changed after rejected submit:\nbefore=%+v\nafter =%+v", before, got)
	}
	rep := advanceCLI(t, state, 1_700_000_000_500)
	if len(rep.Results) != 0 {
		t.Fatalf("rejected submit must not reschedule the wait: %+v", rep.Results)
	}
	if got := queryFullCLI(t, state, "w1"); got != before {
		t.Fatalf("waiting record changed after mid-backoff advance:\nbefore=%+v\nafter =%+v", before, got)
	}
}

// Once a message has been delivered, its id is terminal: re-submitting fails
// with exit code 14 whether the content is identical or different (a
// difference must not be misreported as a content conflict). The saved
// success record stays queryable and unchanged, and later advances never
// deliver the message again.
func TestCLISubmitTerminalIdExit14(t *testing.T) {
	state := setupCoveredDir(t)

	m1 := fullSpec("m1", "chain-a", "chain-b", 7, 90, "hello", 9_000_000_000_000)
	mustSubmit(t, state, m1)
	rep := advanceCLI(t, state, 1_700_000_000_000)
	if got := resultFor(t, rep, "m1"); got.Status != "success" {
		t.Fatalf("setup delivery failed: %+v", got)
	}
	delivered := queryFullCLI(t, state, "m1")
	if delivered.Status != "success" ||
		delivered.Reason != "delivered; proof verified by trusted header at height 100" {
		t.Fatalf("setup success record wrong: %+v", delivered)
	}

	// Identical content: terminal, not a success.
	assertTerminalReject(t, submitSpec(t, state, m1), "m1")
	// Different content: still terminal (14), never a content conflict (13).
	changed := fullSpec("m1", "chain-a", "chain-b", 7, 90, "CHANGED", 9_000_000_000_000)
	assertTerminalReject(t, submitSpec(t, state, changed), "m1")

	if got := queryFullCLI(t, state, "m1"); got != delivered {
		t.Fatalf("success record changed after terminal re-submits:\nbefore=%+v\nafter =%+v", delivered, got)
	}

	// Advancing processing time further cannot make the terminal message
	// reappear as a fresh delivery.
	rep = advanceCLI(t, state, 1_700_000_010_000)
	if len(rep.Results) != 0 {
		t.Fatalf("terminal message must not be delivered again: %+v", rep.Results)
	}
	if got := queryFullCLI(t, state, "m1"); got != delivered {
		t.Fatalf("success record changed after later advance:\nbefore=%+v\nafter =%+v", delivered, got)
	}
	if list := queryListCLI(t, state); len(list) != 1 || list[0] != delivered {
		t.Fatalf("list must still hold exactly the delivered record: %+v", list)
	}
}
