package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These tests pin the command-line observable behaviour of saving headers
// around ErrHeaderConflict: the queue-level conflict rule is covered directly
// in the relayproof package, but users go through stderr rendering and the
// exit-code mapping, so a regression there must never show success while the
// header was rejected, or report a generic failure that loses the conflict
// category. Every scenario runs against a local temp state directory and the
// real binary; no chain or external service is involved.

// cliPath is the relayproof binary built once for all CLI regression tests.
var cliPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "relayproof-cli-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cliPath = filepath.Join(dir, "relayproof")
	// go test runs with the package directory as the working directory.
	build := exec.Command("go", "build", "-o", cliPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "cannot build relayproof CLI: %v\n%s\n", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.Remove(cliPath)
	os.Remove(dir)
	os.Exit(code)
}

type cliResult struct {
	stdout string
	stderr string
	code   int
}

func runCLI(t *testing.T, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(cliPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := cliResult{stdout: stdout.String(), stderr: stderr.String()}
	if err == nil {
		return res
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.code = exitErr.ExitCode()
		return res
	}
	t.Fatalf("run %q: %v", strings.Join(args, " "), err)
	return cliResult{}
}

// queueCLI invokes `relayproof queue <sub> --state <state> rest...`. The
// per-subcommand flag set parses --state, so it follows the subcommand.
func queueCLI(t *testing.T, state, sub string, rest ...string) cliResult {
	t.Helper()
	args := append([]string{"queue", sub, "--state", state}, rest...)
	return runCLI(t, args...)
}

func registerSource(t *testing.T, state, chain string) {
	t.Helper()
	r := queueCLI(t, state, "register-source", "--chain", chain)
	if r.code != 0 || r.stdout != "registered source chain "+chain+"\n" {
		t.Fatalf("register-source %s: code=%d stdout=%q stderr=%q", chain, r.code, r.stdout, r.stderr)
	}
}

func storeHeader(t *testing.T, state, chain string, height int64, root string, trusted bool) cliResult {
	t.Helper()
	args := []string{
		"--chain", chain,
		"--height", strconv.FormatInt(height, 10),
		"--root", root,
	}
	if trusted {
		args = append(args, "--trusted")
	}
	return queueCLI(t, state, "header", args...)
}

func wantStoredHeader(chain string, height int64, trusted bool) string {
	return fmt.Sprintf("stored header chain=%s height=%d trusted=%t\n", chain, height, trusted)
}

func submitMsg(t *testing.T, state, id, from, to string, nonce uint64, proofAt int64) {
	t.Helper()
	r := queueCLI(t, state, "submit",
		"--id", id, "--from", from, "--to", to,
		"--nonce", strconv.FormatUint(nonce, 10),
		"--proof-at", strconv.FormatInt(proofAt, 10),
		"--payload", "p-"+id,
		"--expires-at", "9000000000000",
	)
	if r.code != 0 {
		t.Fatalf("submit %s: code=%d stderr=%q", id, r.code, r.stderr)
	}
}

type cliResultEntry struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type cliAdvanceReport struct {
	NowMs   int64            `json:"nowMs"`
	Results []cliResultEntry `json:"results"`
}

func advanceCLI(t *testing.T, state string, now int64) cliAdvanceReport {
	t.Helper()
	r := queueCLI(t, state, "advance", "--now", strconv.FormatInt(now, 10))
	if r.code != 0 {
		t.Fatalf("advance at %d: code=%d stderr=%q", now, r.code, r.stderr)
	}
	var rep cliAdvanceReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("decode advance output %q: %v", r.stdout, err)
	}
	return rep
}

func resultFor(t *testing.T, rep cliAdvanceReport, id string) cliResultEntry {
	t.Helper()
	for _, r := range rep.Results {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("advance report has no result for %s: %+v", id, rep.Results)
	return cliResultEntry{}
}

type cliQueryRecord struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Attempts  int    `json:"attempts"`
	NextRetry int64  `json:"nextRetryMs"`
}

func queryCLI(t *testing.T, state, id string) cliQueryRecord {
	t.Helper()
	r := queueCLI(t, state, "query", "--id", id)
	if r.code != 0 {
		t.Fatalf("query %s: code=%d stderr=%q", id, r.code, r.stderr)
	}
	var got cliQueryRecord
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("decode query output %q: %v", r.stdout, err)
	}
	return got
}

// assertHeaderConflict requires the exact CLI surface of a trusted-header
// conflict: exit code 16, a stderr line naming the conflict category together
// with chain, height, the submitted root and the accepted root, and nothing on
// stdout (in particular no "stored header" success line).
func assertHeaderConflict(t *testing.T, r cliResult, chain string, height int64, submitted, accepted string) {
	t.Helper()
	if r.code != 16 {
		t.Fatalf("want exit code 16, got %d (stdout=%q stderr=%q)", r.code, r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a rejected header must not print a success line on stdout: %q", r.stdout)
	}
	for _, want := range []string{
		"trusted header conflict",
		`chain "` + chain + `"`,
		"height " + strconv.FormatInt(height, 10),
		"submitted root " + strconv.Quote(submitted),
		"conflicts with accepted root " + strconv.Quote(accepted),
	} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("stderr missing %q:\n%s", want, r.stderr)
		}
	}
}

// With a registered source and an accepted trusted header at height 100 with
// root 0xaaa, saving another trusted header at the same height with root
// 0xbbb ends with exit code 16 and an explicit conflict error; resaving the
// original height and root stays a normal success with the usual output.
func TestCLIHeaderConflictExitCode16(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")

	wantStored := wantStoredHeader("chain-a", 100, true)
	first := storeHeader(t, state, "chain-a", 100, "0xaaa", true)
	if first.code != 0 || first.stdout != wantStored {
		t.Fatalf("initial trusted header: code=%d stdout=%q stderr=%q", first.code, first.stdout, first.stderr)
	}

	conflict := storeHeader(t, state, "chain-a", 100, "0xbbb", true)
	assertHeaderConflict(t, conflict, "chain-a", 100, "0xbbb", "0xaaa")

	// Same height, original root: idempotent acceptance identical to any
	// successful header save.
	again := storeHeader(t, state, "chain-a", 100, "0xaaa", true)
	if again.code != 0 || again.stdout != wantStored || again.stderr != "" {
		t.Fatalf("same height/root resave: code=%d stdout=%q stderr=%q", again.code, again.stdout, again.stderr)
	}
}

// A conflict must not replace the accepted trusted header nor leave the state
// directory unusable: a proof-at-90 message afterwards delivers citing the
// trusted height 100, while a proof-at-101 message keeps waiting for a trusted
// header.
func TestCLIHeaderConflictKeepsCoverageAndQueueUsable(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0xaaa", true); r.code != 0 {
		t.Fatalf("initial trusted header: %v", r)
	}
	assertHeaderConflict(t, storeHeader(t, state, "chain-a", 100, "0xbbb", true),
		"chain-a", 100, "0xbbb", "0xaaa")

	// Every CLI invocation opens the directory afresh, so the following
	// commands also prove the state directory survives a rejected save across
	// process boundaries.
	submitMsg(t, state, "m90", "chain-a", "chain-b", 1, 90)
	rep := advanceCLI(t, state, 1_700_000_000_000)
	got := resultFor(t, rep, "m90")
	if got.Status != "success" {
		t.Fatalf("proof-at-90 must deliver after conflict: %+v", got)
	}
	if want := "delivered; proof verified by trusted header at height 100"; got.Reason != want {
		t.Fatalf("success reason must cite the actually-used trusted height 100: %q", got.Reason)
	}

	submitMsg(t, state, "m101", "chain-a", "chain-b", 2, 101)
	rep = advanceCLI(t, state, 1_700_000_100_000)
	waiting := resultFor(t, rep, "m101")
	if want := "waiting for trusted header covering height 101 (current 100)"; waiting.Status != "waiting" || waiting.Reason != want {
		t.Fatalf("proof-at-101 must still wait on coverage 100: %+v", waiting)
	}
	if rec := queryCLI(t, state, "m101"); rec.Attempts != 1 || rec.NextRetry != 1_700_000_101_000 {
		t.Fatalf("waiting record schedule wrong: %+v", rec)
	}
}

// Saving a header never processes messages: after a conflicting (or
// idempotent) header save, an already waiting record must keep exactly its
// status, reason, attempt count and scheduled retry time.
func TestCLIConflictHeaderSaveLeavesWaitingRecordUntouched(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0xaaa", true); r.code != 0 {
		t.Fatalf("initial trusted header: %v", r)
	}
	submitMsg(t, state, "w1", "chain-a", "chain-b", 1, 101)
	advanceCLI(t, state, 1_700_000_000_000)

	before := queryCLI(t, state, "w1")
	wantBefore := cliQueryRecord{
		ID: "w1", Status: "waiting",
		Reason:    "waiting for trusted header covering height 101 (current 100)",
		Attempts:  1,
		NextRetry: 1_700_000_001_000,
	}
	if before != wantBefore {
		t.Fatalf("setup waiting record wrong: %+v", before)
	}

	// Rejected save: exit 16, record untouched.
	assertHeaderConflict(t, storeHeader(t, state, "chain-a", 100, "0xbbb", true),
		"chain-a", 100, "0xbbb", "0xaaa")
	if got := queryCLI(t, state, "w1"); got != before {
		t.Fatalf("waiting record changed after rejected header save:\nbefore=%+v\nafter =%+v", before, got)
	}

	// Accepted same-root save: record still untouched.
	if r := storeHeader(t, state, "chain-a", 100, "0xaaa", true); r.code != 0 {
		t.Fatalf("idempotent header save failed: %v", r)
	}
	if got := queryCLI(t, state, "w1"); got != before {
		t.Fatalf("waiting record changed after accepted header save:\nbefore=%+v\nafter =%+v", before, got)
	}

	// Advancing before the scheduled retry processes nothing either; the
	// failed header save must not have moved the processing clock.
	rep := advanceCLI(t, state, 1_700_000_000_500)
	if len(rep.Results) != 0 {
		t.Fatalf("no message is due mid-backoff, got %+v", rep.Results)
	}
	if got := queryCLI(t, state, "w1"); got != before {
		t.Fatalf("waiting record changed on a mid-backoff advance:\nbefore=%+v\nafter =%+v", before, got)
	}
}

// Roots compare as the submitted raw strings, byte for byte: surrounding
// whitespace and case differences are normal header-root conflicts, not
// equivalent roots.
func TestCLIHeaderConflictRootsComparedByteForByte(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0xaaa", true); r.code != 0 {
		t.Fatalf("initial trusted header: %v", r)
	}
	for _, root := range []string{"0xAAA", " 0xaaa", "0xaaa ", "0xaaa\t"} {
		assertHeaderConflict(t, storeHeader(t, state, "chain-a", 100, root, true),
			"chain-a", 100, root, "0xaaa")
	}
	// The original raw string is still accepted byte-for-byte.
	if r := storeHeader(t, state, "chain-a", 100, "0xaaa", true); r.code != 0 {
		t.Fatalf("byte-identical root must stay idempotent: code=%d stderr=%q", r.code, r.stderr)
	}
}

// Empty roots are legal input: two trusted headers at the same height with
// empty roots accept normally, while an empty and a non-empty root conflict in
// either submission order with the same conflict category.
func TestCLIHeaderConflictEmptyRoots(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "x")

	wantStored := wantStoredHeader("x", 1, true)
	r1 := storeHeader(t, state, "x", 1, "", true)
	if r1.code != 0 || r1.stdout != wantStored {
		t.Fatalf("first empty-root trusted header: code=%d stdout=%q stderr=%q", r1.code, r1.stdout, r1.stderr)
	}
	r2 := storeHeader(t, state, "x", 1, "", true)
	if r2.code != 0 || r2.stdout != wantStored {
		t.Fatalf("second empty-root trusted header must be idempotent: code=%d stdout=%q stderr=%q", r2.code, r2.stdout, r2.stderr)
	}
	assertHeaderConflict(t, storeHeader(t, state, "x", 1, "other", true),
		"x", 1, "other", "")

	// Reverse direction: accepted non-empty root, submitted empty root.
	state2 := t.TempDir()
	registerSource(t, state2, "y")
	if r := storeHeader(t, state2, "y", 2, "r0", true); r.code != 0 {
		t.Fatalf("non-empty trusted header: %v", r)
	}
	assertHeaderConflict(t, storeHeader(t, state2, "y", 2, "", true),
		"y", 2, "", "r0")
}

// A stored header record that carries both root forms at once is corrupt
// on-disk state, not a header conflict: opening the directory through
// `queue query` fails with the corruption exit code 12 (distinct from the
// same-height-different-root conflict's 16), stderr names the two root
// representations, no query result is printed, and queue.log keeps every
// byte. The frame bytes are hand-built because no build writes such a record.
func TestCLIQueryCorruptHeaderRootBothFormsExitCode12(t *testing.T) {
	state := t.TempDir()
	var raw []byte
	raw = append(raw, "RELAYPROOF-QUEUE-V1\n"...)
	raw = append(raw, cliLogFrame(`{"t":"version","v":1}`)...)
	raw = append(raw, cliLogFrame(`{"t":"header","chain":"a","height":1,"root":"","rootB64":"/w==","trusted":true}`)...)
	logPath := filepath.Join(state, "queue.log")
	if err := os.WriteFile(logPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	r := queueCLI(t, state, "query")
	if r.code != 12 {
		t.Fatalf("want corruption exit code 12, got %d (stdout=%q stderr=%q)", r.code, r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a corrupt directory must not print query results: %q", r.stdout)
	}
	for _, want := range []string{"corrupt", "both root and rootB64"} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("stderr missing %q:\n%s", want, r.stderr)
		}
	}

	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("rejected open modified queue.log: want %d bytes, got %d", len(raw), len(got))
	}
}

// cliLogFrame wraps a JSON payload in the queue.log frame envelope:
// uint32-be length, payload, uint32-be CRC32-IEEE of the payload.
func cliLogFrame(payload string) []byte {
	body := []byte(payload)
	frame := make([]byte, 0, 4+len(body)+4)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	frame = append(frame, hdr[:]...)
	frame = append(frame, body...)
	var crc [4]byte
	binary.BigEndian.PutUint32(crc[:], crc32.ChecksumIEEE(body))
	frame = append(frame, crc[:]...)
	return frame
}

// An untrusted header at the trusted height with a different root saves
// successfully but never replaces the accepted trusted coverage: the accepted
// root stays 0xaaa (a later trusted 0xbbb still conflicts), coverage stays at
// height 100, and the state directory keeps working.
func TestCLIUntrustedSameHeightDifferentRootKeepsCoverage(t *testing.T) {
	state := t.TempDir()
	registerSource(t, state, "chain-a")
	if r := storeHeader(t, state, "chain-a", 100, "0xaaa", true); r.code != 0 {
		t.Fatalf("initial trusted header: %v", r)
	}

	untrusted := storeHeader(t, state, "chain-a", 100, "0xbbb", false)
	if untrusted.code != 0 || untrusted.stdout != wantStoredHeader("chain-a", 100, false) {
		t.Fatalf("untrusted same-height header with a different root must save: code=%d stdout=%q stderr=%q",
			untrusted.code, untrusted.stdout, untrusted.stderr)
	}

	// The untrusted write did not become the accepted root: a trusted 0xbbb at
	// the same height still conflicts against the accepted 0xaaa.
	assertHeaderConflict(t, storeHeader(t, state, "chain-a", 100, "0xbbb", true),
		"chain-a", 100, "0xbbb", "0xaaa")
	if r := storeHeader(t, state, "chain-a", 100, "0xaaa", true); r.code != 0 {
		t.Fatalf("accepted trusted root must remain idempotent: code=%d stderr=%q", r.code, r.stderr)
	}

	// Coverage and normal queue operation are intact.
	submitMsg(t, state, "m100", "chain-a", "chain-b", 1, 100)
	rep := advanceCLI(t, state, 1_700_000_000_000)
	delivered := resultFor(t, rep, "m100")
	if want := "delivered; proof verified by trusted header at height 100"; delivered.Status != "success" || delivered.Reason != want {
		t.Fatalf("covered message must deliver via trusted height 100: %+v", delivered)
	}
	submitMsg(t, state, "m101", "chain-a", "chain-b", 2, 101)
	rep = advanceCLI(t, state, 1_700_000_100_000)
	waiting := resultFor(t, rep, "m101")
	if waiting.Status != "waiting" || waiting.Reason != "waiting for trusted header covering height 101 (current 100)" {
		t.Fatalf("untrusted header must not widen trusted coverage: %+v", waiting)
	}
}
