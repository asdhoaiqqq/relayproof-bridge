package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These tests pin the command-line observable behaviour of saving headers,
// going through the same stderr/exit-code translation a real user hits (the
// queue-level conflict judgement itself is covered in relayproof tests). A
// rejected trusted header must surface as the dedicated conflict category with
// exit code 16, never as a silent success or a generic failure; the accepted
// trusted header, the state directory and every waiting record must stay
// exactly as they were.

var cliBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "relayproof-cli-build-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cliBin = filepath.Join(dir, "relayproof")
	build := exec.Command("go", "build", "-o", cliBin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build relayproof CLI: %v\n%s\n", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// runCLI invokes the built binary, capturing stdout and stderr separately, and
// returns the process exit code (0 on success).
func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(cliBin, args...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errBuf.String(), code
}

func assertContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("output %q must contain %q", got, want)
	}
}

func assertNotContains(t *testing.T, got, unwanted string) {
	t.Helper()
	if strings.Contains(got, unwanted) {
		t.Fatalf("output %q must not contain %q", got, unwanted)
	}
}

func headerArgs(dir, chain string, height int64, root string, trusted bool) []string {
	args := []string{
		"queue", "header", "--state", dir,
		"--chain", chain, "--height", strconv.FormatInt(height, 10), "--root", root,
	}
	if trusted {
		args = append(args, "--trusted")
	}
	return args
}

func registerSource(t *testing.T, dir, chain string) {
	t.Helper()
	out, stderr, code := runCLI(t, "queue", "register-source", "--state", dir, "--chain", chain)
	if code != 0 {
		t.Fatalf("register-source exit=%d stderr=%q", code, stderr)
	}
	assertContains(t, out, "registered source chain "+chain)
}

func submitMsg(t *testing.T, dir, id, from, to string, nonce uint64, proofAt int64) cliRecord {
	t.Helper()
	out, stderr, code := runCLI(t, "queue", "submit", "--state", dir,
		"--id", id, "--from", from, "--to", to,
		"--nonce", strconv.FormatUint(nonce, 10),
		"--proof-at", strconv.FormatInt(proofAt, 10),
		"--payload", "p-"+id, "--expires-at", "9000000000000")
	if code != 0 {
		t.Fatalf("submit %s exit=%d stderr=%q", id, code, stderr)
	}
	return decodeJSON[cliRecord](t, out)
}

func advance(t *testing.T, dir string, now int64) cliAdvance {
	t.Helper()
	out, stderr, code := runCLI(t, "queue", "advance", "--state", dir,
		"--now", strconv.FormatInt(now, 10))
	if code != 0 {
		t.Fatalf("advance exit=%d stderr=%q", code, stderr)
	}
	return decodeJSON[cliAdvance](t, out)
}

func queryID(t *testing.T, dir, id string) cliQuery {
	t.Helper()
	out, stderr, code := runCLI(t, "queue", "query", "--state", dir, "--id", id)
	if code != 0 {
		t.Fatalf("query %s exit=%d stderr=%q", id, code, stderr)
	}
	return decodeJSON[cliQuery](t, out)
}

func decodeJSON[T any](t *testing.T, s string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &v); err != nil {
		t.Fatalf("decode JSON %q: %v", s, err)
	}
	return v
}

type cliRecord struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
	Attempts int    `json:"attempts"`
}

type cliQuery struct {
	ID        string `json:"id"`
	ProofAt   int64  `json:"proofAtHeight"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Attempts  int    `json:"attempts"`
	NextRetry int64  `json:"nextRetryMs"`
}

type cliAdvance struct {
	NowMs   int64 `json:"nowMs"`
	Results []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	} `json:"results"`
}

func (r cliAdvance) result(id string) (struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}, bool) {
	for _, res := range r.Results {
		if res.ID == id {
			return res, true
		}
	}
	return struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	}{}, false
}

// TestCLITrustedHeaderConflictExit16 pins the full conflict timeline as seen
// on the command line:
//
//   - a second trusted header at the accepted height with a different root ends
//     with exit code 16, stderr names the trusted-header-conflict category and
//     shows the source chain, the height, the submitted root and the accepted
//     root, while stdout carries no success message;
//   - resubmitting the original height/root is accepted with exit code 0 and
//     the same success output as the original save;
//   - the conflict neither replaces the accepted trusted header nor breaks the
//     state directory: a proof-at-90 message delivers citing trusted height
//     100, while a proof-at-101 message keeps waiting for a trusted header;
//   - saving a header (rejected or accepted) processes no messages: the
//     waiting record's status, reason, attempt count and next-retry instant are
//     byte-for-byte unchanged;
//   - a same-height different-root UNtrusted header saves successfully but
//     cannot replace the trusted coverage (proof 101 still waits).
func TestCLITrustedHeaderConflictExit16(t *testing.T) {
	dir := t.TempDir()
	const chain = "chain-a"
	const storedLine = "stored header chain=chain-a height=100 trusted=true\n"

	registerSource(t, dir, chain)

	// Accepted trusted header at height 100 with root 0xaaa.
	out, stderr, code := runCLI(t, headerArgs(dir, chain, 100, "0xaaa", true)...)
	if code != 0 {
		t.Fatalf("initial trusted header exit=%d stderr=%q", code, stderr)
	}
	if out != storedLine {
		t.Fatalf("initial trusted header stdout=%q want %q", out, storedLine)
	}

	// Same height, different trusted root: dedicated conflict failure.
	conflictOut, conflictErr, code := runCLI(t, headerArgs(dir, chain, 100, "0xbbb", true)...)
	if code != 16 {
		t.Fatalf("conflicting trusted header exit=%d want 16; stderr=%q", code, conflictErr)
	}
	for _, want := range []string{
		"trusted header conflict",
		"chain " + strconv.Quote(chain),
		"height 100",
		`submitted root "0xbbb"`,
		`accepted root "0xaaa"`,
	} {
		assertContains(t, conflictErr, want)
	}
	// A rejected save must not look successful on stdout.
	if conflictOut != "" {
		t.Fatalf("conflicting header must print nothing to stdout, got %q", conflictOut)
	}
	assertNotContains(t, conflictOut, "stored header")

	// Original height and root again: idempotent acceptance with the same
	// observable result as the first successful save.
	out, stderr, code = runCLI(t, headerArgs(dir, chain, 100, "0xaaa", true)...)
	if code != 0 {
		t.Fatalf("idempotent same-root header exit=%d stderr=%q", code, stderr)
	}
	if out != storedLine {
		t.Fatalf("same-root resave stdout=%q want %q", out, storedLine)
	}

	// The accepted trusted header is still in force and the directory is
	// usable: proof height 90 is covered by the trusted header at 100.
	rec := submitMsg(t, dir, "m90", chain, "chain-b", 1, 90)
	if rec.Status != "pending" {
		t.Fatalf("m90 submit status=%q want pending", rec.Status)
	}
	rep := advance(t, dir, 1_700_000_000_000)
	res, ok := rep.result("m90")
	if !ok {
		t.Fatalf("advance result missing m90: %+v", rep)
	}
	if res.Status != "success" {
		t.Fatalf("m90 status=%q want success (%s)", res.Status, res.Reason)
	}
	assertContains(t, res.Reason, "trusted header at height 100")
	if strings.Contains(res.Reason, "0xbbb") {
		t.Fatalf("success reason must not cite the rejected root: %q", res.Reason)
	}

	// Proof height 101 is beyond the accepted trusted height and must wait;
	// the rejected 0xbbb header must not have let it through.
	submitMsg(t, dir, "m101", chain, "chain-b", 2, 101)
	rep = advance(t, dir, 1_700_000_100_000)
	res, ok = rep.result("m101")
	if !ok {
		t.Fatalf("advance result missing m101: %+v", rep)
	}
	if res.Status != "waiting" {
		t.Fatalf("m101 status=%q want waiting", res.Status)
	}
	const waitingReason = "waiting for trusted header covering height 101 (current 100)"
	if res.Reason != waitingReason {
		t.Fatalf("m101 reason=%q want %q", res.Reason, waitingReason)
	}

	before := queryID(t, dir, "m101")
	if before.Status != "waiting" || before.Attempts != 1 || before.NextRetry != 1_700_000_101_000 {
		t.Fatalf("m101 baseline = %+v, want waiting attempts=1 nextRetry=1700000101000", before)
	}

	// A rejected header save processes no messages: the waiting record must be
	// unchanged in every observable field.
	_, conflictErr, code = runCLI(t, headerArgs(dir, chain, 100, "0xbbb", true)...)
	if code != 16 {
		t.Fatalf("repeat conflict exit=%d want 16 stderr=%q", code, conflictErr)
	}
	after := queryID(t, dir, "m101")
	if after != before {
		t.Fatalf("rejected header save altered waiting record:\n before=%+v\n after =%+v", before, after)
	}

	// A same-height different-root UNtrusted header saves with exit code 0 and
	// the normal success line...
	out, stderr, code = runCLI(t, headerArgs(dir, chain, 100, "0xccc", false)...)
	if code != 0 {
		t.Fatalf("untrusted header exit=%d stderr=%q", code, stderr)
	}
	if out != "stored header chain=chain-a height=100 trusted=false\n" {
		t.Fatalf("untrusted header stdout=%q", out)
	}
	// ...and saving it likewise processes nothing.
	if after = queryID(t, dir, "m101"); after != before {
		t.Fatalf("accepted untrusted header save altered waiting record:\n before=%+v\n after =%+v", before, after)
	}

	// When the retry falls due, the untrusted header must not have replaced the
	// trusted coverage: m101 is evaluated once more and still waits, with the
	// reason citing current trusted height 100.
	rep = advance(t, dir, 1_700_000_101_000)
	if res, ok = rep.result("m101"); !ok || res.Status != "waiting" || res.Reason != waitingReason {
		t.Fatalf("m101 after untrusted header: ok=%v result=%+v, want waiting (%q)", ok, res, waitingReason)
	}
	got := queryID(t, dir, "m101")
	if got.Attempts != 2 || got.NextRetry != 1_700_000_103_000 {
		t.Fatalf("m101 after retry = %+v, want attempts=2 nextRetry=1700000103000", got)
	}
}

// TestCLIHeaderRootByteComparison pins the root-comparison edges at the CLI
// boundary: roots compare as submitted byte strings (no trimming, no case
// folding), empty roots are legal and idempotent, and only the trusted vs
// trusted same-height combination is a conflict.
func TestCLIHeaderRootByteComparison(t *testing.T) {
	const height = int64(7)

	type save struct {
		root    string
		trusted bool
	}
	cases := map[string]struct {
		saves        []save
		wantCode     int
		wantStderr   []string
		wantStdoutOK bool // last save prints the normal stored-header line
	}{
		"two empty roots are idempotent": {
			saves:        []save{{"", true}, {"", true}},
			wantCode:     0,
			wantStdoutOK: true,
		},
		"empty accepted root vs non-empty submitted root": {
			saves:      []save{{"", true}, {"other", true}},
			wantCode:   16,
			wantStderr: []string{"trusted header conflict", `submitted root "other"`, `accepted root ""`},
		},
		"non-empty accepted root vs empty submitted root": {
			saves:      []save{{"0xaaa", true}, {"", true}},
			wantCode:   16,
			wantStderr: []string{"trusted header conflict", `submitted root ""`, `accepted root "0xaaa"`},
		},
		"roots are case sensitive": {
			saves:      []save{{"0xaaa", true}, {"0xAAA", true}},
			wantCode:   16,
			wantStderr: []string{`submitted root "0xAAA"`, `accepted root "0xaaa"`},
		},
		"roots keep surrounding whitespace byte for byte": {
			saves:      []save{{"0xaaa", true}, {" 0xaaa ", true}},
			wantCode:   16,
			wantStderr: []string{`submitted root " 0xaaa "`, `accepted root "0xaaa"`},
		},
		"same-height different-root untrusted header saves": {
			saves:        []save{{"0xaaa", true}, {"0xbbb", false}},
			wantCode:     0,
			wantStdoutOK: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			registerSource(t, dir, "edge-chain")

			var out, stderr string
			var code int
			for i, s := range tc.saves {
				out, stderr, code = runCLI(t, headerArgs(dir, "edge-chain", height, s.root, s.trusted)...)
				if i < len(tc.saves)-1 && code != 0 {
					t.Fatalf("setup save %d (%+v) exit=%d stderr=%q", i, s, code, stderr)
				}
			}
			if code != tc.wantCode {
				t.Fatalf("final save exit=%d want %d stderr=%q", code, tc.wantCode, stderr)
			}
			for _, want := range tc.wantStderr {
				assertContains(t, stderr, want)
			}
			if tc.wantCode == 16 {
				assertNotContains(t, out, "stored header")
				if !strings.Contains(stderr, "edge-chain") || !strings.Contains(stderr, "height 7") {
					t.Fatalf("conflict stderr must name chain and height: %q", stderr)
				}
			}
			if tc.wantStdoutOK {
				last := tc.saves[len(tc.saves)-1]
				wantLine := fmt.Sprintf("stored header chain=edge-chain height=%d trusted=%t\n", height, last.trusted)
				if out != wantLine {
					t.Fatalf("stdout=%q want %q", out, wantLine)
				}
			}
		})
	}
}

// TestCLIConflictKeepsTrustedCoverageForNewMessages verifies on disk (fresh
// process per command) that after a conflict the accepted root is what
// persists: reopening the state directory for a later command still covers
// proof-at-100 with root 0xaaa, and a higher proof cannot be delivered until a
// genuinely higher trusted header arrives.
func TestCLIConflictKeepsTrustedCoverageForNewMessages(t *testing.T) {
	dir := t.TempDir()
	const chain = "chain-a"
	registerSource(t, dir, chain)

	if _, stderr, code := runCLI(t, headerArgs(dir, chain, 100, "0xaaa", true)...); code != 0 {
		t.Fatalf("initial header exit=%d stderr=%q", code, stderr)
	}
	if _, stderr, code := runCLI(t, headerArgs(dir, chain, 100, "0xbbb", true)...); code != 16 {
		t.Fatalf("conflict exit=%d want 16 stderr=%q", code, stderr)
	}

	// New process, same state directory: proof 100 delivers and cites 0xaaa's
	// height; proof 101 waits.
	submitMsg(t, dir, "cov100", chain, "chain-b", 1, 100)
	rep := advance(t, dir, 1_700_000_000_000)
	res, ok := rep.result("cov100")
	if !ok || res.Status != "success" {
		t.Fatalf("proof-100 delivery after reopen: ok=%v res=%+v", ok, res)
	}
	assertContains(t, res.Reason, "trusted header at height 100")

	submitMsg(t, dir, "cov101", chain, "chain-b", 2, 101)
	rep = advance(t, dir, 1_700_000_100_000)
	res, ok = rep.result("cov101")
	if !ok || res.Status != "waiting" {
		t.Fatalf("proof-101 must wait after conflict: ok=%v res=%+v", ok, res)
	}
	assertContains(t, res.Reason, "covering height 101 (current 100)")

	// A genuinely higher trusted header (new root, higher height) finally
	// extends coverage; the conflict left no residue blocking it.
	if _, stderr, code := runCLI(t, headerArgs(dir, chain, 120, "0xddd", true)...); code != 0 {
		t.Fatalf("higher trusted header exit=%d stderr=%q", code, stderr)
	}
	rep = advance(t, dir, 1_700_000_101_000)
	res, ok = rep.result("cov101")
	if !ok || res.Status != "success" {
		t.Fatalf("proof-101 must deliver once trusted height advances: ok=%v res=%+v", ok, res)
	}
	assertContains(t, res.Reason, "trusted header at height 120")
}
