package relayproof

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// These tests pin down the consolidation of message-state recovery: a plain
// result entry (kindResult) and a compacted snapshot entry (kindState) must
// judge the same message status with the same rules — waiting schedule,
// nonce consumption and terminal field hygiene — while keeping their own
// acceptance conditions (results are incremental: non-terminal target,
// attempts exactly +1, no backwards processing time; snapshots are full
// current states after >=1 attempts and may restore a larger attempt count
// directly, but never twice for one message). Corrupt opens must still fail
// with ErrCorrupt, leave queue.log byte-for-byte untouched, and keep the
// record category ("result"/"state"/"entry"), the message id and the reason
// recognizable in the error text.

// waitingRecoveryBase is the entries before a waiting status record: a
// registered but header-less source and one pending message.
func waitingRecoveryBase() []*logEntry {
	return []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindSubmit, Seq: 0, ID: "w", From: "a", To: "b", Nonce: 7, ProofAt: 100},
	}
}

// waitingRecoveryRecord is a valid waiting status record at now=1000 with one
// attempt, retry at 2000. Callers mutate copies.
func waitingRecoveryRecord(kind string) *logEntry {
	return &logEntry{
		T: kind, Now: 1000, ID: "w", Status: StatusWaiting,
		Reason:   "waiting for trusted header covering height 100 (current 0)",
		Attempts: 1, NextRetry: 2000,
	}
}

// successRecoveryBase is the entries before a success status record: a
// registered source with a header covering the proof height and one pending
// message.
func successRecoveryBase() []*logEntry {
	return []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
		{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
	}
}

// successRecoveryRecord is a valid success record consuming its own triple.
func successRecoveryRecord(kind string) *logEntry {
	return &logEntry{
		T: kind, Now: 1000, ID: "m", Status: StatusSuccess,
		Reason:   "delivered; proof verified by trusted header at height 100",
		Attempts: 1, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m",
	}
}

// terminalRecoveryBase is one pending message "t" that a terminal record
// settles as replay.
func terminalRecoveryBase() []*logEntry {
	return []*logEntry{
		{T: kindSource, Chain: "a"},
		{T: kindSubmit, Seq: 0, ID: "t", From: "a", To: "b", Nonce: 1, ProofAt: 10},
	}
}

func terminalRecoveryRecord(kind string) *logEntry {
	return &logEntry{
		T: kind, Now: 1000, ID: "t", Status: StatusReplay,
		Reason: "nonce combination already consumed by message z", Attempts: 1,
	}
}

// assertRecoveryCorrupt writes the entries as a V1 log, requires Open to fail
// with ErrCorrupt and no usable queue, requires every wanted substring to
// appear in the error, and requires the log bytes to stay untouched.
func assertRecoveryCorrupt(t *testing.T, entries []*logEntry, want ...string) {
	t.Helper()
	dir := t.TempDir()
	path := writeLegacyLog(t, dir, entries...)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	q, err := Open(dir)
	if !errors.Is(err, ErrCorrupt) {
		if q != nil {
			q.Close()
		}
		t.Fatalf("want ErrCorrupt, got %v (queue=%v)", err, q != nil)
	}
	if q != nil {
		q.Close()
		t.Fatalf("corrupt open must not return a usable queue")
	}
	msg := err.Error()
	for _, w := range want {
		if !strings.Contains(msg, w) {
			t.Fatalf("error %q does not identify %q", msg, w)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("corrupt log was modified: %d -> %d bytes", len(before), len(after))
	}
}

// TestSharedRecoveryRulesRejectSameShapes verifies that every per-status rule
// rejects a result entry and a compacted state entry identically: the same
// bad shape is corrupt either way, and the error keeps the category and the
// message id recognizable.
func TestSharedRecoveryRulesRejectSameShapes(t *testing.T) {
	cases := []struct {
		name    string
		entries func(kind string) []*logEntry
		want    func(label, successNoun string) []string
	}{
		{
			name: "unknown status",
			entries: func(kind string) []*logEntry {
				r := waitingRecoveryRecord(kind)
				r.Status = "bogus"
				return append(waitingRecoveryBase(), r)
			},
			want: func(label, _ string) []string {
				return []string{fmt.Sprintf("bad %s status", label), `"bogus"`, `"w"`}
			},
		},
		{
			name: "pending status",
			entries: func(kind string) []*logEntry {
				r := waitingRecoveryRecord(kind)
				r.Status = StatusPending
				return append(waitingRecoveryBase(), r)
			},
			want: func(label, _ string) []string {
				return []string{fmt.Sprintf("bad %s status", label), StatusPending, `"w"`}
			},
		},
		{
			name: "waiting wrong retry schedule",
			entries: func(kind string) []*logEntry {
				r := waitingRecoveryRecord(kind)
				r.NextRetry = 4242
				return append(waitingRecoveryBase(), r)
			},
			want: func(label, _ string) []string {
				return []string{fmt.Sprintf("waiting %s has wrong retry schedule", label), `"w"`}
			},
		},
		{
			name: "waiting carries nonce consumption",
			entries: func(kind string) []*logEntry {
				r := waitingRecoveryRecord(kind)
				r.ConsumeBy = "w"
				return append(waitingRecoveryBase(), r)
			},
			want: func(label, _ string) []string {
				return []string{fmt.Sprintf("waiting %s", label), "carries nonce consumption fields", `"w"`}
			},
		},
		{
			name: "success carries retry time",
			entries: func(kind string) []*logEntry {
				r := successRecoveryRecord(kind)
				r.NextRetry = 7
				return append(successRecoveryBase(), r)
			},
			want: func(_, successNoun string) []string {
				return []string{fmt.Sprintf("success %s for %q carries retry time", successNoun, "m")}
			},
		},
		{
			name: "success without nonce consumption",
			entries: func(kind string) []*logEntry {
				r := successRecoveryRecord(kind)
				r.ConsumeFrom, r.ConsumeTo, r.ConsumeNonce = "", "", 0
				return append(successRecoveryBase(), r)
			},
			want: func(_, _ string) []string {
				return []string{"success entry", "carries no nonce consumption", `"m"`}
			},
		},
		{
			name: "success mismatched triple",
			entries: func(kind string) []*logEntry {
				r := successRecoveryRecord(kind)
				r.ConsumeNonce = 9
				return append(successRecoveryBase(), r)
			},
			want: func(_, _ string) []string {
				return []string{"success entry", "mismatched nonce consumption", `"m"`}
			},
		},
		{
			name: "success attributed to another message",
			entries: func(kind string) []*logEntry {
				r := successRecoveryRecord(kind)
				r.ConsumeBy = "x"
				return append(successRecoveryBase(), r)
			},
			want: func(_, _ string) []string {
				return []string{"success entry", "marked consumed by", `"x"`, `"m"`}
			},
		},
		{
			name: "same triple consumed twice",
			entries: func(kind string) []*logEntry {
				base := []*logEntry{
					{T: kindSource, Chain: "a"},
					{T: kindHeader, Chain: "a", Height: 100, Root: "0x100", Trusted: true},
					{T: kindSubmit, Seq: 0, ID: "m", From: "a", To: "b", Nonce: 1, ProofAt: 10},
					{T: kindSubmit, Seq: 1, ID: "n", From: "a", To: "b", Nonce: 1, ProofAt: 10},
				}
				first := &logEntry{
					T: kind, Now: 1000, ID: "m", Status: StatusSuccess, Reason: "ok", Attempts: 1,
					ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m",
				}
				second := &logEntry{
					T: kind, Now: 1000, ID: "n", Status: StatusSuccess, Reason: "ok", Attempts: 1,
					ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "n",
				}
				return append(base, first, second)
			},
			want: func(_, _ string) []string {
				return []string{"already consumed by", `"m"`, `"n"`}
			},
		},
		{
			name: "terminal carries retry time",
			entries: func(kind string) []*logEntry {
				r := terminalRecoveryRecord(kind)
				r.NextRetry = 9
				return append(terminalRecoveryBase(), r)
			},
			want: func(_, successNoun string) []string {
				return []string{fmt.Sprintf("terminal %s for %q carries scheduling/consume fields", successNoun, "t")}
			},
		},
		{
			name: "terminal carries consumption",
			entries: func(kind string) []*logEntry {
				r := terminalRecoveryRecord(kind)
				r.ConsumeNonce = 1
				return append(terminalRecoveryBase(), r)
			},
			want: func(_, successNoun string) []string {
				return []string{fmt.Sprintf("terminal %s for %q carries scheduling/consume fields", successNoun, "t")}
			},
		},
	}

	for _, kind := range []struct {
		t           string
		label       string
		successNoun string
	}{
		{kindResult, "result", "entry"},
		{kindState, "state", "state"},
	} {
		for _, tc := range cases {
			name := kind.t + "/" + tc.name
			t.Run(name, func(t *testing.T) {
				assertRecoveryCorrupt(t, tc.entries(kind.t), tc.want(kind.label, kind.successNoun)...)
			})
		}
	}
}

// Plain result records stay incremental: unknown/terminal targets, attempts
// jumps and backwards processing times are all rejected, with the result
// category and id named.
func TestResultSpecificAcceptance(t *testing.T) {
	t.Run("unknown id", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindResult, Now: 1000, ID: "ghost", Status: StatusExpired, Reason: "x", Attempts: 1},
		}
		assertRecoveryCorrupt(t, entries, "result for unknown id", `"ghost"`)
	})

	t.Run("terminal id", func(t *testing.T) {
		entries := append(successRecoveryBase(), successRecoveryRecord(kindResult))
		again := &logEntry{
			T: kindResult, Now: 2000, ID: "m", Status: StatusExpired, Reason: "later", Attempts: 2,
		}
		entries = append(entries, again)
		assertRecoveryCorrupt(t, entries, "result for terminal id", `"m"`)
	})

	t.Run("attempts must advance by one", func(t *testing.T) {
		r := waitingRecoveryRecord(kindResult)
		r.Attempts = 3 // pending record has zero attempts; the jump 0 -> 3 is invalid
		r.NextRetry = 5000
		entries := append(waitingRecoveryBase(), r)
		assertRecoveryCorrupt(t, entries, "attempts jump 0 -> 3", `"w"`)
	})

	t.Run("processing time must not move backwards", func(t *testing.T) {
		first := waitingRecoveryRecord(kindResult)
		first.Now, first.NextRetry = 2000, 3000
		second := waitingRecoveryRecord(kindResult)
		second.Now, second.Attempts, second.NextRetry = 1000, 2, 3000
		entries := append(waitingRecoveryBase(), first, second)
		assertRecoveryCorrupt(t, entries, "result time 1000 before prior time 2000", `"w"`)
	})
}

// Compacted snapshot records keep their own acceptance: unknown target and a
// repeated snapshot are rejected, zero attempts are rejected, but a snapshot
// may restore an attempt count greater than one directly.
func TestStateSpecificAcceptance(t *testing.T) {
	t.Run("unknown id", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindState, Now: 1000, ID: "ghost", Status: StatusExpired, Reason: "x", Attempts: 1},
		}
		assertRecoveryCorrupt(t, entries, "state for unknown id", `"ghost"`)
	})

	t.Run("duplicate snapshot", func(t *testing.T) {
		entries := append(waitingRecoveryBase(), waitingRecoveryRecord(kindState))
		entries = append(entries, waitingRecoveryRecord(kindState))
		assertRecoveryCorrupt(t, entries, "duplicate state for id", `"w"`)
	})

	t.Run("zero attempts", func(t *testing.T) {
		r := terminalRecoveryRecord(kindState)
		r.Attempts = 0
		entries := append(terminalRecoveryBase(), r)
		assertRecoveryCorrupt(t, entries, "state with zero attempts", `"t"`)
	})
}

// A snapshot may restore the full current status after more than one attempt,
// for both waiting and successful messages; the restored record then behaves
// exactly like one that had gone through those attempts live.
func TestStateRestoresMultiAttemptStatus(t *testing.T) {
	t.Run("waiting after three attempts", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(waitingRecoveryBase(),
			&logEntry{
				T: kindState, Now: 2000, ID: "w", Status: StatusWaiting,
				Reason:   "waiting for trusted header covering height 100 (current 0)",
				Attempts: 3, NextRetry: 6000,
			},
			&logEntry{T: kindAdvance, Now: 2000},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("multi-attempt waiting snapshot must open: %v", err)
		}
		r := statusOf(t, q, "w")
		if r.Status != StatusWaiting || r.Attempts != 3 || r.NextRetry != 6000 {
			t.Fatalf("snapshot not restored: %+v", r)
		}
		if q.Now() != 2000 || len(q.order) != 1 || q.order[0] != "w" {
			t.Fatalf("time/order not restored: now=%d order=%v", q.Now(), q.order)
		}
		// At the scheduled retry the message takes exactly one more attempt;
		// the fourth backoff interval is 8s, so the next retry is 14000.
		if _, err := q.Advance(6000); err != nil {
			t.Fatal(err)
		}
		r = statusOf(t, q, "w")
		if r.Status != StatusWaiting || r.Attempts != 4 || r.NextRetry != 14000 {
			t.Fatalf("restored waiting record did not continue normally: %+v", r)
		}
		if err := q.Close(); err != nil {
			t.Fatal(err)
		}
		q2, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer q2.Close()
		if r := statusOf(t, q2, "w"); r.Attempts != 4 || r.NextRetry != 14000 || r.Status != StatusWaiting {
			t.Fatalf("advanced state lost on reopen: %+v", r)
		}
	})

	t.Run("success after five attempts", func(t *testing.T) {
		dir := t.TempDir()
		entries := append(successRecoveryBase(),
			&logEntry{
				T: kindState, Now: 4000, ID: "m", Status: StatusSuccess,
				Reason:   "delivered; proof verified by trusted header at height 100",
				Attempts: 5, ConsumeFrom: "a", ConsumeTo: "b", ConsumeNonce: 1, ConsumeBy: "m",
			},
			&logEntry{T: kindAdvance, Now: 4000},
		)
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("multi-attempt success snapshot must open: %v", err)
		}
		defer q.Close()
		r := statusOf(t, q, "m")
		if r.Status != StatusSuccess || r.Attempts != 5 || r.NextRetry != 0 {
			t.Fatalf("success snapshot not restored: %+v", r)
		}
		if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m" {
			t.Fatalf("consumption not restored and attributed to m: %q", winner)
		}
		// The consumed triple keeps replaying for new ids after restore.
		if _, err := q.Submit(env("d", "a", "b", 1, 10, 0)); err != nil {
			t.Fatal(err)
		}
		rep, err := q.Advance(5000)
		if err != nil {
			t.Fatal(err)
		}
		res, ok := resultFor(rep, "d")
		if !ok || res.Status != StatusReplay || !strings.Contains(res.Reason, "m") {
			t.Fatalf("restored consumption must keep replaying: %+v", rep.Results)
		}
	})

	t.Run("terminal statuses restored", func(t *testing.T) {
		dir := t.TempDir()
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindSubmit, Seq: 0, ID: "r", From: "a", To: "b", Nonce: 1, ProofAt: 10},
			{T: kindState, Now: 1000, ID: "r", Status: StatusReplay,
				Reason: "nonce combination already consumed by message z", Attempts: 2},
			{T: kindSubmit, Seq: 1, ID: "x", From: "a", To: "b", Nonce: 2, ProofAt: 10, ExpiresAt: 1000},
			{T: kindState, Now: 1000, ID: "x", Status: StatusExpired,
				Reason: "expired at 1000", Attempts: 1},
			{T: kindSubmit, Seq: 2, ID: "u", From: "mars", To: "b", Nonce: 3, ProofAt: 10},
			{T: kindState, Now: 1000, ID: "u", Status: StatusUnknownSrc,
				Reason: "unknown source chain mars", Attempts: 1},
			{T: kindAdvance, Now: 1000},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("terminal snapshots must open: %v", err)
		}
		defer q.Close()
		want := map[string]string{"r": StatusReplay, "x": StatusExpired, "u": StatusUnknownSrc}
		for id, st := range want {
			if r := statusOf(t, q, id); r.Status != st || r.NextRetry != 0 {
				t.Fatalf("%s snapshot not restored as %s: %+v", id, st, r)
			}
		}
		if r := statusOf(t, q, "r"); r.Attempts != 2 || !strings.Contains(r.Reason, "message z") {
			t.Fatalf("replay attempts/reason not restored: %+v", r)
		}
		if len(q.order) != 0 {
			t.Fatalf("all snapshot records are terminal, order must be empty: %v", q.order)
		}
		all := q.Queries()
		if len(all) != 3 || all[0].ID != "r" || all[1].ID != "x" || all[2].ID != "u" {
			t.Fatalf("submission order not preserved: %+v", all)
		}
	})
}

// The shared waiting-schedule rule treats a compacted snapshot exactly like a
// plain result near the ceiling: only the exact legacy additive-overflow
// value is accepted and repaired to the ceiling in memory; any other wrong
// time is corrupt.
func TestStateWaitingScheduleCeilingParity(t *testing.T) {
	t.Run("legacy overflow repaired", func(t *testing.T) {
		dir := t.TempDir()
		wrapped := ceiling + nextRetryDelay(2) // old build: raw now+delay
		if wrapped >= 0 {
			t.Fatalf("test setup: expected negative wrapped value, got %d", wrapped)
		}
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindSubmit, Seq: 0, ID: "w", From: "a", To: "b", Nonce: 7, ProofAt: 100},
			{T: kindState, Now: ceiling, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 2, NextRetry: wrapped},
			{T: kindAdvance, Now: ceiling},
		}
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("legacy overflowed state schedule must open and repair: %v", err)
		}
		defer q.Close()
		if r := statusOf(t, q, "w"); r.Status != StatusWaiting || r.Attempts != 2 || r.NextRetry != ceiling {
			t.Fatalf("overflowed state schedule not repaired to ceiling: %+v", r)
		}
	})

	t.Run("arbitrary wrong time rejected", func(t *testing.T) {
		entries := []*logEntry{
			{T: kindSource, Chain: "a"},
			{T: kindSubmit, Seq: 0, ID: "w", From: "a", To: "b", Nonce: 7, ProofAt: 100},
			{T: kindState, Now: ceiling, ID: "w", Status: StatusWaiting,
				Reason: "waiting", Attempts: 2, NextRetry: ceiling - 1},
		}
		assertRecoveryCorrupt(t, entries, "waiting state has wrong retry schedule", `"w"`)
	})
}

// Successful recovery leaves the on-disk log untouched and a legitimate
// historical directory needs no conversion before further use: a plain-result
// log and a compacted log both reopen, preserve content/status/reason/
// attempts/retry, and accept new operations afterwards.
func TestBothKindsReopenWithoutConversion(t *testing.T) {
	for _, kind := range []string{kindResult, kindState} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			waiting := &logEntry{
				T: kind, Now: 1000, ID: "w", Status: StatusWaiting,
				Reason:   "waiting for trusted header covering height 100 (current 0)",
				Attempts: 1, NextRetry: 2000,
			}
			entries := append(waitingRecoveryBase(), waiting, &logEntry{T: kindAdvance, Now: 1000})
			path := writeLegacyLog(t, dir, entries...)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			q, err := Open(dir)
			if err != nil {
				t.Fatalf("legitimate %s log must open without conversion: %v", kind, err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("opening a good %s log rewrote it", kind)
			}
			r := statusOf(t, q, "w")
			if r.Status != StatusWaiting || r.Attempts != 1 || r.NextRetry != 2000 ||
				!strings.Contains(r.Reason, "height 100") {
				t.Fatalf("recovered record mismatch: %+v", r)
			}
			// Continuing without any migration step.
			if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
				t.Fatal(err)
			}
			if _, err := q.Advance(2000); err != nil {
				t.Fatal(err)
			}
			if r := statusOf(t, q, "w"); r.Status != StatusSuccess || r.Attempts != 2 {
				t.Fatalf("recovered message did not deliver on retry: %+v", r)
			}
			if winner := q.consumed[newConsumeToken("a", "b", 7)]; winner != "w" {
				t.Fatalf("success not attributed to w after recovery: %q", winner)
			}
			q.Close()
		})
	}
}

// Guard against the helper itself drifting: the good fixtures must open.
func TestRecoveryFixturesAreValid(t *testing.T) {
	for _, kind := range []string{kindResult, kindState} {
		dir := t.TempDir()
		entries := append(successRecoveryBase(), successRecoveryRecord(kind))
		entries = append(entries, &logEntry{T: kindAdvance, Now: 1000})
		writeLegacyLog(t, dir, entries...)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("valid %s success fixture must open: %v", kind, err)
		}
		if r := statusOf(t, q, "m"); r.Status != StatusSuccess || r.Attempts != 1 {
			t.Fatalf("valid %s fixture restored wrong: %+v", kind, r)
		}
		q.Close()

		dir2 := t.TempDir()
		entries2 := append(terminalRecoveryBase(), terminalRecoveryRecord(kind))
		writeLegacyLog(t, dir2, entries2...)
		q2, err := Open(dir2)
		if err != nil {
			t.Fatalf("valid %s terminal fixture must open: %v", kind, err)
		}
		if r := statusOf(t, q2, "t"); r.Status != StatusReplay || r.Attempts != 1 {
			t.Fatalf("valid %s terminal fixture restored wrong: %+v", kind, r)
		}
		q2.Close()
	}
}
