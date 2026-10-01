package relayproof

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func openTempQueue(t *testing.T) (*Queue, string) {
	t.Helper()
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return q, dir
}

func env(id, from, to string, nonce uint64, proofAt, expiresAt int64) Envelope {
	return Envelope{
		Message:   Message{ID: id, From: from, To: to, Nonce: nonce, Payload: "p-" + id, ProofAt: proofAt},
		ExpiresAt: expiresAt,
	}
}

func statusOf(t *testing.T, q *Queue, id string) Record {
	t.Helper()
	got, ok := q.Query(id)
	if !ok {
		t.Fatalf("missing record %s", id)
	}
	return Record{
		Msg:       Envelope{Message: Message{ID: got.ID, From: got.From, To: got.To, Nonce: got.Nonce, Payload: got.Payload, ProofAt: got.ProofAt}, ExpiresAt: got.ExpiresAt},
		Status:    got.Status,
		Reason:    got.Reason,
		NextRetry: got.NextRetry,
		Attempts:  got.Attempts,
	}
}

// End-to-end happy path: waiting until a trusted header covers the proof
// height, then delivery with nonce consumption.
func TestHappyPath(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()

	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("m1", "a", "b", 1, 100, 0)); err != nil {
		t.Fatal(err)
	}

	// First advance: registered but no header yet -> waiting, retry at +1s.
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Status != StatusWaiting {
		t.Fatalf("want one waiting result, got %+v", rep.Results)
	}
	r := statusOf(t, q, "m1")
	if r.Status != StatusWaiting || r.NextRetry != 2000 || r.Attempts != 1 {
		t.Fatalf("want waiting retry=2000 attempts=1, got %+v", r)
	}

	// Trusted header still short of proof height.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 99, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(2000); err != nil {
		t.Fatal(err)
	}
	r = statusOf(t, q, "m1")
	if r.Status != StatusWaiting || r.NextRetry != 4000 || r.Attempts != 2 {
		t.Fatalf("want still waiting retry=4000, got %+v", r)
	}

	// Header covering the proof height, but retry time must not be bypassed.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(3000); err != nil {
		t.Fatal(err)
	}
	r = statusOf(t, q, "m1")
	if r.Status != StatusWaiting || r.NextRetry != 4000 {
		t.Fatalf("header must not bypass retry schedule, got %+v", r)
	}

	rep, err = q.Advance(4000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Status != StatusSuccess {
		t.Fatalf("want success, got %+v", rep.Results)
	}
	r = statusOf(t, q, "m1")
	if r.Status != StatusSuccess || r.NextRetry != 0 {
		t.Fatalf("want terminal success without retry, got %+v", r)
	}
	if got := q.consumed[newConsumeToken("a", "b", 1)]; got != "m1" {
		t.Fatalf("nonce not consumed by m1: %q", got)
	}
}

// Untrusted headers keep the message waiting; a later trusted one unblocks.
func TestUntrustedThenTrustedHeader(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.Submit(env("m", "a", "b", 1, 10, 0))

	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: false})
	q.Advance(1000)
	if r := statusOf(t, q, "m"); r.Status != StatusWaiting {
		t.Fatalf("untrusted header: want waiting, got %s", r.Status)
	}
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
	q.Advance(2000)
	if r := statusOf(t, q, "m"); r.Status != StatusSuccess {
		t.Fatalf("trusted header: want success, got %s (%s)", r.Status, r.Reason)
	}
}

// Unknown source is permanently rejected on first processing.
func TestUnknownSource(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.Submit(env("m", "ghost", "b", 1, 10, 0))
	q.Advance(1000)
	r := statusOf(t, q, "m")
	if r.Status != StatusUnknownSrc {
		t.Fatalf("want unknown-source, got %s (%s)", r.Status, r.Reason)
	}
	if !strings.Contains(r.Reason, "ghost") {
		t.Fatalf("reason should name the chain, got %q", r.Reason)
	}
	// Registering the source later must not resurrect a terminal record.
	if err := q.RegisterSource("ghost"); err != nil {
		t.Fatal(err)
	}
	q.UpsertHeader(Header{Chain: "ghost", Height: 100, Trusted: true})
	if _, err := q.Advance(2000); err != nil {
		t.Fatal(err)
	}
	if r := statusOf(t, q, "m"); r.Status != StatusUnknownSrc {
		t.Fatalf("terminal record changed: %s", r.Status)
	}
}

// Submission idempotency, conflict, and terminal rejection.
func TestSubmitDedupConflictTerminal(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")

	e := env("m1", "a", "b", 1, 10, 0)
	if _, err := q.Submit(e); err != nil {
		t.Fatal(err)
	}
	before := len(q.order)
	if _, err := q.Submit(e); err != nil {
		t.Fatalf("identical resubmit must be idempotent: %v", err)
	}
	if len(q.order) != before || len(q.records) != 1 {
		t.Fatalf("identical resubmit added a queue entry")
	}

	diff := e
	diff.Message.Payload = "changed"
	if _, err := q.Submit(diff); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	if got := statusOf(t, q, "m1"); got.Msg.Message.Payload != "p-m1" {
		t.Fatalf("original record mutated by conflicting submit")
	}

	// Same id, same content after terminalization is still rejected.
	q.Advance(1000) // unknown? no, source a registered and no header -> waiting
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
	q.Advance(2000) // success
	if _, err := q.Submit(e); !errors.Is(err, ErrTerminal) {
		t.Fatalf("resubmit of terminal id must be ErrTerminal, got %v", err)
	}
	if _, err := q.Submit(diff); !errors.Is(err, ErrTerminal) {
		t.Fatalf("different content on terminal id must be ErrTerminal, got %v", err)
	}
}

// Different ids may share a nonce combination, but at most one succeeds; the
// loser is recorded as replay when it is processed.
func TestReplayAcrossMessages(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})

	q.Submit(env("win", "a", "b", 9, 10, 0))
	q.Submit(env("lose", "a", "b", 9, 10, 0))
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"win": StatusSuccess, "lose": StatusReplay}
	if len(rep.Results) != 2 {
		t.Fatalf("want 2 results, got %+v", rep.Results)
	}
	for _, res := range rep.Results {
		if res.Status != want[res.ID] {
			t.Fatalf("id %s want %s got %s", res.ID, want[res.ID], res.Status)
		}
	}
	if r := statusOf(t, q, "lose"); r.Status != StatusReplay ||
		!strings.Contains(r.Reason, "win") {
		t.Fatalf("replay reason should name winner, got %+v", r)
	}
}

// A waiting message is immediately marked replay once its nonce is consumed
// by another message, even while its own retry backoff is still running.
func TestReplayWhileWaitingBackoff(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")

	q.Submit(env("early", "a", "b", 5, 10, 0)) // no header yet
	q.Advance(1000)                            // waiting, retry 2000

	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
	q.Submit(env("later", "a", "b", 5, 10, 0))
	rep, err := q.Advance(1500) // before early's retry of 2000
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, res := range rep.Results {
		got[res.ID] = res.Status
	}
	if got["later"] != StatusSuccess {
		t.Fatalf("later should succeed, got %v", got)
	}
	if got["early"] != StatusReplay {
		t.Fatalf("early should be replay despite pending backoff, got %v", got)
	}
}

// Absolute expiry: exactly reaching the expiry instant is expired; replay
// takes precedence when both conditions hold.
func TestExpiryBoundary(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.Submit(env("m", "a", "b", 1, 10, 5000))

	q.Advance(4999) // no header -> waiting; not expired
	if r := statusOf(t, q, "m"); r.Status != StatusWaiting {
		t.Fatalf("want waiting at 4999, got %s", r.Status)
	}
	// Backoff would retry at 5999; at 5000 phase-2 expiry check terminalizes.
	q.Advance(5000)
	if r := statusOf(t, q, "m"); r.Status != StatusExpired {
		t.Fatalf("want expired exactly at 5000, got %s", r.Status)
	}
	if r := statusOf(t, q, "m"); r.NextRetry != 0 {
		t.Fatalf("terminal record must have no retry time")
	}
}

func TestReplayBeatsExpiry(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})

	q.Submit(env("win", "a", "b", 3, 10, 0))
	q.Submit(env("lose", "a", "b", 3, 10, 5000))
	q.Advance(5000) // lose is both replay and expired at the same instant
	if r := statusOf(t, q, "lose"); r.Status != StatusReplay {
		t.Fatalf("replay must win over expiry, got %s", r.Status)
	}
	if r := statusOf(t, q, "win"); r.Status != StatusSuccess {
		t.Fatalf("win must succeed, got %s", r.Status)
	}
}

// A not-yet-expired message with a covering trusted header can still succeed
// at its retry instant; one millisecond later it would expire.
func TestSuccessJustBeforeExpiry(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
	q.Submit(env("m", "a", "b", 1, 10, 2001))
	q.Advance(1000) // success
	if r := statusOf(t, q, "m"); r.Status != StatusSuccess {
		t.Fatalf("want success before expiry, got %s", r.Status)
	}
}

// Backoff schedule: 1,2,4,8,16,32,60,60 seconds; jumping across intervals
// only consumes one attempt.
func TestBackoffScheduleAndJump(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.Submit(env("m", "a", "b", 1, 10, 0))

	want := []int64{2000, 4000, 8000, 16000, 32000, 64000, 124000, 184000}
	now := int64(1000)
	for attempt, next := range want {
		q.Advance(now)
		r := statusOf(t, q, "m")
		if r.Status != StatusWaiting {
			t.Fatalf("attempt %d: want waiting, got %s", attempt+1, r.Status)
		}
		if r.NextRetry != next {
			t.Fatalf("attempt %d: want retry %d got %d", attempt+1, next, r.NextRetry)
		}
		if r.Attempts != attempt+1 {
			t.Fatalf("attempt %d: attempts=%d", attempt+1, r.Attempts)
		}
		now = next
	}

	// Jump far beyond several capped intervals: exactly one more attempt.
	q.Advance(now + 5_000_000)
	r := statusOf(t, q, "m")
	if r.Attempts != len(want)+1 {
		t.Fatalf("jumping intervals must cost one attempt, got %d", r.Attempts)
	}
	if r.NextRetry != now+5_000_000+60_000 {
		t.Fatalf("cap must remain 60s, nextRetry=%d", r.NextRetry)
	}
}

// Equal times may be advanced repeatedly; backwards moves are rejected with
// no state change.
func TestAdvanceTimeMonotonic(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.Submit(env("m", "a", "b", 1, 10, 0))

	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatalf("repeated equal advance must be allowed: %v", err)
	}
	r := statusOf(t, q, "m")
	if r.Attempts != 1 {
		t.Fatalf("equal-time re-advance at retry boundary must not double-process: %d", r.Attempts)
	}
	if _, err := q.Advance(999); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("backwards advance must fail with ErrInvalidArg, got %v", err)
	}
	if q.Now() != 1000 {
		t.Fatalf("failed advance changed processing time: %d", q.Now())
	}
}

// Records that have never been processed, and terminal records, expose no
// retry time; the six states are distinguishable via query.
func TestPendingNeverProcessed(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.Submit(env("m", "a", "b", 1, 10, 0))
	if q.Now() != 0 {
		t.Fatalf("new queue must report never-advanced time 0")
	}
	r, ok := q.Query("m")
	if !ok || r.Status != StatusPending || r.NextRetry != 0 || r.Attempts != 0 {
		t.Fatalf("unprocessed record: %+v ok=%v", r, ok)
	}
}

func TestAllSixStatesDistinguishable(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})

	q.Submit(env("s-ok", "a", "b", 1, 10, 0))
	q.Submit(env("s-replay", "a", "b", 1, 10, 0))
	q.Submit(env("s-expired", "a", "b", 2, 10, 1000))
	q.Submit(env("s-alien", "mars", "b", 0, 10, 0))
	q.Submit(env("s-wait", "a", "b", 7, 1000, 0)) // proof height above header
	q.Submit(env("s-pending", "a", "b", 8, 10, 0))

	q.Advance(1000)
	// s-pending was submitted before the advance, so it processes too; make a
	// genuinely fresh submission afterwards for the pending state.
	q.Submit(env("s-fresh", "a", "b", 9, 10, 0))

	want := map[string]string{
		"s-ok":      StatusSuccess,
		"s-replay":  StatusReplay,
		"s-expired": StatusExpired,
		"s-alien":   StatusUnknownSrc,
		"s-wait":    StatusWaiting,
		"s-fresh":   StatusPending,
	}
	for id, st := range want {
		r, ok := q.Query(id)
		if !ok {
			t.Fatalf("missing %s", id)
		}
		if r.Status != st {
			t.Fatalf("%s: want %s got %s (%s)", id, st, r.Status, r.Reason)
		}
		if r.Reason == "" {
			t.Fatalf("%s: reason must be specific", id)
		}
		switch st {
		case StatusPending, StatusSuccess, StatusReplay, StatusExpired, StatusUnknownSrc:
			if r.NextRetry != 0 {
				t.Fatalf("%s: must have no retry time, got %d", id, r.NextRetry)
			}
		case StatusWaiting:
			if r.NextRetry != 2000 {
				t.Fatalf("%s: retry at 2000, got %d", id, r.NextRetry)
			}
		}
	}
}

// Submission processing order is the first-submission order and survives
// restart; delivered messages are not delivered again.
func TestOrderingAndRecovery(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("m%02d", i)
		if _, err := q.Submit(env(id, "a", "b", uint64(i), 10, 0)); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 5 {
		t.Fatalf("want 5 results, got %d", len(rep.Results))
	}
	for i, res := range rep.Results {
		want := fmt.Sprintf("m%02d", i)
		if res.ID != want || res.Status != StatusSuccess {
			t.Fatalf("position %d: want %s success, got %s %s", i, want, res.ID, res.Status)
		}
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: state must be restored and successes must not deliver again.
	q2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	if q2.Now() != 1000 {
		t.Fatalf("restored now: want 1000 got %d", q2.Now())
	}
	for i := 0; i < 5; i++ {
		r := statusOf(t, q2, fmt.Sprintf("m%02d", i))
		if r.Status != StatusSuccess {
			t.Fatalf("m%02d lost terminal state: %s", i, r.Status)
		}
	}
	rep, err = q2.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range rep.Results {
		t.Fatalf("delivered messages processed again: %+v", res)
	}

	// Waiting order also survives a restart and stays in submission order.
	q2.Submit(env("w2", "a", "b", 20, 9999, 0))
	q2.Submit(env("w1", "a", "b", 21, 9999, 0))
	q2.Advance(2000)
	if err := q2.Close(); err != nil {
		t.Fatal(err)
	}
	q3, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q3.Close()
	if len(q3.order) != 2 || q3.order[0] != "w2" || q3.order[1] != "w1" {
		t.Fatalf("waiting order not restored: %v", q3.order)
	}
	r := statusOf(t, q3, "w1")
	if r.Status != StatusWaiting || r.NextRetry != 3000 {
		t.Fatalf("retry schedule not restored: %+v", r)
	}
}

// Only one process (independent open file description) may hold the directory
// for writing; after the holder closes, the directory is reusable.
func TestProcessLock(t *testing.T) {
	dir := t.TempDir()
	q1, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q2, err := Open(dir)
	if !errors.Is(err, ErrLocked) {
		if q2 != nil {
			q2.Close()
		}
		t.Fatalf("second open must fail ErrLocked, got %v", err)
	}
	if err := q1.Close(); err != nil {
		t.Fatal(err)
	}
	q3, err := Open(dir)
	if err != nil {
		t.Fatalf("directory must be reusable after holder exits: %v", err)
	}
	defer q3.Close()
}

// Corrupt and unsupported formats must be rejected, never silently cleared.
func TestCorruptionRejected(t *testing.T) {
	cases := map[string][]byte{
		"foreign magic":   []byte("NOT-A-RELAYPROOF-LOG!!\n"),
		"truncated magic": []byte("RELAY"),
		"empty":           nil,
		"bad version":     append([]byte(logMagic), encodeFrame(mustMarshal(&logEntry{T: "version", V: 9}))...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, logName)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			q, err := Open(dir)
			if !errors.Is(err, ErrCorrupt) {
				if q != nil {
					q.Close()
				}
				t.Fatalf("want ErrCorrupt, got %v", err)
			}
			// Original bytes must still be there (not wiped).
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if name == "empty" {
				if len(got) != 0 {
					t.Fatalf("empty file must not be rewritten on failed open")
				}
			} else if len(got) != len(data) {
				t.Fatalf("corrupt state was modified: %d -> %d bytes", len(data), len(got))
			}
		})
	}
}

// Corruption before the final frame is fatal; a torn final frame is truncated.
func TestMidLogCorruptionAndTornTail(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("a")
	q.Submit(env("m1", "a", "b", 1, 10, 0))
	q.Submit(env("m2", "a", "b", 2, 10, 0))
	q.Close()

	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}

	// Torn tail: cut the last frame in half; reopen truncates and keeps m1.
	torn := make([]byte, len(raw)-3)
	copy(torn, raw)
	tornDir := t.TempDir()
	os.WriteFile(filepath.Join(tornDir, logName), torn, 0o600)
	qt, err := Open(tornDir)
	if err != nil {
		t.Fatalf("torn tail should truncate and open: %v", err)
	}
	if _, ok := qt.Query("m1"); !ok {
		t.Fatalf("m1 should survive torn-tail recovery")
	}
	if _, ok := qt.Query("m2"); ok {
		t.Fatalf("partial m2 frame must be dropped")
	}
	qt.Close()

	// Flip a byte inside the middle frame (m1 body): checksum mismatch that is
	// not at EOF must be fatal.
	bad := append([]byte(nil), raw...)
	pos := len(logMagic)
	// Flip a byte inside the JSON body of the first frame (the version frame).
	bad[pos+4+2] ^= 0xFF
	badDir := t.TempDir()
	os.WriteFile(filepath.Join(badDir, logName), bad, 0o600)
	if _, err := Open(badDir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mid-log corruption must be ErrCorrupt, got %v", err)
	}
}

// A storage write failure reports a clear error and poisons the queue; after
// reopening, the torn unacknowledged tail is dropped and consistency holds.
func TestStorageFailureRecovery(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("a")
	q.store.injectErr = errors.New("disk on fire")
	if _, err := q.Submit(env("m", "a", "b", 1, 10, 0)); !errors.Is(err, ErrStorage) {
		t.Fatalf("want ErrStorage, got %v", err)
	}
	// Further writes must fail loudly instead of corrupting the log.
	if err := q.RegisterSource("c"); !errors.Is(err, ErrStorage) {
		t.Fatalf("broken queue must refuse writes, got %v", err)
	}
	q.Close()

	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after storage failure: %v", err)
	}
	defer q2.Close()
	if _, ok := q2.Query("m"); ok {
		t.Fatalf("unacknowledged submit must not exist after recovery")
	}
	if !q2.sources["a"] {
		t.Fatalf("acknowledged source registration lost")
	}
}

// Concurrent goroutines sharing one Queue must never double-consume a nonce.
func TestConcurrentNoDoubleConsume(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})

	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = q.Submit(env(fmt.Sprintf("m%d", i), "a", "b", uint64(i%3), 10, 0))
		}(i)
	}
	wg.Wait()
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	delivered := map[uint64]int{}
	for _, res := range rep.Results {
		if res.Status == StatusSuccess {
			delivered[q.records[res.ID].Msg.Message.Nonce]++
		}
	}
	if len(delivered) != 3 {
		t.Fatalf("want exactly 3 consumed nonces, got %d", len(delivered))
	}
	for nonce, count := range delivered {
		if count != 1 {
			t.Fatalf("nonce %d delivered %d times", nonce, count)
		}
	}
	replays := 0
	for _, res := range rep.Results {
		if res.Status == StatusReplay {
			replays++
		}
	}
	if replays != n-3 {
		t.Fatalf("want %d replays, got %d", n-3, replays)
	}
	if len(q.consumed) != 3 {
		t.Fatalf("consumed set: %v", q.consumed)
	}
}

// WAL compaction preserves the exact logical state and lets the log shrink.
func TestCompaction(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
	for i := 0; i < 30; i++ {
		q.Submit(env(fmt.Sprintf("m%02d", i), "a", "b", uint64(i), 10, 0))
	}
	q.Advance(1000)
	q.Submit(env("w1", "a", "b", 99, 5000, 0))
	q.Advance(2000) // w1 waiting, NextRetry=3000
	q.Advance(3000) // w1 waiting again (attempt 2), NextRetry=5000

	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatal(err)
	}
	q.Close()

	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen compacted log: %v", err)
	}
	defer q2.Close()
	for i := 0; i < 30; i++ {
		if r := statusOf(t, q2, fmt.Sprintf("m%02d", i)); r.Status != StatusSuccess {
			t.Fatalf("m%02d: want success got %s", i, r.Status)
		}
	}
	r := statusOf(t, q2, "w1")
	if r.Status != StatusWaiting || r.NextRetry != 5000 || r.Attempts != 2 {
		t.Fatalf("w1 schedule lost: %+v", r)
	}
	if len(q2.consumed) != 30 {
		t.Fatalf("consumed nonces lost: %d", len(q2.consumed))
	}
	if q2.Now() != 3000 {
		t.Fatalf("processing time lost: %d", q2.Now())
	}
	// Equal-time re-advance keeps backoff (next retry 5000) untouched.
	if _, err := q2.Advance(3000); err != nil {
		t.Fatal(err)
	}
	r = statusOf(t, q2, "w1")
	if r.Status != StatusWaiting || r.Attempts != 2 || r.NextRetry != 5000 {
		t.Fatalf("w1 should keep waiting with unchanged schedule: %+v", r)
	}
}

// A later trusted header must not resurrect an expired message.
func TestHeaderDoesNotReactivateExpired(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.Submit(env("m", "a", "b", 1, 1000, 3000))
	q.Advance(1000) // waiting
	q.Advance(3000) // expired (during backoff)
	if r := statusOf(t, q, "m"); r.Status != StatusExpired {
		t.Fatalf("want expired, got %s", r.Status)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 1000, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(4000); err != nil {
		t.Fatal(err)
	}
	if r := statusOf(t, q, "m"); r.Status != StatusExpired {
		t.Fatalf("header update reactivated expired message: %s", r.Status)
	}
}

// Re-submitting the same pending id+content while waiting is a no-op and keeps
// the original submission position, attempts and retry schedule.
func TestIdempotentResubmitWhileWaiting(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.Submit(env("m", "a", "b", 1, 10, 0))
	q.Advance(1000) // waiting, retry 2000
	rec, err := q.Submit(env("m", "a", "b", 1, 10, 0))
	if err != nil {
		t.Fatalf("identical resubmit while waiting: %v", err)
	}
	if rec.Attempts != 1 || rec.NextRetry != 2000 || rec.Status != StatusWaiting {
		t.Fatalf("resubmit must return the existing live record: %+v", rec)
	}
	if len(q.order) != 1 {
		t.Fatalf("resubmit added queue entry: %v", q.order)
	}
}

// Headers and sources registered before a restart remain usable afterwards.
func TestHeaderSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
	q.Submit(env("m", "a", "b", 1, 10, 0))
	q.Close()

	q2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	rep, err := q2.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Status != StatusSuccess {
		t.Fatalf("message should deliver after restart using stored header: %+v", rep.Results)
	}
}

// Expired and replay terminal reasons survive restart exactly.
func TestTerminalReasonsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("a")
	q.Submit(env("m", "a", "b", 1, 10, 2000))
	q.Advance(1000)
	q.Advance(2000)
	q.Close()

	q2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	r := statusOf(t, q2, "m")
	if r.Status != StatusExpired || !strings.Contains(r.Reason, "2000") {
		t.Fatalf("expired state/reason lost: %+v", r)
	}
}

// Validation errors must not touch state.
func TestValidation(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if _, err := q.Submit(env("", "a", "b", 1, 10, 0)); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("empty id: %v", err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: -1}); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("negative height: %v", err)
	}
	if _, err := q.Advance(-1); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("negative time: %v", err)
	}
	if err := q.RegisterSource(""); !errors.Is(err, ErrInvalidArg) {
		t.Fatalf("empty chain: %v", err)
	}
	if len(q.records)+len(q.sources) != 0 {
		t.Fatal("invalid calls mutated state")
	}
}
