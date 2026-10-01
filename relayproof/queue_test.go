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
	if got := q.consumed[consumeKeyOf("a", "b", 1)]; got != "m1" {
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

// Two distinct cross-chain paths that collide under the old composite-string
// encoding must each succeed with nonce 7. Chain names are compared as their
// exact UTF-8 content: "a:b" -> "c" and "a" -> "b:c" are different paths, as
// are "a\x00b" -> "c" and "a" -> "b\x00c".
func TestDistinctPathsSameNonce(t *testing.T) {
	cases := []struct {
		name       string
		from1, to1 string
		from2, to2 string
	}{
		{"colon", "a:b", "c", "a", "b:c"},
		{"zero-byte", "a\x00b", "c", "a", "b\x00c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, _ := openTempQueue(t)
			defer q.Close()
			// Both source chains must be registered and have trusted headers.
			q.RegisterSource(tc.from1)
			q.RegisterSource(tc.from2)
			q.UpsertHeader(Header{Chain: tc.from1, Height: 100, Trusted: true})
			q.UpsertHeader(Header{Chain: tc.from2, Height: 100, Trusted: true})

			q.Submit(env("p1", tc.from1, tc.to1, 7, 10, 0))
			q.Submit(env("p2", tc.from2, tc.to2, 7, 10, 0))
			rep, err := q.Advance(1000)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"p1": StatusSuccess, "p2": StatusSuccess}
			if len(rep.Results) != 2 {
				t.Fatalf("want 2 results, got %+v", rep.Results)
			}
			for _, res := range rep.Results {
				if res.Status != want[res.ID] {
					t.Fatalf("id %s want %s got %s", res.ID, want[res.ID], res.Status)
				}
			}
			// Both consumption triples are distinct and recorded.
			if len(q.consumed) != 2 {
				t.Fatalf("want 2 distinct consumed triples, got %d: %v", len(q.consumed), q.consumed)
			}
			// Full chain names are preserved in queries, including zero bytes.
			for _, id := range []string{"p1", "p2"} {
				r, ok := q.Query(id)
				if !ok {
					t.Fatalf("missing %s", id)
				}
				if r.Status != StatusSuccess {
					t.Fatalf("%s: want success got %s", id, r.Status)
				}
			}
			r1, _ := q.Query("p1")
			if r1.From != tc.from1 || r1.To != tc.to1 {
				t.Fatalf("p1 chain names not preserved: from=%q to=%q", r1.From, r1.To)
			}
			r2, _ := q.Query("p2")
			if r2.From != tc.from2 || r2.To != tc.to2 {
				t.Fatalf("p2 chain names not preserved: from=%q to=%q", r2.From, r2.To)
			}
		})
	}
}

// The memory verification entry keys consumption by the exact triple too.
func TestVerifyDistinctPathsSameNonce(t *testing.T) {
	cases := []struct {
		name       string
		from1, to1 string
		from2, to2 string
	}{
		{"colon", "a:b", "c", "a", "b:c"},
		{"zero-byte", "a\x00b", "c", "a", "b\x00c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]Header{
				tc.from1: {Chain: tc.from1, Height: 100, Root: "0x1", Trusted: true},
				tc.from2: {Chain: tc.from2, Height: 100, Root: "0x1", Trusted: true},
			}
			consumed := map[ConsumeKey]bool{}
			m1 := Message{ID: "p1", From: tc.from1, To: tc.to1, Nonce: 7, ProofAt: 10}
			m2 := Message{ID: "p2", From: tc.from2, To: tc.to2, Nonce: 7, ProofAt: 10}
			if d := Verify(headers, m1, consumed); d.Status != "delivered" {
				t.Fatalf("p1: want delivered got %s (%s)", d.Status, d.Reason)
			}
			if d := Verify(headers, m2, consumed); d.Status != "delivered" {
				t.Fatalf("p2: want delivered got %s (%s)", d.Status, d.Reason)
			}
			if len(consumed) != 2 {
				t.Fatalf("want 2 consumed triples, got %d", len(consumed))
			}
			// Replaying p1 is still rejected.
			if d := Verify(headers, m1, consumed); d.Status != "rejected" {
				t.Fatalf("p1 replay: want rejected got %s", d.Status)
			}
		})
	}
}

// The same real combination is consumed at most once; a different id, payload
// or proof height cannot bypass an already-occurred consumption.
func TestSameTripleReplayRegardlessOfPayload(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})

	q.Submit(env("win", "a", "b", 7, 10, 0))
	lose := env("lose", "a", "b", 7, 10, 0)
	lose.Message.Payload = "different-payload"
	lose.Message.ProofAt = 50
	q.Submit(lose)
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"win": StatusSuccess, "lose": StatusReplay}
	for _, res := range rep.Results {
		if res.Status != want[res.ID] {
			t.Fatalf("id %s want %s got %s", res.ID, want[res.ID], res.Status)
		}
	}
	if len(q.consumed) != 1 {
		t.Fatalf("want exactly 1 consumed triple, got %d", len(q.consumed))
	}
}

// Two distinct paths submitted concurrently do not interfere.
func TestDistinctPathsConcurrent(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a\x00b")
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a\x00b", Height: 100, Trusted: true})
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Alternate between two distinct paths that share nonce 7.
			if i%2 == 0 {
				q.Submit(env(fmt.Sprintf("p%d", i), "a\x00b", "c", 7, 10, 0))
			} else {
				q.Submit(env(fmt.Sprintf("p%d", i), "a", "b\x00c", 7, 10, 0))
			}
		}(i)
	}
	wg.Wait()
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	delivered := 0
	for _, res := range rep.Results {
		if res.Status == StatusSuccess {
			delivered++
		}
	}
	// Exactly one per path: two distinct paths each succeed once.
	if delivered != 2 {
		t.Fatalf("want exactly 2 successes (one per distinct path), got %d", delivered)
	}
	if len(q.consumed) != 2 {
		t.Fatalf("want 2 consumed triples, got %d", len(q.consumed))
	}
}

// Two distinct paths processed in a single Advance do not interfere.
func TestDistinctPathsInOneAdvance(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a:b")
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a:b", Height: 100, Trusted: true})
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})

	q.Submit(env("p1", "a:b", "c", 7, 10, 0))
	q.Submit(env("p2", "a", "b:c", 7, 10, 0))
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("want 2 results, got %+v", rep.Results)
	}
	for _, res := range rep.Results {
		if res.Status != StatusSuccess {
			t.Fatalf("id %s want success got %s (%s)", res.ID, res.Status, res.Reason)
		}
	}
}

// buildV1Log writes a v1 log with the given entries (version record first).
func buildV1Log(t *testing.T, dir string, entries ...*logEntry) {
	t.Helper()
	raw := append([]byte(logMagic), encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: logV1}))...)
	for _, e := range entries {
		raw = append(raw, encodeFrame(mustMarshal(e))...)
	}
	if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Recovery from a v1 log: a historical success consumes only its original
// triple; a path that collided under the old encoding can now be delivered
// with a new id, while the historical replay record stays replay and its id
// cannot be reused.
func TestV1RecoveryCollidingPath(t *testing.T) {
	dir := t.TempDir()
	// m1: from="a", to="b", nonce=7 (success).
	// m2: from="a\x00b", to="c", nonce=7 — collided under the old encoding and
	// was historically marked replay.
	buildV1Log(t, dir,
		&logEntry{T: kindSource, Chain: "a"},
		&logEntry{T: kindHeader, Chain: "a", Height: 100, Root: "0x1", Trusted: true},
		&logEntry{T: kindSubmit, Seq: 0, ID: "m1", From: "a", To: "b", Nonce: 7, ProofAt: 10},
		&logEntry{T: kindResult, Now: 1000, ID: "m1", Status: StatusSuccess, Reason: "delivered", Attempts: 1, ConsumeKey: oldStyleKey("a", "b", 7), ConsumeBy: "m1"},
		&logEntry{T: kindSubmit, Seq: 1, ID: "m2", From: "a\x00b", To: "c", Nonce: 7, ProofAt: 10},
		&logEntry{T: kindResult, Now: 1000, ID: "m2", Status: StatusReplay, Reason: "nonce combination already consumed by message m1", Attempts: 1},
	)

	q, err := Open(dir)
	if err != nil {
		t.Fatalf("open v1 log: %v", err)
	}
	defer q.Close()

	// Historical state preserved.
	if r, ok := q.Query("m1"); !ok || r.Status != StatusSuccess {
		t.Fatalf("m1 should be success, got %+v", r)
	}
	if r, ok := q.Query("m2"); !ok || r.Status != StatusReplay {
		t.Fatalf("m2 should stay replay, got %+v", r)
	}
	// Only the m1 triple is consumed.
	if len(q.consumed) != 1 {
		t.Fatalf("want 1 consumed triple after recovery, got %d: %v", len(q.consumed), q.consumed)
	}
	if got := q.consumed[consumeKeyOf("a", "b", 7)]; got != "m1" {
		t.Fatalf("m1 triple should be consumed by m1, got %q", got)
	}

	// A new message with m2's path (new id) can now succeed.
	q.RegisterSource("a\x00b")
	q.UpsertHeader(Header{Chain: "a\x00b", Height: 100, Trusted: true})
	q.Submit(env("m3", "a\x00b", "c", 7, 10, 0))
	// The other colliding path also succeeds.
	q.Submit(env("m4", "a", "b\x00c", 7, 10, 0))
	// The exact m1 triple still replays.
	q.Submit(env("m5", "a", "b", 7, 10, 0))
	rep, err := q.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"m3": StatusSuccess, "m4": StatusSuccess, "m5": StatusReplay}
	for _, res := range rep.Results {
		if res.Status != want[res.ID] {
			t.Fatalf("id %s want %s got %s (%s)", res.ID, want[res.ID], res.Status, res.Reason)
		}
	}
	// The replay reason points at the actual winner (m1), not another path.
	r, _ := q.Query("m5")
	if !strings.Contains(r.Reason, "m1") {
		t.Fatalf("replay reason should name m1, got %q", r.Reason)
	}
	// Historical replay id cannot be reused.
	if _, err := q.Submit(env("m2", "a\x00b", "c", 7, 10, 0)); !errors.Is(err, ErrTerminal) {
		t.Fatalf("reusing historical replay id must be ErrTerminal, got %v", err)
	}
}

// A v1 success record whose consumeKey does not match its message content is
// rejected as corrupt, and the original data is preserved.
func TestV1CorruptionMismatchedConsumeKey(t *testing.T) {
	dir := t.TempDir()
	buildV1Log(t, dir,
		&logEntry{T: kindSource, Chain: "a"},
		&logEntry{T: kindHeader, Chain: "a", Height: 100, Root: "0x1", Trusted: true},
		&logEntry{T: kindSubmit, Seq: 0, ID: "m1", From: "a", To: "b", Nonce: 7, ProofAt: 10},
		// consumeKey claims a different path than the message content.
		&logEntry{T: kindResult, Now: 1000, ID: "m1", Status: StatusSuccess, Reason: "delivered", Attempts: 1, ConsumeKey: oldStyleKey("a", "c", 7), ConsumeBy: "m1"},
	)
	if _, err := Open(dir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mismatched consumeKey must be ErrCorrupt, got %v", err)
	}
	// Original data preserved.
	raw, _ := os.ReadFile(filepath.Join(dir, logName))
	if len(raw) == 0 {
		t.Fatal("corrupt log must not be wiped")
	}
}

// A v1 log with two success records consuming the same triple is rejected.
func TestV1CorruptionDoubleConsume(t *testing.T) {
	dir := t.TempDir()
	buildV1Log(t, dir,
		&logEntry{T: kindSource, Chain: "a"},
		&logEntry{T: kindHeader, Chain: "a", Height: 100, Root: "0x1", Trusted: true},
		&logEntry{T: kindSubmit, Seq: 0, ID: "m1", From: "a", To: "b", Nonce: 7, ProofAt: 10},
		&logEntry{T: kindResult, Now: 1000, ID: "m1", Status: StatusSuccess, Reason: "delivered", Attempts: 1, ConsumeKey: oldStyleKey("a", "b", 7), ConsumeBy: "m1"},
		&logEntry{T: kindSubmit, Seq: 1, ID: "m2", From: "a", To: "b", Nonce: 7, ProofAt: 10},
		&logEntry{T: kindResult, Now: 2000, ID: "m2", Status: StatusSuccess, Reason: "delivered", Attempts: 1, ConsumeKey: oldStyleKey("a", "b", 7), ConsumeBy: "m2"},
	)
	if _, err := Open(dir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("double consume must be ErrCorrupt, got %v", err)
	}
}

// After compaction and reopen, distinct paths still succeed and the
// consumption relationship is preserved.
func TestCompactionPreservesConsumption(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("a:b")
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a:b", Height: 100, Trusted: true})
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
	q.Submit(env("p1", "a:b", "c", 7, 10, 0))
	q.Submit(env("p2", "a", "b:c", 7, 10, 0))
	q.Advance(1000)

	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatal(err)
	}
	q.Close()

	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen compacted log: %v", err)
	}
	defer q2.Close()
	if len(q2.consumed) != 2 {
		t.Fatalf("want 2 consumed triples after compaction, got %d", len(q2.consumed))
	}
	// A new message with the same triple replays; a distinct path succeeds.
	q2.Submit(env("p3", "a:b", "c", 7, 10, 0))
	q2.Submit(env("p4", "a:b", "d", 7, 10, 0))
	rep, err := q2.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"p3": StatusReplay, "p4": StatusSuccess}
	for _, res := range rep.Results {
		if res.Status != want[res.ID] {
			t.Fatalf("id %s want %s got %s", res.ID, want[res.ID], res.Status)
		}
	}
}

// Two messages sharing the same source and nonce but with different
// destination chains are distinct triples and both succeed.
func TestSameSourceDifferentDestination(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})

	q.Submit(env("p1", "a", "b", 7, 10, 0))
	q.Submit(env("p2", "a", "c", 7, 10, 0))
	rep, err := q.Advance(1000)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"p1": StatusSuccess, "p2": StatusSuccess}
	for _, res := range rep.Results {
		if res.Status != want[res.ID] {
			t.Fatalf("id %s want %s got %s", res.ID, want[res.ID], res.Status)
		}
	}
	if len(q.consumed) != 2 {
		t.Fatalf("want 2 consumed triples, got %d", len(q.consumed))
	}
}

// A normal directory that completes open, write and reopen keeps the
// consumption relationship: success record and nonce consumption never take
// effect separately.
func TestConsumptionAtomicAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
	q.Submit(env("m1", "a", "b", 7, 10, 0))
	q.Advance(1000)
	q.Close()

	q2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	// m1 success and its consumption are both present.
	if r, ok := q2.Query("m1"); !ok || r.Status != StatusSuccess {
		t.Fatalf("m1 should be success, got %+v", r)
	}
	if got := q2.consumed[consumeKeyOf("a", "b", 7)]; got != "m1" {
		t.Fatalf("m1 triple should be consumed by m1, got %q", got)
	}
	// The same triple cannot be delivered again.
	q2.Submit(env("m2", "a", "b", 7, 10, 0))
	rep, err := q2.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range rep.Results {
		if res.ID == "m2" && res.Status != StatusReplay {
			t.Fatalf("m2 should replay, got %s", res.Status)
		}
	}
}
