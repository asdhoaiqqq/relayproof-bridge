package relayproof

import (
	"errors"
	"testing"
)

// Within one advance, an earlier result already acknowledged stays in effect
// when a later result fails to persist. The failed message keeps its prior
// state and never pre-consumes its nonce, the storage failure poisons the
// queue, and queries still reflect every committed result.
func TestAdvancePartialWriteFailureBoundary(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("a")
	q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
	q.Submit(env("a", "a", "b", 1, 10, 0)) // succeeds first (submission order)
	q.Submit(env("b", "a", "b", 2, 10, 0)) // its success append is forced to fail

	q.store.injectFail = func(e *logEntry) error {
		if e.T == kindResult && e.ID == "b" {
			return errors.New("disk on fire")
		}
		return nil
	}
	_, err = q.Advance(1000)
	if !errors.Is(err, ErrStorage) {
		t.Fatalf("want ErrStorage from the failed result, got %v", err)
	}

	// The earlier, committed success survives the later failure.
	if r := statusOf(t, q, "a"); r.Status != StatusSuccess || r.Attempts != 1 || r.NextRetry != 0 {
		t.Fatalf("committed success must survive a later failure: %+v", r)
	}
	if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "a" {
		t.Fatalf("a's nonce consumption lost: %q", winner)
	}

	// The failed message keeps its prior state and never consumed its nonce.
	if r := statusOf(t, q, "b"); r.Status != StatusPending || r.Attempts != 0 || r.NextRetry != 0 {
		t.Fatalf("failed message must keep its prior state: %+v", r)
	}
	if _, taken := q.consumed[newConsumeToken("a", "b", 2)]; taken {
		t.Fatal("nonce must not be consumed by a result that never saved")
	}
	if _, ok := q.Query("a"); !ok {
		t.Fatal("queries must still reflect committed records after a failure")
	}

	// The instance now refuses every write, even valid ones.
	if _, err := q.Submit(env("c", "a", "b", 3, 10, 0)); !errors.Is(err, ErrStorage) {
		t.Fatalf("broken instance must refuse submit, got %v", err)
	}
	if err := q.RegisterSource("z"); !errors.Is(err, ErrStorage) {
		t.Fatalf("broken instance must refuse register-source, got %v", err)
	}
	if _, err := q.Advance(2000); !errors.Is(err, ErrStorage) {
		t.Fatalf("broken instance must refuse advance, got %v", err)
	}
	// The committed record is still readable and the failed one still pending.
	if r := statusOf(t, q, "a"); r.Status != StatusSuccess {
		t.Fatalf("committed success changed on the poisoned instance: %+v", r)
	}
	if r := statusOf(t, q, "b"); r.Status != StatusPending {
		t.Fatalf("failed message changed on the poisoned instance: %+v", r)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: a stays terminal success (never redelivered); b, whose frame was
	// never acknowledged, is pending again and delivers normally.
	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after failed advance: %v", err)
	}
	defer q2.Close()
	if r := statusOf(t, q2, "a"); r.Status != StatusSuccess {
		t.Fatalf("a must remain success after recovery: %+v", r)
	}
	if r := statusOf(t, q2, "b"); r.Status != StatusPending || r.Attempts != 0 {
		t.Fatalf("b must be pending again after recovery: %+v", r)
	}
	rep, err := q2.Advance(2000)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := resultFor(rep, "b")
	if !ok || res.Status != StatusSuccess {
		t.Fatalf("b must deliver on the recovered queue, got %+v", rep.Results)
	}
	if _, ok := resultFor(rep, "a"); ok {
		t.Fatalf("terminal a must not be redelivered: %+v", rep.Results)
	}
}

// A failed waiting write leaves the message exactly as it was before the
// attempt: pending on its first try, with no retry scheduled and no attempt
// counted.
func TestWaitingWriteFailureLeavesPriorState(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	q.RegisterSource("a") // registered but no trusted header -> would wait
	q.Submit(env("w", "a", "b", 1, 100, 0))

	q.store.injectFail = func(e *logEntry) error {
		if e.T == kindResult && e.ID == "w" {
			return errors.New("disk on fire")
		}
		return nil
	}
	if _, err := q.Advance(1000); !errors.Is(err, ErrStorage) {
		t.Fatalf("want ErrStorage, got %v", err)
	}
	if r := statusOf(t, q, "w"); r.Status != StatusPending || r.Attempts != 0 || r.NextRetry != 0 {
		t.Fatalf("failed waiting result must leave prior pending state: %+v", r)
	}
	if _, err := q.Advance(2000); !errors.Is(err, ErrStorage) {
		t.Fatalf("instance must stay poisoned, got %v", err)
	}
}
