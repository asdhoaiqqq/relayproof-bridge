package relayproof

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func msg(id, from, to string, nonce uint64, proofAt, expireAt int64) Message {
	return Message{
		ID:       id,
		From:     from,
		To:       to,
		Nonce:    nonce,
		ProofAt:  proofAt,
		ExpireAt: expireAt,
	}
}

func TestSubmitIdempotentAndConflict(t *testing.T) {
	s := openTestStore(t)
	m := msg("m1", "chain-a", "chain-b", 1, 100, 100000)
	r1, err := s.Submit(m)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if r1.Status != StatusPending {
		t.Fatalf("status=%s, want pending", r1.Status)
	}
	// Same ID + identical content returns the existing record.
	r2, err := s.Submit(m)
	if err != nil {
		t.Fatalf("resubmit identical: %v", err)
	}
	if r2 != r1 {
		t.Fatal("identical resubmit returned a different record")
	}
	if len(s.List()) != 1 {
		t.Fatalf("queue length=%d, want 1", len(s.List()))
	}
	// Same ID + different content is a conflict; original unchanged.
	mDiff := m
	mDiff.Nonce = 2
	if _, err := s.Submit(mDiff); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict err=%v, want ErrConflict", err)
	}
	got, _ := s.Query("m1")
	if got.Message.Nonce != 1 {
		t.Fatalf("original record changed: nonce=%d", got.Message.Nonce)
	}
	if len(s.List()) != 1 {
		t.Fatalf("queue length=%d, want 1", len(s.List()))
	}
}

func TestAdvanceTimeSemantics(t *testing.T) {
	s := openTestStore(t)
	if err := s.Advance(1000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	// Equal time is a no-op.
	if err := s.Advance(1000); err != nil {
		t.Fatalf("equal advance: %v", err)
	}
	// Backward movement rejected, state unchanged.
	if err := s.Advance(999); !errors.Is(err, ErrTimeBackward) {
		t.Fatalf("backward err=%v, want ErrTimeBackward", err)
	}
	now, _ := s.Time()
	if now != 1000 {
		t.Fatalf("time=%d, want 1000", now)
	}
}

func TestUnknownSourceRejectedPermanently(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Submit(msg("m1", "chain-x", "chain-b", 1, 100, 100000)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := s.Advance(1000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ := s.Query("m1")
	if r.Status != StatusUnknownSource {
		t.Fatalf("status=%s, want unknown_source", r.Status)
	}
	if r.NextRetry != nil {
		t.Fatalf("terminal record has retry time: %v", *r.NextRetry)
	}
	// Registering the source later must not reactivate the terminal record.
	if err := s.SetHeader(Header{Chain: "chain-x", Height: 200, Trusted: true}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	if err := s.Advance(2000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ = s.Query("m1")
	if r.Status != StatusUnknownSource {
		t.Fatalf("status after header=%s, want unknown_source (terminal)", r.Status)
	}
}

func TestWaitingHeaderRetryBackoffAndHeaderUpdate(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 50, Trusted: false}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	if _, err := s.Submit(msg("m1", "chain-a", "chain-b", 1, 100, 100000)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// First advance: first processing, header not trusted -> waiting, retry +1s.
	if err := s.Advance(1000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ := s.Query("m1")
	if r.Status != StatusWaitingHeader || r.Attempts != 1 {
		t.Fatalf("status=%s attempts=%d, want waiting_header/1", r.Status, r.Attempts)
	}
	if r.NextRetry == nil || *r.NextRetry != 2000 {
		t.Fatalf("next_retry=%v, want 2000", r.NextRetry)
	}
	// Advance before retry time: still waiting, schedule unchanged.
	if err := s.Advance(1500); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ = s.Query("m1")
	if r.Status != StatusWaitingHeader || r.Attempts != 1 {
		t.Fatalf("status=%s attempts=%d, want waiting_header/1", r.Status, r.Attempts)
	}
	if r.NextRetry == nil || *r.NextRetry != 2000 {
		t.Fatalf("next_retry=%v, want 2000 (unchanged)", r.NextRetry)
	}
	// Advance past retry but header still untrusted: one attempt, retry +2s.
	if err := s.Advance(5000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ = s.Query("m1")
	if r.Status != StatusWaitingHeader || r.Attempts != 2 {
		t.Fatalf("status=%s attempts=%d, want waiting_header/2", r.Status, r.Attempts)
	}
	if r.NextRetry == nil || *r.NextRetry != 7000 {
		t.Fatalf("next_retry=%v, want 7000 (5000+2000)", r.NextRetry)
	}
	// Trusted header update does not bypass the retry schedule.
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 200, Trusted: true}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	if err := s.Advance(6000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ = s.Query("m1")
	if r.Status != StatusWaitingHeader {
		t.Fatalf("status=%s, want waiting_header (retry not due yet)", r.Status)
	}
	// Retry due: trusted header covers proof height and not expired -> success.
	if err := s.Advance(7000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ = s.Query("m1")
	if r.Status != StatusSuccess {
		t.Fatalf("status=%s, want success", r.Status)
	}
	if r.NextRetry != nil {
		t.Fatalf("successful record has retry time: %v", *r.NextRetry)
	}
}

func TestBackoffCapsAtSixtySeconds(t *testing.T) {
	if got := backoff(1); got != 1000 {
		t.Fatalf("backoff(1)=%d, want 1000", got)
	}
	if got := backoff(2); got != 2000 {
		t.Fatalf("backoff(2)=%d, want 2000", got)
	}
	if got := backoff(3); got != 4000 {
		t.Fatalf("backoff(3)=%d, want 4000", got)
	}
	if got := backoff(6); got != 32000 {
		t.Fatalf("backoff(6)=%d, want 32000", got)
	}
	if got := backoff(7); got != 60000 {
		t.Fatalf("backoff(7)=%d, want 60000", got)
	}
	if got := backoff(20); got != 60000 {
		t.Fatalf("backoff(20)=%d, want 60000", got)
	}
}

func TestReplayAndExpiry(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 200, Trusted: true}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	// Two messages with the same nonce combination; at most one succeeds.
	if _, err := s.Submit(msg("m1", "chain-a", "chain-b", 1, 100, 100000)); err != nil {
		t.Fatalf("submit m1: %v", err)
	}
	if _, err := s.Submit(msg("m2", "chain-a", "chain-b", 1, 100, 100000)); err != nil {
		t.Fatalf("submit m2: %v", err)
	}
	if err := s.Advance(1000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r1, _ := s.Query("m1")
	r2, _ := s.Query("m2")
	if r1.Status != StatusSuccess {
		t.Fatalf("m1 status=%s, want success", r1.Status)
	}
	if r2.Status != StatusReplay {
		t.Fatalf("m2 status=%s, want replay", r2.Status)
	}
	// A third message with the same nonce is replay on sight, even before expiry.
	if _, err := s.Submit(msg("m3", "chain-a", "chain-b", 1, 100, 100000)); err != nil {
		t.Fatalf("submit m3: %v", err)
	}
	if err := s.Advance(2000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r3, _ := s.Query("m3")
	if r3.Status != StatusReplay {
		t.Fatalf("m3 status=%s, want replay", r3.Status)
	}
}

func TestExpiryIncludesExactEquality(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 200, Trusted: true}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	if _, err := s.Submit(msg("m1", "chain-a", "chain-b", 1, 100, 5000)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// Advance to exactly the expiry moment: expired.
	if err := s.Advance(5000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ := s.Query("m1")
	if r.Status != StatusExpired {
		t.Fatalf("status=%s, want expired (equality counts)", r.Status)
	}
}

func TestReplayWinsOverExpiry(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 200, Trusted: true}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	// m1 succeeds and consumes the nonce.
	if _, err := s.Submit(msg("m1", "chain-a", "chain-b", 1, 100, 100000)); err != nil {
		t.Fatalf("submit m1: %v", err)
	}
	if err := s.Advance(1000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	// m2 shares the nonce and is already expired at the next advance.
	if _, err := s.Submit(msg("m2", "chain-a", "chain-b", 1, 100, 1500)); err != nil {
		t.Fatalf("submit m2: %v", err)
	}
	if err := s.Advance(2000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r2, _ := s.Query("m2")
	if r2.Status != StatusReplay {
		t.Fatalf("status=%s, want replay (replay wins over expiry)", r2.Status)
	}
}

func TestProcessingOrderPreserved(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 200, Trusted: true}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	for _, id := range []string{"m1", "m2", "m3"} {
		if _, err := s.Submit(msg(id, "chain-a", "chain-b", 1, 100, 100000)); err != nil {
			t.Fatalf("submit %s: %v", id, err)
		}
	}
	if err := s.Advance(1000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	want := map[string]string{
		"m1": StatusSuccess,
		"m2": StatusReplay,
		"m3": StatusReplay,
	}
	for id, status := range want {
		r, _ := s.Query(id)
		if r.Status != status {
			t.Fatalf("%s status=%s, want %s", id, r.Status, status)
		}
	}
}

func TestRestartRecovery(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 200, Trusted: true}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	if _, err := s.Submit(msg("m1", "chain-a", "chain-b", 1, 100, 100000)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := s.Advance(1000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen the same directory: everything is recovered.
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	r, err := s2.Query("m1")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if r.Status != StatusSuccess {
		t.Fatalf("status=%s, want success after restart", r.Status)
	}
	now, _ := s2.Time()
	if now != 1000 {
		t.Fatalf("time=%d, want 1000 after restart", now)
	}
	// The consumed nonce is still consumed: no double delivery.
	if _, err := s2.Submit(msg("m2", "chain-a", "chain-b", 1, 100, 100000)); err != nil {
		t.Fatalf("submit m2: %v", err)
	}
	if err := s2.Advance(2000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r2, _ := s2.Query("m2")
	if r2.Status != StatusReplay {
		t.Fatalf("m2 status=%s, want replay (nonce still consumed)", r2.Status)
	}
}

func TestWaitingStateAndScheduleRecovered(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 50, Trusted: false}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	if _, err := s.Submit(msg("m1", "chain-a", "chain-b", 1, 100, 100000)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := s.Advance(1000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	r, _ := s2.Query("m1")
	if r.Status != StatusWaitingHeader || r.Attempts != 1 {
		t.Fatalf("status=%s attempts=%d after restart, want waiting_header/1", r.Status, r.Attempts)
	}
	if r.NextRetry == nil || *r.NextRetry != 2000 {
		t.Fatalf("next_retry=%v after restart, want 2000", r.NextRetry)
	}
	// Processing order and schedule survive: only one attempt across a big jump.
	if err := s2.Advance(5000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ = s2.Query("m1")
	if r.Status != StatusWaitingHeader || r.Attempts != 2 {
		t.Fatalf("status=%s attempts=%d after jump, want waiting_header/2", r.Status, r.Attempts)
	}
	if r.NextRetry == nil || *r.NextRetry != 7000 {
		t.Fatalf("next_retry=%v, want 7000", r.NextRetry)
	}
}

func TestLockConflictAndRelease(t *testing.T) {
	dir := t.TempDir()
	s1, err := Open(dir)
	if err != nil {
		t.Fatalf("open s1: %v", err)
	}
	defer s1.Close()

	s2, err := Open(dir)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second open err=%v, want ErrLocked", err)
	}
	if s2 != nil {
		s2.Close()
	}
	// After the first exits, the directory is reusable.
	if err := s1.Close(); err != nil {
		t.Fatalf("close s1: %v", err)
	}
	s3, err := Open(dir)
	if err != nil {
		t.Fatalf("open after close: %v", err)
	}
	s3.Close()
}

func TestCorruptStateRejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, stateFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	s, err := Open(dir)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("open corrupt err=%v, want ErrCorrupt", err)
	}
	if s != nil {
		s.Close()
	}
}

func TestUnsupportedVersionRejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, stateFileName), []byte(`{"version":2}`), 0o600); err != nil {
		t.Fatalf("write version: %v", err)
	}
	s, err := Open(dir)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("open version err=%v, want ErrUnsupported", err)
	}
	if s != nil {
		s.Close()
	}
}

func TestUnsupportedVersionDoesNotWipe(t *testing.T) {
	dir := t.TempDir()
	good := []byte(`{"version":1,"headers":[],"records":[],"consumed":{}}`)
	if err := os.WriteFile(filepath.Join(dir, stateFileName), good, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Simulate a future writer bumping the version.
	future := []byte(`{"version":99,"headers":[],"records":[],"consumed":{}}`)
	if err := os.WriteFile(filepath.Join(dir, stateFileName), future, 0o600); err != nil {
		t.Fatalf("write future: %v", err)
	}
	s, err := Open(dir)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err=%v, want ErrUnsupported", err)
	}
	if s != nil {
		s.Close()
	}
	// The on-disk file is untouched.
	got, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(future) {
		t.Fatal("state file was modified after rejecting unsupported version")
	}
}

func TestQueryMissing(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Query("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("query missing err=%v, want ErrNotFound", err)
	}
}

func TestPendingHasNoRetryTime(t *testing.T) {
	s := openTestStore(t)
	r, err := s.Submit(msg("m1", "chain-a", "chain-b", 1, 100, 100000))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if r.Status != StatusPending || r.NextRetry != nil {
		t.Fatalf("status=%s next_retry=%v, want pending/nil", r.Status, r.NextRetry)
	}
}

func TestInsufficientHeightKeepsWaiting(t *testing.T) {
	s := openTestStore(t)
	// Registered and trusted, but height below proof height.
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 50, Trusted: true}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	if _, err := s.Submit(msg("m1", "chain-a", "chain-b", 1, 100, 100000)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := s.Advance(1000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ := s.Query("m1")
	if r.Status != StatusWaitingHeader {
		t.Fatalf("status=%s, want waiting_header (height insufficient)", r.Status)
	}
	// Covering height arrives: success on the next due processing.
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 100, Trusted: true}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	if err := s.Advance(2000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ = s.Query("m1")
	if r.Status != StatusSuccess {
		t.Fatalf("status=%s, want success once height covers proof", r.Status)
	}
}

func TestWaitingMessageExpiresBeforeRetry(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 50, Trusted: false}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	if _, err := s.Submit(msg("m1", "chain-a", "chain-b", 1, 100, 1500)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := s.Advance(1000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ := s.Query("m1")
	if r.Status != StatusWaitingHeader {
		t.Fatalf("status=%s, want waiting_header", r.Status)
	}
	// Retry was scheduled for 2000, but the message expires at 1500.
	if err := s.Advance(1500); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ = s.Query("m1")
	if r.Status != StatusExpired {
		t.Fatalf("status=%s, want expired (expiry wins over pending retry)", r.Status)
	}
	if r.NextRetry != nil {
		t.Fatalf("expired record has retry time: %v", *r.NextRetry)
	}
}

func TestHeaderUpdateNeverReactivatesSuccess(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 200, Trusted: true}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	if _, err := s.Submit(msg("m1", "chain-a", "chain-b", 1, 100, 100000)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := s.Advance(1000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	// A later header update must not touch the terminal success record.
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 999, Trusted: true}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	if err := s.Advance(2000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r, _ := s.Query("m1")
	if r.Status != StatusSuccess {
		t.Fatalf("status=%s, want success (terminal record untouched)", r.Status)
	}
}

func TestDifferentNonceCombinationsIndependent(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetHeader(Header{Chain: "chain-a", Height: 200, Trusted: true}); err != nil {
		t.Fatalf("set header: %v", err)
	}
	// Same nonce, different destination: independent combinations.
	if _, err := s.Submit(msg("m1", "chain-a", "chain-b", 1, 100, 100000)); err != nil {
		t.Fatalf("submit m1: %v", err)
	}
	if _, err := s.Submit(msg("m2", "chain-a", "chain-c", 1, 100, 100000)); err != nil {
		t.Fatalf("submit m2: %v", err)
	}
	if err := s.Advance(1000); err != nil {
		t.Fatalf("advance: %v", err)
	}
	r1, _ := s.Query("m1")
	r2, _ := s.Query("m2")
	if r1.Status != StatusSuccess || r2.Status != StatusSuccess {
		t.Fatalf("m1=%s m2=%s, want both success", r1.Status, r2.Status)
	}
}
