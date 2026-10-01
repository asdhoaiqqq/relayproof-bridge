// Package relayproof implements cross-chain message verification.
package relayproof

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"syscall"
)

// Durable queue statuses. Pending and waiting are live; the rest are terminal.
const (
	StatusPending    = "pending"        // accepted, not processed for the first time yet
	StatusWaiting    = "waiting"        // processed, waiting for a trusted header at proof height
	StatusSuccess    = "success"        // recorded locally and nonce consumed
	StatusReplay     = "replay"         // nonce combination already consumed by another message
	StatusExpired    = "expired"        // absolute expiry reached before delivery
	StatusUnknownSrc = "unknown-source" // source chain was never registered
)

// Common errors. Callers can compare with errors.Is.
var (
	// ErrConflict is returned when an id is reused with different message content.
	ErrConflict = errors.New("message id conflict: existing record has different content")
	// ErrTerminal is returned when re-submitting a terminal id or attempting to
	// reactivate it.
	ErrTerminal = errors.New("message is terminal and cannot be reactivated")
	// ErrInvalidArg is returned for malformed input (empty id, bad times, ...).
	ErrInvalidArg = errors.New("invalid argument")
	// ErrLocked is returned when another process holds the state directory open.
	ErrLocked = errors.New("state directory is locked by another process")
	// ErrCorrupt is returned when on-disk state is unreadable or unsupported.
	ErrCorrupt = errors.New("state directory is corrupt or uses an unsupported format")
	// ErrStorage is returned after a storage failure; the queue must be reopened.
	ErrStorage = errors.New("storage failure; queue must be reopened")
)

// Envelope is a submitted message together with its absolute expiry time.
type Envelope struct {
	Message Message
	// ExpiresAt is an absolute Unix-millisecond instant. Zero means never expire.
	ExpiresAt int64
}

// Record is the full persisted state of one submitted message.
type Record struct {
	Msg        Envelope
	Status     string
	Reason     string
	Seq        int64 // submission order, zero-based
	Attempts   int   // number of processing attempts
	NextRetry  int64 // 0 when not yet processed, or terminal
	LastProcAt int64 // processing time of the most recent attempt
}

// Query is the user-visible view of a Record.
type Query struct {
	ID        string
	From      string
	To        string
	Nonce     uint64
	Payload   string
	ProofAt   int64
	ExpiresAt int64
	Status    string
	Reason    string
	NextRetry int64 // 0 = no retry scheduled (not yet processed, or terminal)
	Attempts  int
}

// Result describes what happened to one message during an Advance.
type Result struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// AdvanceReport is the outcome of one Advance call.
type AdvanceReport struct {
	Now     int64
	Results []Result
}

// ConsumeKey identifies one consumed (source chain, destination chain, nonce)
// triple. Chain names are compared as their exact UTF-8 content, so two
// distinct paths never share a consumption slot even when their names contain
// separator or zero bytes: "a\x00b" -> "c" and "a" -> "b\x00c" are different
// keys despite producing the same old-style composite string.
type ConsumeKey struct {
	From  string
	To    string
	Nonce uint64
}

// consumeKeyOf builds the consumption triple for a message.
func consumeKeyOf(from, to string, nonce uint64) ConsumeKey {
	return ConsumeKey{From: from, To: to, Nonce: nonce}
}

// Queue is a durable local outbox backed by a state directory. A single
// Queue owns the directory for writes; other processes attempting to Open the
// same directory fail with ErrLocked. It is safe for concurrent use by
// multiple goroutines, and a success record plus its nonce consumption commit
// as one durable unit.
type Queue struct {
	mu sync.Mutex

	store  *store
	flock  *os.File
	broken bool // a storage write failed; all further mutations fail

	now      int64              // last advanced Unix-ms time, 0 = never advanced
	sources  map[string]bool    // registered source chains
	headers  map[string]Header  // latest registered header per chain
	records  map[string]*Record // by message id
	order    []string           // non-terminal messages, submission order
	consumed map[ConsumeKey]string // consumption triple -> successful message id
	nextSeq  int64
}

// Open opens (creating if needed) a persistent queue backed by stateDir. It
// takes an exclusive process lock on the directory and refuses to start when
// the on-disk state is corrupt or in an unsupported format, never clearing it.
func Open(stateDir string) (*Queue, error) {
	if stateDir == "" {
		return nil, fmt.Errorf("%w: empty state directory", ErrInvalidArg)
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	abs, err := filepath.Abs(stateDir)
	if err != nil {
		return nil, fmt.Errorf("resolve state directory: %w", err)
	}

	lockPath := filepath.Join(abs, "lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("%w: %v", ErrLocked, err)
	}

	st, state, err := openStore(abs)
	if err != nil {
		syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		lock.Close()
		return nil, err
	}

	q := &Queue{
		store:    st,
		flock:    lock,
		sources:  state.sources,
		headers:  state.headers,
		records:  state.records,
		consumed: state.consumed,
		now:      state.now,
		nextSeq:  state.nextSeq,
	}
	q.order = q.reconstructOrder()
	st.snap = q.snapshot
	return q, nil
}

// reconstructOrder returns non-terminal record ids in submission (seq) order.
func (q *Queue) reconstructOrder() []string {
	seqs := make([]int64, 0, len(q.records))
	live := map[int64]string{}
	for id, rec := range q.records {
		if isTerminal(rec.Status) {
			continue
		}
		seqs = append(seqs, rec.Seq)
		live[rec.Seq] = id
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	order := make([]string, 0, len(seqs))
	for _, seq := range seqs {
		order = append(order, live[seq])
	}
	return order
}

// snapshot returns a detached copy of live state for log compaction. Callers
// must hold mu.
func (q *Queue) snapshot() *loadedState {
	s := &loadedState{
		sources:  map[string]bool{},
		headers:  map[string]Header{},
		records:  map[string]*Record{},
		consumed: map[ConsumeKey]string{},
		now:      q.now,
		nextSeq:  q.nextSeq,
	}
	for c := range q.sources {
		s.sources[c] = true
	}
	for c, h := range q.headers {
		s.headers[c] = h
	}
	for id, rec := range q.records {
		cp := *rec
		s.records[id] = &cp
	}
	for k, v := range q.consumed {
		s.consumed[k] = v
	}
	return s
}

// Close flushes, releases the directory lock and closes the queue.
func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.flock == nil {
		return nil
	}
	var err error
	if !q.broken {
		err = q.store.close()
	} else {
		q.store.forceClose()
	}
	syscall.Flock(int(q.flock.Fd()), syscall.LOCK_UN)
	q.flock.Close()
	q.flock = nil
	return err
}

// fail locks in a storage failure: the log tail may be partially written, so
// no further appends are allowed in this process (another append would turn a
// truncatable torn tail into unrecoverable corruption).
func (q *Queue) fail(op string, err error) error {
	q.broken = true
	return fmt.Errorf("%w: %s: %v", ErrStorage, op, err)
}

func (q *Queue) checkWritable() error {
	if q.flock == nil {
		return fmt.Errorf("%w: queue is closed", ErrStorage)
	}
	if q.broken {
		return fmt.Errorf("%w: a previous write failed; reopen the queue", ErrStorage)
	}
	return nil
}

// RegisterSource records that messages may originate from chain. Idempotent.
func (q *Queue) RegisterSource(chain string) error {
	if chain == "" {
		return fmt.Errorf("%w: empty source chain", ErrInvalidArg)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.checkWritable(); err != nil {
		return err
	}
	if q.sources[chain] {
		return nil
	}
	if err := q.store.appendRegisterSource(chain); err != nil {
		return q.fail("register source", err)
	}
	q.sources[chain] = true
	return q.maybeCompact()
}

// UpsertHeader stores the latest known header for a chain. A header with
// Trusted=false records the chain tip but grants no proof coverage; a later
// trusted header covering the proof height can unblock waiting messages.
// Header updates never bypass retry scheduling and never reactivate terminal
// messages.
func (q *Queue) UpsertHeader(h Header) error {
	if h.Chain == "" {
		return fmt.Errorf("%w: empty header chain", ErrInvalidArg)
	}
	if h.Height < 0 {
		return fmt.Errorf("%w: negative header height", ErrInvalidArg)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.checkWritable(); err != nil {
		return err
	}
	if err := q.store.appendHeader(h); err != nil {
		return q.fail("upsert header", err)
	}
	q.headers[h.Chain] = h
	return q.maybeCompact()
}

// Submit enqueues a message with an absolute expiry (Unix milliseconds; zero
// means never expire). Re-submitting the same id with identical content
// returns the existing record without adding a queue entry; the same id with
// different content returns ErrConflict and leaves the original untouched;
// re-submitting a terminal id returns ErrTerminal. Success is reported only
// after the submission is durably persisted.
func (q *Queue) Submit(env Envelope) (*Record, error) {
	m := env.Message
	if m.ID == "" {
		return nil, fmt.Errorf("%w: empty message id", ErrInvalidArg)
	}
	if m.From == "" || m.To == "" {
		return nil, fmt.Errorf("%w: empty source or destination chain", ErrInvalidArg)
	}
	if m.ProofAt < 0 {
		return nil, fmt.Errorf("%w: negative proof height", ErrInvalidArg)
	}
	if env.ExpiresAt < 0 {
		return nil, fmt.Errorf("%w: negative expiry time", ErrInvalidArg)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.checkWritable(); err != nil {
		return nil, err
	}

	if existing, ok := q.records[m.ID]; ok {
		if isTerminal(existing.Status) {
			return nil, fmt.Errorf("%w: message %s is %s", ErrTerminal, m.ID, existing.Status)
		}
		if sameEnvelope(existing.Msg, env) {
			out := *existing
			return &out, nil
		}
		return nil, fmt.Errorf("%w: message %s", ErrConflict, m.ID)
	}

	rec := &Record{
		Msg:    env,
		Status: StatusPending,
		Reason: "awaiting first processing",
		Seq:    q.nextSeq,
	}
	if err := q.store.appendSubmit(rec); err != nil {
		return nil, q.fail("submit", err)
	}
	q.records[m.ID] = rec
	q.order = append(q.order, m.ID)
	q.nextSeq++
	if err := q.maybeCompact(); err != nil {
		return nil, err
	}
	out := *rec
	return &out, nil
}

// Advance moves processing time to nowMs (Unix milliseconds). Equal time may
// be advanced repeatedly; going backwards is rejected and changes nothing.
//
// Each advance, in submission order:
//  1. due messages (new messages are due on the next advance; others when now
//     has reached their next retry time) are evaluated for replay and expiry,
//     replay winning on a tie and now == ExpiresAt counting as expired, then
//     for source registration and trusted-header coverage, and finally
//     delivered;
//  2. afterwards every remaining non-terminal message, regardless of its
//     retry schedule, is re-checked for replay and expiry at the new time.
//
// Unregistered sources are permanently rejected as unknown-source; registered
// sources without a trusted header covering the proof height stay waiting and
// do not consume the nonce. Waiting retry intervals are 1,2,4,... seconds,
// doubling to a 60-second cap, measured from the actual processing time;
// jumping over several intervals still costs one attempt.
func (q *Queue) Advance(nowMs int64) (*AdvanceReport, error) {
	if nowMs < 0 {
		return nil, fmt.Errorf("%w: negative processing time", ErrInvalidArg)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.checkWritable(); err != nil {
		return nil, err
	}
	if q.now != 0 && nowMs < q.now {
		return nil, fmt.Errorf("%w: processing time %d precedes last advanced time %d", ErrInvalidArg, nowMs, q.now)
	}

	report := &AdvanceReport{Now: nowMs}

	// Phase 1: due messages, first-submission order.
	for _, id := range append([]string(nil), q.order...) {
		rec := q.records[id]
		if rec == nil || isTerminal(rec.Status) {
			continue
		}
		due := rec.Attempts == 0 || nowMs >= rec.NextRetry
		if !due {
			continue
		}
		if r, done, err := q.checkReplayExpiry(rec, nowMs); err != nil {
			return nil, err
		} else if done {
			report.Results = append(report.Results, r)
			continue
		}
		r, err := q.processDue(rec, nowMs)
		if err != nil {
			return nil, err
		}
		report.Results = append(report.Results, r)
	}

	// Phase 2: replay/expiry hold for every non-terminal message at the new
	// time, even while its retry backoff is still running.
	for _, id := range append([]string(nil), q.order...) {
		rec := q.records[id]
		if rec == nil || isTerminal(rec.Status) {
			continue
		}
		if r, done, err := q.checkReplayExpiry(rec, nowMs); err != nil {
			return nil, err
		} else if done {
			report.Results = append(report.Results, r)
		}
	}

	if err := q.store.appendAdvance(nowMs); err != nil {
		return nil, q.fail("advance", err)
	}
	q.now = nowMs
	if err := q.maybeCompact(); err != nil {
		return nil, err
	}
	return report, nil
}

// maybeCompact rewrites the WAL as a snapshot once it grows past the
// threshold. Live state already reflects every acknowledged append, so the
// snapshot cannot lose records. A compaction failure is a storage failure:
// the queue is marked broken and must be reopened.
func (q *Queue) maybeCompact() error {
	if !q.store.needsCompaction() {
		return nil
	}
	if err := q.store.compact(q.snapshot()); err != nil {
		return q.fail("compact log", err)
	}
	return nil
}

// checkReplayExpiry terminalizes rec when its nonce was consumed by another
// message or its absolute expiry has been reached. Replay wins when both
// hold. The bool reports whether the message was terminalized.
func (q *Queue) checkReplayExpiry(rec *Record, now int64) (Result, bool, error) {
	id := rec.Msg.Message.ID
	key := consumeKeyOf(rec.Msg.Message.From, rec.Msg.Message.To, rec.Msg.Message.Nonce)
	if winner, taken := q.consumed[key]; taken && winner != id {
		reason := "nonce combination already consumed by message " + winner
		if err := q.terminalize(rec, now, StatusReplay, reason); err != nil {
			return Result{}, false, err
		}
		return Result{ID: id, Status: StatusReplay, Reason: reason}, true, nil
	}
	if rec.Msg.ExpiresAt != 0 && now >= rec.Msg.ExpiresAt {
		reason := "expired at " + strconv.FormatInt(rec.Msg.ExpiresAt, 10)
		if err := q.terminalize(rec, now, StatusExpired, reason); err != nil {
			return Result{}, false, err
		}
		return Result{ID: id, Status: StatusExpired, Reason: reason}, true, nil
	}
	return Result{}, false, nil
}

// processDue classifies a due message against source registration and header
// trust, or delivers it.
func (q *Queue) processDue(rec *Record, now int64) (Result, error) {
	id := rec.Msg.Message.ID
	if !q.sources[rec.Msg.Message.From] {
		reason := "unknown source chain " + rec.Msg.Message.From
		if err := q.terminalize(rec, now, StatusUnknownSrc, reason); err != nil {
			return Result{}, err
		}
		return Result{ID: id, Status: StatusUnknownSrc, Reason: reason}, nil
	}
	h, hasHeader := q.headers[rec.Msg.Message.From]
	if !hasHeader || !h.Trusted || h.Height < rec.Msg.Message.ProofAt {
		cur := int64(0)
		if hasHeader {
			cur = h.Height
		}
		reason := fmt.Sprintf("waiting for trusted header covering height %d (current %d)", rec.Msg.Message.ProofAt, cur)
		if err := q.markWaiting(rec, now, reason); err != nil {
			return Result{}, err
		}
		return Result{ID: id, Status: StatusWaiting, Reason: reason}, nil
	}

	// Deliver: success record and nonce consumption are one log entry.
	key := consumeKeyOf(rec.Msg.Message.From, rec.Msg.Message.To, rec.Msg.Message.Nonce)
	reason := "delivered; proof verified by trusted header at height " + strconv.FormatInt(h.Height, 10)
	if err := q.store.appendResult(now, rec, StatusSuccess, reason, rec.Attempts+1, key, id, true); err != nil {
		return Result{}, q.fail("deliver", err)
	}
	rec.Attempts++
	rec.LastProcAt = now
	rec.Status = StatusSuccess
	rec.Reason = reason
	rec.NextRetry = 0
	q.consumed[key] = id
	q.removeFromOrder(id)
	return Result{ID: id, Status: StatusSuccess, Reason: reason}, nil
}

func (q *Queue) terminalize(rec *Record, now int64, status, reason string) error {
	if err := q.store.appendResult(now, rec, status, reason, rec.Attempts+1, ConsumeKey{}, "", false); err != nil {
		return q.fail("terminalize", err)
	}
	rec.Attempts++
	rec.LastProcAt = now
	rec.Status = status
	rec.Reason = reason
	rec.NextRetry = 0
	q.removeFromOrder(rec.Msg.Message.ID)
	return nil
}

func (q *Queue) markWaiting(rec *Record, now int64, reason string) error {
	attempt := rec.Attempts + 1
	if err := q.store.appendResult(now, rec, StatusWaiting, reason, attempt, ConsumeKey{}, "", false); err != nil {
		return q.fail("schedule retry", err)
	}
	rec.Attempts = attempt
	rec.LastProcAt = now
	rec.Status = StatusWaiting
	rec.Reason = reason
	rec.NextRetry = now + nextRetryDelay(attempt)
	return nil
}

func (q *Queue) removeFromOrder(id string) {
	for i, cand := range q.order {
		if cand == id {
			q.order = append(q.order[:i], q.order[i+1:]...)
			return
		}
	}
}

// nextRetryDelay is the backoff after the attempt-th processing (1-based):
// 1s, 2s, 4s, 8s, 16s, 32s, then 60s capped, in milliseconds.
func nextRetryDelay(attempt int) int64 {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 6 {
		return 60_000
	}
	return int64(1) << (attempt - 1) * 1000
}

func isTerminal(status string) bool {
	switch status {
	case StatusSuccess, StatusReplay, StatusExpired, StatusUnknownSrc:
		return true
	}
	return false
}

func sameEnvelope(a, b Envelope) bool {
	return a.ExpiresAt == b.ExpiresAt &&
		a.Message.ID == b.Message.ID &&
		a.Message.From == b.Message.From &&
		a.Message.To == b.Message.To &&
		a.Message.Nonce == b.Message.Nonce &&
		a.Message.Payload == b.Message.Payload &&
		a.Message.ProofAt == b.Message.ProofAt
}

// Query returns the current state of a message.
func (q *Queue) Query(id string) (Query, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	rec, ok := q.records[id]
	if !ok {
		return Query{}, false
	}
	return toQuery(rec), true
}

// Queries returns all records in first-submission order.
func (q *Queue) Queries() []Query {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Query, 0, len(q.records))
	for _, rec := range q.records {
		out = append(out, toQuery(rec))
	}
	sort.Slice(out, func(i, j int) bool {
		return q.records[out[i].ID].Seq < q.records[out[j].ID].Seq
	})
	return out
}

// Now returns the last advanced processing time, or 0 if never advanced.
func (q *Queue) Now() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.now
}

func toQuery(rec *Record) Query {
	return Query{
		ID:        rec.Msg.Message.ID,
		From:      rec.Msg.Message.From,
		To:        rec.Msg.Message.To,
		Nonce:     rec.Msg.Message.Nonce,
		Payload:   rec.Msg.Message.Payload,
		ProofAt:   rec.Msg.Message.ProofAt,
		ExpiresAt: rec.Msg.ExpiresAt,
		Status:    rec.Status,
		Reason:    rec.Reason,
		NextRetry: rec.NextRetry,
		Attempts:  rec.Attempts,
	}
}
