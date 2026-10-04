// Package relayproof implements cross-chain message verification.
package relayproof

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"syscall"
)

// maxProcessTime is the largest legal processing time: non-negative int64
// Unix milliseconds, up to the int64 ceiling.
const maxProcessTime = math.MaxInt64

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
	// ErrHeaderConflict is returned when a trusted header is submitted at the
	// height of the accepted highest trusted header with a different root. The
	// accepted trusted header is kept and the queue remains usable.
	ErrHeaderConflict = errors.New("trusted header conflict: different root at the accepted height")
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

// AdvanceReport is the outcome of one Advance call.
type AdvanceReport struct {
	Now     int64
	Results []Result
}

// Result describes what happened to one message during an Advance.
type Result struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// headerState records the headers seen for one chain: the latest header
// written (any trust level) and the highest trusted header accepted. Proof
// coverage is determined solely by the highest trusted header — a later
// untrusted header, even at a greater height, can never lower or invalidate
// it. The zero value is a chain with no recorded headers.
type headerState struct {
	latest  Header
	trusted *Header
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

	now      int64                   // last advanced Unix-ms time, 0 = never advanced
	sources  map[string]bool         // registered source chains
	headers  map[string]*headerState // per-chain recorded headers (latest + highest trusted)
	records  map[string]*Record      // by message id
	order    []string                // non-terminal messages, submission order
	consumed map[consumeToken]string // (source, destination, nonce) -> successful message id
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
		headers:  map[string]*headerState{},
		records:  map[string]*Record{},
		consumed: map[consumeToken]string{},
		now:      q.now,
		nextSeq:  q.nextSeq,
	}
	for c := range q.sources {
		s.sources[c] = true
	}
	for c, h := range q.headers {
		cp := &headerState{latest: h.latest}
		if h.trusted != nil {
			t := *h.trusted
			cp.trusted = &t
		}
		s.headers[c] = cp
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

// UpsertHeader records a header for a chain. The latest header is always
// recorded, but proof coverage is determined solely by the highest trusted
// header accepted for the chain:
//
//   - the first trusted header establishes coverage;
//   - a higher trusted header advances it;
//   - a lower trusted header, or an untrusted header of any height, is
//     recorded but can never lower or invalidate established coverage;
//   - a trusted header at the current highest trusted height with the same
//     root is an idempotent no-op;
//   - a trusted header at that height with a different root is an
//     ErrHeaderConflict: the accepted trusted header is kept and the queue
//     remains usable.
//
// Header updates never bypass retry scheduling, never process messages, and
// never reactivate terminal messages.
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
	hs := q.headers[h.Chain]
	if hs == nil {
		hs = &headerState{}
		q.headers[h.Chain] = hs
	}
	if h.Trusted && hs.trusted != nil &&
		h.Height == hs.trusted.Height && h.Root != hs.trusted.Root {
		return fmt.Errorf("%w: chain %q height %d: submitted root %q conflicts with accepted root %q",
			ErrHeaderConflict, h.Chain, h.Height, h.Root, hs.trusted.Root)
	}
	if err := q.store.appendHeader(h); err != nil {
		return q.fail("upsert header", err)
	}
	hs.latest = h
	if h.Trusted && (hs.trusted == nil || h.Height > hs.trusted.Height) {
		t := h
		hs.trusted = &t
	}
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
//
// The retry instant saturates at the int64 ceiling: a waiting message whose
// computed retry would overflow is scheduled for math.MaxInt64 instead, never
// a negative, zero or earlier-than-processing instant. Once such a message has
// been processed at the ceiling, every later advance is at the same instant,
// so it is never due again and keeps its waiting status, reason, attempt
// count and ceiling retry time; it is neither reprocessed nor reported again
// as a waiting result. Replay and expiry checks, which run independently of
// the retry schedule, still apply to it, and a header update alone never
// delivers it.
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
		due := rec.Attempts == 0 || retryDue(rec, nowMs)
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
	token := newConsumeToken(rec.Msg.Message.From, rec.Msg.Message.To, rec.Msg.Message.Nonce)
	if winner, taken := q.consumed[token]; taken && winner != id {
		reason := "nonce combination already consumed by message " + winner
		o := newOutcome(rec, now, StatusReplay, reason)
		if err := q.commitOutcome(rec, o); err != nil {
			return Result{}, false, err
		}
		return o.result(), true, nil
	}
	if rec.Msg.ExpiresAt != 0 && now >= rec.Msg.ExpiresAt {
		reason := "expired at " + strconv.FormatInt(rec.Msg.ExpiresAt, 10)
		o := newOutcome(rec, now, StatusExpired, reason)
		if err := q.commitOutcome(rec, o); err != nil {
			return Result{}, false, err
		}
		return o.result(), true, nil
	}
	return Result{}, false, nil
}

// processDue classifies a due message against source registration and header
// trust, or delivers it.
func (q *Queue) processDue(rec *Record, now int64) (Result, error) {
	id := rec.Msg.Message.ID
	if !q.sources[rec.Msg.Message.From] {
		reason := "unknown source chain " + rec.Msg.Message.From
		o := newOutcome(rec, now, StatusUnknownSrc, reason)
		if err := q.commitOutcome(rec, o); err != nil {
			return Result{}, err
		}
		return o.result(), nil
	}
	hs := q.headers[rec.Msg.Message.From]
	if hs == nil || hs.trusted == nil || hs.trusted.Height < rec.Msg.Message.ProofAt {
		cur := int64(0)
		if hs != nil && hs.trusted != nil {
			cur = hs.trusted.Height
		}
		reason := fmt.Sprintf("waiting for trusted header covering height %d (current %d)", rec.Msg.Message.ProofAt, cur)
		o := newWaitingOutcome(rec, now, reason)
		if err := q.commitOutcome(rec, o); err != nil {
			return Result{}, err
		}
		return o.result(), nil
	}

	// Deliver: success record and nonce consumption are one log entry. The
	// coverage height is the highest trusted header actually accepted — never
	// a higher untrusted header.
	reason := "delivered; proof verified by trusted header at height " + strconv.FormatInt(hs.trusted.Height, 10)
	o := newOutcome(rec, now, StatusSuccess, reason)
	o.consumeToken = newConsumeToken(rec.Msg.Message.From, rec.Msg.Message.To, rec.Msg.Message.Nonce)
	o.consumeBy = id
	if err := q.commitOutcome(rec, o); err != nil {
		return Result{}, err
	}
	return o.result(), nil
}

// outcome is one fully determined processing result: the status and reason the
// message gets, which attempt it was, the retry instant a waiting result
// schedules, and — for a success — the (source, destination, nonce) triple the
// message consumes. Every processing path builds one and hands it to
// commitOutcome, so the rule for how a result is persisted and then reflected
// onto the live record is maintained in exactly one place.
type outcome struct {
	id        string
	status    string
	reason    string
	now       int64
	attempts  int
	nextRetry int64 // waiting only; zero clears any prior retry

	// success only: the consumed triple and the id of the consuming message.
	consumeToken consumeToken
	consumeBy    string
}

// newOutcome builds a non-waiting result (a terminal failure or a success).
// Success callers must set consumeToken/consumeBy; terminal failures never
// touch either and schedule no retry.
func newOutcome(rec *Record, now int64, status, reason string) outcome {
	return outcome{
		id:       rec.Msg.Message.ID,
		status:   status,
		reason:   reason,
		now:      now,
		attempts: rec.Attempts + 1,
	}
}

// newWaitingOutcome builds a waiting result with the canonical saturated
// backoff schedule for the new attempt.
func newWaitingOutcome(rec *Record, now int64, reason string) outcome {
	attempts := rec.Attempts + 1
	return outcome{
		id:        rec.Msg.Message.ID,
		status:    StatusWaiting,
		reason:    reason,
		now:       now,
		attempts:  attempts,
		nextRetry: nextRetryAt(now, attempts),
	}
}

// result renders the user-facing report row for a committed outcome.
func (o outcome) result() Result {
	return Result{ID: o.id, Status: o.status, Reason: o.reason}
}

// commitOutcome persists one processing result and, only once the write is
// durably acknowledged, makes it take effect on the live record. Nothing
// before a successful return changes the message: a failed write leaves the
// record's prior status, reason, attempt count, processing time and retry
// schedule untouched and leaves the nonce unconsumed, while the storage
// failure poisons the queue so this instance refuses every later write. On
// success the shared fields are applied once here; a success additionally
// records the nonce consumption, and every settled (non-waiting) result leaves
// the live processing order.
func (q *Queue) commitOutcome(rec *Record, o outcome) error {
	if err := q.store.appendOutcome(rec, o); err != nil {
		return q.fail(o.failOp(), err)
	}
	rec.Attempts = o.attempts
	rec.LastProcAt = o.now
	rec.Status = o.status
	rec.Reason = o.reason
	rec.NextRetry = o.nextRetry
	switch o.status {
	case StatusSuccess:
		q.consumed[o.consumeToken] = o.consumeBy
		q.removeFromOrder(o.consumeBy)
	case StatusWaiting:
		// stays live and processable and keeps its place in processing order
	default:
		q.removeFromOrder(rec.Msg.Message.ID)
	}
	return nil
}

// failOp names the storage operation in the ErrStorage message. The labels
// preserve the historical per-path wording.
func (o outcome) failOp() string {
	switch o.status {
	case StatusWaiting:
		return "schedule retry"
	case StatusSuccess:
		return "deliver"
	default:
		return "terminalize"
	}
}

// retryDue reports whether a waiting record's next retry is reached at now.
// Backoff delays are always positive, so every representable retry lies
// strictly after the processing time that scheduled it; a waiting message is
// therefore evaluated at most once per distinct processing time. The only
// instant where the retry cannot lie later is the int64 ceiling: there the
// schedule saturates to the ceiling itself. Once the message was processed at
// the ceiling, every legal advance is at the same instant, so the retry can
// never be reached "later" — treating equal time as due would reprocess the
// message on every advance, inflate attempts and re-report waiting forever.
func retryDue(rec *Record, now int64) bool {
	if now < rec.NextRetry {
		return false
	}
	return now != rec.LastProcAt
}

func (q *Queue) removeFromOrder(id string) {
	for i, cand := range q.order {
		if cand == id {
			q.order = append(q.order[:i], q.order[i+1:]...)
			return
		}
	}
}

// nextRetryAt returns the retry instant after the attempt-th processing at
// now: now plus the backoff delay, saturated at math.MaxInt64. Saturation
// keeps the scheduled retry non-negative, never zero (when processed at a
// positive time) and never earlier than the processing time; when the true
// retry overflows int64 the ceiling is the nearest representable instant.
func nextRetryAt(now int64, attempt int) int64 {
	delay := nextRetryDelay(attempt)
	if now > maxProcessTime-delay {
		return maxProcessTime // now+delay would overflow; delay is at most 60000
	}
	return now + delay
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
