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
	order    []string                // non-terminal messages, submission order; ids terminalized during an advance are dropped in one pass when that advance completes
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

	// The order slice is not mutated while an advance runs: outcomes only
	// change record fields, and the ids terminalized here are dropped from
	// the order in a single pass once processing is over. Both phases can
	// therefore iterate the live order directly, skipping records that are
	// already terminal.
	//
	// Phase 1: due messages, first-submission order.
	for _, id := range q.order {
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
	for _, id := range q.order {
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

	// Order maintenance: drop the messages this advance terminalized in one
	// pass, preserving the survivors' relative submission order. Removing
	// each terminalized id on the spot would make a burst of terminal
	// outcomes cost quadratic in the number of live messages.
	live := q.order[:0]
	for _, id := range q.order {
		if rec := q.records[id]; rec != nil && !isTerminal(rec.Status) {
			live = append(live, id)
		}
	}
	q.order = live

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
		r, err := q.applyOutcome(rec, now, terminalOutcome(StatusReplay, reason))
		if err != nil {
			return Result{}, false, err
		}
		return r, true, nil
	}
	if rec.Msg.ExpiresAt != 0 && now >= rec.Msg.ExpiresAt {
		reason := "expired at " + strconv.FormatInt(rec.Msg.ExpiresAt, 10)
		r, err := q.applyOutcome(rec, now, terminalOutcome(StatusExpired, reason))
		if err != nil {
			return Result{}, false, err
		}
		return r, true, nil
	}
	return Result{}, false, nil
}

// processDue classifies a due message against source registration and header
// trust, or delivers it.
func (q *Queue) processDue(rec *Record, now int64) (Result, error) {
	m := rec.Msg.Message
	if !q.sources[m.From] {
		reason := "unknown source chain " + m.From
		return q.applyOutcome(rec, now, terminalOutcome(StatusUnknownSrc, reason))
	}
	hs := q.headers[m.From]
	if hs == nil || hs.trusted == nil || hs.trusted.Height < m.ProofAt {
		cur := int64(0)
		if hs != nil && hs.trusted != nil {
			cur = hs.trusted.Height
		}
		reason := fmt.Sprintf("waiting for trusted header covering height %d (current %d)", m.ProofAt, cur)
		return q.applyOutcome(rec, now, waitingOutcome(reason))
	}

	// Deliver: success record and nonce consumption are one log entry. The
	// coverage height is the highest trusted header actually accepted — never
	// a higher untrusted header.
	token := newConsumeToken(m.From, m.To, m.Nonce)
	reason := "delivered; proof verified by trusted header at height " + strconv.FormatInt(hs.trusted.Height, 10)
	return q.applyOutcome(rec, now, successOutcome(reason, token))
}

// outcome describes one processing result independently of which path found
// it: waiting for header coverage, delivery, or one of the terminal rejections
// (replay, expiry, unknown source). It carries only the business differences
// between the result kinds; the rules shared by every result — one more
// attempt, the processing-time stamp, how the result is persisted and when the
// record may change — live solely in applyOutcome.
type outcome struct {
	status string
	reason string
	// consume is set only for success: the message's own
	// (source, destination, nonce) triple, attributed to that message. No
	// other result kind consumes a nonce.
	consume *consumeToken
	// op labels the failing operation in the storage error for this kind of
	// result, keeping each path's historical error wording.
	op string
}

// waitingOutcome keeps the message live with its status unchanged in kind and
// its existing backoff machinery: the actual retry instant is computed by
// applyOutcome from the processing time and the new attempt number.
func waitingOutcome(reason string) outcome {
	return outcome{status: StatusWaiting, reason: reason, op: "schedule retry"}
}

// terminalOutcome settles a non-success result that ends processing: replay,
// expiry or unknown-source. Such results clear the retry schedule, consume no
// nonce and leave the live processing order.
func terminalOutcome(status, reason string) outcome {
	return outcome{status: status, reason: reason, op: "terminalize"}
}

// successOutcome delivers the message: it clears the retry schedule, leaves
// the processing order and records consumption of the message's own triple,
// attributed to the message itself, in the same durable record as the success
// state.
func successOutcome(reason string, token consumeToken) outcome {
	return outcome{status: StatusSuccess, reason: reason, consume: &token, op: "deliver"}
}

// applyOutcome is the single path through which every processing result is
// saved and takes effect. It persists the result first and touches the record
// only after the save is acknowledged, so a failed write changes nothing: the
// message keeps its previous status, reason, attempt count, processing time
// and retry schedule, its nonce is not consumed, and earlier results already
// acknowledged in the same advance stay in force. On success every result
// counts exactly one more attempt and stamps LastProcAt with the processing
// time; a waiting result additionally keeps its saturated backoff schedule,
// while success and terminal results clear the retry time; success also
// records the nonce consumption. Terminal records stop being processed
// immediately via their status and are dropped from the live processing
// order by the enclosing advance's single closing pass.
func (q *Queue) applyOutcome(rec *Record, now int64, oc outcome) (Result, error) {
	id := rec.Msg.Message.ID
	attempt := rec.Attempts + 1
	nextRetry := int64(0)
	if oc.status == StatusWaiting {
		nextRetry = nextRetryAt(now, attempt)
	}
	if err := q.store.appendOutcome(now, rec, attempt, nextRetry, oc); err != nil {
		return Result{}, q.fail(oc.op, err)
	}
	rec.Attempts = attempt
	rec.LastProcAt = now
	rec.Status = oc.status
	rec.Reason = oc.reason
	rec.NextRetry = nextRetry
	if oc.consume != nil {
		q.consumed[*oc.consume] = id
	}
	return Result{ID: id, Status: oc.status, Reason: oc.reason}, nil
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
