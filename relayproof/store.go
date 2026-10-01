package relayproof

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// On-disk format (queue.log):
//
//	magic   = "RELAYPROOF-QUEUE-V1\n"
//	frame   = uint32-be payload length(N) | N bytes JSON payload | uint32-be CRC32-IEEE(payload)
//
// The log is an append-only write-ahead log. Every mutating operation is
// persisted as one framed, checksummed record and fsynced before it is
// acknowledged; a success record frames the local success entry and the nonce
// consumption together, so the two can never take effect separately.
//
// Crash recovery: a frame missing bytes at end of file, or a final frame with
// a bad checksum, is the torn tail of a write that was never acknowledged and
// is truncated. Bad checksums or framing anywhere before the end, a foreign
// header, or an unsupported version reject the directory with ErrCorrupt;
// state is never silently cleared.

const (
	logName          = "queue.log"
	logMagic         = "RELAYPROOF-QUEUE-V1\n"
	compactThreshold = 4 << 20 // compact when the active log grows past 4 MiB
	compactFileMode  = 0o600
	frameHeaderSize  = 4
	frameCRCsSize    = 4
)

// Log versions. v1 encoded nonce consumption as a single composite string
// (from + NUL + to + NUL + nonce), which collided for paths whose names
// contained separator bytes. v2 carries the three independent values.
const (
	currentLogV = 2
	logV1       = 1
	logV2       = 2
)

var crcTable = crc32.MakeTable(crc32.IEEE)

// JSON log entry kinds.
const (
	kindVersion = "version"
	kindSource  = "source"
	kindHeader  = "header"
	kindSubmit  = "submit"
	kindResult  = "result"
	kindState   = "state" // compacted snapshot: full status after >=1 attempts
	kindAdvance = "advance"
)

type logEntry struct {
	T string `json:"t"`
	V int    `json:"v,omitempty"`

	Chain   string `json:"chain,omitempty"`
	Height  int64  `json:"height,omitempty"`
	Root    string `json:"root,omitempty"`
	Trusted bool   `json:"trusted,omitempty"`

	Seq       int64  `json:"seq,omitempty"`
	ID        string `json:"id,omitempty"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	Nonce     uint64 `json:"nonce,omitempty"`
	Payload   string `json:"payload,omitempty"`
	ProofAt   int64  `json:"proofAt,omitempty"`
	ExpiresAt int64  `json:"expiresAt,omitempty"`

	Now        int64  `json:"now,omitempty"`
	Status     string `json:"status,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Attempts   int    `json:"attempts,omitempty"`
	NextRetry  int64  `json:"nextRetry,omitempty"`
	ConsumeKey string `json:"consumeKey,omitempty"` // v1 composite string (read-only legacy)
	ConsumeBy  string `json:"consumeBy,omitempty"`
	// v2 consumption triple, stored as three independent values.
	ConsumeFrom  string `json:"consumeFrom,omitempty"`
	ConsumeTo    string `json:"consumeTo,omitempty"`
	ConsumeNonce uint64 `json:"consumeNonce,omitempty"`
}

type store struct {
	dir  string
	f    *os.File
	size int64
	// snap, when set, supplies a live-state snapshot for log compaction.
	snap func() *loadedState
	// injectErr is a test hook forcing append to fail after opening the file.
	injectErr error
}

// loadedState is the fully replayed (or live) queue state.
type loadedState struct {
	sources  map[string]bool
	headers  map[string]Header
	records  map[string]*Record
	consumed map[ConsumeKey]string
	nextSeq  int64
	now      int64
}

func openStore(dir string) (*store, *loadedState, error) {
	path := filepath.Join(dir, logName)

	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("stat %s: %w", logName, err)
		}
		if err := createLog(path, dir); err != nil {
			return nil, nil, err
		}
	} else if err := checkMagic(path); err != nil {
		return nil, nil, err
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", logName, err)
	}
	goodLen, state, err := replayLog(raw)
	if err != nil {
		return nil, nil, err
	}
	if int64(len(raw)) != goodLen {
		// Drop the torn tail of an entry that can never have been acknowledged.
		tf, err := os.OpenFile(path, os.O_RDWR, compactFileMode)
		if err != nil {
			return nil, nil, fmt.Errorf("open %s for repair: %w", logName, err)
		}
		if err := tf.Truncate(goodLen); err != nil {
			tf.Close()
			return nil, nil, fmt.Errorf("truncate torn log tail: %w", err)
		}
		if err := tf.Sync(); err != nil {
			tf.Close()
			return nil, nil, fmt.Errorf("sync repaired %s: %w", logName, err)
		}
		if err := tf.Close(); err != nil {
			return nil, nil, err
		}
		if err := syncDir(dir); err != nil {
			return nil, nil, err
		}
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, compactFileMode)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s for append: %w", logName, err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, nil, err
	}
	return &store{dir: dir, f: f, size: goodLen}, state, nil
}

func createLog(path, dir string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, compactFileMode)
	if err != nil {
		return fmt.Errorf("create %s: %w", logName, err)
	}
	frame := encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))
	if _, err := f.Write(append([]byte(logMagic), frame...)); err != nil {
		f.Close()
		return fmt.Errorf("write %s header: %w", logName, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync %s: %w", logName, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	return syncDir(dir)
}

func mustMarshal(e *logEntry) []byte {
	b, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}
	return b
}

// encodeFrame wraps a payload with its big-endian length and CRC32.
func encodeFrame(payload []byte) []byte {
	frame := make([]byte, 0, frameHeaderSize+len(payload)+frameCRCsSize)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	frame = append(frame, hdr[:]...)
	frame = append(frame, payload...)
	var crc [4]byte
	binary.BigEndian.PutUint32(crc[:], crc32.Checksum(payload, crcTable))
	frame = append(frame, crc[:]...)
	return frame
}

func checkMagic(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", logName, err)
	}
	defer f.Close()
	buf := make([]byte, len(logMagic))
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return fmt.Errorf("read %s header: %w", logName, err)
	}
	if n < len(logMagic) || !bytes.Equal(buf, []byte(logMagic)) {
		return fmt.Errorf("%w: missing or foreign %s header", ErrCorrupt, logName)
	}
	return nil
}

// replayLog parses and validates the log, returning the byte length of the
// longest intact prefix and the reconstructed state.
func replayLog(raw []byte) (int64, *loadedState, error) {
	if !bytes.HasPrefix(raw, []byte(logMagic)) {
		return 0, nil, fmt.Errorf("%w: missing %s header", ErrCorrupt, logMagic)
	}
	pos := len(logMagic)
	state := &loadedState{
		sources:  map[string]bool{},
		headers:  map[string]Header{},
		records:  map[string]*Record{},
		consumed: map[ConsumeKey]string{},
	}

	sawVersion := false
	for pos < len(raw) {
		// Need at least the length header.
		if len(raw)-pos < frameHeaderSize {
			return int64(pos), state, nil // torn length header of an unacked write
		}
		n := int(binary.BigEndian.Uint32(raw[pos : pos+frameHeaderSize]))
		if n == 0 {
			return 0, nil, fmt.Errorf("%w: zero-length record at offset %d", ErrCorrupt, pos)
		}
		bodyStart := pos + frameHeaderSize
		frameEnd := bodyStart + n + frameCRCsSize
		if frameEnd > len(raw) {
			return int64(pos), state, nil // torn body/CRC of an unacked write
		}
		payload := raw[bodyStart : bodyStart+n]
		wantCRC := binary.BigEndian.Uint32(raw[bodyStart+n : frameEnd])
		if crc32.Checksum(payload, crcTable) != wantCRC {
			if frameEnd == len(raw) {
				// Torn sectors of the final, unacknowledged frame.
				return int64(pos), state, nil
			}
			return 0, nil, fmt.Errorf("%w: checksum mismatch at offset %d", ErrCorrupt, pos)
		}
		var e logEntry
		if err := json.Unmarshal(payload, &e); err != nil {
			return 0, nil, fmt.Errorf("%w: invalid record at offset %d: %v", ErrCorrupt, pos, err)
		}
		if !sawVersion {
			if e.T != kindVersion || (e.V != logV1 && e.V != logV2) {
				return 0, nil, fmt.Errorf("%w: unsupported log version entry: %+v", ErrCorrupt, e)
			}
			sawVersion = true
		} else if e.T == kindVersion {
			return 0, nil, fmt.Errorf("%w: unexpected version record at offset %d", ErrCorrupt, pos)
		} else if err := applyEntry(state, &e); err != nil {
			return 0, nil, err
		}
		pos = frameEnd
	}
	if !sawVersion {
		return 0, nil, fmt.Errorf("%w: missing version record", ErrCorrupt)
	}
	return int64(pos), state, nil
}

// oldStyleKey is the v1 nonce encoding: from, zero byte, to, zero byte,
// decimal nonce. Used only to validate v1 logs on open.
func oldStyleKey(from, to string, nonce uint64) string {
	return from + "\x00" + to + "\x00" + strconv.FormatUint(nonce, 10)
}

// applyConsumption validates a success entry's nonce consumption against the
// record's own message and records it. v1 logs encode the triple as a single
// composite consumeKey string; v2 logs carry the three independent values.
// Either way the consumption must match the message exactly, and the same
// triple can never be consumed twice.
func applyConsumption(s *loadedState, e *logEntry, rec *Record) error {
	corrupt := func(msg string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(msg, args...))
	}
	m := rec.Msg.Message
	if e.ConsumeBy != e.ID {
		return corrupt("success entry for %q carries mismatched consumer id", e.ID)
	}
	switch {
	case e.ConsumeKey != "":
		// v1: composite string must equal the old-style concatenation.
		if e.ConsumeKey != oldStyleKey(m.From, m.To, m.Nonce) {
			return corrupt("success entry for %q carries mismatched nonce consumption", e.ID)
		}
	case e.ConsumeFrom != "":
		// v2: three independent values must match the message.
		if e.ConsumeFrom != m.From || e.ConsumeTo != m.To || e.ConsumeNonce != m.Nonce {
			return corrupt("success entry for %q carries mismatched nonce consumption", e.ID)
		}
	default:
		return corrupt("success entry for %q carries no nonce consumption", e.ID)
	}
	key := consumeKeyOf(m.From, m.To, m.Nonce)
	if winner, taken := s.consumed[key]; taken {
		return corrupt("nonce combination already consumed by %q while accepting %q", winner, e.ID)
	}
	s.consumed[key] = e.ID
	return nil
}

func applyEntry(s *loadedState, e *logEntry) error {
	corrupt := func(msg string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(msg, args...))
	}
	switch e.T {
	case kindSource:
		if e.Chain == "" {
			return corrupt("source entry with empty chain")
		}
		s.sources[e.Chain] = true
	case kindHeader:
		if e.Chain == "" || e.Height < 0 {
			return corrupt("bad header entry: %+v", e)
		}
		s.headers[e.Chain] = Header{Chain: e.Chain, Height: e.Height, Root: e.Root, Trusted: e.Trusted}
	case kindSubmit:
		if e.ID == "" || e.From == "" || e.To == "" || e.ProofAt < 0 || e.ExpiresAt < 0 {
			return corrupt("bad submit entry: %+v", e)
		}
		if _, dup := s.records[e.ID]; dup {
			return corrupt("duplicate submit for id %q", e.ID)
		}
		if e.Seq != s.nextSeq {
			return corrupt("submit seq %d out of order, expected %d", e.Seq, s.nextSeq)
		}
		s.records[e.ID] = &Record{
			Msg: Envelope{
				Message: Message{
					ID:      e.ID,
					From:    e.From,
					To:      e.To,
					Nonce:   e.Nonce,
					Payload: e.Payload,
					ProofAt: e.ProofAt,
				},
				ExpiresAt: e.ExpiresAt,
			},
			Status: StatusPending,
			Reason: "awaiting first processing",
			Seq:    e.Seq,
		}
		s.nextSeq++
	case kindResult:
		rec, ok := s.records[e.ID]
		if !ok {
			return corrupt("result for unknown id %q", e.ID)
		}
		if isTerminal(rec.Status) {
			return corrupt("result for terminal id %q", e.ID)
		}
		if rec.Attempts > 0 && e.Now < rec.LastProcAt {
			return corrupt("result time %d before prior time %d for %q", e.Now, rec.LastProcAt, e.ID)
		}
		if e.Attempts != rec.Attempts+1 {
			return corrupt("attempts jump %d -> %d for %q", rec.Attempts, e.Attempts, e.ID)
		}
		if !validStatus(e.Status) || e.Status == StatusPending {
			return corrupt("bad result status %q for %q", e.Status, e.ID)
		}
		switch e.Status {
		case StatusWaiting:
			if e.NextRetry != e.Now+nextRetryDelay(e.Attempts) {
				return corrupt("waiting result has wrong retry schedule for %q", e.ID)
			}
		case StatusSuccess:
			if err := applyConsumption(s, e, rec); err != nil {
				return err
			}
			if e.NextRetry != 0 {
				return corrupt("success entry for %q carries retry time", e.ID)
			}
		default: // terminal failure kinds
			if e.NextRetry != 0 || e.ConsumeKey != "" || e.ConsumeBy != "" ||
				e.ConsumeFrom != "" || e.ConsumeTo != "" || e.ConsumeNonce != 0 {
				return corrupt("terminal entry for %q carries scheduling/consume fields", e.ID)
			}
		}
		rec.Attempts = e.Attempts
		rec.LastProcAt = e.Now
		rec.Status = e.Status
		rec.Reason = e.Reason
		rec.NextRetry = e.NextRetry
		if e.Now > s.now {
			s.now = e.Now
		}
	case kindState:
		// Compacted snapshot: the message already has >=1 attempts and the
		// entry carries its full current status, so there is no attempts-jump
		// invariant to check against prior result entries (there are none).
		rec, ok := s.records[e.ID]
		if !ok {
			return corrupt("state for unknown id %q", e.ID)
		}
		if rec.Attempts != 0 {
			return corrupt("duplicate state for id %q", e.ID)
		}
		if !validStatus(e.Status) || e.Status == StatusPending {
			return corrupt("bad state status %q for %q", e.Status, e.ID)
		}
		if e.Attempts < 1 {
			return corrupt("state with zero attempts for %q", e.ID)
		}
		switch e.Status {
		case StatusWaiting:
			if e.NextRetry != e.Now+nextRetryDelay(e.Attempts) {
				return corrupt("state has wrong retry schedule for %q", e.ID)
			}
		case StatusSuccess:
			if err := applyConsumption(s, e, rec); err != nil {
				return err
			}
			if e.NextRetry != 0 {
				return corrupt("success state for %q carries retry time", e.ID)
			}
		default:
			if e.NextRetry != 0 || e.ConsumeKey != "" || e.ConsumeBy != "" ||
				e.ConsumeFrom != "" || e.ConsumeTo != "" || e.ConsumeNonce != 0 {
				return corrupt("terminal state for %q carries scheduling/consume fields", e.ID)
			}
		}
		rec.Attempts = e.Attempts
		rec.LastProcAt = e.Now
		rec.Status = e.Status
		rec.Reason = e.Reason
		rec.NextRetry = e.NextRetry
		if e.Now > s.now {
			s.now = e.Now
		}
	case kindAdvance:
		if e.Now < s.now {
			return corrupt("advance checkpoint %d before known time %d", e.Now, s.now)
		}
		s.now = e.Now
	default:
		return corrupt("unknown record type %q", e.T)
	}
	return nil
}

func validStatus(s string) bool {
	switch s {
	case StatusPending, StatusWaiting, StatusSuccess, StatusReplay, StatusExpired, StatusUnknownSrc:
		return true
	}
	return false
}

func (s *store) close() error {
	if s.f == nil {
		return nil
	}
	err := s.f.Sync()
	cerr := s.f.Close()
	s.f = nil
	if err != nil {
		return err
	}
	return cerr
}

// forceClose releases the file without the final sync after a failed write.
func (s *store) forceClose() {
	if s.f == nil {
		return
	}
	s.f.Close()
	s.f = nil
}

// append writes one framed, checksummed, fsynced record.
func (s *store) append(e *logEntry) error {
	if s.injectErr != nil {
		return s.injectErr
	}
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode log entry: %w", err)
	}
	if _, err := s.f.Write(encodeFrame(body)); err != nil {
		return fmt.Errorf("write %s: %w", logName, err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", logName, err)
	}
	if info, err := s.f.Stat(); err == nil {
		s.size = info.Size()
	} else {
		s.size += int64(frameHeaderSize + len(body) + frameCRCsSize)
	}
	return nil
}

// needsCompaction reports whether the log crossed the compaction threshold.
func (s *store) needsCompaction() bool {
	return s.size > compactThreshold && s.snap != nil
}

func (s *store) appendRegisterSource(chain string) error {
	return s.append(&logEntry{T: kindSource, Chain: chain})
}

func (s *store) appendHeader(h Header) error {
	return s.append(&logEntry{T: kindHeader, Chain: h.Chain, Height: h.Height, Root: h.Root, Trusted: h.Trusted})
}

func (s *store) appendSubmit(rec *Record) error {
	m := rec.Msg.Message
	return s.append(&logEntry{
		T: kindSubmit, Seq: rec.Seq, ID: m.ID, From: m.From, To: m.To,
		Nonce: m.Nonce, Payload: m.Payload, ProofAt: m.ProofAt, ExpiresAt: rec.Msg.ExpiresAt,
	})
}

// appendResult records one processing outcome. On success the nonce
// consumption triple (consumeFrom/consumeTo/consumeNonce/consumeBy) is part of
// the same durable record, committing together atomically.
func (s *store) appendResult(now int64, rec *Record, status, reason string, attempts int, key ConsumeKey, consumeBy string, success bool) error {
	e := &logEntry{
		T: kindResult, Now: now, ID: rec.Msg.Message.ID,
		Status: status, Reason: reason, Attempts: attempts,
	}
	if status == StatusWaiting {
		e.NextRetry = now + nextRetryDelay(attempts)
	}
	if success {
		e.ConsumeFrom = key.From
		e.ConsumeTo = key.To
		e.ConsumeNonce = key.Nonce
		e.ConsumeBy = consumeBy
	}
	return s.append(e)
}

func (s *store) appendAdvance(now int64) error {
	return s.append(&logEntry{T: kindAdvance, Now: now})
}

// compact atomically replaces the log with a deterministic snapshot of live
// state. It must run while Queue.mu is held (no concurrent mutation), and only
// after in-memory state reflects every acknowledged append.
func (s *store) compact(state *loadedState) error {
	entries := []*logEntry{{T: kindVersion, V: currentLogV}}

	chains := make([]string, 0, len(state.sources))
	for c := range state.sources {
		chains = append(chains, c)
	}
	sort.Strings(chains)
	for _, c := range chains {
		entries = append(entries, &logEntry{T: kindSource, Chain: c})
	}

	headerChains := make([]string, 0, len(state.headers))
	for c := range state.headers {
		headerChains = append(headerChains, c)
	}
	sort.Strings(headerChains)
	for _, c := range headerChains {
		h := state.headers[c]
		entries = append(entries, &logEntry{T: kindHeader, Chain: h.Chain, Height: h.Height, Root: h.Root, Trusted: h.Trusted})
	}

	seqs := make([]int64, 0, len(state.records))
	bySeq := make(map[int64]*Record, len(state.records))
	for _, rec := range state.records {
		seqs = append(seqs, rec.Seq)
		bySeq[rec.Seq] = rec
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for _, seq := range seqs {
		rec := bySeq[seq]
		m := rec.Msg.Message
		entries = append(entries, &logEntry{
			T: kindSubmit, Seq: rec.Seq, ID: m.ID, From: m.From, To: m.To,
			Nonce: m.Nonce, Payload: m.Payload, ProofAt: m.ProofAt, ExpiresAt: rec.Msg.ExpiresAt,
		})
		if rec.Attempts > 0 {
			re := &logEntry{
				T: kindState, Now: rec.LastProcAt, ID: m.ID,
				Status: rec.Status, Reason: rec.Reason, Attempts: rec.Attempts,
			}
			if rec.Status == StatusWaiting {
				re.NextRetry = rec.NextRetry
			}
			if rec.Status == StatusSuccess {
				re.ConsumeFrom = m.From
				re.ConsumeTo = m.To
				re.ConsumeNonce = m.Nonce
				re.ConsumeBy = m.ID
			}
			entries = append(entries, re)
		}
	}
	if state.now > 0 {
		entries = append(entries, &logEntry{T: kindAdvance, Now: state.now})
	}

	tmp := filepath.Join(s.dir, logName+".compact")
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, compactFileMode)
	if err != nil {
		return err
	}
	abort := func(err error) error {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := f.WriteString(logMagic); err != nil {
		return abort(err)
	}
	for _, e := range entries {
		body, err := json.Marshal(e)
		if err != nil {
			return abort(err)
		}
		if _, err := f.Write(encodeFrame(body)); err != nil {
			return abort(err)
		}
	}
	if err := f.Sync(); err != nil {
		return abort(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, logName)); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := syncDir(s.dir); err != nil {
		return err
	}
	nf, err := os.OpenFile(filepath.Join(s.dir, logName), os.O_RDWR|os.O_APPEND, compactFileMode)
	if err != nil {
		return err
	}
	if _, err := nf.Seek(0, io.SeekEnd); err != nil {
		nf.Close()
		return err
	}
	s.f.Close()
	s.f = nf
	if info, err := nf.Stat(); err == nil {
		s.size = info.Size()
	}
	return nil
}

// syncDir fsyncs a directory so that file creation and rename survive a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync directory %s: %w", dir, err)
	}
	return nil
}
