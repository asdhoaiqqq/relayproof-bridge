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
// A success (result or compacted state) names the consumed triple in three
// independent fields, consumeFrom/consumeTo/consumeNonce, alongside consumeBy.
// Chain names are stored verbatim as raw UTF-8 — they may contain ':' or even
// U+0000 — so the triple is never flattened into one delimiter-joined string,
// which would let distinct routing paths share one consumption identity.
//
// Crash recovery: a frame missing bytes at end of file, or a final frame with
// a bad checksum, is the torn tail of a write that was never acknowledged and
// is truncated. That recovery is only available once the log's leading
// version record has itself been read whole and verified: the magic alone
// never establishes a usable version, so a log whose very first record is
// partial (only some length bytes, or the length without the body and CRC),
// complete but checksum-bad, not a version record, or names an unsupported
// version is rejected wholesale with ErrCorrupt and left byte-for-byte
// untouched — it can never be truncated down to an empty-looking log that a
// later append would turn into a headerless one. Bad checksums or framing
// anywhere before the end, a foreign header, or an unsupported version
// likewise reject the directory with ErrCorrupt; state is never silently
// cleared.
//
// Logs written by older builds recorded the consumption as one NUL-joined
// consumeKey string. Such success entries are still accepted on replay: the
// key is validated against the record's own (from,to,nonce) and consumeBy,
// and only the record's own triple is marked consumed. A legacy key that does
// not match the record it is attached to — a genuinely inconsistent old
// record — rejects the whole directory with ErrCorrupt instead of silently
// accepting or "repairing" the bad entry.

const (
	logName          = "queue.log"
	logMagic         = "RELAYPROOF-QUEUE-V1\n"
	compactThreshold = 4 << 20 // compact when the active log grows past 4 MiB
	compactFileMode  = 0o600
	frameHeaderSize  = 4
	frameCRCsSize    = 4
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
	currentLogV = 1
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

	Now       int64  `json:"now,omitempty"`
	Status    string `json:"status,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Attempts  int    `json:"attempts,omitempty"`
	NextRetry int64  `json:"nextRetry,omitempty"`

	// Consumed triple of a success entry, stored as three independent values
	// so routing paths that share a flattened key stay distinct. consumeBy is
	// the id of the successful message.
	ConsumeFrom  string `json:"consumeFrom,omitempty"`
	ConsumeTo    string `json:"consumeTo,omitempty"`
	ConsumeNonce uint64 `json:"consumeNonce,omitempty"`
	ConsumeBy    string `json:"consumeBy,omitempty"`

	// ConsumeKey is the legacy (pre-triple) NUL-joined consumption string. It
	// is accepted only while replaying logs written by older builds and is
	// never written anymore.
	ConsumeKey string `json:"consumeKey,omitempty"`
}

// legacyNonceKey reproduces the consumption string used by older builds:
// from NUL to NUL nonce. It exists solely to validate records in pre-existing
// state directories; new state always uses consumeToken triples.
func legacyNonceKey(from, to string, nonce uint64) string {
	return from + "\x00" + to + "\x00" + strconv.FormatUint(nonce, 10)
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
	headers  map[string]*headerState
	records  map[string]*Record
	consumed map[consumeToken]string
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
	state := &loadedState{
		sources:  map[string]bool{},
		headers:  map[string]*headerState{},
		records:  map[string]*Record{},
		consumed: map[consumeToken]string{},
	}

	// The leading version record is the precondition for every later recovery
	// decision: nothing after the magic can be replayed or treated as a
	// truncatable tail until it has been read complete, checksummed and
	// confirmed to be a supported version. Validate it on its own so a torn or
	// bad first record can never look like an empty log that is safe to append
	// to.
	verEnd, err := readVersionRecord(raw, len(logMagic))
	if err != nil {
		return 0, nil, err
	}
	pos := verEnd

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
		if e.T == kindVersion {
			return 0, nil, fmt.Errorf("%w: unexpected version record at offset %d", ErrCorrupt, pos)
		}
		if err := applyEntry(state, &e); err != nil {
			return 0, nil, err
		}
		pos = frameEnd
	}
	return int64(pos), state, nil
}

// readVersionRecord reads and validates the log's first record at offset
// start, returning the offset just past it. A correct magic prefix alone is
// not a valid log: the version record must be fully present, its checksum
// must match, and it must name a supported version. Every other shape — a
// record cut short at end of file (one to three length bytes, or the length
// without the body and CRC), a complete final record with a bad checksum,
// invalid JSON, a non-version record, or an unsupported version — is a
// corrupt log, never a truncatable tail.
func readVersionRecord(raw []byte, start int) (int, error) {
	if len(raw)-start < frameHeaderSize {
		return 0, fmt.Errorf("%w: incomplete version record: only %d of %d length bytes after header",
			ErrCorrupt, len(raw)-start, frameHeaderSize)
	}
	n := int(binary.BigEndian.Uint32(raw[start : start+frameHeaderSize]))
	if n == 0 {
		return 0, fmt.Errorf("%w: zero-length version record at offset %d", ErrCorrupt, start)
	}
	bodyStart := start + frameHeaderSize
	frameEnd := bodyStart + n + frameCRCsSize
	if frameEnd > len(raw) {
		return 0, fmt.Errorf("%w: incomplete version record: length %d but only %d body/checksum bytes present",
			ErrCorrupt, n, len(raw)-bodyStart)
	}
	payload := raw[bodyStart : bodyStart+n]
	wantCRC := binary.BigEndian.Uint32(raw[bodyStart+n : frameEnd])
	if crc32.Checksum(payload, crcTable) != wantCRC {
		return 0, fmt.Errorf("%w: checksum mismatch in version record at offset %d", ErrCorrupt, start)
	}
	var e logEntry
	if err := json.Unmarshal(payload, &e); err != nil {
		return 0, fmt.Errorf("%w: invalid version record at offset %d: %v", ErrCorrupt, start, err)
	}
	if e.T != kindVersion {
		return 0, fmt.Errorf("%w: first record is %q, not a version record", ErrCorrupt, e.T)
	}
	if e.V != currentLogV {
		return 0, fmt.Errorf("%w: unsupported log version %d", ErrCorrupt, e.V)
	}
	return frameEnd, nil
}

// entryCarriesConsumption reports whether a non-success entry smuggles any
// consumption field, which is always corrupt.
func entryCarriesConsumption(e *logEntry) bool {
	return e.ConsumeFrom != "" || e.ConsumeTo != "" || e.ConsumeNonce != 0 ||
		e.ConsumeKey != "" || e.ConsumeBy != ""
}

// acceptConsumption validates the triple consumed by a success result or
// compacted state entry and records it in s.consumed. The triple must
// identify the record's own message and be consumed by that message.
//
// Logs written by older builds carry the consumption as one NUL-joined
// consumeKey. Such an entry is accepted only when that legacy key matches the
// record's own triple; it is the record's own triple that is marked consumed,
// never the ambiguous flattened string — so two distinct paths that happened
// to share one old flattened key each consume only themselves. A legacy key
// that does not match its record is an inconsistent record and rejected.
func acceptConsumption(s *loadedState, rec *Record, e *logEntry, corrupt func(string, ...any) error) (consumeToken, error) {
	m := rec.Msg.Message
	if e.ConsumeBy != e.ID {
		return consumeToken{}, corrupt("success entry for %q is marked consumed by %q", e.ID, e.ConsumeBy)
	}
	token := newConsumeToken(m.From, m.To, m.Nonce)
	hasTriple := e.ConsumeFrom != "" || e.ConsumeTo != "" || e.ConsumeNonce != 0
	switch {
	case hasTriple:
		if e.ConsumeKey != "" {
			return consumeToken{}, corrupt("success entry for %q carries both a triple and a legacy consume key", e.ID)
		}
		if e.ConsumeFrom != m.From || e.ConsumeTo != m.To || e.ConsumeNonce != m.Nonce {
			return consumeToken{}, corrupt("success entry for %q carries mismatched nonce consumption: %q -> %q nonce %d", e.ID, e.ConsumeFrom, e.ConsumeTo, e.ConsumeNonce)
		}
	case e.ConsumeKey != "":
		if want := legacyNonceKey(m.From, m.To, m.Nonce); e.ConsumeKey != want {
			return consumeToken{}, corrupt("success entry for %q carries a legacy consume key for a different path", e.ID)
		}
	default:
		return consumeToken{}, corrupt("success entry for %q carries no nonce consumption", e.ID)
	}
	if winner, taken := s.consumed[token]; taken {
		return consumeToken{}, corrupt("nonce %s already consumed by %q while accepting %q", token, winner, e.ID)
	}
	s.consumed[token] = e.ID
	return token, nil
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
		// Replay is permissive: historical same-height coverage is never
		// rejected as a conflict, and recovery relies only on the header
		// records actually kept in the log. The latest header is the last one
		// written; the highest trusted header is the max-height trusted one,
		// with ties going to the later write (matching old overwrite
		// semantics). Neither is fabricated from lost history.
		hs := s.headers[e.Chain]
		if hs == nil {
			hs = &headerState{}
			s.headers[e.Chain] = hs
		}
		hs.latest = Header{Chain: e.Chain, Height: e.Height, Root: e.Root, Trusted: e.Trusted}
		if e.Trusted && (hs.trusted == nil || e.Height >= hs.trusted.Height) {
			t := hs.latest
			hs.trusted = &t
		}
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
			if e.NextRetry != retryAt(e.Now, e.Attempts) {
				return corrupt("waiting result has wrong retry schedule for %q", e.ID)
			}
			if entryCarriesConsumption(e) {
				return corrupt("waiting result for %q carries nonce consumption fields", e.ID)
			}
		case StatusSuccess:
			if e.NextRetry != 0 {
				return corrupt("success entry for %q carries retry time", e.ID)
			}
			if _, err := acceptConsumption(s, rec, e, corrupt); err != nil {
				return err
			}
		default: // terminal failure kinds
			if e.NextRetry != 0 || entryCarriesConsumption(e) {
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
			if e.NextRetry != retryAt(e.Now, e.Attempts) {
				return corrupt("state has wrong retry schedule for %q", e.ID)
			}
			if entryCarriesConsumption(e) {
				return corrupt("waiting state for %q carries nonce consumption fields", e.ID)
			}
		case StatusSuccess:
			if e.NextRetry != 0 {
				return corrupt("success state for %q carries retry time", e.ID)
			}
			if _, err := acceptConsumption(s, rec, e, corrupt); err != nil {
				return err
			}
		default:
			if e.NextRetry != 0 || entryCarriesConsumption(e) {
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

// appendResult records one processing outcome. On success the consumed triple
// (consumeFrom/consumeTo/consumeNonce) and its consumer are part of the same
// durable record, committing together atomically. token is nil for every
// non-success status.
func (s *store) appendResult(now int64, rec *Record, status, reason string, attempts int, token *consumeToken, consumeBy string) error {
	e := &logEntry{
		T: kindResult, Now: now, ID: rec.Msg.Message.ID,
		Status: status, Reason: reason, Attempts: attempts,
	}
	if status == StatusWaiting {
		e.NextRetry = retryAt(now, attempts)
	}
	if status == StatusSuccess {
		if token == nil || consumeBy == "" {
			return fmt.Errorf("internal error: success result for %q missing nonce consumption", rec.Msg.Message.ID)
		}
		e.ConsumeFrom = token.from
		e.ConsumeTo = token.to
		e.ConsumeNonce = token.nonce
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
		hs := state.headers[c]
		// Write the highest trusted header first, then the latest header when
		// it differs. Replay reconstructs latest as the last entry and the
		// highest trusted as the max-height trusted entry, so this order
		// restores both exactly.
		if hs.trusted != nil {
			entries = append(entries, &logEntry{T: kindHeader, Chain: hs.trusted.Chain, Height: hs.trusted.Height, Root: hs.trusted.Root, Trusted: hs.trusted.Trusted})
		}
		if hs.trusted == nil || hs.latest != *hs.trusted {
			entries = append(entries, &logEntry{T: kindHeader, Chain: hs.latest.Chain, Height: hs.latest.Height, Root: hs.latest.Root, Trusted: hs.latest.Trusted})
		}
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
