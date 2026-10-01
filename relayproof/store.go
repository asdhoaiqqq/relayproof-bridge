package relayproof

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Status codes for queued records.
const (
	StatusPending       = "pending"        // 待处理：已提交，尚未首次处理
	StatusWaitingHeader = "waiting_header" // 等待可信头：来源已登记但头不可信或高度不足
	StatusSuccess       = "success"        // 成功：已进入本地成功记录并消费 nonce 组合
	StatusReplay        = "replay"         // 重放：nonce 组合已被消费
	StatusExpired       = "expired"        // 超时：已到或超过绝对过期时刻
	StatusUnknownSource = "unknown_source" // 未知来源：来源链未登记，永久拒绝
)

// Store errors.
var (
	ErrConflict     = errors.New("message id conflict: different content already exists")
	ErrNotFound     = errors.New("message not found")
	ErrLocked       = errors.New("state directory is locked by another process")
	ErrCorrupt      = errors.New("state file is corrupt")
	ErrUnsupported  = errors.New("unsupported state format version")
	ErrTimeBackward = errors.New("cannot advance processing time backwards")
)

const (
	stateFileName = "store.json"
	lockFileName  = "LOCK"
	stateVersion  = 1
)

// Record is one queued message and its current processing state.
type Record struct {
	Message   Message `json:"message"`
	Status    string  `json:"status"`
	Reason    string  `json:"reason"`
	Attempts  int     `json:"attempts"`
	NextRetry *int64  `json:"next_retry"`
	Seq       int64   `json:"seq"`
}

// Store is a persistent, single-writer message queue backed by a state directory.
type Store struct {
	dir   string
	lock  *os.File
	state *persistedState
	byID  map[string]*Record
}

type persistedState struct {
	Version  int               `json:"version"`
	Time     int64             `json:"time"`
	HasTime  bool              `json:"has_time"`
	Headers  map[string]Header `json:"headers"`
	Records  []*Record         `json:"records"`
	Consumed map[string]bool   `json:"consumed"`
}

// wireState is the on-disk representation with deterministic ordering.
type wireState struct {
	Version  int               `json:"version"`
	Time     int64             `json:"time"`
	HasTime  bool              `json:"has_time"`
	Headers  []Header          `json:"headers"`
	Records  []*Record         `json:"records"`
	Consumed map[string]bool   `json:"consumed"`
}

// Open opens (or creates) the state directory and acquires the exclusive write lock.
// Only one process may hold the directory open at a time; a second opener fails immediately.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	lockPath := filepath.Join(dir, lockFileName)
	lf, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lf.Close()
		return nil, fmt.Errorf("%w: %s", ErrLocked, dir)
	}
	s := &Store{dir: dir, lock: lf}
	if err := s.load(); err != nil {
		syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
		lf.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the write lock so another process may open the directory.
func (s *Store) Close() error {
	if s.lock == nil {
		return nil
	}
	if err := syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN); err != nil {
		s.lock.Close()
		s.lock = nil
		return fmt.Errorf("release lock: %w", err)
	}
	if err := s.lock.Close(); err != nil {
		s.lock = nil
		return fmt.Errorf("close lock file: %w", err)
	}
	s.lock = nil
	return nil
}

func newPersistedState() *persistedState {
	return &persistedState{
		Version:  stateVersion,
		Headers:  map[string]Header{},
		Records:  []*Record{},
		Consumed: map[string]bool{},
	}
}

func (s *Store) load() error {
	data, err := os.ReadFile(filepath.Join(s.dir, stateFileName))
	if os.IsNotExist(err) {
		s.state = newPersistedState()
		s.byID = map[string]*Record{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read state file: %w", err)
	}
	var wire wireState
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if wire.Version != stateVersion {
		return fmt.Errorf("%w: version %d (supported %d)", ErrUnsupported, wire.Version, stateVersion)
	}
	st := persistedState{
		Version:  wire.Version,
		Time:     wire.Time,
		HasTime:  wire.HasTime,
		Headers:  map[string]Header{},
		Records:  wire.Records,
		Consumed: wire.Consumed,
	}
	seenChains := map[string]bool{}
	for _, h := range wire.Headers {
		if seenChains[h.Chain] {
			return fmt.Errorf("%w: duplicate header for chain %q", ErrCorrupt, h.Chain)
		}
		seenChains[h.Chain] = true
		st.Headers[h.Chain] = h
	}
	if st.Records == nil {
		st.Records = []*Record{}
	}
	if st.Consumed == nil {
		st.Consumed = map[string]bool{}
	}
	if err := validate(&st); err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	s.state = &st
	s.byID = make(map[string]*Record, len(st.Records))
	for _, r := range st.Records {
		s.byID[r.Message.ID] = r
	}
	return nil
}

// save atomically persists the full state. The success record and its nonce
// consumption live in the same file replacement, so they can never take effect
// separately.
func (s *Store) save() error {
	st := s.state

	headerNames := make([]string, 0, len(st.Headers))
	for name := range st.Headers {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	headers := make([]Header, 0, len(headerNames))
	for _, name := range headerNames {
		headers = append(headers, st.Headers[name])
	}

	consumedKeys := make([]string, 0, len(st.Consumed))
	for k := range st.Consumed {
		consumedKeys = append(consumedKeys, k)
	}
	sort.Strings(consumedKeys)
	consumed := make(map[string]bool, len(consumedKeys))
	for _, k := range consumedKeys {
		consumed[k] = true
	}

	wire := wireState{
		Version:  st.Version,
		Time:     st.Time,
		HasTime:  st.HasTime,
		Headers:  headers,
		Records:  st.Records,
		Consumed: consumed,
	}
	data, err := json.MarshalIndent(wire, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}

	tmp := filepath.Join(s.dir, stateFileName+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}
	if err := syncFile(tmp); err != nil {
		return err
	}
	final := filepath.Join(s.dir, stateFileName)
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("commit state file: %w", err)
	}
	if err := syncDir(s.dir); err != nil {
		return err
	}
	return nil
}

func validate(st *persistedState) error {
	if st.Headers == nil || st.Records == nil || st.Consumed == nil {
		return errors.New("missing required sections")
	}
	ids := map[string]bool{}
	seqs := map[int64]bool{}
	for _, r := range st.Records {
		if r == nil {
			return errors.New("null record")
		}
		if r.Message.ID == "" {
			return errors.New("record with empty id")
		}
		if ids[r.Message.ID] {
			return fmt.Errorf("duplicate id %q", r.Message.ID)
		}
		ids[r.Message.ID] = true
		if seqs[r.Seq] {
			return fmt.Errorf("duplicate seq %d", r.Seq)
		}
		seqs[r.Seq] = true
		if !knownStatus(r.Status) {
			return fmt.Errorf("unknown status %q", r.Status)
		}
		if terminalStatus(r.Status) && r.NextRetry != nil {
			return fmt.Errorf("terminal record %q has retry time", r.Message.ID)
		}
	}
	for k := range st.Consumed {
		parts := strings.Split(k, "\x00")
		if len(parts) != 3 {
			return fmt.Errorf("bad consumed key %q", k)
		}
		if parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("bad consumed key %q", k)
		}
		if _, err := strconv.ParseUint(parts[2], 10, 64); err != nil {
			return fmt.Errorf("bad consumed key %q", k)
		}
	}
	return nil
}

func knownStatus(status string) bool {
	switch status {
	case StatusPending, StatusWaitingHeader, StatusSuccess, StatusReplay, StatusExpired, StatusUnknownSource:
		return true
	}
	return false
}

func terminalStatus(status string) bool {
	switch status {
	case StatusSuccess, StatusReplay, StatusExpired, StatusUnknownSource:
		return true
	}
	return false
}

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open state file for fsync: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync state file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close state file: %w", err)
	}
	return nil
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open state directory for fsync: %w", err)
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return fmt.Errorf("fsync state directory: %w", err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("close state directory: %w", err)
	}
	return nil
}
