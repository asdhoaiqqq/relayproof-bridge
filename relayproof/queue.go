package relayproof

import (
	"fmt"
	"strconv"
)

// Submit enqueues a message. Submitting the same ID with identical content
// returns the existing record without adding a queue item; the same ID with
// different content returns ErrConflict and leaves the original unchanged.
func (s *Store) Submit(m Message) (*Record, error) {
	if m.ID == "" {
		return nil, fmt.Errorf("message id is required")
	}
	if r, ok := s.byID[m.ID]; ok {
		if r.Message == m {
			return r, nil
		}
		return nil, ErrConflict
	}
	r := &Record{
		Message: m,
		Status:  StatusPending,
		Seq:     int64(len(s.state.Records)) + 1,
	}
	s.state.Records = append(s.state.Records, r)
	s.byID[m.ID] = r
	if err := s.save(); err != nil {
		s.state.Records = s.state.Records[:len(s.state.Records)-1]
		delete(s.byID, m.ID)
		return nil, err
	}
	return r, nil
}

// SetHeader registers or replaces the header for a source chain. Terminal
// records are never reactivated by a header update; waiting messages pick up
// the new header only when their retry time arrives.
func (s *Store) SetHeader(h Header) error {
	if h.Chain == "" {
		return fmt.Errorf("chain is required")
	}
	if s.state.Headers == nil {
		s.state.Headers = map[string]Header{}
	}
	s.state.Headers[h.Chain] = h
	return s.save()
}

// Advance moves the processing time to now (Unix milliseconds). Equal time is
// a no-op; backward movement is rejected without state change. Each advance
// first checks replay and expiry for non-terminal records (both true is handled
// as replay, expiry includes exact equality), then processes due records in
// first-submission order.
func (s *Store) Advance(now int64) error {
	if s.state.HasTime && now < s.state.Time {
		return fmt.Errorf("%w: %d < %d", ErrTimeBackward, now, s.state.Time)
	}
	if s.state.HasTime && now == s.state.Time {
		return nil
	}
	s.state.Time = now
	s.state.HasTime = true

	// Phase 1: terminal conditions. Replay wins over expiry when both hold.
	for _, r := range s.state.Records {
		if terminalStatus(r.Status) {
			continue
		}
		expired := r.Message.ExpireAt > 0 && now >= r.Message.ExpireAt
		replayed := s.state.Consumed[nonceKey(r.Message)]
		switch {
		case replayed && expired:
			r.Status = StatusReplay
			r.Reason = "replay: nonce already consumed"
			r.NextRetry = nil
		case expired:
			r.Status = StatusExpired
			r.Reason = "message expired at " + strconv.FormatInt(now, 10)
			r.NextRetry = nil
		case replayed:
			r.Status = StatusReplay
			r.Reason = "replay: nonce already consumed"
			r.NextRetry = nil
		}
	}

	// Phase 2: first processing and retries in first-submission order.
	for _, r := range s.state.Records {
		if terminalStatus(r.Status) {
			continue
		}
		if r.NextRetry != nil && *r.NextRetry > now {
			continue
		}
		if _, ok := s.state.Headers[r.Message.From]; !ok {
			r.Status = StatusUnknownSource
			r.Reason = "unknown source chain"
			r.NextRetry = nil
			continue
		}
		hdr := s.state.Headers[r.Message.From]
		if !hdr.Trusted || hdr.Height < r.Message.ProofAt {
			r.Attempts++
			r.Status = StatusWaitingHeader
			r.Reason = "header not yet trusted at proof height"
			next := now + backoff(r.Attempts)
			r.NextRetry = &next
			continue
		}
		if s.state.Consumed[nonceKey(r.Message)] {
			r.Status = StatusReplay
			r.Reason = "replay: nonce already consumed"
			r.NextRetry = nil
			continue
		}
		s.state.Consumed[nonceKey(r.Message)] = true
		r.Status = StatusSuccess
		r.Reason = "proof verified at height " + strconv.FormatInt(hdr.Height, 10)
		r.NextRetry = nil
	}
	return s.save()
}

// Query returns the record for id, or ErrNotFound.
func (s *Store) Query(id string) (*Record, error) {
	r, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return r, nil
}

// List returns all records in first-submission order.
func (s *Store) List() []*Record {
	out := make([]*Record, len(s.state.Records))
	copy(out, s.state.Records)
	return out
}

// Header returns the registered header for a chain and whether it exists.
func (s *Store) Header(chain string) (Header, bool) {
	h, ok := s.state.Headers[chain]
	return h, ok
}

// Time returns the currently advanced processing time and whether it has been set.
func (s *Store) Time() (int64, bool) {
	return s.state.Time, s.state.HasTime
}

// backoff returns the retry delay for the given attempt (1-based):
// 1s, 2s, 4s, ... doubling to a 60s cap.
func backoff(attempt int) int64 {
	d := int64(1000) << uint(attempt-1)
	if d > 60000 {
		return 60000
	}
	return d
}

func nonceKey(m Message) string {
	return m.From + "\x00" + m.To + "\x00" + strconv.FormatUint(m.Nonce, 10)
}
