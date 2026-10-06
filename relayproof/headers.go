package relayproof

import "fmt"

// headerState records the headers seen for one chain: the latest header
// written (any trust level) and the highest trusted header accepted. Proof
// coverage is determined solely by the highest trusted header — a later
// untrusted header, even at a greater height, can never lower or invalidate
// it. The zero value is a chain with no recorded headers.
type headerState struct {
	latest  Header
	trusted *Header
}

// sameHeightPolicy is the one acceptance rule the two header save paths judge
// differently: a trusted header arriving at exactly the current highest
// trusted height. It reports whether the incoming header replaces the
// accepted trusted header, or rejects the header outright with a non-nil
// error, in which case nothing is recorded. Roots compare as their exact
// bytes: the empty root is a legal root, and two roots differing in any byte
// — including invalid UTF-8 bytes — are different roots; the replacement
// character never stands in for them.
type sameHeightPolicy func(accepted, incoming Header) (replace bool, err error)

// submitSameHeight is the new-submission acceptance rule (Queue.UpsertHeader):
// a trusted header at the accepted highest trusted height with the same root
// is an idempotent re-save that keeps the accepted trusted header; one with a
// different root is an ErrHeaderConflict — the header is rejected before it
// is persisted, the accepted trusted header and the latest header are both
// kept, and the queue remains usable.
func submitSameHeight(accepted, incoming Header) (bool, error) {
	if incoming.Root != accepted.Root {
		return false, fmt.Errorf("%w: chain %q height %d: submitted root %q conflicts with accepted root %q",
			ErrHeaderConflict, incoming.Chain, incoming.Height, incoming.Root, accepted.Root)
	}
	return false, nil
}

// replaySameHeight is the historical-recovery acceptance rule (log replay):
// same-height coverage recorded by older builds is never rejected as a
// conflict, and when several trusted headers share the highest trusted height
// the later write wins, matching the overwrite semantics of the logs that
// produced them.
func replaySameHeight(_, _ Header) (bool, error) {
	return true, nil
}

// headerUpdate is the effect recording one header has on a chain's header
// state: the header always becomes the chain's latest header, and
// advanceTrusted reports whether it also becomes the highest trusted header.
type headerUpdate struct {
	advanceTrusted bool
}

// planUpdate judges one header against the chain's current header state under
// the coverage rules both save paths share, without changing anything:
//
//   - the first trusted header establishes coverage;
//   - a higher trusted header advances it;
//   - a lower trusted header, or an untrusted header of any height, is
//     recorded as the latest header only — it can never lower or invalidate
//     established coverage;
//   - a trusted header at exactly the current highest trusted height is
//     decided by sameHeight, the one rule new submission and historical
//     recovery keep distinct.
//
// A non-nil error rejects the header outright: it must neither be persisted
// nor recorded.
func (hs *headerState) planUpdate(h Header, sameHeight sameHeightPolicy) (headerUpdate, error) {
	if h.Trusted && hs.trusted != nil && h.Height == hs.trusted.Height {
		replace, err := sameHeight(*hs.trusted, h)
		return headerUpdate{advanceTrusted: replace}, err
	}
	advance := h.Trusted && (hs.trusted == nil || h.Height > hs.trusted.Height)
	return headerUpdate{advanceTrusted: advance}, nil
}

// applyUpdate records h together with its planned update. Planning and
// applying are separate steps so the submission path can persist the header
// between judging it and letting it take effect; recovery applies each
// replayed entry as it is read.
func (hs *headerState) applyUpdate(h Header, u headerUpdate) {
	hs.latest = h
	if u.advanceTrusted {
		t := h
		hs.trusted = &t
	}
}
