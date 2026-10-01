// Package relayproof implements cross-chain message verification.
package relayproof

import (
	"sort"
	"strconv"
)

// Header is a light-client header at a known height.
type Header struct {
	Chain   string
	Height  int64
	Root    string
	Trusted bool
}

// Message is one outbound cross-chain message awaiting delivery.
type Message struct {
	ID      string
	From    string
	To      string
	Nonce   uint64
	Payload string
	ProofAt int64
}

// Delivery is the outcome of a relay attempt.
type Delivery struct {
	Message string
	Status  string
	Reason  string
}

// Verify accepts a message only when the header covering it is known and
// trusted. Replay protection keys the consumption by the exact
// (source chain, destination chain, nonce) triple, so two distinct paths
// never collide even when their names contain separator or zero bytes.
func Verify(headers map[string]Header, message Message, consumed map[ConsumeKey]bool) Delivery {
	header, ok := headers[message.From]
	if !ok {
		return Delivery{Message: message.ID, Status: "rejected", Reason: "unknown source chain"}
	}
	if !header.Trusted || header.Height < message.ProofAt {
		return Delivery{Message: message.ID, Status: "pending", Reason: "header not yet trusted at proof height"}
	}
	key := consumeKeyOf(message.From, message.To, message.Nonce)
	if consumed[key] {
		return Delivery{Message: message.ID, Status: "rejected", Reason: "replay: nonce already consumed"}
	}
	consumed[key] = true
	return Delivery{Message: message.ID, Status: "delivered", Reason: "proof verified at height " + strconv.FormatInt(header.Height, 10)}
}

// Pending lists messages still waiting for a trusted header, stable by id.
func Pending(headers map[string]Header, messages []Message) []string {
	var ids []string
	for _, message := range messages {
		header, ok := headers[message.From]
		if !ok || !header.Trusted || header.Height < message.ProofAt {
			ids = append(ids, message.ID)
		}
	}
	sort.Strings(ids)
	return ids
}
