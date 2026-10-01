// Package relayproof implements cross-chain message verification.
package relayproof

import (
	"encoding/binary"
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

// consumeToken is the injective identity of a (source chain, destination
// chain, nonce) consumption. Replay protection must judge consumption by
// these three values independently: chain names are kept as their raw UTF-8
// bytes, including ':' and U+0000, so joining them with a separator character
// would merge distinct paths (e.g. "a:b"->"c" with "a"->"b:c"). Length
// prefixes on the two strings make the encoding unambiguous for every
// possible string content without forbidding, truncating or rewriting names.
type consumeToken struct {
	from  string
	to    string
	nonce uint64
}

func newConsumeToken(from, to string, nonce uint64) consumeToken {
	return consumeToken{from: from, to: to, nonce: nonce}
}

// marshal renders the token as a self-delimited byte sequence. It is only
// used where a string key is required; equality on the struct itself is the
// primary identity comparison and remains exact for all strings.
func (t consumeToken) marshal() string {
	var buf []byte
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(t.from)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, t.from...)
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(t.to)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, t.to...)
	binary.BigEndian.PutUint64(lenBuf[:], t.nonce)
	buf = append(buf, lenBuf[:]...)
	return string(buf)
}

// String renders a human-readable, quoted view for diagnostics. It is never
// used as an identity key.
func (t consumeToken) String() string {
	return strconv.QuoteToASCII(t.from) + " -> " + strconv.QuoteToASCII(t.to) +
		" nonce " + strconv.FormatUint(t.nonce, 10)
}

// Verify accepts a message only when the header covering it is known and trusted.
func Verify(headers map[string]Header, message Message, consumed map[string]bool) Delivery {
	header, ok := headers[message.From]
	if !ok {
		return Delivery{Message: message.ID, Status: "rejected", Reason: "unknown source chain"}
	}
	if !header.Trusted || header.Height < message.ProofAt {
		return Delivery{Message: message.ID, Status: "pending", Reason: "header not yet trusted at proof height"}
	}
	key := newConsumeToken(message.From, message.To, message.Nonce).marshal()
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
