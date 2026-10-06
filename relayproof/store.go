package relayproof

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"unicode/utf8"
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
//
// Header roots are arbitrary byte strings and must survive the log
// byte-for-byte: roots compare as their exact bytes, so two roots that differ
// in any byte are different roots. JSON string encoding silently rewrites
// invalid UTF-8 bytes to U+FFFD, which would merge distinct roots (and make a
// resubmitted original root conflict with its own saved value after a
// reopen). A root that is valid UTF-8 — including the empty root — keeps the
// historical plain "root" field, so existing logs keep their meaning
// byte-for-byte; a root holding invalid UTF-8 bytes is stored base64-encoded
// in "rootB64" instead, preserving the exact byte sequence across save,
// reopen and compaction. Roots an older build already rewrote to replacement
// characters stay those characters on replay — the lost bytes are never
// guessed. The two representations are mutually exclusive by key presence: a
// record that carries "root" and "rootB64" together — even when one is the
// empty string, and even when the two happen to decode to the same bytes — is
// an inconsistent record no build writes and rejects the directory with
// ErrCorrupt. The empty string counts as a present key, so the legal empty
// root ("root":"" alone, or neither key on old records) is never confused
// with a dual-root record.
//
// Message payloads have the same contract and use the same encoding: the Go
// submit interface accepts any string without requiring valid UTF-8 (empty
// text, NUL bytes, stray 0xFF/0xFE bytes or text mixed with them), and a
// payload read back after a reopen or compaction must equal the submitted
// bytes exactly, since payloads participate in same-id content comparison. A
// valid-UTF-8 payload keeps the historical plain "payload" field, so existing
// logs and the CLI stay compatible; an invalid-UTF-8 payload is stored
// base64-encoded in "payloadB64". The bytes 0xFF, 0xFE and the legal
// character U+FFFD are three different payloads and are never conflated.
// Payloads an older build already rewrote to replacement characters stay
// those characters on replay — again, the lost bytes are never guessed. The
// two representations are mutually exclusive by key presence: a record that
// carries "payload" and "payloadB64" together — even when one is the empty
// string, both are empty, or the two happen to decode to the same bytes — is
// an inconsistent record no build writes and rejects the directory with
// ErrCorrupt, regardless of field order. The empty string counts as a present
// key, so the legal empty payload ("payload":"" alone, a sole empty
// "payloadB64":"", or neither key on old records) is never confused with a
// dual-payload record. A checksum-valid record carrying an undecodable
// payloadB64 likewise rejects the directory with ErrCorrupt, leaving the file
// untouched — it is never read back as an empty or replacement-filled
// payload.
//
// Destination chain names have the same contract and use the same encoding:
// replay identity is the exact (source chain, destination chain, nonce)
// triple, so a destination name holding invalid UTF-8 bytes must survive as
// those bytes, not as what a display layer happens to render. The Go submit
// interface accepts any non-empty destination without requiring valid UTF-8 —
// text, colons, NUL bytes, stray 0xFF/0xFE bytes or text mixed with them — and
// the bytes 0xFF, 0xFE and the legal character U+FFFD are three different
// destinations that must never merge: after a reopen or compaction a
// byte-identical resubmit must still find its own unterminated record, the
// replay triple it belongs to must stay keyed by the original bytes, and a
// message to the visually similar replacement character must not be mistaken
// for one that consumed the invalid-byte destination. JSON string encoding
// would silently rewrite an invalid destination to U+FFFD in the submit
// entry's "to" and a success entry's "consumeTo", so a valid-UTF-8 destination
// keeps the historical plain fields while an invalid-UTF-8 destination is
// stored base64-encoded in "toB64" and "consumeToB64". Destinations an older
// build already rewrote to replacement characters stay those characters on
// replay — the lost bytes are never guessed. As with the other split fields,
// carrying both representations at once (by key presence, the empty string
// included) or an undecodable base64 value is an inconsistent record that
// rejects the directory with ErrCorrupt. Source chains are not split: the Go
// interface accepts only valid-UTF-8 source names (and an unregistered source
// never delivers), so historical "from" values are always read at face value.
//
// Message ids have the same contract and use the same encoding: identity is
// judged by the id's exact bytes, never by its display form. The Go submit
// interface accepts any non-empty id without requiring valid UTF-8 — plain
// text, Chinese text, whitespace, colons, NUL bytes, stray 0xFF/0xFE bytes,
// or text mixed with them — and the bytes 0xFF, 0xFE and the legal character
// U+FFFD are three different ids that must never merge into one record. JSON
// string encoding would silently rewrite invalid id bytes to U+FFFD, so after
// a reopen the original id would no longer find its message and two distinct
// ids could replay as duplicate submits, making the directory unopenable. A
// valid-UTF-8 id keeps the historical plain "id" field (and a success entry's
// "consumeBy"), so existing logs and the CLI stay byte-compatible; an
// invalid-UTF-8 id is stored base64-encoded in "idB64" (and "consumeByB64").
// Result and snapshot reasons embed such raw bytes too — a replay reason
// names the winning message id and an unknown-source reason names the chain —
// so an invalid-UTF-8 reason is likewise stored in "reasonB64". Ids an older
// build already rewrote to replacement characters stay those characters on
// replay; the lost bytes are never guessed. A record carrying both a plain
// field and its base64 form, or an undecodable base64 field, is corrupt and
// rejects the directory with ErrCorrupt.
//
// Processing-time validation on replay: a plain result's time must be a
// non-negative Unix-millisecond instant and no earlier than any queue-wide
// time the log has already confirmed — an advance checkpoint or any earlier
// result or snapshot, of any message — because no legal advance can produce
// an outcome stamped before the time the queue had already reached. A
// compacted snapshot's time must likewise be non-negative, but snapshots need
// not be time-ordered among themselves: each records its own message's last
// processing instant in first-submission order. A complete, checksum-valid
// record that violates these rules is corrupt (ErrCorrupt), never a
// truncatable torn tail, so the log's length and bytes are preserved.

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

	// RootB64 carries a header root's raw bytes base64-encoded when the root
	// is not valid UTF-8; see setRoot/headerRoot. Never set together with
	// Root.
	RootB64 string `json:"rootB64,omitempty"`

	Seq       int64  `json:"seq,omitempty"`
	ID        string `json:"id,omitempty"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	Nonce     uint64 `json:"nonce,omitempty"`
	Payload   string `json:"payload,omitempty"`
	ProofAt   int64  `json:"proofAt,omitempty"`
	ExpiresAt int64  `json:"expiresAt,omitempty"`

	// ToB64 carries a submit entry's destination chain raw bytes base64-encoded
	// when the destination is not valid UTF-8; see setTo/entryTo. Never set
	// together with To.
	ToB64 string `json:"toB64,omitempty"`

	// IDB64 carries a message id's raw bytes base64-encoded when the id is
	// not valid UTF-8; see setID/entryID. Never set together with ID.
	IDB64 string `json:"idB64,omitempty"`

	// PayloadB64 carries a message payload's raw bytes base64-encoded when the
	// payload is not valid UTF-8; see setPayload/entryPayload. Never set
	// together with Payload.
	PayloadB64 string `json:"payloadB64,omitempty"`

	Now       int64  `json:"now,omitempty"`
	Status    string `json:"status,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Attempts  int    `json:"attempts,omitempty"`
	NextRetry int64  `json:"nextRetry,omitempty"`

	// ReasonB64 carries a result/snapshot reason's raw bytes base64-encoded
	// when the reason is not valid UTF-8 (it may embed a raw-bytes message id
	// or chain name); see setReason/entryReason. Never set together with
	// Reason.
	ReasonB64 string `json:"reasonB64,omitempty"`

	// Consumed triple of a success entry, stored as three independent values
	// so routing paths that share a flattened key stay distinct. consumeBy is
	// the id of the successful message.
	ConsumeFrom  string `json:"consumeFrom,omitempty"`
	ConsumeTo    string `json:"consumeTo,omitempty"`
	ConsumeNonce uint64 `json:"consumeNonce,omitempty"`
	ConsumeBy    string `json:"consumeBy,omitempty"`

	// ConsumeToB64 is the base64 form of ConsumeTo for an invalid-UTF-8
	// destination chain; see setConsumeTo/entryConsumeTo. Never set together
	// with ConsumeTo.
	ConsumeToB64 string `json:"consumeToB64,omitempty"`

	// ConsumeByB64 is the base64 form of ConsumeBy for an invalid-UTF-8
	// message id; see setConsumeBy/entryConsumeBy. Never set together with
	// ConsumeBy.
	ConsumeByB64 string `json:"consumeByB64,omitempty"`

	// ConsumeKey is the legacy (pre-triple) NUL-joined consumption string. It
	// is accepted only while replaying logs written by older builds and is
	// never written anymore.
	ConsumeKey string `json:"consumeKey,omitempty"`

	// present records which JSON keys the replayed record literally carried,
	// for the plain/base64-split fields — root/rootB64, payload/payloadB64,
	// to/toB64 and consumeTo/consumeToB64. The split's mutual-exclusion and
	// empty-value rules are keyed on presence, not the decoded value: the
	// empty string is a legal value and is written as an explicitly present
	// "…":"", so it must never double as the signal that the key was omitted.
	// Set only by UnmarshalJSON and never marshalled.
	present map[string]bool
}

// splitJSONKeys are the plain/base64 field pairs whose mutual-exclusion rule
// is keyed on literal JSON key presence (see logEntry.present and
// splitFieldSpec). Field order in the record is irrelevant.
var splitJSONKeys = []string{
	"root", "rootB64",
	"payload", "payloadB64",
	"to", "toB64",
	"consumeTo", "consumeToB64",
}

// UnmarshalJSON decodes a log record while recording which plain/base64 keys
// the record literally carried. The plain/base64 split needs presence, not
// just the decoded value: the empty root/payload is a legal value written as
// "root":""/"payload":"", so the empty string cannot double as the signal
// that the key was omitted. The exported fields decode exactly as with the
// default unmarshalling (the alias avoids listing them by hand); only the
// presence map is extra.
func (e *logEntry) UnmarshalJSON(data []byte) error {
	type plain logEntry
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*e = logEntry(p)
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	e.present = make(map[string]bool, len(splitJSONKeys))
	for _, k := range splitJSONKeys {
		_, e.present[k] = keys[k]
	}
	return nil
}

// splitFieldSpec is one plain/base64 field pair's recovery policy: the JSON
// key names, a way to read the two decoded values off a replayed entry, and
// the field's own wording for the two corruption verdicts. Every pair shares
// exactly one byte-preservation rule set — implemented once in decode — and
// differs only in this descriptor, so each value keeps its business meaning
// (header root, message payload, destination chain, consumed destination) and
// its existing, field-specific error text.
//
// plainKey is empty for fields that predate presence tracking (id/idB64,
// reason/reasonB64, consumeBy/consumeByB64): those pairs keep their historical
// value-based mutual exclusion (they are never written with an empty plain
// value), which decode applies when plainKey is empty.
type splitFieldSpec struct {
	plainKey       string
	b64Key         string
	plain          func(e *logEntry) string
	b64            func(e *logEntry) string
	bothErr        string
	undecodableErr string
}

// decode is the single inverse of the plain/base64 field split every raw-bytes
// log value uses. The rules are:
//
//   - With the base64 key absent, the plain value is taken at face value. That
//     covers historical records that predate the split, including bytes an old
//     build rewrote to U+FFFD: the saved characters stay literal and are never
//     guessed back.
//   - With the base64 key present (alone, including an empty base64 string),
//     the base64 value is decoded to the original byte sequence.
//   - Both representations present is an inconsistent record no build writes —
//     judged by key presence where tracked, so even "":"" or two forms that
//     decode to the identical bytes clash — regardless of field order.
//   - A present base64 value that does not decode is corruption, never an empty
//     or replacement-filled value.
func (s splitFieldSpec) decode(e *logEntry) (string, error) {
	b64Value := s.b64(e)
	var b64Present bool
	if s.plainKey != "" {
		// Presence-based mutual exclusion: the empty string counts as present.
		if e.present[s.plainKey] && e.present[s.b64Key] {
			return "", errors.New(s.bothErr)
		}
		b64Present = e.present[s.b64Key]
	} else {
		// Historical value-based mutual exclusion for fields whose plain value
		// is never written empty alongside a base64 form: a set plain value
		// with a set base64 value clashes; an empty base64 is simply absent.
		if s.plain(e) != "" && b64Value != "" {
			return "", errors.New(s.bothErr)
		}
		b64Present = b64Value != ""
	}
	if !b64Present {
		return s.plain(e), nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64Value)
	if err != nil {
		return "", fmt.Errorf("%s: %v", s.undecodableErr, err)
	}
	return string(raw), nil
}

// splitFields is the one place each plain/base64 log pair is declared: the
// JSON key names, accessors and field-specific corruption wording. Adding a
// raw-bytes field means adding one descriptor, not another copy of the
// presence/empty/decode-error handling. Message id, result reason and the
// success entry's consuming id share the same decoder through these
// descriptors too; their pairs keep value-based exclusion (empty plainKey).
var splitFields = struct {
	id        splitFieldSpec
	reason    splitFieldSpec
	consumeBy splitFieldSpec
	root      splitFieldSpec
	payload   splitFieldSpec
	to        splitFieldSpec
	consumeTo splitFieldSpec
}{
	id: splitFieldSpec{
		b64Key:         "idB64",
		plain:          func(e *logEntry) string { return e.ID },
		b64:            func(e *logEntry) string { return e.IDB64 },
		bothErr:        "entry carries both id and idB64",
		undecodableErr: "entry carries undecodable idB64",
	},
	reason: splitFieldSpec{
		b64Key:         "reasonB64",
		plain:          func(e *logEntry) string { return e.Reason },
		b64:            func(e *logEntry) string { return e.ReasonB64 },
		bothErr:        "entry carries both reason and reasonB64",
		undecodableErr: "entry carries undecodable reasonB64",
	},
	consumeBy: splitFieldSpec{
		b64Key:         "consumeByB64",
		plain:          func(e *logEntry) string { return e.ConsumeBy },
		b64:            func(e *logEntry) string { return e.ConsumeByB64 },
		bothErr:        "success entry carries both consumeBy and consumeByB64",
		undecodableErr: "success entry carries undecodable consumeByB64",
	},
	root: splitFieldSpec{
		plainKey:       "root",
		b64Key:         "rootB64",
		plain:          func(e *logEntry) string { return e.Root },
		b64:            func(e *logEntry) string { return e.RootB64 },
		bothErr:        "header entry carries both root and rootB64",
		undecodableErr: "header entry carries undecodable rootB64",
	},
	payload: splitFieldSpec{
		plainKey:       "payload",
		b64Key:         "payloadB64",
		plain:          func(e *logEntry) string { return e.Payload },
		b64:            func(e *logEntry) string { return e.PayloadB64 },
		bothErr:        "submit entry carries both payload and payloadB64",
		undecodableErr: "submit entry carries undecodable payloadB64",
	},
	to: splitFieldSpec{
		plainKey:       "to",
		b64Key:         "toB64",
		plain:          func(e *logEntry) string { return e.To },
		b64:            func(e *logEntry) string { return e.ToB64 },
		bothErr:        "submit entry carries both to and toB64",
		undecodableErr: "submit entry carries undecodable toB64",
	},
	consumeTo: splitFieldSpec{
		plainKey:       "consumeTo",
		b64Key:         "consumeToB64",
		plain:          func(e *logEntry) string { return e.ConsumeTo },
		b64:            func(e *logEntry) string { return e.ConsumeToB64 },
		bothErr:        "success entry carries both consumeTo and consumeToB64",
		undecodableErr: "success entry carries undecodable consumeToB64",
	},
}

// setID encodes a message id for the log without altering its bytes.
func (e *logEntry) setID(id string) {
	if utf8.ValidString(id) {
		e.ID = id
		e.IDB64 = ""
		return
	}
	e.ID = ""
	e.IDB64 = base64.StdEncoding.EncodeToString([]byte(id))
}

// entryID decodes an entry's id back to its exact submitted bytes.
func (e *logEntry) entryID() (string, error) {
	return splitFields.id.decode(e)
}

// setReason encodes a processing result reason for the log without altering
// its bytes. Reasons may quote a raw-bytes message id (replay) or chain name
// (unknown source).
func (e *logEntry) setReason(reason string) {
	if utf8.ValidString(reason) {
		e.Reason = reason
		e.ReasonB64 = ""
		return
	}
	e.Reason = ""
	e.ReasonB64 = base64.StdEncoding.EncodeToString([]byte(reason))
}

// entryReason decodes a result/snapshot entry's reason back to its exact bytes.
func (e *logEntry) entryReason() (string, error) {
	return splitFields.reason.decode(e)
}

// setConsumeBy records the successful message's raw id alongside the consumed
// triple, using the same plain/base64 split as the id field.
func (e *logEntry) setConsumeBy(id string) {
	if utf8.ValidString(id) {
		e.ConsumeBy = id
		e.ConsumeByB64 = ""
		return
	}
	e.ConsumeBy = ""
	e.ConsumeByB64 = base64.StdEncoding.EncodeToString([]byte(id))
}

// entryConsumeBy decodes the consuming message id back to its exact bytes.
func (e *logEntry) entryConsumeBy() (string, error) {
	return splitFields.consumeBy.decode(e)
}

// setRoot encodes a header root for the log without altering its bytes. A
// root that is valid UTF-8 (including the empty root) keeps the historical
// plain "root" field, so logs stay byte-compatible with older builds. A root
// holding invalid UTF-8 bytes would be silently rewritten to U+FFFD by JSON
// string encoding, so it is instead stored base64-encoded in "rootB64",
// preserving the exact byte sequence across save, reopen and compaction.
func (e *logEntry) setRoot(root string) {
	if utf8.ValidString(root) {
		e.Root = root
		return
	}
	e.RootB64 = base64.StdEncoding.EncodeToString([]byte(root))
}

// headerRoot decodes a header entry's root back to its exact submitted
// bytes. Entries written before rootB64 existed carry only "root" and are
// taken at face value — including roots an old build had already rewritten to
// replacement characters, which stay those characters; the lost bytes are
// never guessed. An entry carrying both fields at once, or a rootB64 that does
// not decode, is an inconsistent record no build writes and is corrupt. The
// two representations are mutually exclusive by key presence: an explicitly
// empty "root":"" is a legal plain root, but "root":"" together with any
// rootB64 — even one that decodes to the same bytes, or to the empty root —
// still carries two representations and is rejected. The presence/empty/
// decode-error rules themselves are the shared ones in splitFieldSpec.decode;
// only the wording is header-root specific.
func (e *logEntry) headerRoot() (string, error) {
	return splitFields.root.decode(e)
}

// setPayload encodes a message payload for the log without altering its
// bytes. A payload that is valid UTF-8 (including the empty payload) keeps
// the historical plain "payload" field, so logs stay byte-compatible with
// older builds and the CLI text interface. A payload holding invalid UTF-8
// bytes would be silently rewritten to U+FFFD by JSON string encoding, so it
// is instead stored base64-encoded in "payloadB64", preserving the exact
// byte sequence and order across save, reopen and compaction.
func (e *logEntry) setPayload(payload string) {
	if utf8.ValidString(payload) {
		e.Payload = payload
		return
	}
	e.PayloadB64 = base64.StdEncoding.EncodeToString([]byte(payload))
}

// entryPayload decodes a submit entry's payload back to its exact submitted
// bytes. Entries written before payloadB64 existed carry only "payload" and
// are taken at face value — including payloads an old build had already
// rewritten to replacement characters, which stay those characters; the lost
// bytes are never guessed. An entry carrying both fields at once, or a
// payloadB64 that does not decode, is an inconsistent record no build writes
// and is corrupt; it is never read back as an empty or replacement-filled
// payload. The two representations are mutually exclusive by key presence: an
// explicitly empty "payload":"" is a legal plain payload, but "payload":""
// together with any payloadB64 — even an empty one, even one that decodes to
// the same bytes — still carries two representations of the message content
// and is rejected. Field order does not change the verdict. The
// presence/empty/decode-error rules themselves are the shared ones in
// splitFieldSpec.decode; only the wording is payload specific.
func (e *logEntry) entryPayload() (string, error) {
	return splitFields.payload.decode(e)
}

// setTo encodes a submit entry's destination chain for the log without
// altering its bytes. A destination that is valid UTF-8 (ordinary text, colons,
// NUL bytes) keeps the historical plain "to" field, so logs stay
// byte-compatible with older builds and the CLI text interface. A destination
// holding invalid UTF-8 bytes would be silently rewritten to U+FFFD by JSON
// string encoding, so it is instead stored base64-encoded in "toB64",
// preserving the exact byte sequence across save, reopen and compaction — the
// destination is half of the replay identity and must never change identity.
func (e *logEntry) setTo(to string) {
	if utf8.ValidString(to) {
		e.To = to
		return
	}
	e.ToB64 = base64.StdEncoding.EncodeToString([]byte(to))
}

// entryTo decodes a submit entry's destination chain back to its exact
// submitted bytes. Entries written before toB64 existed carry only "to" and
// are taken at face value — including a destination an old build had already
// rewritten to a replacement character, which stays that character; the lost
// bytes are never guessed. An entry carrying both fields at once (judged by
// key presence, the empty string included), or a toB64 that does not decode,
// is an inconsistent record no build writes and is corrupt. Those rules are
// the shared ones in splitFieldSpec.decode; only the wording is destination
// specific.
func (e *logEntry) entryTo() (string, error) {
	return splitFields.to.decode(e)
}

// setConsumeTo records the successful message's destination chain alongside
// the consumed triple, using the same plain/base64 split as the submit entry's
// "to" field, so the consumption attribution survives invalid UTF-8 byte for
// byte.
func (e *logEntry) setConsumeTo(to string) {
	if utf8.ValidString(to) {
		e.ConsumeTo = to
		return
	}
	e.ConsumeToB64 = base64.StdEncoding.EncodeToString([]byte(to))
}

// entryConsumeTo decodes a success entry's consumed destination back to its
// exact bytes. A record with both consumeTo and consumeToB64 set (by key
// presence, the empty string included), or an undecodable consumeToB64, is
// corrupt. Those rules are the shared ones in splitFieldSpec.decode; only the
// wording is success-entry specific.
func (e *logEntry) entryConsumeTo() (string, error) {
	return splitFields.consumeTo.decode(e)
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
	// injectErrOnCall is a test hook that, when positive, delays injectErr
	// until this 1-based append call number (later appends keep failing too);
	// zero means injectErr fails every append.
	injectErrOnCall int
	appendCalls     int
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

// frame is one located record frame: the on-disk envelope every log record
// shares — uint32-be payload length, payload, uint32-be CRC32-IEEE of the
// payload. Locating a frame and verifying its checksum is identical for the
// leading version record and for every later record, so those rules live here
// exactly once; what differs is the recovery policy each caller applies to a
// frame that is torn, zero-length, or checksum-bad, and those decisions stay
// in the callers.
type frame struct {
	pos       int // offset of the length header
	n         int // declared payload length
	bodyStart int // offset of the payload; zero while even the header is incomplete
	end       int // offset just past the frame
}

// errZeroLengthFrame reports a declared payload length of zero, which is
// corrupt in every context; each caller wraps it with its own record wording.
var errZeroLengthFrame = errors.New("zero-length record frame")

// scanFrame locates the record frame starting at raw[pos]. A frame cut short
// by end of file — an incomplete length header, or a declared body/checksum
// running past the end — is reported as torn, with the frame fields set as
// far as they could be determined (bodyStart stays zero when even the length
// header is incomplete). Whether a torn frame is a truncatable unacknowledged
// write or a corrupt log is the caller's policy, as is the judgment of a
// checksum mismatch.
func scanFrame(raw []byte, pos int) (frame, bool, error) {
	f := frame{pos: pos}
	if len(raw)-pos < frameHeaderSize {
		return f, true, nil
	}
	f.n = int(binary.BigEndian.Uint32(raw[pos : pos+frameHeaderSize]))
	if f.n == 0 {
		return f, false, errZeroLengthFrame
	}
	f.bodyStart = pos + frameHeaderSize
	f.end = f.bodyStart + f.n + frameCRCsSize
	if f.end > len(raw) {
		return f, true, nil
	}
	return f, false, nil
}

// payload returns the complete frame's payload bytes and reports whether the
// stored CRC32 matches them.
func (f frame) payload(raw []byte) ([]byte, bool) {
	payload := raw[f.bodyStart : f.bodyStart+f.n]
	wantCRC := binary.BigEndian.Uint32(raw[f.bodyStart+f.n : f.end])
	return payload, crc32.Checksum(payload, crcTable) == wantCRC
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
		f, torn, err := scanFrame(raw, pos)
		if errors.Is(err, errZeroLengthFrame) {
			return 0, nil, fmt.Errorf("%w: zero-length record at offset %d", ErrCorrupt, pos)
		}
		if torn {
			// Torn length header or body/CRC of an unacked write.
			return int64(pos), state, nil
		}
		payload, ok := f.payload(raw)
		if !ok {
			if f.end == len(raw) {
				// Torn sectors of the final, unacknowledged frame.
				return int64(pos), state, nil
			}
			return 0, nil, fmt.Errorf("%w: checksum mismatch at offset %d", ErrCorrupt, pos)
		}
		var e logEntry
		if err := json.Unmarshal(payload, &e); err != nil {
			return 0, nil, fmt.Errorf("%w: invalid record at offset %d: %v", ErrCorrupt, pos, err)
		}
		if err := normalizeEntryRaw(&e); err != nil {
			return 0, nil, fmt.Errorf("%w: invalid record at offset %d: %v", ErrCorrupt, pos, err)
		}
		if e.T == kindVersion {
			return 0, nil, fmt.Errorf("%w: unexpected version record at offset %d", ErrCorrupt, pos)
		}
		if err := applyEntry(state, &e); err != nil {
			return 0, nil, err
		}
		pos = f.end
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
// corrupt log, never a truncatable tail. The framing rules themselves (length
// header, body range, CRC32) are the shared ones in scanFrame; only the
// acceptance policy is the version record's own.
func readVersionRecord(raw []byte, start int) (int, error) {
	f, torn, err := scanFrame(raw, start)
	if errors.Is(err, errZeroLengthFrame) {
		return 0, fmt.Errorf("%w: zero-length version record at offset %d", ErrCorrupt, start)
	}
	if torn {
		if f.bodyStart == 0 {
			return 0, fmt.Errorf("%w: incomplete version record: only %d of %d length bytes after header",
				ErrCorrupt, len(raw)-start, frameHeaderSize)
		}
		return 0, fmt.Errorf("%w: incomplete version record: length %d but only %d body/checksum bytes present",
			ErrCorrupt, f.n, len(raw)-f.bodyStart)
	}
	payload, ok := f.payload(raw)
	if !ok {
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
	return f.end, nil
}

// normalizeEntryRaw decodes every raw-bytes field of a replayed entry back to
// its exact submitted bytes in place, so the rest of replay compares ids,
// reasons and consumer attributions as raw strings just like the live queue.
// A plain/base64 clash or an undecodable base64 value is corruption.
func normalizeEntryRaw(e *logEntry) error {
	id, err := e.entryID()
	if err != nil {
		return err
	}
	e.ID = id
	e.IDB64 = ""
	to, err := e.entryTo()
	if err != nil {
		return err
	}
	e.To = to
	e.ToB64 = ""
	consumeTo, err := e.entryConsumeTo()
	if err != nil {
		return err
	}
	e.ConsumeTo = consumeTo
	e.ConsumeToB64 = ""
	reason, err := e.entryReason()
	if err != nil {
		return err
	}
	e.Reason = reason
	e.ReasonB64 = ""
	by, err := e.entryConsumeBy()
	if err != nil {
		return err
	}
	e.ConsumeBy = by
	e.ConsumeByB64 = ""
	return nil
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

// recoveryKind distinguishes the two log record shapes that can carry a
// message's post-processing state. They are never merged into one kind: a
// plain result ("result") is one incremental outcome and must follow the
// attempts-jump and monotonic-time rules, while a compacted snapshot ("state")
// stores the full current status after >=1 attempts. recoveryKind only selects
// the record-category wording in corrupt errors and the kind-specific
// acceptance checks; both kinds then run the *same* per-status rules.
//
// waitingNoun is the word the historical waiting errors use ("result" for a
// plain result, "state" for a snapshot); entryNoun is the word the historical
// success/terminal errors use ("entry" for a plain result, "state" for a
// snapshot). Keeping them separate preserves every corrupt message verbatim.
type recoveryKind struct {
	waitingNoun string
	entryNoun   string
}

var (
	recoveryResult = recoveryKind{waitingNoun: "result", entryNoun: "entry"}
	recoveryState  = recoveryKind{waitingNoun: "state", entryNoun: "state"}
)

// validateRecoveryTime is the shared processing-time floor for a result entry
// and a compacted state entry: the time is a Unix-millisecond instant and can
// never be negative (zero is a valid processing time). The additional
// monotonicity rule — a plain result may not predate any queue-wide time the
// log has already confirmed — lives in applyEntry, because it does not apply
// to snapshots: compaction writes snapshots in first-submission order, each
// stamped with its own message's last processing instant, so a later snapshot
// may legitimately carry an earlier time than the ones before it.
func validateRecoveryTime(e *logEntry, rk recoveryKind) error {
	corrupt := func(msg string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(msg, args...))
	}
	if e.Now < 0 {
		return corrupt("%s time %d is negative for %q", rk.waitingNoun, e.Now, e.ID)
	}
	return nil
}

// validateRecoveryStatus is the first shared check for a result entry and a
// compacted state entry: the carried status must be one of the known statuses
// and must never be pending (pending is established by the submit entry, not
// by a post-processing record).
func validateRecoveryStatus(e *logEntry, rk recoveryKind) error {
	corrupt := func(msg string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(msg, args...))
	}
	if !validStatus(e.Status) || e.Status == StatusPending {
		return corrupt("bad %s status %q for %q", rk.waitingNoun, e.Status, e.ID)
	}
	return nil
}

// acceptRecoveryStatus is the second shared check, run after the
// kind-specific acceptance rules (including the snapshot's >=1-attempts
// requirement): waiting must carry the canonical retry schedule (with the
// sole legacy-overflow exception repaired in memory) and no consumption,
// success must keep no retry time and consume its own (from,to,nonce)
// attributed to itself, and terminal failures carry neither a retry time nor
// consumption fields. The repaired retry time of a legacy overflowed schedule
// is written back onto e.
func acceptRecoveryStatus(s *loadedState, rec *Record, e *logEntry, rk recoveryKind) error {
	corrupt := func(msg string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(msg, args...))
	}
	switch e.Status {
	case StatusWaiting:
		scheduled, ok := validWaitingSchedule(e.Now, e.Attempts, e.NextRetry)
		if !ok {
			return corrupt("waiting %s has wrong retry schedule for %q", rk.waitingNoun, e.ID)
		}
		// Repair a legacy overflowed (negative) retry to the ceiling in
		// memory; the next compaction writes the repaired value back.
		e.NextRetry = scheduled
		if entryCarriesConsumption(e) {
			return corrupt("waiting %s for %q carries nonce consumption fields", rk.waitingNoun, e.ID)
		}
	case StatusSuccess:
		if e.NextRetry != 0 {
			return corrupt("success %s for %q carries retry time", rk.entryNoun, e.ID)
		}
		if _, err := acceptConsumption(s, rec, e, corrupt); err != nil {
			return err
		}
	default: // terminal failure kinds
		if e.NextRetry != 0 || entryCarriesConsumption(e) {
			return corrupt("terminal %s for %q carries scheduling/consume fields", rk.entryNoun, e.ID)
		}
	}
	return nil
}

// applyRecoveredState copies the validated post-processing state of one result
// or compacted-state entry onto the record. Both record kinds describe the
// same message state the same way, so the assignment lives in one place.
func applyRecoveredState(s *loadedState, rec *Record, e *logEntry) {
	rec.Attempts = e.Attempts
	rec.LastProcAt = e.Now
	rec.Status = e.Status
	rec.Reason = e.Reason
	rec.NextRetry = e.NextRetry
	if e.Now > s.now {
		s.now = e.Now
	}
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
		root, err := e.headerRoot()
		if err != nil {
			return corrupt("bad header entry: %v", err)
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
		hs.latest = Header{Chain: e.Chain, Height: e.Height, Root: root, Trusted: e.Trusted}
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
		payload, err := e.entryPayload()
		if err != nil {
			return corrupt("bad submit entry: %v", err)
		}
		s.records[e.ID] = &Record{
			Msg: Envelope{
				Message: Message{
					ID:      e.ID,
					From:    e.From,
					To:      e.To,
					Nonce:   e.Nonce,
					Payload: payload,
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
		// A plain result is one incremental processing outcome: it applies
		// only to a known, still non-terminal record, attempts must advance by
		// exactly one, and the processing time must be a non-negative instant
		// that never moves backwards — neither against the message's own prior
		// processing nor against any queue-wide time the log has already
		// confirmed: an advance checkpoint, or any earlier result or snapshot
		// of any message, checkpointed or not. A result stamped earlier than
		// that is an outcome no legal advance can have produced, however
		// intact and well-checksummed the record is. The per-status
		// validation (waiting schedule, success consumption, terminal fields)
		// is shared with compacted state entries.
		rec, ok := s.records[e.ID]
		if !ok {
			return corrupt("result for unknown id %q", e.ID)
		}
		if isTerminal(rec.Status) {
			return corrupt("result for terminal id %q", e.ID)
		}
		if err := validateRecoveryTime(e, recoveryResult); err != nil {
			return err
		}
		// s.now never drops below any record's LastProcAt, so the same-message
		// check is the queue-wide one restricted to this record; it stays
		// first to keep its historical error wording.
		if rec.Attempts > 0 && e.Now < rec.LastProcAt {
			return corrupt("result time %d before prior time %d for %q", e.Now, rec.LastProcAt, e.ID)
		}
		if e.Now < s.now {
			return corrupt("result time %d before known time %d for %q", e.Now, s.now, e.ID)
		}
		if e.Attempts != rec.Attempts+1 {
			return corrupt("attempts jump %d -> %d for %q", rec.Attempts, e.Attempts, e.ID)
		}
		if err := validateRecoveryStatus(e, recoveryResult); err != nil {
			return err
		}
		if err := acceptRecoveryStatus(s, rec, e, recoveryResult); err != nil {
			return err
		}
		applyRecoveredState(s, rec, e)
	case kindState:
		// A compacted snapshot stores the message's full current status after
		// >=1 attempts: it may restore an attempt count greater than one
		// directly, but it applies only to a known record and never twice for
		// the same message. Its processing time must be non-negative, but —
		// unlike a plain result — it need not exceed the times of the
		// snapshots before it: compaction writes snapshots in first-submission
		// order, each stamped with its own message's last processing instant,
		// so their times are not ordered among themselves. The per-status
		// validation is shared with plain result entries; the two kinds stay
		// distinct on disk.
		rec, ok := s.records[e.ID]
		if !ok {
			return corrupt("state for unknown id %q", e.ID)
		}
		if rec.Attempts != 0 {
			return corrupt("duplicate state for id %q", e.ID)
		}
		if err := validateRecoveryTime(e, recoveryState); err != nil {
			return err
		}
		if err := validateRecoveryStatus(e, recoveryState); err != nil {
			return err
		}
		if e.Attempts < 1 {
			return corrupt("state with zero attempts for %q", e.ID)
		}
		if err := acceptRecoveryStatus(s, rec, e, recoveryState); err != nil {
			return err
		}
		applyRecoveredState(s, rec, e)
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

// validWaitingSchedule validates the retry instant recorded on a waiting
// result or compacted-state entry against the processing time and attempt
// number. The canonical schedule is nextRetryAt(now, attempts): now plus the
// backoff delay, saturated at math.MaxInt64 when it would overflow.
//
// Logs written by older builds contain the raw now+delay even near the
// ceiling, where the addition wrapped around to a value below now (typically
// negative). That exact wrapped value is the only non-canonical schedule
// accepted: it proves the entry came from the old scheduler rather than from
// arbitrary corruption, and it is repaired in memory to the saturated
// ceiling, which the next compaction persists. Any other retry time — zero,
// an arbitrary instant, or a value before the processing time that is not the
// exact legacy overflow — is rejected as corrupt.
func validWaitingSchedule(now int64, attempts int, stored int64) (int64, bool) {
	canonical := nextRetryAt(now, attempts)
	if stored == canonical {
		return stored, true
	}
	wrapped := now + nextRetryDelay(attempts)
	if wrapped < now && stored == wrapped {
		return math.MaxInt64, true
	}
	return 0, false
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
	s.appendCalls++
	if s.injectErr != nil && (s.injectErrOnCall <= 0 || s.appendCalls >= s.injectErrOnCall) {
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
	e := &logEntry{T: kindHeader, Chain: h.Chain, Height: h.Height, Trusted: h.Trusted}
	e.setRoot(h.Root)
	return s.append(e)
}

// newSubmitEntry builds the record that restores one message's original
// content and first-submission position. It is the single construction rule
// for both save paths: the incremental appendSubmit writes one per Submit call
// and compact writes one per snapshotted record, so id, source and destination
// chains, nonce, payload, proof height, expiry and seq — including the
// plain/base64 byte preservation for id, destination and payload — are encoded
// identically in a plain result log and in a compacted log.
func newSubmitEntry(rec *Record) *logEntry {
	m := rec.Msg.Message
	e := &logEntry{
		T: kindSubmit, Seq: rec.Seq, From: m.From,
		Nonce: m.Nonce, ProofAt: m.ProofAt, ExpiresAt: rec.Msg.ExpiresAt,
	}
	e.setID(m.ID)
	e.setTo(m.To)
	e.setPayload(m.Payload)
	return e
}

func (s *store) appendSubmit(rec *Record) error {
	return s.append(newSubmitEntry(rec))
}

// setSuccessConsumption fills a success entry's consumed triple and attributes
// it to the successful message id. It is the one fill rule shared by the
// incremental result path and the compacted-state path, so a success state and
// its nonce consumption are always written together, as one record, with the
// same plain/base64 destination and id encoding.
func setSuccessConsumption(e *logEntry, id string, token *consumeToken) {
	e.ConsumeFrom = token.from
	e.setConsumeTo(token.to)
	e.ConsumeNonce = token.nonce
	e.setConsumeBy(id)
}

// newStatusEntry builds one post-processing record from the same message-record
// fields both save paths persist: kindResult for the incremental appendOutcome
// path (one outcome per processing), kindState for the compacted snapshot (the
// message's current status after >=1 attempts). The kind differs only in T and
// in what replay accepts; every populated field — processing time, status,
// reason, attempt count, the waiting retry instant and, on success, the
// consumed triple attributed to this message — is chosen by one rule here, so
// the two paths can never drift on status meaning, the plain-vs-raw-bytes
// reason/id encoding, or when a nonce is consumed. nextRetry is the saturated
// retry instant for a waiting result and zero otherwise (omitted on disk).
func newStatusEntry(kind string, now, nextRetry int64, attempts int, id, status, reason string, consume *consumeToken) (*logEntry, error) {
	e := &logEntry{
		T: kind, Now: now,
		Status: status, Attempts: attempts, NextRetry: nextRetry,
	}
	e.setID(id)
	e.setReason(reason)
	if status == StatusSuccess {
		if consume == nil {
			return nil, fmt.Errorf("internal error: success result for %q missing nonce consumption", id)
		}
		setSuccessConsumption(e, id, consume)
	}
	return e, nil
}

// appendOutcome records one processing result. Every result carries the
// processing time, the post-attempt attempt count and the resulting status and
// reason; a waiting result additionally carries the retry instant the queue
// layer already computed and saturated, so the log never carries an overflowed
// negative schedule. On success the consumed triple
// (consumeFrom/consumeTo/consumeNonce) and its consumer are part of the same
// durable record, committing together atomically; oc.consume is nil for every
// non-success status. The entry itself is built by newStatusEntry, the same
// constructor the compacted snapshot uses.
func (s *store) appendOutcome(now int64, rec *Record, attempts int, nextRetry int64, oc outcome) error {
	e, err := newStatusEntry(kindResult, now, nextRetry, attempts,
		rec.Msg.Message.ID, oc.status, oc.reason, oc.consume)
	if err != nil {
		return err
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
			e := &logEntry{T: kindHeader, Chain: hs.trusted.Chain, Height: hs.trusted.Height, Trusted: hs.trusted.Trusted}
			e.setRoot(hs.trusted.Root)
			entries = append(entries, e)
		}
		if hs.trusted == nil || hs.latest != *hs.trusted {
			e := &logEntry{T: kindHeader, Chain: hs.latest.Chain, Height: hs.latest.Height, Trusted: hs.latest.Trusted}
			e.setRoot(hs.latest.Root)
			entries = append(entries, e)
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
		// The submit entry is built by the same constructor the ordinary
		// appendSubmit path uses, so the snapshot restores the message's
		// original content and submission position byte for byte.
		entries = append(entries, newSubmitEntry(rec))
		if rec.Attempts > 0 {
			// The status entry is built by the same constructor the ordinary
			// appendOutcome path uses, only with kindState: the snapshot saves
			// the message's current status — not a new attempt — with the same
			// waiting schedule and success-consumption fill either path writes.
			nextRetry := int64(0)
			var consume *consumeToken
			if rec.Status == StatusWaiting {
				nextRetry = rec.NextRetry
			}
			if rec.Status == StatusSuccess {
				t := newConsumeToken(rec.Msg.Message.From, rec.Msg.Message.To, rec.Msg.Message.Nonce)
				consume = &t
			}
			re, err := newStatusEntry(kindState, rec.LastProcAt, nextRetry, rec.Attempts,
				rec.Msg.Message.ID, rec.Status, rec.Reason, consume)
			if err != nil {
				return err
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
