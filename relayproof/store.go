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
	"strings"
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
// ErrCorrupt, regardless of field order. Field-name casing changes nothing:
// encoding/json fills the same struct field from "PAYLOADB64" or a mixed-case
// spelling, so key presence is folded the same way on replay — a sole
// re-cased base64 field still decodes to its exact bytes and a re-cased plain
// field beside a base64 field is still two representations at once. The empty
// string counts as a present key, so the legal empty payload ("payload":""
// alone, a sole empty "payloadB64":"", or neither key on old records) is never
// confused with a dual-payload record. A checksum-valid record carrying an
// undecodable payloadB64 likewise rejects the directory with ErrCorrupt,
// leaving the file untouched — it is never read back as an empty or
// replacement-filled payload.
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
// rejects the directory with ErrCorrupt.
//
// Source chain names have the same contract and use the same encoding: the
// replay identity's first element is the source chain's exact bytes, source
// registration and trusted-header coverage apply per byte-identical chain,
// and an unknown-source reason quotes the chain. The Go interface accepts any
// non-empty source name without requiring valid UTF-8 — ordinary text,
// colons, NUL bytes, stray 0xFF/0xFE bytes or text mixed with them — and the
// bytes 0xFF, 0xFE and the legal character U+FFFD are three different source
// chains that must never merge: two names that differ only in an invalid byte
// are distinct in the same process, so saving one as the replacement
// character would, after a reopen, mix the two chains' registrations, trusted
// headers and consumed nonces. JSON string encoding would silently rewrite an
// invalid source name in a source or header entry's "chain", a submit entry's
// "from" and a success entry's "consumeFrom", so a valid-UTF-8 name keeps the
// historical plain fields while an invalid-UTF-8 name is stored
// base64-encoded in "chainB64", "fromB64" and "consumeFromB64". Names an
// older build already rewrote to replacement characters stay those characters
// on replay — the lost bytes are never guessed, and a message terminalized by
// such a legacy record is never reactivated. As with the other split fields,
// carrying both representations at once (by key presence, the empty string
// included) or an undecodable base64 value is an inconsistent record that
// rejects the directory with ErrCorrupt.
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
// due-result (success or waiting) of an already processed message must
// additionally respect that message's own retry schedule: it may only be
// stamped at a distinct processing instant at or after the retry its last
// result scheduled, however intact and well-checksummed the record is —
// replaying an early success would otherwise consume a nonce that normal
// advances could not. Replay and expired results are not bounded by the
// schedule: phase-2 replay/expiry holds settle a waiting message while its
// backoff is still running. A compacted snapshot's time must likewise be
// non-negative, but snapshots need not be time-ordered among themselves:
// each records its own message's last processing instant in first-submission
// order. A complete, checksum-valid record that violates these rules is
// corrupt (ErrCorrupt), never a truncatable torn tail, so the log's length
// and bytes are preserved.
//
// Source-registration validation on replay: a success — a plain result or a
// compacted state — is a recorded delivery, so just like a live advance it is
// only legal when the message's own source chain was registered. A saved
// trusted header never stands in for registration: normal processing
// terminalizes an unregistered source as unknown-source however high its
// trusted coverage is, so recovery must not resurrect such a message as
// success and consume its nonce. For a plain result only registrations saved
// in earlier records count, so a source registered after the success was
// recorded can never retroactively legalize it; a compacted state is judged
// against the registrations the snapshot retained (compaction writes them
// before the records), with no reconstruction of compacted-away registration
// history. Registering another chain never covers the message — chain names
// are their raw bytes, never their display form. A complete, checksum-valid
// success from an unregistered source is corrupt (ErrCorrupt), never a
// truncatable torn tail, so the log's length and bytes are preserved.
//
// Trusted-coverage validation on replay: a success — a plain result or a
// compacted state — is a recorded delivery, so just like a live advance it is
// only legal when the message's own source chain has a trusted header at least
// at its proof height. For a plain result only headers saved in earlier
// records count, so a trusted header written after the success can never
// retroactively cover it; a compacted state is judged against the trusted
// coverage the snapshot retained, with no reconstruction of compacted-away
// header history. Another chain's trusted headers never cover the message —
// chains are their raw bytes — untrusted headers at any height never establish
// coverage, a lower trusted header never narrows it, and a trusted height
// exactly equal to the proof height does cover. The saved reason text never
// stands in for a saved trusted header and need not name the retained highest
// trusted height. A complete, checksum-valid success that lacks coverage is
// corrupt (ErrCorrupt), never a truncatable torn tail, so the log's length
// and bytes are preserved.
//
// Absolute-expiry validation on replay: a success — a plain result or a
// compacted state — is a recorded delivery, so just like a live advance it is
// only legal when the success record's own processing time is strictly before
// the message's saved absolute expiry. A live advance turns processing at the
// expiry instant itself into an expired outcome before delivery is attempted,
// so a success stamped at or after that instant — even a complete,
// checksum-valid record at the very end of the log that passes every other
// recovery check — could never have been produced normally and must not be
// restored with its nonce consumption. The decision reads only the two
// instants saved with the message and the success: never the wall-clock time
// at which the directory is opened, any queue time later advances reached, or
// when compaction ran. A success legitimately recorded before its deadline
// therefore stays a success on a reopen long afterwards and compaction never
// re-expires it or requires the compacted-away processing history. An expiry
// of zero means never expire and is never treated as a deadline at time zero.
// A complete, checksum-valid success that violates the strict-before rule is
// corrupt (ErrCorrupt), never a truncatable torn tail, an expired rewrite or
// an empty replacement queue, so the log's length and bytes are preserved.

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

	// ChainB64 carries a source/header entry's chain name raw bytes
	// base64-encoded when the name is not valid UTF-8; see setChain/entryChain.
	// Never set together with Chain.
	ChainB64 string `json:"chainB64,omitempty"`

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

	// FromB64 carries a submit entry's source chain raw bytes base64-encoded
	// when the source is not valid UTF-8; see setFrom/entryFrom. Never set
	// together with From.
	FromB64 string `json:"fromB64,omitempty"`

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

	// ConsumeFromB64 is the base64 form of ConsumeFrom for an invalid-UTF-8
	// source chain; see setConsumeFrom/entryConsumeFrom. Never set together
	// with ConsumeFrom.
	ConsumeFromB64 string `json:"consumeFromB64,omitempty"`

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
	// to/toB64, from/fromB64, chain/chainB64, consumeTo/consumeToB64 and
	// consumeFrom/consumeFromB64. The split's mutual-exclusion and empty-value rules are keyed on presence, not the decoded value: the
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
	"from", "fromB64",
	"chain", "chainB64",
	"consumeTo", "consumeToB64",
	"consumeFrom", "consumeFromB64",
}

// UnmarshalJSON decodes a log record while recording which plain/base64 keys
// the record literally carried. The plain/base64 split needs presence, not
// just the decoded value: the empty root/payload is a legal value written as
// "root":""/"payload":"", so the empty string cannot double as the signal
// that the key was omitted. The exported fields decode exactly as with the
// default unmarshalling (the alias avoids listing them by hand); only the
// presence map is extra.
//
// Presence is matched case-insensitively — with strings.EqualFold, the same
// folding encoding/json uses when selecting a struct field for a JSON key —
// because the struct value and the presence map must describe the same key.
// The struct decoder fills PayloadB64 from a key spelled "PAYLOADB64" or
// "PayloadB64"; a literal lookup would miss it, so a sole re-cased base64 key
// would be mistaken for an omitted one (its decoded bytes silently dropped to
// the empty plain value) and a re-cased plain key alongside a normal base64
// key would no longer read as two representations at once. Canonicalizing the
// literal keys keeps the verdict identical across every casing.
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
	for literal := range keys {
		for _, canonical := range splitJSONKeys {
			if strings.EqualFold(literal, canonical) {
				e.present[canonical] = true
				break
			}
		}
	}
	return nil
}

// splitFieldSpec is one plain/base64 field pair's descriptor: the JSON key
// names, ways to read and write the two slots on a log entry, and the field's
// own wording for the two corruption verdicts. Every pair shares exactly one
// byte-preservation rule set — the write half in encode and the read half in
// decode, each implemented once — and differs only in this descriptor, so
// each value keeps its business meaning (message id, processing reason,
// header root, message payload, source and destination chains, and the
// success entry's consumed triple) and its existing, field-specific error
// text. Adding another raw-bytes field means adding one descriptor, not
// another copy of the UTF-8/base64 or presence/empty/decode handling.
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
	set            func(e *logEntry, plain, b64 string)
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

// encode is the single write half of the plain/base64 field split every
// raw-bytes log value uses, the exact inverse of decode:
//
//   - A value that is valid UTF-8 is written to the plain slot unchanged, so
//     ordinary text, Chinese, colons, whitespace and U+0000 keep the
//     historical plain field (the empty value included), and existing logs
//     stay byte-compatible.
//   - A value holding invalid UTF-8 bytes would be silently rewritten to
//     U+FFFD by JSON string encoding, so it is base64-encoded into the b64
//     slot instead, preserving the exact byte sequence across save, reopen
//     and compaction.
//
// The two slots are always written through set together, so one field can
// never carry both representations at once: the slot the value does not use
// is cleared. The rule takes no position on what the bytes mean — that is the
// caller's field — it only chooses the representation.
func (s splitFieldSpec) encode(e *logEntry, value string) {
	if utf8.ValidString(value) {
		s.set(e, value, "")
		return
	}
	s.set(e, "", base64.StdEncoding.EncodeToString([]byte(value)))
}

// splitFields is the one place each plain/base64 log pair is declared: the
// JSON key names, accessors and field-specific corruption wording. Adding a
// raw-bytes field means adding one descriptor, not another copy of the
// UTF-8/base64 or presence/empty/decode-error handling. Message id, result
// reason and the success entry's consuming id share the same encode/decode
// through these descriptors too; their pairs keep value-based exclusion
// (empty plainKey).
var splitFields = struct {
	id          splitFieldSpec
	reason      splitFieldSpec
	consumeBy   splitFieldSpec
	root        splitFieldSpec
	payload     splitFieldSpec
	to          splitFieldSpec
	from        splitFieldSpec
	chain       splitFieldSpec
	consumeTo   splitFieldSpec
	consumeFrom splitFieldSpec
}{
	id: splitFieldSpec{
		b64Key:         "idB64",
		plain:          func(e *logEntry) string { return e.ID },
		b64:            func(e *logEntry) string { return e.IDB64 },
		set:            func(e *logEntry, plain, b64 string) { e.ID, e.IDB64 = plain, b64 },
		bothErr:        "entry carries both id and idB64",
		undecodableErr: "entry carries undecodable idB64",
	},
	reason: splitFieldSpec{
		b64Key:         "reasonB64",
		plain:          func(e *logEntry) string { return e.Reason },
		b64:            func(e *logEntry) string { return e.ReasonB64 },
		set:            func(e *logEntry, plain, b64 string) { e.Reason, e.ReasonB64 = plain, b64 },
		bothErr:        "entry carries both reason and reasonB64",
		undecodableErr: "entry carries undecodable reasonB64",
	},
	consumeBy: splitFieldSpec{
		b64Key:         "consumeByB64",
		plain:          func(e *logEntry) string { return e.ConsumeBy },
		b64:            func(e *logEntry) string { return e.ConsumeByB64 },
		set:            func(e *logEntry, plain, b64 string) { e.ConsumeBy, e.ConsumeByB64 = plain, b64 },
		bothErr:        "success entry carries both consumeBy and consumeByB64",
		undecodableErr: "success entry carries undecodable consumeByB64",
	},
	root: splitFieldSpec{
		plainKey:       "root",
		b64Key:         "rootB64",
		plain:          func(e *logEntry) string { return e.Root },
		b64:            func(e *logEntry) string { return e.RootB64 },
		set:            func(e *logEntry, plain, b64 string) { e.Root, e.RootB64 = plain, b64 },
		bothErr:        "header entry carries both root and rootB64",
		undecodableErr: "header entry carries undecodable rootB64",
	},
	payload: splitFieldSpec{
		plainKey:       "payload",
		b64Key:         "payloadB64",
		plain:          func(e *logEntry) string { return e.Payload },
		b64:            func(e *logEntry) string { return e.PayloadB64 },
		set:            func(e *logEntry, plain, b64 string) { e.Payload, e.PayloadB64 = plain, b64 },
		bothErr:        "submit entry carries both payload and payloadB64",
		undecodableErr: "submit entry carries undecodable payloadB64",
	},
	to: splitFieldSpec{
		plainKey:       "to",
		b64Key:         "toB64",
		plain:          func(e *logEntry) string { return e.To },
		b64:            func(e *logEntry) string { return e.ToB64 },
		set:            func(e *logEntry, plain, b64 string) { e.To, e.ToB64 = plain, b64 },
		bothErr:        "submit entry carries both to and toB64",
		undecodableErr: "submit entry carries undecodable toB64",
	},
	from: splitFieldSpec{
		plainKey:       "from",
		b64Key:         "fromB64",
		plain:          func(e *logEntry) string { return e.From },
		b64:            func(e *logEntry) string { return e.FromB64 },
		set:            func(e *logEntry, plain, b64 string) { e.From, e.FromB64 = plain, b64 },
		bothErr:        "submit entry carries both from and fromB64",
		undecodableErr: "submit entry carries undecodable fromB64",
	},
	chain: splitFieldSpec{
		plainKey:       "chain",
		b64Key:         "chainB64",
		plain:          func(e *logEntry) string { return e.Chain },
		b64:            func(e *logEntry) string { return e.ChainB64 },
		set:            func(e *logEntry, plain, b64 string) { e.Chain, e.ChainB64 = plain, b64 },
		bothErr:        "entry carries both chain and chainB64",
		undecodableErr: "entry carries undecodable chainB64",
	},
	consumeTo: splitFieldSpec{
		plainKey:       "consumeTo",
		b64Key:         "consumeToB64",
		plain:          func(e *logEntry) string { return e.ConsumeTo },
		b64:            func(e *logEntry) string { return e.ConsumeToB64 },
		set:            func(e *logEntry, plain, b64 string) { e.ConsumeTo, e.ConsumeToB64 = plain, b64 },
		bothErr:        "success entry carries both consumeTo and consumeToB64",
		undecodableErr: "success entry carries undecodable consumeToB64",
	},
	consumeFrom: splitFieldSpec{
		plainKey:       "consumeFrom",
		b64Key:         "consumeFromB64",
		plain:          func(e *logEntry) string { return e.ConsumeFrom },
		b64:            func(e *logEntry) string { return e.ConsumeFromB64 },
		set:            func(e *logEntry, plain, b64 string) { e.ConsumeFrom, e.ConsumeFromB64 = plain, b64 },
		bothErr:        "success entry carries both consumeFrom and consumeFromB64",
		undecodableErr: "success entry carries undecodable consumeFromB64",
	},
}

// setID encodes a message id for the log without altering its bytes.
func (e *logEntry) setID(id string) {
	splitFields.id.encode(e, id)
}

// entryID decodes an entry's id back to its exact submitted bytes.
func (e *logEntry) entryID() (string, error) {
	return splitFields.id.decode(e)
}

// setReason encodes a processing result reason for the log without altering
// its bytes. Reasons may quote a raw-bytes message id (replay) or chain name
// (unknown source).
func (e *logEntry) setReason(reason string) {
	splitFields.reason.encode(e, reason)
}

// entryReason decodes a result/snapshot entry's reason back to its exact bytes.
func (e *logEntry) entryReason() (string, error) {
	return splitFields.reason.decode(e)
}

// setConsumeBy records the successful message's raw id alongside the consumed
// triple, using the same plain/base64 split as the id field.
func (e *logEntry) setConsumeBy(id string) {
	splitFields.consumeBy.encode(e, id)
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
	splitFields.root.encode(e, root)
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
	splitFields.payload.encode(e, payload)
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
	splitFields.to.encode(e, to)
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
	splitFields.consumeTo.encode(e, to)
}

// entryConsumeTo decodes a success entry's consumed destination back to its
// exact bytes. A record with both consumeTo and consumeToB64 set (by key
// presence, the empty string included), or an undecodable consumeToB64, is
// corrupt. Those rules are the shared ones in splitFieldSpec.decode; only the
// wording is success-entry specific.
func (e *logEntry) entryConsumeTo() (string, error) {
	return splitFields.consumeTo.decode(e)
}

// setFrom encodes a submit entry's source chain for the log without altering
// its bytes. A source that is valid UTF-8 (ordinary text, colons, NUL bytes)
// keeps the historical plain "from" field, so logs stay byte-compatible with
// older builds and the CLI text interface. A source holding invalid UTF-8
// bytes would be silently rewritten to U+FFFD by JSON string encoding, so it
// is instead stored base64-encoded in "fromB64", preserving the exact byte
// sequence across save, reopen and compaction — the source chain is part of
// the replay identity and of registration/header-coverage lookup, and must
// never change identity.
func (e *logEntry) setFrom(from string) {
	splitFields.from.encode(e, from)
}

// entryFrom decodes a submit entry's source chain back to its exact submitted
// bytes. Entries written before fromB64 existed carry only "from" and are
// taken at face value — including a source an old build had already rewritten
// to a replacement character, which stays that character; the lost bytes are
// never guessed. An entry carrying both fields at once (judged by key
// presence, the empty string included), or a fromB64 that does not decode, is
// an inconsistent record no build writes and is corrupt. Those rules are the
// shared ones in splitFieldSpec.decode; only the wording is source specific.
func (e *logEntry) entryFrom() (string, error) {
	return splitFields.from.decode(e)
}

// setChain encodes a source or header entry's chain name for the log without
// altering its bytes, using the same plain/base64 split as the submit entry's
// "from" field: valid UTF-8 keeps the historical plain "chain" field, invalid
// UTF-8 is stored base64-encoded in "chainB64". Registration and trusted
// headers must take effect for exactly the byte sequence they were saved
// with, never for what a display layer happens to render.
func (e *logEntry) setChain(chain string) {
	splitFields.chain.encode(e, chain)
}

// entryChain decodes a source or header entry's chain name back to its exact
// bytes. Entries written before chainB64 existed carry only "chain" and are
// taken at face value — including a name an old build had already rewritten
// to replacement characters, which stays those characters; the lost bytes are
// never guessed. An entry carrying both fields at once (judged by key
// presence, the empty string included), or a chainB64 that does not decode,
// is an inconsistent record no build writes and is corrupt. Those rules are
// the shared ones in splitFieldSpec.decode; only the wording is chain
// specific.
func (e *logEntry) entryChain() (string, error) {
	return splitFields.chain.decode(e)
}

// setConsumeFrom records the successful message's source chain alongside the
// consumed triple, using the same plain/base64 split as the submit entry's
// "from" field, so the consumption attribution survives invalid UTF-8 byte
// for byte.
func (e *logEntry) setConsumeFrom(from string) {
	splitFields.consumeFrom.encode(e, from)
}

// entryConsumeFrom decodes a success entry's consumed source back to its
// exact bytes. A record with both consumeFrom and consumeFromB64 set (by key
// presence, the empty string included), or an undecodable consumeFromB64, is
// corrupt. Those rules are the shared ones in splitFieldSpec.decode; only the
// wording is success-entry specific.
func (e *logEntry) entryConsumeFrom() (string, error) {
	return splitFields.consumeFrom.decode(e)
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
//
// The declared length and the frame end are kept wider than a machine int on
// purpose: n stays a uint32 so a declared length is never sign-mangled by a
// narrow int, and end is an int64 so bodyStart+n+CRC can never overflow. A
// 32-bit build therefore judges a huge declared length (e.g. 2^31 or 2^32-1)
// exactly like a 64-bit one — torn when it runs past the file — instead of
// wrapping the range back inside the file and slicing out of bounds.
type frame struct {
	pos       int    // offset of the length header
	n         uint32 // declared payload length
	bodyStart int    // offset of the payload; zero while even the header is incomplete
	end       int64  // offset just past the frame; may exceed len(raw)
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
	f.n = binary.BigEndian.Uint32(raw[pos : pos+frameHeaderSize])
	if f.n == 0 {
		return f, false, errZeroLengthFrame
	}
	f.bodyStart = pos + frameHeaderSize
	// The end offset is computed in int64 so the sum of a full-range uint32
	// length, the position and the CRC fits on every architecture: a declared
	// length a 32-bit int cannot hold (or one whose sum with the position
	// would overflow it) is judged against the actual file size, never
	// wrapped into a negative or in-range offset.
	f.end = int64(f.bodyStart) + int64(f.n) + frameCRCsSize
	if f.end > int64(len(raw)) {
		return f, true, nil
	}
	return f, false, nil
}

// payload returns the complete frame's payload bytes and reports whether the
// stored CRC32 matches them. It may only be called on a frame scanFrame
// reported complete, so f.end is within the file and fits an int on any
// architecture.
func (f frame) payload(raw []byte) ([]byte, bool) {
	bodyEnd := int(f.end) - frameCRCsSize
	payload := raw[f.bodyStart:bodyEnd]
	wantCRC := binary.BigEndian.Uint32(raw[bodyEnd:int(f.end)])
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
			if f.end == int64(len(raw)) {
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
		pos = int(f.end)
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
	return int(f.end), nil
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
	from, err := e.entryFrom()
	if err != nil {
		return err
	}
	e.From = from
	e.FromB64 = ""
	chain, err := e.entryChain()
	if err != nil {
		return err
	}
	e.Chain = chain
	e.ChainB64 = ""
	to, err := e.entryTo()
	if err != nil {
		return err
	}
	e.To = to
	e.ToB64 = ""
	consumeFrom, err := e.entryConsumeFrom()
	if err != nil {
		return err
	}
	e.ConsumeFrom = consumeFrom
	e.ConsumeFromB64 = ""
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

// validateRecoveryDue enforces, for one incremental result, the schedule the
// message's previously saved state (an earlier plain result or a compacted
// state) already established: a success or waiting result is a phase-1
// outcome of a due processing, so once a message has been processed and left a
// retry instant behind, such a result may only be stamped when that retry is
// due at a distinct processing time. Recovery judges with the live queue's
// own retryDue predicate — the result's own processing time against this
// message's saved schedule, never the wall clock — so a recovered message
// obeys exactly the timing a live advance would: an early success cannot be
// reconstructed to consume a nonce, and an extra waiting attempt cannot be
// added, while the backoff is still running. Replay and expired results are
// exempt — they are the phase-2 hold outcomes that settle a waiting message
// independently of its schedule, including at the same instant as its wait —
// and a message's first processing carries no schedule (the waiting record
// it schedules is accepted by first-processing rules, adding no backoff).
func validateRecoveryDue(rec *Record, e *logEntry) error {
	corrupt := func(msg string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(msg, args...))
	}
	if rec.Attempts == 0 {
		return nil // never processed before: no backoff to honor
	}
	if e.Status != StatusWaiting && e.Status != StatusSuccess {
		return nil // replay/expired holds are not bounded by the retry schedule
	}
	if e.Now == rec.LastProcAt {
		return corrupt("result time %d re-processes %q at the same instant as its prior processing", e.Now, e.ID)
	}
	if !retryDue(rec, e.Now) {
		return corrupt("result time %d precedes scheduled retry %d for %q", e.Now, rec.NextRetry, e.ID)
	}
	return nil
}

// validateSuccessRegistration enforces, for a recovered success — a plain
// result or a compacted state — the same source-registration precondition a
// live advance applies: the message's own source chain must be registered, or
// normal processing would have terminalized it as unknown-source instead of
// delivering it and consuming its nonce. A saved trusted header never
// substitutes for registration.
//
// For a plain result, only registrations saved in earlier records count:
// replay applies entries in log order, so a source registered after the
// success was recorded can never retroactively legalize it, while a
// registration completed any time before the success — even after the message
// was submitted — does. A compacted state is judged against the registrations
// the snapshot retained (compaction writes them before the records), without
// reconstructing the compacted-away registration history. Another chain's
// registration never covers the message: chain names are their raw bytes, so
// two names that merely display alike stay distinct.
func validateSuccessRegistration(s *loadedState, rec *Record, e *logEntry, rk recoveryKind) error {
	corrupt := func(msg string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(msg, args...))
	}
	m := rec.Msg.Message
	if s.sources[m.From] {
		return nil
	}
	return corrupt("success %s for %q from source chain %q is not registered: no source registration saved",
		rk.entryNoun, e.ID, m.From)
}

// validateSuccessExpiry enforces, for a recovered success — a plain result or
// a compacted state — the same absolute-expiry boundary a live advance
// applies: delivery only succeeds at a processing time strictly before the
// message's expiry, because checkReplayExpiry turns now == ExpiresAt into an
// expired outcome before delivery is ever attempted. A success stamped at or
// after the saved expiry is therefore an outcome no normal advance can have
// produced, however complete and checksum-valid the record is.
//
// The rule reads only the two instants saved together with the message: the
// success record's own processing time and the submit record's expiry — never
// the time the directory is reopened, any time the queue later advanced to, or
// when compaction happened. A message that legitimately succeeded before its
// deadline therefore stays a success however long afterwards it is reopened,
// and compaction neither re-expires a completed success nor requires the
// compacted-away processing history. An expiry of zero means never expire and
// is no deadline at all; in particular a zero-expiry success stamped at time
// zero is legal.
func validateSuccessExpiry(rec *Record, e *logEntry, rk recoveryKind) error {
	corrupt := func(msg string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(msg, args...))
	}
	expires := rec.Msg.ExpiresAt
	if expires != 0 && e.Now >= expires {
		return corrupt("success %s for %q processed at %d is not before its saved expiry %d",
			rk.entryNoun, e.ID, e.Now, expires)
	}
	return nil
}

// validateSuccessCoverage enforces, for a recovered success — a plain result
// or a compacted state — the same delivery precondition a live advance
// applies: the source chain's highest trusted header accepted so far must
// cover the message's proof height.
//
// For a plain result, "so far" is the log prefix before the result: the
// trusted header must already have been saved when the success was recorded,
// so a higher trusted header written only afterwards can never retroactively
// legalize a success that no advance could have delivered. A compacted state
// is judged against the headers the snapshot retained — compaction writes
// them before the records — without reconstructing the compacted-away header
// history; a later-higher retained trusted header may therefore widen the
// coverage beyond the height named in the saved reason, which need not match
// it. Untrusted headers never establish coverage, a lower trusted header
// never narrows it, another chain's headers never cover this chain's messages
// (chain names are their raw bytes), and a trusted height exactly equal to
// the proof height does cover. The reason text never substitutes for a saved
// trusted header.
func validateSuccessCoverage(s *loadedState, rec *Record, e *logEntry, rk recoveryKind) error {
	corrupt := func(msg string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(msg, args...))
	}
	m := rec.Msg.Message
	hs := s.headers[m.From]
	if hs != nil && hs.trusted != nil && hs.trusted.Height >= m.ProofAt {
		return nil
	}
	if hs == nil || hs.trusted == nil {
		return corrupt("success %s for %q from source chain %q lacks trusted header coverage: proof height %d but no trusted header saved",
			rk.entryNoun, e.ID, m.From, m.ProofAt)
	}
	return corrupt("success %s for %q from source chain %q lacks trusted header coverage: highest trusted height %d is below proof height %d",
		rk.entryNoun, e.ID, m.From, hs.trusted.Height, m.ProofAt)
}

// acceptRecoveryStatus is the second shared check, run after the
// kind-specific acceptance rules (including the snapshot's >=1-attempts
// requirement): waiting must carry the canonical retry schedule (with the
// sole legacy-overflow exception repaired in memory) and no consumption,
// success must be stamped strictly before the message's saved absolute expiry
// (a zero expiry never expires), come from a source chain registered no later
// than the success record and be covered by a trusted header of the message's
// own source chain saved no later than the success record, keep no retry time
// and consume its own (from,to,nonce) attributed to itself, and terminal
// failures carry neither a retry time nor consumption fields. The repaired
// retry time of a legacy overflowed schedule is written back onto e.
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
		// Expiry first, then registration and coverage — the same order a live
		// advance judges a due message (the replay/expiry hold precedes
		// unknown-source, which precedes waiting/delivery).
		if err := validateSuccessExpiry(rec, e, rk); err != nil {
			return err
		}
		if err := validateSuccessRegistration(s, rec, e, rk); err != nil {
			return err
		}
		if err := validateSuccessCoverage(s, rec, e, rk); err != nil {
			return err
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
		// Replay applies the shared header-state update rules with the
		// recovery acceptance policy: historical same-height coverage is never
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
		h := Header{Chain: e.Chain, Height: e.Height, Root: root, Trusted: e.Trusted}
		update, err := hs.planUpdate(h, replaySameHeight)
		if err != nil {
			return corrupt("bad header entry: %v", err)
		}
		hs.applyUpdate(h, update)
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
		// intact and well-checksummed the record is. A waiting or success
		// result is a phase-1 due-processing outcome and must additionally be
		// stamped at a distinct instant at or after the retry the message's
		// previous result (or compacted state) scheduled: recovery may not
		// deliver — and consume a nonce for — a message whose backoff had not
		// elapsed, nor add a waiting attempt the live queue could not have
		// made. Replay and expired results are the phase-2 hold outcomes and
		// stay exempt: they settle a waiting message while its backoff is
		// still running, at the same instant as its wait included. A message's
		// first processing has no schedule to obey (time zero included). The
		// per-status validation (waiting schedule, success consumption,
		// terminal fields) is shared with compacted state entries.
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
		if err := validateRecoveryDue(rec, e); err != nil {
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
	e := &logEntry{T: kindSource}
	e.setChain(chain)
	return s.append(e)
}

func (s *store) appendHeader(h Header) error {
	e := &logEntry{T: kindHeader, Height: h.Height, Trusted: h.Trusted}
	e.setChain(h.Chain)
	e.setRoot(h.Root)
	return s.append(e)
}

// newSubmitEntry builds the record that restores one message's original
// content and first-submission position. It is the single construction rule
// for both save paths: the incremental appendSubmit writes one per Submit call
// and compact writes one per snapshotted record, so id, source and destination
// chains, nonce, payload, proof height, expiry and seq — including the
// plain/base64 byte preservation for id, source, destination and payload — are
// encoded identically in a plain result log and in a compacted log.
func newSubmitEntry(rec *Record) *logEntry {
	m := rec.Msg.Message
	e := &logEntry{
		T: kindSubmit, Seq: rec.Seq,
		Nonce: m.Nonce, ProofAt: m.ProofAt, ExpiresAt: rec.Msg.ExpiresAt,
	}
	e.setID(m.ID)
	e.setFrom(m.From)
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
// same plain/base64 source, destination and id encoding.
func setSuccessConsumption(e *logEntry, id string, token *consumeToken) {
	e.setConsumeFrom(token.from)
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
		e := &logEntry{T: kindSource}
		e.setChain(c)
		entries = append(entries, e)
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
			e := &logEntry{T: kindHeader, Height: hs.trusted.Height, Trusted: hs.trusted.Trusted}
			e.setChain(hs.trusted.Chain)
			e.setRoot(hs.trusted.Root)
			entries = append(entries, e)
		}
		if hs.trusted == nil || hs.latest != *hs.trusted {
			e := &logEntry{T: kindHeader, Height: hs.latest.Height, Trusted: hs.latest.Trusted}
			e.setChain(hs.latest.Chain)
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
