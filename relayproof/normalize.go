// Log field normalization so detection rules can read logs from different
// sources through one canonical event shape.
package relayproof

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Canonical event field names.
const (
	FieldTimestamp = "timestamp"
	FieldSourceIP  = "source_ip"
	FieldAction    = "action"
)

// canonicalField describes one standard event field: the accepted aliases,
// whether the field is required, and how an already-decoded JSON string for
// it is validated and reduced to canonical text.
type canonicalField struct {
	name      string
	aliases   []string
	required  bool
	normalize func(canonical, s string) (string, error)
}

// canonicalFields is the single registry of the mapped field set. Every fact
// about the grouping is stated here once: which keys belong to one field
// (canonical name plus aliases), which fields are required, and the order in
// which provided fields are checked (and missing required fields reported).
// Alias lookup and validation are derived from this list, so maintaining a
// rule means editing only its entry. Only top-level keys are looked up here.
var canonicalFields = []canonicalField{
	{
		name:      FieldTimestamp,
		aliases:   []string{"time"},
		required:  true,
		normalize: normalizeTimestamp,
	},
	{
		name:      FieldSourceIP,
		aliases:   []string{"src_ip"},
		required:  false,
		normalize: normalizeSourceIP,
	},
	{
		name:      FieldAction,
		aliases:   []string{"event_type"},
		required:  true,
		normalize: normalizeAction,
	},
}

// fieldByKey maps both canonical names and aliases to their field, so key
// recognition and alias attribution are one lookup: a canonical name and its
// aliases can never be maintained out of sync. Unknown keys are simply absent
// and stay in extra.
var fieldByKey = func() map[string]*canonicalField {
	byKey := make(map[string]*canonicalField)
	for i := range canonicalFields {
		field := &canonicalFields[i]
		byKey[field.name] = field
		for _, alias := range field.aliases {
			byKey[alias] = field
		}
	}
	return byKey
}()

// NormalizedEvent is the canonical representation of one log line.
type NormalizedEvent struct {
	Timestamp string                     `json:"timestamp"`
	SourceIP  string                     `json:"source_ip,omitempty"`
	Action    string                     `json:"action"`
	Extra     map[string]json.RawMessage `json:"extra,omitempty"`
}

// NormalizeResult is emitted for every non-blank complete input line, in
// input order.
type NormalizeResult struct {
	Line  int              `json:"line"`
	OK    bool             `json:"ok"`
	Event *NormalizedEvent `json:"event,omitempty"`
	Error string           `json:"error,omitempty"`
}

// ErrLogRead and ErrLogWrite let callers tell stream-level I/O failures
// apart from per-line normalization failures: NormalizeReader wraps the
// underlying error with the matching sentinel, and a single invalid log
// line never carries either.
var (
	ErrLogRead  = errors.New("log stream read failure")
	ErrLogWrite = errors.New("log stream write failure")
)

// shortWriteDetectingWriter enforces the io.Writer contract at the output
// boundary: a Write that acknowledges fewer bytes than it was offered while
// reporting a nil error becomes io.ErrShortWrite. The guard matters for
// results larger than the buffering writer's 4 KiB buffer: those bypass the
// buffer and are handed to the underlying Writer in one call, and bufio
// retries a nil-error short acknowledgement forever (a (0, nil) answer loops
// without making progress), so without the normalization NormalizeReader
// would never return. Turning the broken acknowledgement into an ordinary
// error makes bufio stop on the first short write and lets the failure
// surface as ErrLogWrite wrapping io.ErrShortWrite. A Write that already
// reports a concrete error passes it through untouched: that error stays the
// write failure's original cause and is never replaced by io.ErrShortWrite.
type shortWriteDetectingWriter struct {
	w io.Writer
}

func (w shortWriteDetectingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if err == nil && n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, err
}

// SourceCIDRFilter restricts emitted successful events to one IPv4 source
// network. It is the parsed, validated form of an argument like
// "192.0.2.123/24": host bits in the spelled address do not narrow the range,
// so "192.0.2.123/24" and "192.0.2.0/24" admit the same sources, "/32" admits
// only the one address, and "/0" admits every normalized IPv4 source.
//
// Matching uses the fully normalized source_ip. A plain IPv4 address and its
// IPv4-mapped IPv6 spellings (e.g. 192.0.2.1 and ::ffff:192.0.2.1) normalize
// to the same address and therefore admit identically; a genuine IPv6 source
// whose tail happens to embed the same 32 bits (e.g. ::192.0.2.1) is not an
// IPv4-mapped address and never admits. A valid event without a source
// address, or whose normalized source stays IPv6, is simply not emitted by a
// filtered run; that is neither a success result nor a failure.
type SourceCIDRFilter struct {
	network *net.IPNet
}

// sourceCIDRPattern pins the argument grammar before any range checking:
// exactly four 1-3 digit octets, a single "/", and a 1-3 digit prefix
// length. net.ParseCIDR is deliberately not used: it accepts IPv6 networks
// (the option is IPv4-only) and its error text does not distinguish the
// rejected shapes, while strict parsing here lets each failure name the
// exact octet or prefix that was wrong.
var sourceCIDRPattern = regexp.MustCompile(`^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,3})$`)

// ParseSourceCIDRFilter validates one IPv4 network argument: a dotted decimal
// IPv4 address, a slash, and a prefix length of 0-32. Each octet must be a
// plain 0-255 decimal number, with no leading-zero padding, sign, or other
// notation. Host bits are interpreted as part of the network — they are masked
// away rather than rejected — so "192.0.2.123/24" is the same filter as
// "192.0.2.0/24".
func ParseSourceCIDRFilter(s string) (SourceCIDRFilter, error) {
	m := sourceCIDRPattern.FindStringSubmatch(s)
	if m == nil {
		return SourceCIDRFilter{}, errors.New(`must be an IPv4 network in dotted decimal with a "/0" to "/32" prefix length, e.g. "192.0.2.0/24"`)
	}
	var octets [4]byte
	for i := 0; i < 4; i++ {
		part := m[i+1]
		// The pattern caps each octet at three digits; reject leading-zero
		// padding such as "192.168.001.001", which is not the promised dotted
		// decimal spelling (and ambiguous with historic octal parsing).
		if len(part) > 1 && part[0] == '0' {
			return SourceCIDRFilter{}, fmt.Errorf("invalid IPv4 network %q: octet %q must not have leading zeroes", s, part)
		}
		v, _ := strconv.Atoi(part)
		if v > 255 {
			return SourceCIDRFilter{}, fmt.Errorf("invalid IPv4 network %q: octet %d out of range (0-255)", s, v)
		}
		octets[i] = byte(v)
	}
	prefixPart := m[5]
	if len(prefixPart) > 1 && prefixPart[0] == '0' {
		return SourceCIDRFilter{}, fmt.Errorf("invalid IPv4 network %q: prefix length %q must not have leading zeroes", s, prefixPart)
	}
	prefix, _ := strconv.Atoi(prefixPart)
	if prefix > 32 {
		return SourceCIDRFilter{}, fmt.Errorf("invalid IPv4 network %q: prefix length %d out of range (0-32)", s, prefix)
	}
	// Mask host bits away so the written host address cannot narrow the
	// range: network.IP already carries the masked address.
	mask := net.CIDRMask(prefix, 32)
	ip := net.IPv4(octets[0], octets[1], octets[2], octets[3]).To4()
	return SourceCIDRFilter{network: &net.IPNet{IP: ip.Mask(mask), Mask: mask}}, nil
}

// String renders the canonical network the filter admits, e.g.
// ParseSourceCIDRFilter("192.0.2.123/24").String() == "192.0.2.0/24".
func (f SourceCIDRFilter) String() string {
	return f.network.String()
}

// admits reports whether a normalized source_ip string falls in the IPv4
// network. Text that is not a single IPv4 address is never admitted: a
// normalized IPv6 spelling (including ::192.0.2.1) stays IPv6 and is rejected
// even when its final 32 bits match. Normalized mapped spellings have already
// been printed in dotted form by net.IP.String, so they take the IPv4 path.
func (f SourceCIDRFilter) admits(normalizedSourceIP string) bool {
	ip := net.ParseIP(normalizedSourceIP)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return f.network.Contains(v4)
	}
	return false
}

// NormalizeReader streams newline-delimited JSON logs from r and writes one
// NormalizeResult JSON object per non-blank physical line to w. Blank lines
// produce no output but still advance the physical line counter. It returns
// the number of complete lines that failed normalization; processing of
// later lines continues after any per-line failure.
//
// Stream-level failures are distinct from bad log lines: a read error stops
// processing and is returned wrapped with ErrLogRead, after every complete
// line already read has been processed in order; any unterminated fragment
// delivered together with the read error is part of the failed read rather
// than a complete log line, so it is neither normalized nor counted and gets
// no result of its own. A read error is recorded at the exact Read call that
// returns it, including when that call hands back complete newline-ended
// logs in the same delivery, so it stays the primary failure even when the
// output later fails while emitting those very results: the write failure is
// shown in the message text but is not wrapped, and neither ErrLogWrite nor
// the write's cause matches via errors.Is. Conversely, a write failure with
// no read error in hand is reported as such immediately, without reading any
// further input to decide precedence. A write error is returned wrapped with
// ErrLogWrite and leaves the failure count unchanged: an output end that
// acknowledges fewer bytes than offered with a nil error (an io.Writer
// contract violation) ends the run the same way, with io.ErrShortWrite kept
// in the error chain instead of retried until it recovers; bytes already
// accepted remain as the prefix of the would-be output, including an
// incomplete final JSON record. A clean EOF is not an error, including when
// the final complete line has no trailing newline.
func NormalizeReader(r io.Reader, w io.Writer) (failures int, err error) {
	return NormalizeReaderFiltered(r, w, nil)
}

// NormalizeReaderFiltered behaves like NormalizeReader, except that when
// filter is non-nil a successfully normalized event is written only when its
// normalized source_ip is admitted by the filter. Filtered-out successes are
// not written and are not failures: they leave both the failure count and
// the exit status unchanged. The filter never hides bad logs: a line that
// fails normalization is still emitted with its physical line number and
// original error reason and carries no event, whether or not its raw address
// was inside, outside, or absent from the network, and later lines keep
// processing. A nil filter reproduces NormalizeReader exactly.
func NormalizeReaderFiltered(r io.Reader, w io.Writer, filter *SourceCIDRFilter) (failures int, err error) {
	// Guard the output end before buffering: a result that exceeds the
	// 4 KiB buffer is forwarded straight to the underlying Writer, so the
	// Flush path alone cannot catch a nil-error short acknowledgement there.
	bw := bufio.NewWriter(shortWriteDetectingWriter{w: w})
	var readErr error // first stream read error, always the primary failure
	// readErrorWins reports a write fault after a read fault has already been
	// delivered: the read failure and its original cause stay the only error
	// chain (both reachable via errors.Is), while the later write fault only
	// contributes its message text and must not replace or join the chain.
	readErrorWins := func(writeErr error) error {
		wrapped := fmt.Errorf("%w: %w", ErrLogRead, readErr)
		if writeErr != nil {
			wrapped = fmt.Errorf("%w: %v", wrapped, writeErr)
		}
		return wrapped
	}
	defer func() {
		flushErr := bw.Flush()
		if err != nil {
			// A mid-stream error was already wrapped above; a write fault met
			// there was classified against readErr at the instant it fired.
			return
		}
		switch {
		case readErr != nil:
			// The original read failure must survive a write failure during
			// shutdown: both the read marker and the underlying cause stay
			// reachable via errors.Is, while the later flush failure only
			// contributes its text (it must not mask the original cause).
			err = readErrorWins(flushErr)
		case flushErr != nil:
			err = fmt.Errorf("%w: %w", ErrLogWrite, flushErr)
		}
	}()
	encoder := json.NewEncoder(bw)
	encoder.SetEscapeHTML(false)

	// Drive the upstream Reader directly instead of bufio.Reader.ReadBytes.
	// ReadBytes latches an error that arrives together with a
	// delimiter-ended chunk: the complete line comes back with a nil error and
	// the fault is only returned on the NEXT call. Emitting that line could
	// then fail on the output first, and the plain write return would mask the
	// already-delivered read cause. Owning the loop makes every (bytes, err)
	// pair observable at the exact call it arrives, so a non-EOF fault is
	// recorded before the bytes that came with it are processed and can never
	// be reclassified by a write fault that follows in processing order. A
	// clean EOF is recorded as ordinary end-of-input and is never a fault.
	// pending holds bytes of the current physical line (plus any complete
	// lines delivered in the same read) not yet processed. scanned is the
	// number of leading pending bytes already searched for '\n' on a previous
	// delivery: the next search starts there, so a long line arriving in many
	// short pieces scans each delivered byte exactly once instead of
	// re-examining every earlier byte on every read. Both indices are
	// positions in the current pending slice; any discard below resets them.
	var pending []byte
	scanned := 0
	chunk := make([]byte, 64*1024)
	lineNo := 0
	emptyReads := 0
	// processLine normalizes and emits one complete physical line (including
	// its trailing newline). It reports only an output failure; per-line
	// normalization failures are counted and emitted as results instead.
	processLine := func(raw []byte) error {
		lineNo++
		if strings.TrimSpace(string(raw)) == "" {
			return nil
		}
		result := NormalizeLine(lineNo, raw)
		emit := true
		if !result.OK {
			failures++
		} else if filter != nil && !filter.admits(result.Event.SourceIP) {
			// A valid event whose normalized source is outside the selected
			// network (or absent, or still IPv6) is filtered out: no result and
			// no failure. The filter never runs on failed lines, so a bad
			// address outside the network is still reported as a failure.
			emit = false
		}
		if !emit {
			return nil
		}
		return encoder.Encode(result)
	}
	// writeFailure classifies an output fault: once a read fault is in hand it
	// stays primary even though the write fired first in time; otherwise this
	// is the ordinary write-failure report and processing stops without
	// reading any further input to decide precedence.
	writeFailure := func(werr error) error {
		if readErr != nil {
			return readErrorWins(werr)
		}
		return fmt.Errorf("%w: %w", ErrLogWrite, werr)
	}

	for {
		n, rerr := r.Read(chunk)
		if n > 0 {
			pending = append(pending, chunk[:n]...)
			emptyReads = 0
		} else if rerr == nil {
			// A well-behaved Reader never returns (0, nil); bound the
			// retries instead of spinning without progress, matching bufio.
			emptyReads++
			if emptyReads > 100 {
				readErr = io.ErrNoProgress
				return failures, nil
			}
			continue
		}
		eof := errors.Is(rerr, io.EOF)
		fault := rerr != nil && !eof
		if fault {
			// The fault is recorded before the bytes delivered with it are
			// touched, so it survives even if pushing their results out fails.
			readErr = rerr
		}

		// Process every newline-ended line the delivered bytes complete.
		// Only the unsearched suffix is examined: every byte before scanned
		// arrived in an earlier delivery and is already known to carry no
		// '\n', so a long line fed to the reader in short pieces has its
		// accumulated prefix scanned once rather than once per delivery.
		for {
			i := bytes.IndexByte(pending[scanned:], '\n')
			if i < 0 {
				scanned = len(pending)
				break
			}
			i += scanned
			werr := processLine(pending[:i+1])
			pending = pending[i+1:]
			scanned = 0 // the remaining slice is the unsearched tail of this delivery
			if werr != nil {
				return failures, writeFailure(werr)
			}
		}
		if len(pending) == 0 {
			// Release the grown accumulator once every delivered byte is a
			// processed complete line, so retention tracks the longest line
			// rather than the whole stream.
			pending = nil
			scanned = 0
		}

		switch {
		case fault:
			// The newline-less remainder belongs to the failed read: it is
			// neither normalized nor counted and gets no result of its own.
			// Stop immediately; no further input is read to set precedence.
			return failures, nil
		case eof:
			// A clean EOF is normal completion: any remaining bytes are the
			// final complete line without a trailing newline.
			if len(pending) > 0 {
				if werr := processLine(pending); werr != nil {
					return failures, writeFailure(werr)
				}
			}
			return failures, nil
		}
	}
}

// NormalizeLine normalizes a single raw JSON log line. The line number is
// echoed unchanged in the result.
func NormalizeLine(lineNo int, raw []byte) NormalizeResult {
	event, err := normalizeEvent(trimJSONWhitespace(raw))
	if err != nil {
		return NormalizeResult{Line: lineNo, OK: false, Error: err.Error()}
	}
	return NormalizeResult{Line: lineNo, OK: true, Event: event}
}

// trimJSONWhitespace strips only the whitespace JSON allows around a
// document (RFC 8259 §2): space, horizontal tab, carriage return, and line
// feed. bytes.TrimSpace must not be used on a raw log line: it also removes
// characters like U+000B, U+000C, and U+00A0, which are not legal JSON
// separators, and would silently delete them before the syntax check instead
// of letting the decoder reject the line. Whitespace inside string values is
// never touched — only the bytes surrounding the document are examined.
func trimJSONWhitespace(raw []byte) []byte {
	return bytes.Trim(raw, " \t\r\n")
}

func normalizeEvent(raw []byte) (*NormalizedEvent, error) {
	if err := checkCharacterIntegrity(raw); err != nil {
		return nil, err
	}
	object, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}

	// Sort source keys so candidate order (and therefore error messages) is
	// deterministic regardless of Go map iteration order.
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Group raw values under their canonical field; keys the registry does
	// not know stay in extra untouched, since mapping is top-level only.
	groups := make(map[string][]json.RawMessage)
	extra := make(map[string]json.RawMessage)
	for _, key := range keys {
		if field, mapped := fieldByKey[key]; mapped {
			groups[field.name] = append(groups[field.name], object[key])
		} else {
			extra[key] = object[key]
		}
	}

	// Validate every provided field in registry order and keep its canonical
	// value. Required-field checks run only after all provided values are
	// legal, so an invalid value is always reported before a missing field.
	values := make(map[string]string)
	for i := range canonicalFields {
		field := &canonicalFields[i]
		candidates := groups[field.name]
		if len(candidates) == 0 {
			continue
		}
		value, err := field.validate(candidates)
		if err != nil {
			return nil, err
		}
		values[field.name] = value
	}

	// Missing required fields are reported in registry order (timestamp
	// before action); the optional address field is skipped here.
	for i := range canonicalFields {
		field := &canonicalFields[i]
		if field.required {
			if _, present := values[field.name]; !present {
				return nil, fmt.Errorf("missing required field %q", field.name)
			}
		}
	}

	event := &NormalizedEvent{
		Timestamp: values[FieldTimestamp],
		Action:    values[FieldAction],
	}
	if sourceIP, present := values[FieldSourceIP]; present {
		event.SourceIP = sourceIP
	}
	if len(extra) > 0 {
		event.Extra = extra
	}
	return event, nil
}

// validate checks every raw value mapped to one field independently, then
// compares the normalized results. A valid canonical value never masks an
// invalid alias: each candidate must be legal on its own. Equal canonical
// results merge, so equivalent time and IP spellings and leading/trailing
// action whitespace collapse together; genuinely different results fail the
// whole line.
func (f *canonicalField) validate(candidates []json.RawMessage) (string, error) {
	var canonicalValue string
	for i, raw := range candidates {
		s, err := requireString(f.name, raw)
		if err != nil {
			return "", err
		}
		value, err := f.normalize(f.name, strings.TrimSpace(s))
		if err != nil {
			return "", err
		}
		if i == 0 {
			canonicalValue = value
			continue
		}
		if value != canonicalValue {
			return "", fmt.Errorf("field %q has conflicting values: %q and %q", f.name, canonicalValue, value)
		}
	}
	return canonicalValue, nil
}

// checkCharacterIntegrity rejects log lines whose characters cannot be
// represented exactly. The raw bytes must be valid UTF-8, and every \uXXXX
// escape inside a JSON string — field names and string values at any depth,
// including unmapped fields and an input's own extra — must denote a Unicode
// scalar value: a high surrogate escape (D800-DBFF) is only legal immediately
// followed by a low surrogate escape (DC00-DFFF), and a low surrogate escape
// never appears on its own. encoding/json silently rewrites both defects to
// U+FFFD, so decoding without this check would map fields, compare aliases,
// and preserve extra data built from corrupted text. Nothing is repaired:
// no bytes are dropped, no escapes are completed, and no replacement
// characters are substituted — the whole line fails instead. A literal
// U+FFFD the user actually wrote (as UTF-8 bytes or as a \uFFFD escape) is valid
// input and passes.
func checkCharacterIntegrity(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("invalid UTF-8 encoding at byte offset %d", invalidUTF8Offset(raw))
	}
	return checkUnicodeEscapes(raw)
}

// invalidUTF8Offset locates the first byte that cannot start or continue a
// valid UTF-8 sequence. Callers must only invoke it on input utf8.Valid has
// already rejected.
func invalidUTF8Offset(raw []byte) int {
	for i := 0; i < len(raw); {
		_, size := utf8.DecodeRune(raw[i:])
		if size == 1 && raw[i] >= utf8.RuneSelf {
			return i
		}
		i += size
	}
	return 0 // unreachable: utf8.Valid reported the input invalid
}

// checkUnicodeEscapes scans the string literals of a JSON document and
// rejects unpaired surrogate escapes. Only bytes inside a string are
// examined; a backslash anywhere else is a JSON syntax error the decoder
// reports. Escapes other than \u are skipped as two-byte pairs, so an
// escaped backslash hides nothing: in "\\uD800" the uD800 part is ordinary
// text, not an escape, and stays untouched. A \u escape that is truncated or
// carries non-hex digits is left for the decoder, which rejects the line as
// invalid JSON.
func checkUnicodeEscapes(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		if c == '"' {
			inString = false
			continue
		}
		if c != '\\' {
			continue
		}
		if i+1 >= len(raw) || raw[i+1] != 'u' {
			i++ // two-byte escape (\\, \", \n, ...); a trailing lone backslash is the decoder's error
			continue
		}
		if i+6 > len(raw) {
			continue // truncated \u escape: invalid JSON, reported by the decoder
		}
		code, ok := hex4(raw[i+2 : i+6])
		if !ok {
			continue // malformed \u escape: invalid JSON, reported by the decoder
		}
		switch {
		case code >= 0xD800 && code <= 0xDBFF:
			if i+12 <= len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' {
				if low, ok := hex4(raw[i+8 : i+12]); ok && low >= 0xDC00 && low <= 0xDFFF {
					i += 11 // consume the whole surrogate pair
					continue
				}
			}
			return fmt.Errorf("unpaired Unicode escape \\u%04X at byte offset %d: high surrogate must be followed immediately by a low surrogate escape", code, i)
		case code >= 0xDC00 && code <= 0xDFFF:
			return fmt.Errorf("unpaired Unicode escape \\u%04X at byte offset %d: low surrogate must follow a high surrogate escape", code, i)
		default:
			i += 5 // consume \uXXXX
		}
	}
	return nil
}

// hex4 parses exactly four hexadecimal digits.
func hex4(b []byte) (int, bool) {
	v := 0
	for _, c := range b {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}

// decodeObject parses one JSON object and rejects duplicate top-level keys,
// including when the repeated key carries the same value.
func decodeObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return nil, errors.New("log must be a JSON object")
	}

	object := make(map[string]json.RawMessage)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid JSON: %v", err)
		}
		key := keyToken.(string)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid JSON in field %q: %v", key, err)
		}
		if _, exists := object[key]; exists {
			return nil, fmt.Errorf("duplicate field %q", key)
		}
		object[key] = value
	}
	if _, err := decoder.Token(); err != nil { // consume closing '}'
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}
	if tok, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("invalid JSON: unexpected trailing token %s", tok)
		}
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}
	return object, nil
}

func normalizeTimestamp(canonical, s string) (string, error) {
	t, err := parseTimestamp(s)
	if err != nil {
		return "", fmt.Errorf("field %q: invalid RFC3339 timestamp: %v", canonical, err)
	}
	return t.UTC().Format(time.RFC3339Nano), nil
}

func normalizeAction(canonical, s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("field %q: action must not be empty", canonical)
	}
	return s, nil
}

func normalizeSourceIP(canonical, s string) (string, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("field %q: invalid IP address %q (no port allowed)", canonical, s)
	}
	return ip.String(), nil
}

// requireString enforces that a mapped value is a JSON string. An explicit
// null fails rather than being treated as an omitted field.
func requireString(canonical string, raw json.RawMessage) (string, error) {
	b := bytes.TrimSpace(raw)
	if len(b) == 0 {
		return "", fmt.Errorf("field %q: value is missing", canonical)
	}
	switch b[0] {
	case '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return "", fmt.Errorf("field %q: invalid JSON string: %v", canonical, err)
		}
		return s, nil
	case 'n':
		return "", fmt.Errorf("field %q: value must be a string, got null", canonical)
	case '{':
		return "", fmt.Errorf("field %q: value must be a string, got object", canonical)
	case '[':
		return "", fmt.Errorf("field %q: value must be a string, got array", canonical)
	case 't', 'f':
		return "", fmt.Errorf("field %q: value must be a string, got boolean", canonical)
	default:
		return "", fmt.Errorf("field %q: value must be a string, got number", canonical)
	}
}

// strictRFC3339Pattern pins the public RFC3339 shape: four-digit year and
// two-digit month/day/hour/minute/second, optional fractional seconds that
// must use a dot with exactly 1-9 digits, and a mandatory "Z" or numeric
// offset. time.Parse accepts shapes outside this grammar — single-digit
// hours, comma decimals, and unbounded offsets — so the layout is checked
// here before any value is handed to the calendar logic.
var strictRFC3339Pattern = regexp.MustCompile(
	`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$`,
)

// parseTimestamp accepts exactly a public RFC3339 string: the hour field
// must be two digits, fractional seconds must use a dot with 1-9 digits,
// and a numeric offset must keep its hour within 00-23 and its minute
// within 00-59. time.Parse silently pads short fields, accepts a comma as
// the decimal separator, truncates over-long fractions, and carries
// out-of-range offset components into neighboring units; all of those
// rewrites are rejected here rather than normalized away. The parsed
// instant must also convert to a UTC year within 0000-9999, since a
// success event serializes its timestamp in RFC3339Nano, which can only
// carry a four-digit unsigned year.
func parseTimestamp(s string) (time.Time, error) {
	m := strictRFC3339Pattern.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, errors.New("not an RFC3339 timestamp (need YYYY-MM-DDTHH:MM:SS with two-digit fields, a dot fraction of 1-9 digits, and Z or ±HH:MM offset)")
	}

	hour, _ := strconv.Atoi(s[11:13])
	minute, _ := strconv.Atoi(s[14:16])
	second, _ := strconv.Atoi(s[17:19])

	// Range-check every numeric component explicitly; no padding or carry
	// is applied to any field. (:60 leap seconds are not part of RFC3339.)
	if hour > 23 {
		return time.Time{}, fmt.Errorf("hour %02d out of range (00-23)", hour)
	}
	if minute > 59 {
		return time.Time{}, fmt.Errorf("minute %02d out of range (00-59)", minute)
	}
	if second > 59 {
		return time.Time{}, fmt.Errorf("second %02d out of range (00-59)", second)
	}

	if zone := m[2]; zone != "Z" {
		offsetHour, _ := strconv.Atoi(zone[1:3])
		offsetMinute, _ := strconv.Atoi(zone[4:6])
		if offsetHour > 23 {
			return time.Time{}, fmt.Errorf("timezone offset hour %02d out of range (00-23)", offsetHour)
		}
		if offsetMinute > 59 {
			return time.Time{}, fmt.Errorf("timezone offset minute %02d out of range (00-59)", offsetMinute)
		}
	}

	// Delegate calendar validation (month, day-of-month, leap years) and
	// zone math to the standard library. The strict pattern above keeps it
	// from truncating or rewriting any component.
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}

	// A legal local instant can still land outside the four-digit-year
	// window after the zone conversion (e.g. 0000-01-01T00:00:00+00:01
	// becomes the previous year). RFC3339Nano would then emit a signed or
	// five-digit year, which is not a value this function accepts on input,
	// so reject it instead of reporting success.
	if utc := t.UTC(); utc.Year() < 0 || utc.Year() > 9999 {
		return time.Time{}, fmt.Errorf("UTC year %d out of range (0000-9999) after timezone conversion", utc.Year())
	}
	return t, nil
}
