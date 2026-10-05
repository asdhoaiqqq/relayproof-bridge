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
// no result of its own. A write error is returned wrapped with ErrLogWrite
// and leaves the failure count unchanged. When both sides fail, the earlier
// read error is reported. A clean EOF is not an error, including when the
// final complete line has no trailing newline.
func NormalizeReader(r io.Reader, w io.Writer) (failures int, err error) {
	reader := bufio.NewReader(r)
	bw := bufio.NewWriter(w)
	var readErr error // first stream read error, reported even if flushing fails
	defer func() {
		flushErr := bw.Flush()
		if err != nil {
			return // a mid-stream error was already wrapped above
		}
		switch {
		case readErr != nil:
			// The original read failure must survive a write failure
			// during shutdown: both the read marker and the underlying
			// cause stay reachable via errors.Is, while the later flush
			// failure only contributes its text (it must not mask the
			// original cause).
			wrapped := fmt.Errorf("%w: %w", ErrLogRead, readErr)
			if flushErr != nil {
				wrapped = fmt.Errorf("%w: %v", wrapped, flushErr)
			}
			err = wrapped
		case flushErr != nil:
			err = fmt.Errorf("%w: %w", ErrLogWrite, flushErr)
		}
	}()
	encoder := json.NewEncoder(bw)
	encoder.SetEscapeHTML(false)

	lineNo := 0
	for {
		line, rerr := reader.ReadBytes('\n')
		complete := rerr == nil || errors.Is(rerr, io.EOF)
		if !complete {
			// The read failed mid-line: the bytes in hand are a fragment
			// of the failed read, not a complete log line. Keep the line
			// numbering of processed lines stable, emit nothing for the
			// fragment, and surface only the read failure on return.
			readErr = rerr
			return failures, nil
		}
		if len(line) > 0 {
			lineNo++
			if strings.TrimSpace(string(line)) != "" {
				result := NormalizeLine(lineNo, line)
				if !result.OK {
					failures++
				}
				if encErr := encoder.Encode(result); encErr != nil {
					return failures, fmt.Errorf("%w: %w", ErrLogWrite, encErr)
				}
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return failures, nil
			}
			readErr = rerr
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
