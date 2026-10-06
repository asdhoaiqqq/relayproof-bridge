// Log field normalization so detection rules can read logs from different
// sources through one canonical event shape.
package relayproof

import (
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

// SourceCIDRFilter restricts emitted successful events to one source
// network, IPv4 or IPv6. It is the parsed, validated form of an argument
// like "192.0.2.123/24" or "2001:db8::1234/64": host bits in the spelled
// address do not narrow the range, so "192.0.2.123/24" and "192.0.2.0/24"
// admit the same sources and likewise "2001:db8::1234/64" and
// "2001:db8::/64". A "/32" (or "/128") filter admits only the one address,
// and a "/0" filter admits every normalized source of the filter's own
// address family.
//
// A filter matches exactly one address family: matching always uses the
// fully normalized source_ip, and a plain IPv4 address and its IPv4-mapped
// IPv6 spellings (e.g. 192.0.2.1 and ::ffff:192.0.2.1) normalize to the
// same dotted IPv4 address, so both only ever match an IPv4 network. A
// genuine IPv6 source whose tail happens to embed the same 32 bits (e.g.
// ::192.0.2.1, normalized to ::c000:201) is not IPv4-mapped and only
// matches an IPv6 network that contains it. An IPv4-mapped IPv6 address
// supplied as the *filter argument* is rejected: callers must spell that
// network as IPv4. A valid event without a source address is never admitted
// by either family; that is neither a success result nor a failure.
type SourceCIDRFilter struct {
	network *net.IPNet
	// v6 selects the family the filter admits. The network itself carries
	// 4-byte (IPv4) or 16-byte (IPv6) addressing; this flag makes the
	// family boundary explicit so an IPv4-mapped source can never slip
	// through an IPv6 filter (or vice versa).
	v6 bool
}

// sourceCIDRPattern pins the IPv4 argument grammar before any range
// checking: exactly four 1-3 digit octets, a single "/", and a 1-3 digit
// prefix length. A strict pattern here lets each failure name the exact
// octet or prefix that was wrong instead of net.ParseCIDR's generic text.
var sourceCIDRPattern = regexp.MustCompile(`^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,3})$`)

// sourceCIDRv6Pattern is the coarse IPv6 candidate grammar: an address
// portion containing a colon and using hex letters/digits, colons, dots,
// and the bracket/percent characters a port or zone identifier arrives
// with, followed by a single "/" and a 1-3 digit decimal prefix length.
// Actual IPv6 legality — zero compression, group count, non-hex letters,
// embedded-tail placement, ports and zones — is delegated to net.ParseIP,
// which accepts only bare valid spellings; every other colon-bearing
// shape fails there with an error naming the rejected address. Requiring
// a colon guarantees every IPv6-shaped value reaches this path and every
// dotted-only value reaches the IPv4 grammar; a value with other
// characters (spaces, hyphens) matches neither and gets the grammar error.
var sourceCIDRv6Pattern = regexp.MustCompile(`^([0-9A-Za-z:.[\]%]+:[0-9A-Za-z:.[\]%]*)/([0-9]{1,3})$`)

// sourceCIDRGrammarError names the accepted grammar when a value matches
// neither the IPv4 nor the IPv6 shape.
const sourceCIDRGrammarError = `must be an IP network: an IPv4 network in dotted decimal with a "/0" to "/32" prefix length (e.g. "192.0.2.0/24") or an IPv6 network with a "/0" to "/128" prefix length (e.g. "2001:db8::/64")`

// ParseSourceCIDRFilter validates one source network argument: either a
// dotted decimal IPv4 address with a 0-32 prefix length or an IPv6 address
// with a 0-128 prefix length. Each IPv4 octet must be a plain 0-255 decimal
// number with no leading-zero padding, sign, or other notation; the IPv6
// address accepts both compressed ("2001:db8::1") and full
// ("2001:db8:0:0:0:0:0:1") spellings and no port or zone identifier, and
// the decimal prefix length never accepts leading-zero padding in either
// family. Host bits are interpreted as part of the network — they are
// masked away rather than rejected — so "192.0.2.123/24" is the same
// filter as "192.0.2.0/24" and "2001:db8::1234/64" the same as
// "2001:db8::/64". An IPv4-mapped IPv6 address (e.g. ::ffff:192.0.2.0) is
// rejected rather than converted: such a network must be written as IPv4.
func ParseSourceCIDRFilter(s string) (SourceCIDRFilter, error) {
	switch {
	case sourceCIDRPattern.MatchString(s):
		return parseIPv4SourceCIDRFilter(s)
	case sourceCIDRv6Pattern.MatchString(s):
		return parseIPv6SourceCIDRFilter(s)
	default:
		return SourceCIDRFilter{}, errors.New(sourceCIDRGrammarError)
	}
}

// parseIPv4SourceCIDRFilter handles a value sourceCIDRPattern already
// matched; it range-checks octets and prefix length and masks host bits.
func parseIPv4SourceCIDRFilter(s string) (SourceCIDRFilter, error) {
	m := sourceCIDRPattern.FindStringSubmatch(s)
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

// parseIPv6SourceCIDRFilter handles a value sourceCIDRv6Pattern already
// matched: net.ParseIP validates the address spelling, the prefix length is
// range-checked without padding, and host bits are masked. An IPv4-mapped
// IPv6 address is refused with an instruction to use the IPv4 network
// instead — its prefix is never converted automatically.
func parseIPv6SourceCIDRFilter(s string) (SourceCIDRFilter, error) {
	m := sourceCIDRv6Pattern.FindStringSubmatch(s)
	addrPart, prefixPart := m[1], m[2]
	ip := net.ParseIP(addrPart)
	if ip == nil {
		return SourceCIDRFilter{}, fmt.Errorf("invalid IPv6 network %q: not a valid IPv6 address without a port or zone identifier", s)
	}
	// A mapped address denotes an IPv4 source after normalization; letting
	// it define an IPv6 network would silently match a different family.
	if v4 := ip.To4(); v4 != nil {
		return SourceCIDRFilter{}, fmt.Errorf("invalid IPv6 network %q: %s is an IPv4-mapped IPv6 address; specify the IPv4 network instead", s, ip)
	}
	if len(prefixPart) > 1 && prefixPart[0] == '0' {
		return SourceCIDRFilter{}, fmt.Errorf("invalid IPv6 network %q: prefix length %q must not have leading zeroes", s, prefixPart)
	}
	prefix, _ := strconv.Atoi(prefixPart)
	if prefix > 128 {
		return SourceCIDRFilter{}, fmt.Errorf("invalid IPv6 network %q: prefix length %d out of range (0-128)", s, prefix)
	}
	// Mask host bits away with a 16-byte mask, so "2001:db8::1234/64" and
	// "2001:db8::/64" describe and render as one and the same network.
	mask := net.CIDRMask(prefix, 128)
	return SourceCIDRFilter{network: &net.IPNet{IP: ip.Mask(mask), Mask: mask}, v6: true}, nil
}

// String renders the canonical network the filter admits, e.g.
// ParseSourceCIDRFilter("192.0.2.123/24").String() == "192.0.2.0/24" and
// ParseSourceCIDRFilter("2001:db8::1234/64").String() == "2001:db8::/64".
func (f SourceCIDRFilter) String() string {
	return f.network.String()
}

// admits reports whether a normalized source_ip string falls in the
// selected network, within the network's own address family only. Text
// that is not a single address of that family is never admitted: an IPv6
// network does not match a normalized dotted IPv4 source (including one
// that arrived as an ::ffff: mapping), and an IPv4 network does not match
// a normalized IPv6 spelling such as ::c000:201 even when its final 32
// bits coincide.
func (f SourceCIDRFilter) admits(normalizedSourceIP string) bool {
	ip := net.ParseIP(normalizedSourceIP)
	if ip == nil {
		return false
	}
	if f.v6 {
		if ip.To4() != nil {
			return false // normalized IPv4 sources, mapped spellings included
		}
		return f.network.Contains(ip)
	}
	if v4 := ip.To4(); v4 != nil {
		return f.network.Contains(v4)
	}
	return false
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
