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
)

// Canonical event field names.
const (
	FieldTimestamp = "timestamp"
	FieldSourceIP  = "source_ip"
	FieldAction    = "action"
)

// fieldAliases maps accepted alternative log keys to canonical field names.
var fieldAliases = map[string]string{
	"time":       FieldTimestamp,
	"src_ip":     FieldSourceIP,
	"event_type": FieldAction,
}

// canonicalFieldOrder is the fixed order in which mapped fields are validated,
// so the first reported error for a malformed line is deterministic.
var canonicalFieldOrder = []string{FieldTimestamp, FieldSourceIP, FieldAction}

// NormalizedEvent is the canonical representation of one log line.
type NormalizedEvent struct {
	Timestamp string                     `json:"timestamp"`
	SourceIP  string                     `json:"source_ip,omitempty"`
	Action    string                     `json:"action"`
	Extra     map[string]json.RawMessage `json:"extra,omitempty"`
}

// NormalizeResult is emitted for every non-blank input line, in input order.
type NormalizeResult struct {
	Line  int              `json:"line"`
	OK    bool             `json:"ok"`
	Event *NormalizedEvent `json:"event,omitempty"`
	Error string           `json:"error,omitempty"`
}

type fieldCandidate struct {
	from string
	raw  json.RawMessage
}

// NormalizeReader streams newline-delimited JSON logs from r and writes one
// NormalizeResult JSON object per non-blank physical line to w. Blank lines
// produce no output but still advance the physical line counter. It returns
// the number of lines that failed normalization; processing of later lines
// continues after any per-line failure.
func NormalizeReader(r io.Reader, w io.Writer) (failures int, err error) {
	reader := bufio.NewReader(r)
	bw := bufio.NewWriter(w)
	defer func() {
		if flushErr := bw.Flush(); err == nil {
			err = flushErr
		}
	}()
	encoder := json.NewEncoder(bw)
	encoder.SetEscapeHTML(false)

	lineNo := 0
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			lineNo++
			if strings.TrimSpace(string(line)) != "" {
				result := NormalizeLine(lineNo, line)
				if !result.OK {
					failures++
				}
				if encErr := encoder.Encode(result); encErr != nil {
					return failures, encErr
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return failures, nil
			}
			return failures, readErr
		}
	}
}

// NormalizeLine normalizes a single raw JSON log line. The line number is
// echoed unchanged in the result.
func NormalizeLine(lineNo int, raw []byte) NormalizeResult {
	event, err := normalizeEvent(bytes.TrimSpace(raw))
	if err != nil {
		return NormalizeResult{Line: lineNo, OK: false, Error: err.Error()}
	}
	return NormalizeResult{Line: lineNo, OK: true, Event: event}
}

func normalizeEvent(raw []byte) (*NormalizedEvent, error) {
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

	groups := make(map[string][]fieldCandidate)
	extra := make(map[string]json.RawMessage)
	for _, key := range keys {
		switch key {
		case FieldTimestamp, FieldSourceIP, FieldAction:
			groups[key] = append(groups[key], fieldCandidate{from: key, raw: object[key]})
		default:
			if canonical, ok := fieldAliases[key]; ok {
				groups[canonical] = append(groups[canonical], fieldCandidate{from: key, raw: object[key]})
			} else {
				extra[key] = object[key]
			}
		}
	}

	values := make(map[string]string)
	for _, canonical := range canonicalFieldOrder {
		candidates := groups[canonical]
		if len(candidates) == 0 {
			continue
		}
		var canonicalValue string
		for i, candidate := range candidates {
			value, err := normalizeFieldValue(canonical, candidate.raw)
			if err != nil {
				return nil, err
			}
			if i == 0 {
				canonicalValue = value
				continue
			}
			// Every candidate must be valid; consistent values merge and
			// divergent values fail the whole line.
			if value != canonicalValue {
				return nil, fmt.Errorf("field %q has conflicting values: %q and %q", canonical, canonicalValue, value)
			}
		}
		values[canonical] = canonicalValue
	}

	timestamp, ok := values[FieldTimestamp]
	if !ok {
		return nil, fmt.Errorf("missing required field %q", FieldTimestamp)
	}
	action, ok := values[FieldAction]
	if !ok {
		return nil, fmt.Errorf("missing required field %q", FieldAction)
	}

	event := &NormalizedEvent{
		Timestamp: timestamp,
		Action:    action,
	}
	if sourceIP, present := values[FieldSourceIP]; present {
		event.SourceIP = sourceIP
	}
	if len(extra) > 0 {
		event.Extra = extra
	}
	return event, nil
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

func normalizeFieldValue(canonical string, raw json.RawMessage) (string, error) {
	s, err := requireString(canonical, raw)
	if err != nil {
		return "", err
	}
	switch canonical {
	case FieldTimestamp:
		t, err := parseTimestamp(strings.TrimSpace(s))
		if err != nil {
			return "", fmt.Errorf("field %q: invalid RFC3339 timestamp: %v", canonical, err)
		}
		utc := t.UTC()
		// The input year is four digits, but applying the offset can push the
		// UTC instant before year 0000 or past year 9999, which RFC3339Nano
		// cannot represent (it would emit a negative or five-digit year).
		if year := utc.Year(); year < 0 || year > 9999 {
			return "", fmt.Errorf("field %q: UTC year %d out of range (0000-9999) after timezone offset conversion", canonical, year)
		}
		return utc.Format(time.RFC3339Nano), nil
	case FieldAction:
		value := strings.TrimSpace(s)
		if value == "" {
			return "", fmt.Errorf("field %q: action must not be empty", canonical)
		}
		return value, nil
	case FieldSourceIP:
		value := strings.TrimSpace(s)
		ip := net.ParseIP(value)
		if ip == nil {
			return "", fmt.Errorf("field %q: invalid IP address %q (no port allowed)", canonical, value)
		}
		return ip.String(), nil
	default:
		return "", fmt.Errorf("field %q: unknown canonical field", canonical)
	}
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
// rewrites are rejected here rather than normalized away.
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
	return t, nil
}
