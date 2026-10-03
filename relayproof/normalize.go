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
	"sort"
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
		return t.UTC().Format(time.RFC3339Nano), nil
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

// parseTimestamp accepts a strict RFC3339 string with a mandatory timezone.
// The date and clock fields use fixed-width digits (the hour is always two
// digits), an optional fractional second uses a decimal point followed by one
// to nine digits, and numeric timezone offsets have hours in 00-23 and minutes
// in 00-59. time.Parse is lenient about all of these (it accepts comma
// fractions and single-digit hours, normalizes offsets such as +24:00/+00:60
// by carrying into the date, and silently truncates over-long fractions), so
// the shape is verified explicitly before handing the string to time.Parse.
func parseTimestamp(s string) (time.Time, error) {
	if err := validateRFC3339Shape(s); err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}

// validateRFC3339Shape enforces the fixed-width grammar of RFC3339
// (date-time = full-date "T" partial-time time-offset), which time.Parse
// alone does not. Calendar ranges (month, day, and the clock hour 00-23) are
// left to time.Parse.
func validateRFC3339Shape(s string) error {
	// "YYYY-MM-DDTHH:MM:SS" occupies the first 19 bytes; at least a trailing
	// "Z" must follow.
	const baseLen = len("2006-01-02T15:04:05")
	if len(s) < baseLen+1 {
		return errors.New("expected RFC3339 timestamp such as 2006-01-02T15:04:05Z")
	}
	allDigits := func(lo, hi int) bool {
		for i := lo; i < hi; i++ {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
		return true
	}
	if !allDigits(0, 4) || s[4] != '-' ||
		!allDigits(5, 7) || s[7] != '-' ||
		!allDigits(8, 10) || s[10] != 'T' ||
		!allDigits(11, 13) || s[13] != ':' ||
		!allDigits(14, 16) || s[16] != ':' ||
		!allDigits(17, 19) {
		return errors.New("expected YYYY-MM-DDTHH:MM:SS with two-digit hour, minute and second")
	}

	i := baseLen
	switch s[i] {
	case 'Z':
		if len(s) != i+1 {
			return errors.New("unexpected characters after timezone designator Z")
		}
		return nil
	case '.':
		j := i + 1
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		n := j - (i + 1)
		if n == 0 {
			return errors.New("expected 1 to 9 fractional digits after the decimal point")
		}
		if n > 9 {
			return fmt.Errorf("fractional second has %d digits, at most 9 allowed", n)
		}
		i = j
	case ',':
		return errors.New("fractional seconds must use a decimal point, got comma")
	case '+', '-':
		// Numeric offset follows immediately; validated below.
	default:
		return errors.New("expected Z or numeric timezone offset (+HH:MM) after the time")
	}

	// Timezone: either "Z" or ("+" / "-") HH ":" MM with HH in 00-23 and
	// minutes in 00-59.
	if s[i] == 'Z' {
		if len(s) != i+1 {
			return errors.New("unexpected characters after timezone designator Z")
		}
		return nil
	}
	if len(s) != i+6 || (s[i] != '+' && s[i] != '-') ||
		!allDigits(i+1, i+3) || s[i+3] != ':' || !allDigits(i+4, i+6) {
		return errors.New("invalid timezone offset, expected Z or +HH:MM")
	}
	offsetHour := int(s[i+1]-'0')*10 + int(s[i+2]-'0')
	offsetMinute := int(s[i+4]-'0')*10 + int(s[i+5]-'0')
	if offsetHour > 23 {
		return fmt.Errorf("timezone offset hour %02d is out of range (must be 00 to 23)", offsetHour)
	}
	if offsetMinute > 59 {
		return fmt.Errorf("timezone offset minute %02d is out of range (must be 00 to 59)", offsetMinute)
	}
	return nil
}
