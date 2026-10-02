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

// parseTimestamp accepts an RFC3339 string with a mandatory timezone and at
// most nine fractional-second digits. time.Parse silently truncates longer
// fractions, so the digit count is checked explicitly.
func parseTimestamp(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		n := 0
		for dot+1+n < len(s) && s[dot+1+n] >= '0' && s[dot+1+n] <= '9' {
			n++
		}
		if n == 0 {
			return time.Time{}, errors.New("expected fractional digits after decimal point")
		}
		if n > 9 {
			return time.Time{}, fmt.Errorf("fractional second has %d digits, at most 9 allowed", n)
		}
	}
	return t, nil
}
