package relayproof

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Event is a normalized log event.
type Event struct {
	Timestamp string                     `json:"timestamp"`
	SourceIP  string                     `json:"source_ip,omitempty"`
	Action    string                     `json:"action"`
	Extra     map[string]json.RawMessage `json:"extra,omitempty"`
}

// LineResult is the outcome of normalizing one physical log line.
type LineResult struct {
	Line  int    `json:"line"`
	OK    bool   `json:"ok"`
	Event *Event `json:"event,omitempty"`
	Error string `json:"error,omitempty"`
}

// fieldAliases maps each standard event field to its accepted aliases.
var fieldAliases = map[string][]string{
	"timestamp": {"time"},
	"source_ip": {"src_ip"},
	"action":    {"event_type"},
}

// fieldOrder fixes the order in which standard fields are validated.
var fieldOrder = []string{"timestamp", "source_ip", "action"}

// NormalizeLine normalizes one physical log line and tags it with its line number.
func NormalizeLine(line string, lineNo int) LineResult {
	event, err := NormalizeLog(line)
	if err != nil {
		return LineResult{Line: lineNo, OK: false, Error: err.Error()}
	}
	return LineResult{Line: lineNo, OK: true, Event: event}
}

// NormalizeLog parses and normalizes a single JSON log line.
//
// The event fields timestamp, source_ip and action are accepted under their
// standard names and the aliases time, src_ip and event_type respectively.
// All candidate values must be valid; when a standard name and an alias are
// both present and normalize to different values the line fails. Any field
// not participating in the mapping is preserved verbatim in Extra.
func NormalizeLog(line string) (*Event, error) {
	raw, err := parseTopLevelObject(line)
	if err != nil {
		return nil, err
	}

	event := &Event{}
	consumed := map[string]bool{}

	for _, field := range fieldOrder {
		var canonical string
		found := false
		for _, key := range append([]string{field}, fieldAliases[field]...) {
			val, ok := raw[key]
			if !ok {
				continue
			}
			consumed[key] = true
			norm, err := normalizeField(field, val)
			if err != nil {
				return nil, err
			}
			if found && norm != canonical {
				return nil, fmt.Errorf("conflicting values for field %q", field)
			}
			canonical = norm
			found = true
		}
		if !found {
			if field == "timestamp" || field == "action" {
				return nil, fmt.Errorf("%s: missing required field", field)
			}
			continue
		}
		switch field {
		case "timestamp":
			event.Timestamp = canonical
		case "source_ip":
			event.SourceIP = canonical
		case "action":
			event.Action = canonical
		}
	}

	for key, val := range raw {
		if consumed[key] {
			continue
		}
		if event.Extra == nil {
			event.Extra = map[string]json.RawMessage{}
		}
		event.Extra[key] = val
	}

	return event, nil
}

// parseTopLevelObject parses line as a single JSON object. Duplicate top-level
// keys are rejected even when their values are identical.
func parseTopLevelObject(line string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(strings.NewReader(line))

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, fmt.Errorf("JSON log must be an object")
	}

	raw := map[string]json.RawMessage{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid JSON: %v", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("invalid JSON: object key must be a string")
		}
		if _, dup := raw[key]; dup {
			return nil, fmt.Errorf("duplicate top-level key %q", key)
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, fmt.Errorf("invalid JSON: %v", err)
		}
		raw[key] = val
	}

	closeTok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}
	if closeTok != json.Delim('}') {
		return nil, fmt.Errorf("invalid JSON: expected closing object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing data after JSON object")
	}
	return raw, nil
}

// normalizeField validates and canonicalizes one candidate value for a standard
// event field. Errors always name the standard field.
func normalizeField(field string, raw json.RawMessage) (string, error) {
	if string(raw) == "null" {
		return "", fmt.Errorf("%s: value must be a string", field)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("%s: value must be a string", field)
	}
	switch field {
	case "timestamp":
		return normalizeTimestamp(s)
	case "action":
		s = strings.TrimSpace(s)
		if s == "" {
			return "", fmt.Errorf("action: must not be empty")
		}
		return s, nil
	case "source_ip":
		s = strings.TrimSpace(s)
		ip := net.ParseIP(s)
		if ip == nil {
			return "", fmt.Errorf("source_ip: invalid IPv4 or IPv6 address")
		}
		return ip.String(), nil
	}
	return "", fmt.Errorf("unknown field %q", field)
}

// normalizeTimestamp parses an RFC3339 timestamp with timezone, rejects
// fractional seconds beyond nanosecond precision, and returns it in UTC
// formatted as RFC3339Nano.
func normalizeTimestamp(s string) (string, error) {
	if frac := fractionDigits(s); frac > 9 {
		return "", fmt.Errorf("timestamp: fractional seconds must have at most 9 digits, got %d", frac)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "", fmt.Errorf("timestamp: invalid RFC3339 timestamp: %v", err)
	}
	return t.UTC().Format(time.RFC3339Nano), nil
}

// fractionDigits counts the digits of the seconds fraction in s, accepting
// either '.' or ',' as the separator.
func fractionDigits(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' || s[i] == ',' {
			j := i + 1
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			return j - (i + 1)
		}
	}
	return 0
}
