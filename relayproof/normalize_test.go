package relayproof

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// runNormalize parses every emitted result line into ordered maps so tests
// can inspect JSON key order and type preservation in extra.
func runNormalize(t *testing.T, input string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("NormalizeReader returned error: %v", err)
	}
	results := []map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decoding result: %v", err)
		}
		results = append(results, m)
	}
	if got := countFailures(results); got != failures {
		t.Fatalf("NormalizeReader returned %d failures but output shows %d", failures, got)
	}
	return results
}

func countFailures(results []map[string]any) int {
	n := 0
	for _, r := range results {
		if r["ok"] == false {
			n++
		}
	}
	return n
}

func eventOf(t *testing.T, r map[string]any) map[string]any {
	t.Helper()
	event, ok := r["event"].(map[string]any)
	if !ok {
		t.Fatalf("result has no event: %#v", r)
	}
	return event
}

func TestNormalizeBasicAliases(t *testing.T) {
	input := `{"time":"2026-01-02T08:04:05+08:00","src_ip":"2001:db8::1","event_type":"login","user":" alice ","role":"admin","retries":2,"ok":true}`
	results := runNormalize(t, input)
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("expected one ok result, got %#v", results)
	}
	event := eventOf(t, results[0])
	if event["timestamp"] != "2026-01-02T00:04:05Z" {
		t.Fatalf("timestamp not converted to UTC RFC3339Nano: %v", event["timestamp"])
	}
	if event["source_ip"] != "2001:db8::1" {
		t.Fatalf("source_ip mismatch: %v", event["source_ip"])
	}
	if event["action"] != "login" {
		t.Fatalf("action mismatch: %v", event["action"])
	}
	extra := event["extra"].(map[string]any)
	if extra["user"] != " alice " {
		t.Fatalf("extra string must be preserved verbatim, got %v", extra["user"])
	}
	if extra["role"] != "admin" {
		t.Fatalf("extra role mismatch: %v", extra["role"])
	}
	if extra["retries"] != float64(2) {
		t.Fatalf("extra number must be preserved, got %v", extra["retries"])
	}
	if extra["ok"] != true {
		t.Fatalf("extra boolean must be preserved, got %v", extra["ok"])
	}
}

func TestNormalizeCanonicalNames(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"logout"}`
	results := runNormalize(t, input)
	event := eventOf(t, results[0])
	if event["timestamp"] != "2026-01-02T00:00:00Z" || event["action"] != "logout" {
		t.Fatalf("unexpected event: %#v", event)
	}
	if _, exists := event["source_ip"]; exists {
		t.Fatalf("absent source_ip must not be serialized")
	}
	if _, exists := event["extra"]; exists {
		t.Fatalf("empty extra must not be serialized")
	}
}

func TestNormalizeTrimsMappedStrings(t *testing.T) {
	input := `{"timestamp":"  2026-01-02T00:00:00Z  ","source_ip":" 127.0.0.1 ","action":"  x  "}`
	results := runNormalize(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("expected ok, got %#v", results[0])
	}
	event := eventOf(t, results[0])
	if event["timestamp"] != "2026-01-02T00:00:00Z" {
		t.Fatalf("timestamp not trimmed: %v", event["timestamp"])
	}
	if event["source_ip"] != "127.0.0.1" {
		t.Fatalf("source_ip not trimmed: %v", event["source_ip"])
	}
	if event["action"] != "x" {
		t.Fatalf("action not trimmed: %v", event["action"])
	}
}

func TestNormalizeIPEquivalence(t *testing.T) {
	pairs := [][]string{
		{"127.0.0.1", "127.0.0.1"},
		{"0:0:0:0:0:0:0:1", "::1"},
		{"2001:DB8:0:0:0:0:0:1", "2001:db8::1"},
		{"::ffff:192.0.2.1", "192.0.2.1"},
		{"::", "::"},
	}
	for _, pair := range pairs {
		for _, raw := range pair {
			input := `{"timestamp":"2026-01-02T00:00:00Z","src_ip":"` + raw + `","action":"a"}`
			results := runNormalize(t, input)
			if results[0]["ok"] != true {
				t.Fatalf("ip %q failed: %#v", raw, results[0])
			}
			got := eventOf(t, results[0])["source_ip"]
			if got != pair[1] {
				t.Fatalf("ip %q normalized to %v, want %q", raw, got, pair[1])
			}
		}
	}
}

func TestNormalizeInvalidIPs(t *testing.T) {
	for _, ip := range []string{"127.0.0.1:80", "[::1]:443", "999.1.1.1", "192.168.001.001", "fe80::1%eth0", "not-an-ip", "1.2.3"} {
		input := `{"timestamp":"2026-01-02T00:00:00Z","source_ip":"` + ip + `","action":"a"}`
		results := runNormalize(t, input)
		if results[0]["ok"] != false {
			t.Fatalf("ip %q should fail", ip)
		}
		msg, _ := results[0]["error"].(string)
		if !strings.Contains(msg, FieldSourceIP) {
			t.Fatalf("error for ip %q must name field %q, got %q", ip, FieldSourceIP, msg)
		}
	}
}

func TestNormalizeWhitespaceOnlyIPFails(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","source_ip":"   ","action":"a"}`
	results := runNormalize(t, input)
	if results[0]["ok"] != false {
		t.Fatalf("whitespace-only source_ip must not count as omitted")
	}
}

func TestNormalizeTimestampFormats(t *testing.T) {
	ok := map[string]string{
		"2026-01-02T15:04:05Z":           "2026-01-02T15:04:05Z",
		"2026-01-02T23:04:05+08:00":      "2026-01-02T15:04:05Z",
		"2026-01-02T10:04:05-05:00":      "2026-01-02T15:04:05Z",
		"2026-01-02T15:04:05.1Z":         "2026-01-02T15:04:05.1Z",
		"2026-01-02T15:04:05.123456789Z": "2026-01-02T15:04:05.123456789Z",
		"2026-01-02T15:04:05.100000000Z": "2026-01-02T15:04:05.1Z",
		"2026-01-02T15:04:05.000000000Z": "2026-01-02T15:04:05Z",
		"2026-01-02T15:04:05+00:00":      "2026-01-02T15:04:05Z",
	}
	for in, want := range ok {
		results := runNormalize(t, `{"time":"`+in+`","action":"a"}`)
		if results[0]["ok"] != true {
			t.Fatalf("timestamp %q should parse, got %#v", in, results[0])
		}
		if got := eventOf(t, results[0])["timestamp"]; got != want {
			t.Fatalf("timestamp %q -> %v, want %q", in, got, want)
		}
	}
	bad := []string{
		"2026-01-02T15:04:05",             // no timezone
		"2026-01-02t15:04:05z",            // lowercase t/z
		"2026-01-02T15:04:05.1234567890Z", // 10 fractional digits
		"2026-01-02T15:04:05.123456789012Z",
		"2026-01-02T15:04:05.Z",    // dot without digits
		"2026-01-02T15:04:05+0800", // non-RFC3339 offset
		"2026-13-02T15:04:05Z",     // month out of range
		"not-a-time",
	}
	for _, in := range bad {
		results := runNormalize(t, `{"time":"`+in+`","action":"a"}`)
		if results[0]["ok"] != false {
			t.Fatalf("timestamp %q should fail", in)
		}
		msg, _ := results[0]["error"].(string)
		if !strings.Contains(msg, FieldTimestamp) {
			t.Fatalf("error for timestamp %q must name field %q, got %q", in, FieldTimestamp, msg)
		}
	}
}

func TestNormalizeStrictTimestampRejects(t *testing.T) {
	// Inputs Go's time.Parse rewrites (pad, comma, truncate, carry) must
	// all fail outright instead of yielding a successful event.
	bad := []string{
		"2026-01-02T5:04:05Z",             // single-digit hour
		"2026-01-02T15:4:05Z",             // single-digit minute
		"2026-01-02T15:04:5Z",             // single-digit second
		"2026-01-02T15:04:05,1Z",          // comma decimal separator
		"2026-01-02T15:04:05,1234567890Z", // 10 fractional digits, comma
		"2026-01-02T15:04:05.1234567890Z", // 10 fractional digits, dot
		"2026-01-02T15:04:05+24:00",       // offset hour out of range
		"2026-01-02T15:04:05-24:00",
		"2026-01-02T15:04:05+00:60", // offset minute carried by time.Parse
		"2026-01-02T15:04:05+24:60",
		"2026-01-02T24:04:05Z", // wall-clock hour out of range
		"2026-01-02T15:60:05Z",
		"2026-01-02T15:04:60Z",
	}
	for _, in := range bad {
		for _, wrapper := range []string{
			`{"timestamp":"` + in + `","action":"a"}`,
			`{"time":"` + in + `","action":"a"}`,
		} {
			results := runNormalize(t, wrapper)
			if results[0]["ok"] != false {
				t.Fatalf("timestamp %q must fail, got %#v", in, results[0])
			}
			if _, exists := results[0]["event"]; exists {
				t.Fatalf("rejected timestamp %q must not emit a partial event", in)
			}
			msg, _ := results[0]["error"].(string)
			if !strings.Contains(msg, FieldTimestamp) {
				t.Fatalf("error for %q must name %q, got %q", in, FieldTimestamp, msg)
			}
		}
	}
}

func TestNormalizeInvalidAliasFailsEvenWhenRewritable(t *testing.T) {
	// The single-digit-hour alias denotes the same instant as the legal
	// timestamp, but validity is checked per field first: the illegal
	// spelling must fail the whole line, never be padded and then merged.
	input := `{"timestamp":"2026-01-02T15:04:05Z","time":"2026-01-02T15:04:05,1Z","action":"a"}`
	results := runNormalize(t, input)
	if results[0]["ok"] != false {
		t.Fatalf("comma-fraction alias must fail despite denoting the same instant: %#v", results[0])
	}
	input = `{"timestamp":"2026-01-02T15:04:05Z","time":"2026-01-02T16:04:05+00:60","action":"a"}`
	results = runNormalize(t, input)
	if results[0]["ok"] != false {
		t.Fatalf("carried offset alias must fail despite denoting the same instant: %#v", results[0])
	}
	msg, _ := results[0]["error"].(string)
	if !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("error must name %q, got %q", FieldTimestamp, msg)
	}
}

func TestNormalizeStrictTimestampPreserves(t *testing.T) {
	ok := map[string]string{
		// Fractional precision is kept and trailing zeros dropped across zones.
		"2026-01-02T23:04:05.100000000+08:00": "2026-01-02T15:04:05.1Z",
		"2026-01-02T15:04:05.000000001Z":      "2026-01-02T15:04:05.000000001Z",
		// Boundary-valid offsets must stay accepted after the range checks.
		"2026-01-02T15:04:05+23:59": "2026-01-01T15:05:05Z",
		"2026-01-02T15:04:05-23:59": "2026-01-03T15:03:05Z",
		"2026-01-02T15:04:05+00:00": "2026-01-02T15:04:05Z",
	}
	for in, want := range ok {
		results := runNormalize(t, `{"timestamp":"`+in+`","action":"a"}`)
		if results[0]["ok"] != true {
			t.Fatalf("legal timestamp %q should parse, got %#v", in, results[0])
		}
		if got := eventOf(t, results[0])["timestamp"]; got != want {
			t.Fatalf("timestamp %q -> %v, want %q", in, got, want)
		}
	}
}

func TestNormalizeEmptyAction(t *testing.T) {
	for _, action := range []string{"", "   ", "\t\n "} {
		results := runNormalize(t, `{"timestamp":"2026-01-02T00:00:00Z","action":`+jsonString(action)+`}`)
		if results[0]["ok"] != false {
			t.Fatalf("action %q must fail", action)
		}
		msg, _ := results[0]["error"].(string)
		if !strings.Contains(msg, FieldAction) {
			t.Fatalf("error must name %q, got %q", FieldAction, msg)
		}
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestNormalizeMissingRequired(t *testing.T) {
	results := runNormalize(t, `{"action":"a"}`)
	if results[0]["ok"] != false || !strings.Contains(results[0]["error"].(string), FieldTimestamp) {
		t.Fatalf("missing timestamp must fail naming the field: %#v", results[0])
	}
	results = runNormalize(t, `{"timestamp":"2026-01-02T00:00:00Z"}`)
	if results[0]["ok"] != false || !strings.Contains(results[0]["error"].(string), FieldAction) {
		t.Fatalf("missing action must fail naming the field: %#v", results[0])
	}
}

func TestNormalizeNullIsNotOmission(t *testing.T) {
	cases := []string{
		`{"timestamp":null,"action":"a"}`,
		`{"time":null,"action":"a"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":null}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","src_ip":null}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":null}`,
		`{"timestamp":"2026-01-02T00:00:00Z","event_type":null}`,
	}
	for _, in := range cases {
		results := runNormalize(t, in)
		if results[0]["ok"] != false {
			t.Fatalf("null mapped value must fail: %s", in)
		}
	}
}

func TestNormalizeWrongTypes(t *testing.T) {
	cases := []string{
		`{"timestamp":1735689600,"action":"a"}`,
		`{"timestamp":true,"action":"a"}`,
		`{"timestamp":["2026-01-02T00:00:00Z"],"action":"a"}`,
		`{"timestamp":{"x":1},"action":"a"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":123}`,
		`{"timestamp":"2026-01-02T00:00:00Z","src_ip":3232235521}`,
	}
	for _, in := range cases {
		results := runNormalize(t, in)
		if results[0]["ok"] != false {
			t.Fatalf("wrong type must fail: %s", in)
		}
		if _, exists := results[0]["event"]; exists {
			t.Fatalf("failure must not emit a partial event: %s", in)
		}
	}
}

func TestNormalizeConsistentAliasesMerge(t *testing.T) {
	input := `{"time":" 2026-01-02T08:04:05+08:00 ","timestamp":"2026-01-02T00:04:05Z","src_ip":"0:0:0:0:0:0:0:1","source_ip":"::1","event_type":" login ","action":"login"}`
	results := runNormalize(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("consistent aliases must merge, got %#v", results[0])
	}
	event := eventOf(t, results[0])
	if event["timestamp"] != "2026-01-02T00:04:05Z" {
		t.Fatalf("timestamp mismatch: %v", event["timestamp"])
	}
	if event["source_ip"] != "::1" {
		t.Fatalf("source_ip mismatch: %v", event["source_ip"])
	}
	if event["action"] != "login" {
		t.Fatalf("action mismatch: %v", event["action"])
	}
}

func TestNormalizeConflictingAliases(t *testing.T) {
	cases := []struct {
		input string
		field string
	}{
		{`{"time":"2026-01-02T00:04:05Z","timestamp":"2026-01-02T00:05:00Z","action":"a"}`, FieldTimestamp},
		{`{"time":"2026-01-02T00:04:05Z","timestamp":"not-a-time","action":"a"}`, FieldTimestamp},
		{`{"src_ip":"1.2.3.4","source_ip":"5.6.7.8","time":"2026-01-02T00:00:00Z","action":"a"}`, FieldSourceIP},
		{`{"src_ip":"1.2.3.4:99","source_ip":"1.2.3.4","time":"2026-01-02T00:00:00Z","action":"a"}`, FieldSourceIP},
		{`{"event_type":"login","action":"logout","time":"2026-01-02T00:00:00Z"}`, FieldAction},
		{`{"event_type":"   ","action":"login","time":"2026-01-02T00:00:00Z"}`, FieldAction},
	}
	for _, tc := range cases {
		results := runNormalize(t, tc.input)
		if results[0]["ok"] != false {
			t.Fatalf("conflicting candidates must fail: %s", tc.input)
		}
		msg := results[0]["error"].(string)
		if !strings.Contains(msg, tc.field) {
			t.Fatalf("error %q must name conflicting field %q", msg, tc.field)
		}
	}
}

func TestNormalizeDuplicateKeys(t *testing.T) {
	cases := []string{
		`{"action":"a","action":"a"}`,
		`{"time":"2026-01-02T00:00:00Z","time":"2026-01-02T00:00:00Z","action":"a"}`,
		`{"extra":{"a":1},"extra":{"a":1},"time":"2026-01-02T00:00:00Z","action":"a"}`,
		`{"foo":1,"foo":1,"time":"2026-01-02T00:00:00Z","action":"a"}`,
	}
	for _, in := range cases {
		results := runNormalize(t, in)
		if results[0]["ok"] != false {
			t.Fatalf("duplicate key must fail even with equal values: %s", in)
		}
		msg := results[0]["error"].(string)
		if !strings.Contains(strings.ToLower(msg), "duplicate") {
			t.Fatalf("error should mention duplicate key, got %q", msg)
		}
	}
}

func TestNormalizeExtraPreserved(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","extra":{"nested":{"a":[1,2,{"b":true}]},"s":"x"},"user_id":"u-1"}`
	results := runNormalize(t, input)
	event := eventOf(t, results[0])
	extra := event["extra"].(map[string]any)
	nested, ok := extra["extra"].(map[string]any)
	if !ok {
		t.Fatalf("input extra must be kept as an ordinary extra field, got %v", extra["extra"])
	}
	arr := nested["nested"].(map[string]any)["a"].([]any)
	if arr[0] != float64(1) || arr[2].(map[string]any)["b"] != true {
		t.Fatalf("nested structure not preserved: %#v", nested)
	}
	if extra["user_id"] != "u-1" {
		t.Fatalf("plain extra field mismatch: %v", extra["user_id"])
	}
}

func TestNormalizeNullExtraPreserved(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","extra":null,"note":"hi"}`
	results := runNormalize(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("null extra must be accepted as ordinary data: %#v", results[0])
	}
	extra := eventOf(t, results[0])["extra"].(map[string]any)
	if v, ok := extra["extra"]; !ok || v != nil {
		t.Fatalf("extra.extra should be JSON null, got %v ok=%v", v, ok)
	}
	if extra["note"] != "hi" {
		t.Fatalf("extra note mismatch: %v", extra["note"])
	}
}

func TestNormalizeNonObjectAndSyntaxErrors(t *testing.T) {
	cases := []string{
		`[1,2,3]`,
		`"hello"`,
		`123`,
		`true`,
		`null`,
		`{"action":"a",}`,
		`{not json`,
		`{"action":"a" "x":"y"}`,
	}
	for _, in := range cases {
		results := runNormalize(t, in)
		if len(results) != 1 || results[0]["ok"] != false {
			t.Fatalf("non-object/syntax input must yield one failure: %s -> %#v", in, results)
		}
	}
}

func TestNormalizeLineNumberingAndOrder(t *testing.T) {
	input := "{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"a\"}\n" +
		"\n" +
		"   \t \n" +
		"not json\n" +
		"\n" +
		"{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"b\"}\n"
	results := runNormalize(t, input)
	if len(results) != 3 {
		t.Fatalf("expected 3 results for 6 physical lines, got %d: %#v", len(results), results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 mismatch: %#v", results[0])
	}
	if results[1]["line"] != float64(4) || results[1]["ok"] != false {
		t.Fatalf("bad input is physical line 4, got: %#v", results[1])
	}
	if results[2]["line"] != float64(6) || results[2]["ok"] != true {
		t.Fatalf("valid line 6 must still be processed, got: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "b" {
		t.Fatalf("input order not preserved")
	}
}

func TestNormalizeNoFinalNewline(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}`
	results := runNormalize(t, input)
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("final line without newline must still process: %#v", results)
	}
}

func TestNormalizeEmptyAndBlankInput(t *testing.T) {
	for _, input := range []string{"", "\n", "  \n\n\t\n"} {
		var out bytes.Buffer
		failures, err := NormalizeReader(strings.NewReader(input), &out)
		if err != nil || failures != 0 {
			t.Fatalf("blank input must be clean, got failures=%d err=%v", failures, err)
		}
		if out.Len() != 0 {
			t.Fatalf("blank input must produce no output, got %q", out.String())
		}
	}
}

func TestNormalizeDeterministic(t *testing.T) {
	input := strings.Join([]string{
		`{"src_ip":"2001:DB8::1","time":"2026-01-02T08:04:05.123456789+08:00","event_type":" login ","device":{"os":["linux",null],"v":3}}`,
		`{"time":"2026-01-02T00:00:00Z","timestamp":"2026-01-02T01:00:00Z","action":"x"}`,
		`{"timestamp":"bad","action":"x"}`,
		`null`,
		`{"time":"2026-01-02T00:00:00Z","action":"y"}`,
	}, "\n")
	var first bytes.Buffer
	if _, err := NormalizeReader(strings.NewReader(input), &first); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		var again bytes.Buffer
		if _, err := NormalizeReader(strings.NewReader(input), &again); err != nil {
			t.Fatal(err)
		}
		if again.String() != first.String() {
			t.Fatalf("normalization is not deterministic on iteration %d", i)
		}
	}
	if strings.Contains(first.String(), "0001-01-01") {
		t.Fatalf("output must not synthesize a zero/current timestamp")
	}
}

func TestNormalizeUTCYearRange(t *testing.T) {
	// Legal four-digit-year inputs whose UTC conversion escapes 0000-9999
	// must fail; RFC3339Nano cannot represent the result and detection
	// rules must never receive an out-of-range canonical timestamp.
	outOfRange := []string{
		"0000-01-01T00:00:00+00:01",
		"0000-01-01T00:00:59+01:00",
		"0000-01-01T00:00:00+23:59", // largest legal offset: lands in year -1
		"9999-12-31T23:59:59-00:01",
		"9999-12-31T23:00:00-01:00",
		"9999-12-31T23:59:00-23:59",
	}
	for _, in := range outOfRange {
		for _, wrapper := range []string{
			`{"timestamp":"` + in + `","action":"a"}`,
			`{"time":"` + in + `","action":"a"}`,
		} {
			results := runNormalize(t, wrapper)
			if results[0]["ok"] != false {
				t.Fatalf("timestamp %q must fail after UTC conversion, got %#v", in, results[0])
			}
			if _, exists := results[0]["event"]; exists {
				t.Fatalf("out-of-range timestamp %q must not emit an event", in)
			}
			msg, _ := results[0]["error"].(string)
			if !strings.Contains(msg, FieldTimestamp) {
				t.Fatalf("error for %q must name %q, got %q", in, FieldTimestamp, msg)
			}
			if !strings.Contains(msg, "UTC year") || !strings.Contains(msg, "0000-9999") {
				t.Fatalf("error for %q must state the UTC year range, got %q", in, msg)
			}
		}
	}

	// The range endpoints are inclusive and fractional precision must
	// survive at the edges, with trailing zeros still trimmed.
	ok := map[string]string{
		"0000-01-01T00:00:00Z":             "0000-01-01T00:00:00Z",
		"0000-01-01T00:01:00+00:01":        "0000-01-01T00:00:00Z",
		"0000-01-01T00:00:00-23:59":        "0000-01-01T23:59:00Z",
		"0000-01-01T00:00:00.123456+00:00": "0000-01-01T00:00:00.123456Z",
		"9999-12-31T23:59:59Z":             "9999-12-31T23:59:59Z",
		"9999-12-31T23:58:59-00:01":        "9999-12-31T23:59:59Z",
		"9999-12-31T23:59:59.100000000Z":   "9999-12-31T23:59:59.1Z",
		"9999-12-31T23:59:59.000000001Z":   "9999-12-31T23:59:59.000000001Z",
	}
	for in, want := range ok {
		results := runNormalize(t, `{"timestamp":"`+in+`","action":"a"}`)
		if results[0]["ok"] != true {
			t.Fatalf("boundary timestamp %q should succeed, got %#v", in, results[0])
		}
		if got := eventOf(t, results[0])["timestamp"]; got != want {
			t.Fatalf("timestamp %q -> %v, want %q", in, got, want)
		}
	}
}

func TestNormalizeUTCYearRangeAliases(t *testing.T) {
	cases := []struct {
		name  string
		input string
		ok    bool
		want  string
	}{
		{
			name:  "same out-of-range instant spelled twice",
			input: `{"timestamp":"0000-01-01T00:00:00+00:01","time":"0000-01-01T00:01:00+00:02","action":"a"}`,
			ok:    false,
		},
		{
			name:  "same out-of-range instant repeated",
			input: `{"timestamp":"9999-12-31T23:59:59-00:01","time":"9999-12-31T23:59:59-00:01","action":"a"}`,
			ok:    false,
		},
		{
			name:  "one legal value one out of range",
			input: `{"timestamp":"0000-01-01T00:00:00Z","time":"0000-01-01T00:00:00+00:01","action":"a"}`,
			ok:    false,
		},
		{
			name:  "legal consistent values at lower edge merge",
			input: `{"timestamp":"0000-01-01T00:00:00Z","time":"0000-01-01T00:01:00+00:01","action":"a"}`,
			ok:    true,
			want:  "0000-01-01T00:00:00Z",
		},
		{
			name:  "legal consistent values at upper edge merge",
			input: `{"timestamp":"9999-12-31T23:59:59Z","time":"9999-12-31T23:58:59-00:01","action":"a"}`,
			ok:    true,
			want:  "9999-12-31T23:59:59Z",
		},
		{
			name:  "distinct legal instants still conflict",
			input: `{"timestamp":"0000-01-01T00:01:00+00:01","time":"0000-01-01T00:02:00+00:01","action":"a"}`,
			ok:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := runNormalize(t, tc.input)
			if tc.ok {
				if results[0]["ok"] != true {
					t.Fatalf("expected success, got %#v", results[0])
				}
				if got := eventOf(t, results[0])["timestamp"]; got != tc.want {
					t.Fatalf("timestamp %v, want %q", got, tc.want)
				}
				return
			}
			if results[0]["ok"] != false {
				t.Fatalf("expected failure, got %#v", results[0])
			}
			if _, exists := results[0]["event"]; exists {
				t.Fatalf("failure must not emit an event")
			}
			msg, _ := results[0]["error"].(string)
			if !strings.Contains(msg, FieldTimestamp) {
				t.Fatalf("error must name %q, got %q", FieldTimestamp, msg)
			}
		})
	}
}

func TestNormalizeUTCYearRangeMixedStream(t *testing.T) {
	// The year-range error is a single-line failure: surrounding legal
	// lines still come out in order with their physical line numbers,
	// blank lines only advance the counter, and the run reports the
	// failure count (which drives exit status 1 in the CLI).
	input := "{\"timestamp\":\"0000-01-01T00:01:00+00:01\",\"action\":\"a\"}\n" +
		"\n" +
		"{\"timestamp\":\"0000-01-01T00:00:00+00:01\",\"action\":\"b\"}\n" +
		"   \n" +
		"{\"timestamp\":\"9999-12-31T23:59:59-00:01\",\"action\":\"c\"}\n" +
		"{\"timestamp\":\"9999-12-31T23:59:59Z\",\"action\":\"d\"}\n"
	results := runNormalize(t, input)
	if len(results) != 4 {
		t.Fatalf("expected 4 results for 6 physical lines, got %d: %#v", len(results), results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must succeed: %#v", results[0])
	}
	if got := eventOf(t, results[0])["timestamp"]; got != "0000-01-01T00:00:00Z" {
		t.Fatalf("line 1 timestamp %v", got)
	}
	if results[1]["line"] != float64(3) || results[1]["ok"] != false {
		t.Fatalf("line 3 must fail preserving its line number: %#v", results[1])
	}
	if results[2]["line"] != float64(5) || results[2]["ok"] != false {
		t.Fatalf("line 5 must fail preserving its line number: %#v", results[2])
	}
	if results[3]["line"] != float64(6) || results[3]["ok"] != true {
		t.Fatalf("legal line 6 must still be processed: %#v", results[3])
	}
	if eventOf(t, results[3])["action"] != "d" {
		t.Fatalf("input order not preserved")
	}
}

// runNormalizeJSON works like runNormalize but decodes result lines with
// json.Number, so tests can assert that high-precision numbers in extra
// survive normalization verbatim instead of being rounded into float64.
func runNormalizeJSON(t *testing.T, input string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("NormalizeReader returned error: %v", err)
	}
	results := []map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	dec.UseNumber()
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decoding result: %v", err)
		}
		results = append(results, m)
	}
	if got := countFailures(results); got != failures {
		t.Fatalf("NormalizeReader returned %d failures but output shows %d", failures, got)
	}
	return results
}

// runNormalizeRaw returns the exact bytes NormalizeReader wrote, for
// assertions on the serialized form of preserved numbers.
func runNormalizeRaw(t *testing.T, input string) string {
	t.Helper()
	var out bytes.Buffer
	if _, err := NormalizeReader(strings.NewReader(input), &out); err != nil {
		t.Fatalf("NormalizeReader returned error: %v", err)
	}
	return out.String()
}

func extraOf(t *testing.T, r map[string]any) map[string]any {
	t.Helper()
	event := eventOf(t, r)
	extra, ok := event["extra"].(map[string]any)
	if !ok {
		t.Fatalf("event has no extra object: %#v", event)
	}
	return extra
}

// mustNumber asserts v is a JSON number whose serialized form is exactly
// want — no rounding, no truncation, no conversion to string.
func mustNumber(t *testing.T, v any, want string) {
	t.Helper()
	n, ok := v.(json.Number)
	if !ok {
		t.Fatalf("expected JSON number %s, got %T (%v)", want, v, v)
	}
	if n.String() != want {
		t.Fatalf("number preserved as %q, want %q", n.String(), want)
	}
}

func TestNormalizeExtraHighPrecisionNumbers(t *testing.T) {
	// Numbers beyond float64/int64 precision in unmapped fields must reach
	// the event's extra with their exact literal form intact.
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a",` +
		`"big":9007199254740993,` +
		`"neg_big":-9007199254740993,` +
		`"precise":1.0000000000000000001,` +
		`"huge":1e400,` +
		`"tiny":1e-400}`
	results := runNormalizeJSON(t, input)
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("high-precision extra numbers must succeed, got %#v", results)
	}
	extra := extraOf(t, results[0])
	mustNumber(t, extra["big"], "9007199254740993")
	mustNumber(t, extra["neg_big"], "-9007199254740993")
	mustNumber(t, extra["precise"], "1.0000000000000000001")
	mustNumber(t, extra["huge"], "1e400")
	mustNumber(t, extra["tiny"], "1e-400")

	raw := runNormalizeRaw(t, input)
	for _, want := range []string{"9007199254740993", "1.0000000000000000001", "1e400", "1e-400"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("serialized output must contain the exact literal %s, got %s", want, raw)
		}
	}
	if strings.Contains(raw, "9007199254740992") {
		t.Fatalf("big integer was rounded to a float64 neighbor: %s", raw)
	}
	if strings.Contains(raw, "Infinity") || strings.Contains(raw, "inf") {
		t.Fatalf("out-of-float-range exponent must not serialize as infinity: %s", raw)
	}
}

func TestNormalizeExtraNestedPrecision(t *testing.T) {
	// Precision preservation applies at every depth of unmapped objects and
	// arrays, not just the top level; array order and the JSON types of
	// values adjacent to the numbers must survive too.
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","payload":{` +
		`"deep":{"id":9007199254740993},` +
		`"list":[1.0000000000000000001,9007199254740993,"9007199254740993",true,null,3]}}`
	results := runNormalizeJSON(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("nested high-precision numbers must succeed, got %#v", results[0])
	}
	payload, ok := extraOf(t, results[0])["payload"].(map[string]any)
	if !ok {
		t.Fatalf("payload object must be preserved, got %#v", extraOf(t, results[0])["payload"])
	}
	deep, ok := payload["deep"].(map[string]any)
	if !ok {
		t.Fatalf("nested object level must be preserved, got %#v", payload["deep"])
	}
	mustNumber(t, deep["id"], "9007199254740993")

	list, ok := payload["list"].([]any)
	if !ok || len(list) != 6 {
		t.Fatalf("array level and length must be preserved, got %#v", payload["list"])
	}
	mustNumber(t, list[0], "1.0000000000000000001")
	mustNumber(t, list[1], "9007199254740993")
	// A string that spells a number stays a string; it is not converted.
	if s, ok := list[2].(string); !ok || s != "9007199254740993" {
		t.Fatalf("string-formed number must stay a string, got %T (%v)", list[2], list[2])
	}
	if list[3] != true {
		t.Fatalf("adjacent boolean must keep its type, got %#v", list[3])
	}
	if list[4] != nil {
		t.Fatalf("adjacent null must keep its type, got %#v", list[4])
	}
	mustNumber(t, list[5], "3")
}

func TestNormalizeInputExtraKeepsPrecisionAndNesting(t *testing.T) {
	// An input's own "extra" field is an ordinary unmapped field: it lands
	// inside the output extra as one nested object, its high-precision
	// numbers survive, and it is not flattened into the sibling fields.
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a",` +
		`"extra":{"balance":9007199254740993,"ratio":1.0000000000000000001,"tags":["x",1e400]},` +
		`"other":2}`
	results := runNormalizeJSON(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("nested input extra must succeed, got %#v", results[0])
	}
	extra := extraOf(t, results[0])
	if len(extra) != 2 {
		t.Fatalf("input extra must stay one nested field, not be flattened: %#v", extra)
	}
	inner, ok := extra["extra"].(map[string]any)
	if !ok {
		t.Fatalf("input extra must be a nested object under extra, got %#v", extra["extra"])
	}
	mustNumber(t, inner["balance"], "9007199254740993")
	mustNumber(t, inner["ratio"], "1.0000000000000000001")
	tags, ok := inner["tags"].([]any)
	if !ok || len(tags) != 2 || tags[0] != "x" {
		t.Fatalf("nested array inside input extra not preserved: %#v", inner["tags"])
	}
	mustNumber(t, tags[1], "1e400")
	if _, leaked := extra["balance"]; leaked {
		t.Fatalf("nested extra fields must not be hoisted to the top level: %#v", extra)
	}
	mustNumber(t, extra["other"], "2")
}

func TestNormalizeMappedFieldsStillRejectNumbers(t *testing.T) {
	// Precision preservation is scoped to unmapped data: a number — even a
	// legal high-precision one — in a mapped field still fails type checks.
	cases := []struct {
		input string
		field string
	}{
		{`{"timestamp":9007199254740993,"action":"a"}`, FieldTimestamp},
		{`{"time":1.0000000000000000001,"action":"a"}`, FieldTimestamp},
		{`{"timestamp":"2026-01-02T00:00:00Z","action":123}`, FieldAction},
		{`{"timestamp":"2026-01-02T00:00:00Z","event_type":1e400}`, FieldAction},
		{`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":9007199254740993}`, FieldSourceIP},
		{`{"timestamp":"2026-01-02T00:00:00Z","action":"a","src_ip":1e400}`, FieldSourceIP},
	}
	for _, tc := range cases {
		results := runNormalize(t, tc.input)
		if results[0]["ok"] != false {
			t.Fatalf("number in mapped field must fail: %s", tc.input)
		}
		if _, exists := results[0]["event"]; exists {
			t.Fatalf("failure must not emit a partial event: %s", tc.input)
		}
		msg, _ := results[0]["error"].(string)
		if !strings.Contains(msg, tc.field) {
			t.Fatalf("error for %s must name field %q, got %q", tc.input, tc.field, msg)
		}
	}
}

func TestNormalizeInvalidJSONNumbersFail(t *testing.T) {
	// Tokens that are not legal JSON numbers must fail the whole line with
	// an error and no partial event, even inside unmapped fields.
	cases := []string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":NaN}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":Infinity}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":-Infinity}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":01}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":+1}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":1.}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":{"nested":007}}`,
	}
	for _, in := range cases {
		results := runNormalize(t, in)
		if len(results) != 1 || results[0]["ok"] != false {
			t.Fatalf("invalid JSON number must fail: %s -> %#v", in, results)
		}
		if _, exists := results[0]["event"]; exists {
			t.Fatalf("invalid JSON number must not emit a partial event: %s", in)
		}
		if msg, _ := results[0]["error"].(string); msg == "" {
			t.Fatalf("invalid JSON number must produce an error message: %s", in)
		}
	}
}

func TestNormalizeMixedStreamHighPrecision(t *testing.T) {
	// In one stream, invalid-number lines and wrong-typed mapped fields
	// fail while surrounding legal high-precision logs still succeed in
	// order; the failure count covers only the genuinely bad lines.
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","big":9007199254740993}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":NaN}` + "\n" +
		`{"timestamp":9007199254740993,"action":"a"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"b","extra":{"v":1.0000000000000000001}}` + "\n"
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("NormalizeReader returned error: %v", err)
	}
	if failures != 2 {
		t.Fatalf("expected exactly 2 failures (legal extra numbers must not count), got %d", failures)
	}
	results := []map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	dec.UseNumber()
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decoding result: %v", err)
		}
		results = append(results, m)
	}
	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d: %#v", len(results), results)
	}
	if results[0]["ok"] != true || results[1]["ok"] != false || results[2]["ok"] != false || results[3]["ok"] != true {
		t.Fatalf("ok pattern mismatch: %#v", results)
	}
	mustNumber(t, extraOf(t, results[0])["big"], "9007199254740993")
	inner, ok := extraOf(t, results[3])["extra"].(map[string]any)
	if !ok {
		t.Fatalf("line 4 input extra must stay nested, got %#v", extraOf(t, results[3]))
	}
	mustNumber(t, inner["v"], "1.0000000000000000001")
}

func TestNormalizeCRLF(t *testing.T) {
	input := "{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"a\"}\r\n\r\nnot json\r\n"
	results := runNormalize(t, input)
	if len(results) != 2 || results[0]["line"] != float64(1) || results[1]["line"] != float64(3) {
		t.Fatalf("CRLF line handling wrong: %#v", results)
	}
}
