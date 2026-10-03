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
		"2026-01-02T15:04:05Z":                "2026-01-02T15:04:05Z",
		"2026-01-02T23:04:05+08:00":           "2026-01-02T15:04:05Z",
		"2026-01-02T10:04:05-05:00":           "2026-01-02T15:04:05Z",
		"2026-01-02T15:04:05.1Z":              "2026-01-02T15:04:05.1Z",
		"2026-01-02T15:04:05.123456789Z":      "2026-01-02T15:04:05.123456789Z",
		"2026-01-02T15:04:05.100000000Z":      "2026-01-02T15:04:05.1Z",
		"2026-01-02T15:04:05.000000000Z":      "2026-01-02T15:04:05Z",
		"2026-01-02T23:04:05.100000000+08:00": "2026-01-02T15:04:05.1Z",
		"2026-01-02T15:04:05+00:00":           "2026-01-02T15:04:05Z",
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
		"2026-01-02T5:04:05Z",             // single-digit hour
		"2026-01-02T05:4:05Z",             // single-digit minute
		"2026-01-02T15:04:05,1Z",          // comma fraction, one digit
		"2026-01-02T15:04:05,123456789Z",  // comma fraction, nine digits
		"2026-01-02T15:04:05,1234567890Z", // comma fraction, ten digits
		"2026-01-02T15:04:05.1234567890Z", // 10 fractional digits
		"2026-01-02T15:04:05.123456789012Z",
		"2026-01-02T15:04:05.Z",    // dot without digits
		"2026-01-02T15:04:05+0800", // non-RFC3339 offset
		"2026-01-02T15:04:05+24:00",
		"2026-01-02T15:04:05-24:00",
		"2026-01-02T15:04:05+00:60",
		"2026-01-02T15:04:05+23:60",
		"2026-13-02T15:04:05Z",         // month out of range
		"2026-11-31T15:04:05Z",         // day out of range
		"2026-01-02T24:04:05Z",         // clock hour out of range
		"2026-01-02T15:04:05.1Z extra", // trailing garbage
		"2026-01-02T15:04:05+08:00:30", // seconds in offset
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

func TestNormalizeTimestampAndTimeBothValidated(t *testing.T) {
	// Even when the malformed value would denote the same instant after the
	// parser rewrites it, the whole line must fail: neither field is dropped
	// and no (partial) event is emitted.
	failCases := []string{
		// Single-digit hour "rewrites" to the same wall-clock hour.
		`{"timestamp":"2026-01-02T15:04:05Z","time":"2026-01-02T5:04:05Z","action":"a"}`,
		// Comma fraction would parse to .1, matching the valid field.
		`{"timestamp":"2026-01-02T15:04:05.1Z","time":"2026-01-02T15:04:05,1Z","action":"a"}`,
		// Ten digits would be truncated to .123456789, matching the valid field.
		`{"timestamp":"2026-01-02T15:04:05.123456789Z","time":"2026-01-02T15:04:05.1234567890Z","action":"a"}`,
		// +24:00 carries the date back one day, landing on the valid instant.
		`{"timestamp":"2026-01-01T15:04:05Z","time":"2026-01-02T15:04:05+24:00","action":"a"}`,
		// +00:60 carries the hour forward, landing on the valid instant.
		`{"timestamp":"2026-01-02T14:04:05Z","time":"2026-01-02T15:04:05+00:60","action":"a"}`,
	}
	for _, in := range failCases {
		results := runNormalize(t, in)
		if results[0]["ok"] != false {
			t.Fatalf("malformed dual timestamp must fail even if rewriting matches: %s", in)
		}
		if _, exists := results[0]["event"]; exists {
			t.Fatalf("failure must not emit a partial event: %s", in)
		}
		msg, _ := results[0]["error"].(string)
		if !strings.Contains(msg, FieldTimestamp) {
			t.Fatalf("error must name %q, got %q", FieldTimestamp, msg)
		}
	}

	// Two valid, differently-shaped timezone expressions of the same instant
	// still merge as before.
	okCases := []struct {
		input string
		want  string
	}{
		{`{"timestamp":"2026-01-02T23:04:05+08:00","time":"2026-01-02T15:04:05Z","action":"a"}`,
			"2026-01-02T15:04:05Z"},
		{`{"timestamp":"2026-01-02T23:04:05.100000000+08:00","time":"2026-01-02T15:04:05.1Z","action":"a"}`,
			"2026-01-02T15:04:05.1Z"},
		{`{"timestamp":"  2026-01-02T15:04:05Z  ","time":"2026-01-02T15:04:05+00:00","action":"a"}`,
			"2026-01-02T15:04:05Z"},
	}
	for _, tc := range okCases {
		results := runNormalize(t, tc.input)
		if results[0]["ok"] != true {
			t.Fatalf("equivalent valid timezones must merge: %s -> %#v", tc.input, results[0])
		}
		if got := eventOf(t, results[0])["timestamp"]; got != tc.want {
			t.Fatalf("timestamp = %v, want %q", got, tc.want)
		}
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

func TestNormalizeCRLF(t *testing.T) {
	input := "{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"a\"}\r\n\r\nnot json\r\n"
	results := runNormalize(t, input)
	if len(results) != 2 || results[0]["line"] != float64(1) || results[1]["line"] != float64(3) {
		t.Fatalf("CRLF line handling wrong: %#v", results)
	}
}
