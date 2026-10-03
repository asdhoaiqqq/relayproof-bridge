package relayproof

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// runNormalizeNumbers mirrors runNormalize but decodes result lines with
// json.Number, so numeric literals in extra can be compared exactly instead
// of through float64, which would hide the precision loss these tests guard
// against. It also returns the raw output for byte-level literal checks.
func runNormalizeNumbers(t *testing.T, input string) ([]map[string]any, string) {
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
	return results, out.String()
}

func extraOf(t *testing.T, r map[string]any) map[string]any {
	t.Helper()
	extra, ok := eventOf(t, r)["extra"].(map[string]any)
	if !ok {
		t.Fatalf("event has no extra object: %#v", r)
	}
	return extra
}

// requireNumber asserts v is a JSON number (not a string, not null) and
// returns its exact literal.
func requireNumber(t *testing.T, v any) string {
	t.Helper()
	n, ok := v.(json.Number)
	if !ok {
		t.Fatalf("expected a JSON number, got %T (%v)", v, v)
	}
	return n.String()
}

func TestNormalizeExtraLargeIntegerPreserved(t *testing.T) {
	// 9007199254740993 is 2^53+1: not representable as float64, and a
	// float64 round-trip would silently emit 9007199254740992.
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","big":9007199254740993,"neg":-9007199254740993}`
	results, raw := runNormalizeNumbers(t, input)
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("expected one ok result, got %#v", results)
	}
	extra := extraOf(t, results[0])
	if got := requireNumber(t, extra["big"]); got != "9007199254740993" {
		t.Fatalf("big integer changed: got %s, want 9007199254740993", got)
	}
	if got := requireNumber(t, extra["neg"]); got != "-9007199254740993" {
		t.Fatalf("negative big integer changed: got %s", got)
	}
	if !strings.Contains(raw, "9007199254740993") {
		t.Fatalf("raw output lost the exact literal: %s", raw)
	}
	if strings.Contains(raw, "9007199254740992") {
		t.Fatalf("raw output contains the float64-rounded value: %s", raw)
	}
}

func TestNormalizeExtraHighPrecisionDecimalPreserved(t *testing.T) {
	// 1.0000000000000000001 rounds to 1 in float64; the extra literal must
	// survive normalization untouched.
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","frac":1.0000000000000000001}`
	results, raw := runNormalizeNumbers(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("expected ok, got %#v", results[0])
	}
	extra := extraOf(t, results[0])
	if got := requireNumber(t, extra["frac"]); got != "1.0000000000000000001" {
		t.Fatalf("high-precision decimal changed: got %s", got)
	}
	if !strings.Contains(raw, "1.0000000000000000001") {
		t.Fatalf("raw output lost the exact literal: %s", raw)
	}
}

func TestNormalizeExtraOutOfRangeExponentPreserved(t *testing.T) {
	// 1e400 and 1e-400 are legal JSON numbers outside the float64 range.
	// They must not fail the line, and must not come back as Infinity or
	// null (or a string).
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","huge":1e400,"hugeNeg":-1e400,"tiny":1e-400}`
	results, raw := runNormalizeNumbers(t, input)
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("out-of-float-range exponents must not fail the line: %#v", results)
	}
	extra := extraOf(t, results[0])
	if got := requireNumber(t, extra["huge"]); got != "1e400" {
		t.Fatalf("1e400 changed: got %s", got)
	}
	if got := requireNumber(t, extra["hugeNeg"]); got != "-1e400" {
		t.Fatalf("-1e400 changed: got %s", got)
	}
	if got := requireNumber(t, extra["tiny"]); got != "1e-400" {
		t.Fatalf("1e-400 changed: got %s", got)
	}
	if strings.Contains(raw, "Infinity") || strings.Contains(raw, "inf") {
		t.Fatalf("output must not contain an infinity marker: %s", raw)
	}
	for _, key := range []string{"huge", "hugeNeg", "tiny"} {
		if extra[key] == nil {
			t.Fatalf("%s must not become null", key)
		}
	}
}

func TestNormalizeExtraNestedNumbersPreserved(t *testing.T) {
	// Precision protection applies at every nesting level, not just the
	// outermost value: depth, array order, and adjacent JSON types must all
	// survive.
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","deep":{"list":[9007199254740993,"9007199254740993",1.0000000000000000001,true,null,{"inner":1e400}]}}`
	results, _ := runNormalizeNumbers(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("expected ok, got %#v", results[0])
	}
	deep, ok := extraOf(t, results[0])["deep"].(map[string]any)
	if !ok {
		t.Fatalf("nesting level lost: %#v", extraOf(t, results[0]))
	}
	list, ok := deep["list"].([]any)
	if !ok || len(list) != 6 {
		t.Fatalf("array structure not preserved: %#v", deep)
	}
	if got := requireNumber(t, list[0]); got != "9007199254740993" {
		t.Fatalf("nested big integer changed: got %s", got)
	}
	if s, ok := list[1].(string); !ok || s != "9007199254740993" {
		t.Fatalf("string spelling of the same digits must stay a string: %#v", list[1])
	}
	if got := requireNumber(t, list[2]); got != "1.0000000000000000001" {
		t.Fatalf("nested decimal changed: got %s", got)
	}
	if list[3] != true {
		t.Fatalf("adjacent boolean changed type: %#v", list[3])
	}
	if list[4] != nil {
		t.Fatalf("adjacent null changed: %#v", list[4])
	}
	inner, ok := list[5].(map[string]any)
	if !ok {
		t.Fatalf("nested object lost: %#v", list[5])
	}
	if got := requireNumber(t, inner["inner"]); got != "1e400" {
		t.Fatalf("deeply nested exponent changed: got %s", got)
	}
}

func TestNormalizeInputExtraFieldPrecision(t *testing.T) {
	// The input's own extra object is one ordinary unmapped field: its
	// nested high-precision numbers must survive, and it must stay nested
	// under extra.extra rather than being flattened into sibling fields.
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","extra":{"big":9007199254740993,"frac":1.0000000000000000001},"other":1}`
	results, _ := runNormalizeNumbers(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("expected ok, got %#v", results[0])
	}
	extra := extraOf(t, results[0])
	if len(extra) != 2 {
		t.Fatalf("input extra must stay one field, not be flattened: %#v", extra)
	}
	if _, leaked := extra["big"]; leaked {
		t.Fatalf("nested extra field leaked to the top level: %#v", extra)
	}
	nested, ok := extra["extra"].(map[string]any)
	if !ok {
		t.Fatalf("input extra must remain a nested object: %#v", extra["extra"])
	}
	if got := requireNumber(t, nested["big"]); got != "9007199254740993" {
		t.Fatalf("nested extra big integer changed: got %s", got)
	}
	if got := requireNumber(t, nested["frac"]); got != "1.0000000000000000001" {
		t.Fatalf("nested extra decimal changed: got %s", got)
	}
	if got := requireNumber(t, extra["other"]); got != "1" {
		t.Fatalf("sibling extra field mismatch: got %s", got)
	}
}

func TestNormalizeExtraStringNumbersStayStrings(t *testing.T) {
	// A string that happens to hold digits is not a number: it must not be
	// converted, even alongside real high-precision numbers in the same
	// extra object.
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","count":"9007199254740993","real":9007199254740993}`
	results, _ := runNormalizeNumbers(t, input)
	if results[0]["ok"] != true {
		t.Fatalf("expected ok, got %#v", results[0])
	}
	extra := extraOf(t, results[0])
	if s, ok := extra["count"].(string); !ok || s != "9007199254740993" {
		t.Fatalf("string digits must stay a string, got %T (%v)", extra["count"], extra["count"])
	}
	if got := requireNumber(t, extra["real"]); got != "9007199254740993" {
		t.Fatalf("real number changed: got %s", got)
	}
}

func TestNormalizeMappedNumberStillFails(t *testing.T) {
	// Number preservation is scoped to unmapped fields: a number — even a
	// high-precision one — in a mapped field still fails type validation.
	cases := []struct {
		input string
		field string
	}{
		{`{"timestamp":9007199254740993,"action":"a"}`, FieldTimestamp},
		{`{"timestamp":"2026-01-02T00:00:00Z","action":1e400}`, FieldAction},
		{`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":1.0000000000000000001}`, FieldSourceIP},
	}
	for _, tc := range cases {
		results, _ := runNormalizeNumbers(t, tc.input)
		if results[0]["ok"] != false {
			t.Fatalf("number in mapped field must fail: %s", tc.input)
		}
		if _, exists := results[0]["event"]; exists {
			t.Fatalf("failure must not emit a partial event: %s", tc.input)
		}
		msg, _ := results[0]["error"].(string)
		if !strings.Contains(msg, tc.field) {
			t.Fatalf("error must name field %q, got %q", tc.field, msg)
		}
	}
}

func TestNormalizeInvalidJSONNumbersFail(t *testing.T) {
	// NaN, Infinity, and leading-zero integers are not legal JSON numbers;
	// each must fail the line with an error and no partial event.
	cases := []string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":NaN}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":Infinity}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":-Infinity}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":01}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":-01}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":+1}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":1.}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":.5}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":1e}`,
	}
	for _, in := range cases {
		results, _ := runNormalizeNumbers(t, in)
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

func TestNormalizeMixedStreamWithPrecision(t *testing.T) {
	// Lines with invalid JSON numbers fail, but surrounding legal
	// high-precision lines still succeed in order, and the failure count
	// reflects only the bad lines.
	input := "{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"a\",\"big\":9007199254740993}\n" +
		"{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"b\",\"bad\":NaN}\n" +
		"{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"c\",\"huge\":1e400}\n" +
		"{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"d\",\"bad\":01}\n" +
		"{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"e\",\"frac\":1.0000000000000000001}\n"
	var out bytes.Buffer
	failures, err := NormalizeReader(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("NormalizeReader returned error: %v", err)
	}
	if failures != 2 {
		t.Fatalf("expected exactly 2 failures, got %d", failures)
	}
	results, _ := runNormalizeNumbers(t, input)
	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d: %#v", len(results), results)
	}
	for _, i := range []int{0, 2, 4} {
		if results[i]["ok"] != true {
			t.Fatalf("legal line %d must succeed: %#v", i+1, results[i])
		}
	}
	for _, i := range []int{1, 3} {
		if results[i]["ok"] != false {
			t.Fatalf("invalid-number line %d must fail: %#v", i+1, results[i])
		}
		if _, exists := results[i]["event"]; exists {
			t.Fatalf("failed line %d must not emit an event", i+1)
		}
	}
	if got := requireNumber(t, extraOf(t, results[0])["big"]); got != "9007199254740993" {
		t.Fatalf("line 1 big integer changed: got %s", got)
	}
	if got := requireNumber(t, extraOf(t, results[2])["huge"]); got != "1e400" {
		t.Fatalf("line 3 exponent changed: got %s", got)
	}
	if got := requireNumber(t, extraOf(t, results[4])["frac"]); got != "1.0000000000000000001" {
		t.Fatalf("line 5 decimal changed: got %s", got)
	}
}
