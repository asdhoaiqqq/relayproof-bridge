package main

// CLI-level regression coverage for numeric evidence carried by unknown log
// fields, exercised through the real `relayproof normalize` binary: users
// submit newline-delimited JSON on stdin and must receive one JSON result per
// non-blank physical line on stdout. Numbers in unknown fields land in the
// success event's extra as JSON numbers with their exact input spelling —
// integers past float64 precision must not round to a neighbor, long
// fractional tails must not truncate, 1e400 must not become Infinity, and
// 1e-400 must not collapse to zero; an equivalent spelling elsewhere is no
// reason to canonicalize this one. A number written as a JSON string stays a
// string. Preservation applies inside nested objects and arrays at any depth
// (including an input's own "extra", which stays one nested field), while
// timestamp UTC conversion, action trimming and alias mapping proceed as
// before. Numbers handed directly to timestamp/source_ip/action (or their
// aliases) still fail the whole line with a reason that names the standard
// field and demands a string, and tokens that are not legal JSON numbers
// (01, NaN, ...) fail as invalid JSON. Failure records carry only the
// physical line number, ok:false and a reason — never an event — and later
// legal lines still come out in order. A fully legal batch exits 0, a batch
// containing failures exits 1, and stderr is empty in both cases.

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// decodeStdoutResultsNumbered parses stdout as newline-delimited JSON result
// objects, decoding every JSON number as json.Number so the exact serialized
// literal — not a float64-rounded value — can be inspected.
func decodeStdoutResultsNumbered(t *testing.T, stdout string) []map[string]any {
	t.Helper()
	var results []map[string]any
	decoder := json.NewDecoder(strings.NewReader(stdout))
	decoder.UseNumber()
	for {
		var record map[string]any
		if err := decoder.Decode(&record); err != nil {
			if err == io.EOF {
				return results
			}
			t.Fatalf("stdout must contain only JSON result objects, got decode error %v after %d records: %q",
				err, len(results), stdout)
		}
		results = append(results, record)
	}
}

// mustJSONNumber asserts v is a JSON number whose literal form is exactly
// want — no rounding, no truncation, no scientific-notation rewrite, no
// conversion to a string.
func mustJSONNumber(t *testing.T, v any, want string) {
	t.Helper()
	n, ok := v.(json.Number)
	if !ok {
		t.Fatalf("expected JSON number %s, got %T (%v)", want, v, v)
	}
	if n.String() != want {
		t.Fatalf("number preserved as %q, want exact literal %q", n.String(), want)
	}
}

// A fully legal batch whose unknown fields carry numbers outside float64's
// exact-integer range, beyond its exponent limits, and with more fractional
// digits than it keeps: the whole line succeeds, every literal reaches stdout
// byte-for-byte as a JSON number, a mathematically equivalent alternative
// spelling is not canonicalized, and a number spelled as a string stays a
// string. Alias keys still map to the standard fields, which keep their own
// normalization (UTC conversion, trimming). Exit 0 and silent stderr are part
// of the contract.
func TestNormalizeCLIExtraNumbersPreservedExactly(t *testing.T) {
	input := `{"time":"2026-01-02T08:04:05+08:00","event_type":"  login  ",` +
		`"big":9007199254740993,` +
		`"neg_big":-9007199254740993,` +
		`"precise":1.0000000000000000001,` +
		`"huge":1e400,` +
		`"tiny":1e-400,` +
		`"compact":1E3,` +
		`"plain":42,` +
		`"big_as_string":"9007199254740993"}` + "\n"

	result := runNormalizeCLI(t, strings.NewReader(input))

	if result.exitCode != 0 {
		t.Fatalf("a fully legal high-precision batch must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("a clean run must not write to stderr, got %q", result.stderr)
	}

	results := decodeStdoutResultsNumbered(t, result.stdout)
	if len(results) != 1 || results[0]["ok"] != true || results[0]["line"] != json.Number("1") {
		t.Fatalf("expected one ok result for physical line 1, got %#v", results)
	}
	event := eventOf(t, results[0])

	// Standard fields normalize exactly as they do without extension data:
	// the time alias converts to UTC and the event_type alias is trimmed.
	if got := event["timestamp"]; got != "2026-01-02T00:04:05Z" {
		t.Fatalf("timestamp must still convert to UTC alongside preserved numbers, got %v", got)
	}
	if got := event["action"]; got != "login" {
		t.Fatalf("action must still trim alongside preserved numbers, got %v", got)
	}

	extra, ok := event["extra"].(map[string]any)
	if !ok {
		t.Fatalf("unknown fields must be kept in extra: %#v", event)
	}
	mustJSONNumber(t, extra["big"], "9007199254740993")
	mustJSONNumber(t, extra["neg_big"], "-9007199254740993")
	mustJSONNumber(t, extra["precise"], "1.0000000000000000001")
	mustJSONNumber(t, extra["huge"], "1e400")
	mustJSONNumber(t, extra["tiny"], "1e-400")
	mustJSONNumber(t, extra["plain"], "42")

	// 1E3 denotes the same value as 1000/1e3, but this spelling is evidence:
	// it must not be rewritten into another notation or padded.
	mustJSONNumber(t, extra["compact"], "1E3")

	if s, ok := extra["big_as_string"].(string); !ok || s != "9007199254740993" {
		t.Fatalf("a number spelled as a JSON string must stay a string, got %T (%v)",
			extra["big_as_string"], extra["big_as_string"])
	}

	// Pin the serialized bytes directly: downstream tools parse stdout
	// themselves, so the literals must survive on the wire, not just inside
	// this test's decoder.
	raw := result.stdout
	for _, want := range []string{
		"9007199254740993",
		"1.0000000000000000001",
		"1e400",
		"1e-400",
		"1E3",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("serialized stdout must contain the exact literal %s, got %s", want, raw)
		}
	}
	if strings.Contains(raw, "9007199254740992") {
		t.Fatalf("the big integer must not round to its float64 neighbor, got %s", raw)
	}
	if strings.Contains(raw, "Infinity") || strings.Contains(raw, "-Infinity") {
		t.Fatalf("the out-of-range exponent must not serialize as infinity, got %s", raw)
	}
}

// Preservation reaches numbers nested inside unknown-field objects and arrays
// at every depth: object levels, array order, and the JSON types of the
// values adjacent to the numbers (string, boolean, null, ordinary number) all
// survive. An input's own "extra" member is an ordinary unknown field: it
// stays one nested object inside the output extra (with its numbers intact)
// and is never split apart or merged into sibling members.
func TestNormalizeCLIExtraNestedNumbersAndInputExtra(t *testing.T) {
	input := `{"timestamp":"2026-01-02T00:00:00Z","action":"a","payload":{` +
		`"deep":{"id":9007199254740993},` +
		`"list":[1.0000000000000000001,9007199254740993,"9007199254740993",true,null,3]},` +
		`"extra":{"balance":9007199254740993,"tags":["x",1e400],"tiny":1e-400},` +
		`"other":2}` + "\n"

	result := runNormalizeCLI(t, strings.NewReader(input))

	if result.exitCode != 0 {
		t.Fatalf("nested high-precision extra must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("a clean run must not write to stderr, got %q", result.stderr)
	}

	results := decodeStdoutResultsNumbered(t, result.stdout)
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("expected one ok result, got %#v", results)
	}
	extra, ok := eventOf(t, results[0])["extra"].(map[string]any)
	if !ok {
		t.Fatalf("event must carry extra: %#v", results[0])
	}
	if len(extra) != 3 { // payload, the input's own extra, and other
		t.Fatalf("input extra must stay one nested field, got %d members: %#v", len(extra), extra)
	}

	payload, ok := extra["payload"].(map[string]any)
	if !ok {
		t.Fatalf("payload object must be preserved, got %#v", extra["payload"])
	}
	deep, ok := payload["deep"].(map[string]any)
	if !ok {
		t.Fatalf("nested object level must be preserved, got %#v", payload["deep"])
	}
	mustJSONNumber(t, deep["id"], "9007199254740993")

	list, ok := payload["list"].([]any)
	if !ok || len(list) != 6 {
		t.Fatalf("nested array and its length must be preserved, got %#v", payload["list"])
	}
	mustJSONNumber(t, list[0], "1.0000000000000000001")
	mustJSONNumber(t, list[1], "9007199254740993")
	if s, ok := list[2].(string); !ok || s != "9007199254740993" {
		t.Fatalf("string-formed array element must stay a string, got %T (%v)", list[2], list[2])
	}
	if list[3] != true {
		t.Fatalf("adjacent boolean must keep its type, got %#v", list[3])
	}
	if list[4] != nil {
		t.Fatalf("adjacent null must keep its type, got %#v", list[4])
	}
	mustJSONNumber(t, list[5], "3")

	inner, ok := extra["extra"].(map[string]any)
	if !ok {
		t.Fatalf("the input's own extra must survive as a nested object under extra, got %#v", extra["extra"])
	}
	mustJSONNumber(t, inner["balance"], "9007199254740993")
	mustJSONNumber(t, inner["tiny"], "1e-400")
	tags, ok := inner["tags"].([]any)
	if !ok || len(tags) != 2 || tags[0] != "x" {
		t.Fatalf("nested array inside input extra not preserved: %#v", inner["tags"])
	}
	mustJSONNumber(t, tags[1], "1e400")
	if _, leaked := inner["id"]; leaked {
		t.Fatalf("payload siblings must not be merged into the input extra: %#v", inner)
	}
	if _, hoisted := extra["balance"]; hoisted {
		t.Fatalf("nested input-extra members must not be hoisted to the top level: %#v", extra)
	}
	mustJSONNumber(t, extra["other"], "2")
}

// Number preservation is scoped to unknown fields. A number handed directly
// to timestamp, source_ip or action — including under their time/src_ip/
// event_type aliases, and even when the number itself is a perfectly legal
// high-precision literal — fails the whole line: the record carries only
// line/ok/error, no event, and its reason names the standard field and the
// string requirement.
func TestNormalizeCLINumbersInStandardFieldsFail(t *testing.T) {
	cases := []struct {
		name  string
		input string
		field string
	}{
		{"timestamp big integer", `{"timestamp":9007199254740993,"action":"a"}`, "timestamp"},
		{"time high-precision decimal", `{"time":1.0000000000000000001,"action":"a"}`, "timestamp"},
		{"timestamp huge exponent", `{"timestamp":1e400,"action":"a"}`, "timestamp"},
		{"source_ip big integer", `{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":9007199254740993}`, "source_ip"},
		{"src_ip huge exponent", `{"timestamp":"2026-01-02T00:00:00Z","action":"a","src_ip":1e400}`, "source_ip"},
		{"action plain number", `{"timestamp":"2026-01-02T00:00:00Z","action":123}`, "action"},
		{"event_type big integer", `{"timestamp":"2026-01-02T00:00:00Z","event_type":9007199254740993}`, "action"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := runNormalizeCLI(t, strings.NewReader(tc.input+"\n"))

			if result.exitCode != 1 {
				t.Fatalf("a number in %q must set exit status 1, got %d (stderr: %q)", tc.field, result.exitCode, result.stderr)
			}
			if result.stderr != "" {
				t.Fatalf("per-line failures belong in result records, not stderr, got %q", result.stderr)
			}

			results := decodeStdoutResults(t, result.stdout)
			if len(results) != 1 {
				t.Fatalf("expected exactly one record, got %#v", results)
			}
			r := results[0]
			if r["line"] != float64(1) || r["ok"] != false {
				t.Fatalf("the line must fail as line 1: %#v", r)
			}
			if _, exists := r["event"]; exists {
				t.Fatalf("a failed standard field must not emit an event: %#v", r)
			}
			if len(r) != 3 {
				t.Fatalf("a failure record carries exactly line, ok and error, got %#v", r)
			}
			msg, _ := r["error"].(string)
			if !strings.Contains(msg, tc.field) {
				t.Fatalf("reason must name standard field %q, got %q", tc.field, msg)
			}
			if !strings.Contains(msg, "string") {
				t.Fatalf("reason must state the field requires a string, got %q", msg)
			}
		})
	}
}

// Tokens that are not legal JSON numbers are never accepted as extension
// values, including inside nested unknown-field objects and arrays: the whole
// line fails with an invalid-JSON reason and no event, regardless of valid
// standard fields. Each is an ordinary per-line failure (exit 1, empty
// stderr), not a stream error.
func TestNormalizeCLIInvalidJSONNumberLiteralsFail(t *testing.T) {
	cases := []string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":NaN}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":Infinity}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":-Infinity}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":01}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":+1}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":1.}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":{"nested":007}}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":[NaN]}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","extra":{"v":01}}`,
	}
	for _, in := range cases {
		result := runNormalizeCLI(t, strings.NewReader(in+"\n"))

		if result.exitCode != 1 {
			t.Fatalf("illegal number %s must set exit status 1, got %d (stderr: %q)", in, result.exitCode, result.stderr)
		}
		if result.stderr != "" {
			t.Fatalf("per-line failures belong in result records, not stderr, got %q", result.stderr)
		}

		results := decodeStdoutResults(t, result.stdout)
		if len(results) != 1 {
			t.Fatalf("illegal number %s must yield exactly one record, got %#v", in, results)
		}
		r := results[0]
		if r["line"] != float64(1) || r["ok"] != false {
			t.Fatalf("illegal number %s must fail line 1: %#v", in, r)
		}
		if _, exists := r["event"]; exists {
			t.Fatalf("illegal number %s must not emit a partial event: %#v", in, r)
		}
		if len(r) != 3 {
			t.Fatalf("a failure record carries exactly line, ok and error, got %#v", r)
		}
		if msg, _ := r["error"].(string); msg == "" {
			t.Fatalf("illegal number %s must produce a reason", in)
		}
	}
}

// The end-to-end batch contract when legal high-precision logs share a stream
// with both failure classes: an illegal JSON number in an extension field and
// a number handed to a standard field. Blank physical lines only consume line
// numbers. The two bad lines get bare failure records (no event), every
// surrounding legal log is still emitted in input order with its numbers
// intact — including numbers inside a nested array, a string-formed number
// beside a real one, and an input's own "extra". The process exits 1 even
// though more than half the logs succeed, and stderr stays empty.
func TestNormalizeCLIMixedNumericEvidenceBatch(t *testing.T) {
	lines := []string{
		// physical line 1: ok — big integer and high-precision decimal.
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","big":9007199254740993,"precise":1.0000000000000000001}`,
		"", // physical line 2: blank, no record
		// physical line 3: fail — NaN is not a legal JSON number in extra.
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","x":NaN}`,
		// physical line 4: fail — number supplied to the time alias.
		`{"time":1e400,"action":"a"}`,
		// physical line 5: ok — alias mapping plus UTC/trim normalization
		// alongside a nested array mixing numbers, a string number, bool/null.
		`{"time":"2026-01-02T08:04:05+08:00","event_type":" login ","payload":{"ids":[9007199254740993,"9007199254740993",true,null,1e-400]}}`,
		"  \t ", // physical line 6: blank, no record
		// physical line 7: ok — input's own extra stays nested, not flattened.
		`{"timestamp":"2026-01-02T00:00:00Z","action":"z","extra":{"balance":9007199254740993},"ratio":1.0000000000000000001}`,
	}
	input := strings.Join(lines, "\n")

	result := runNormalizeCLI(t, strings.NewReader(input))

	if result.exitCode != 1 {
		t.Fatalf("a batch containing any failed log must exit 1, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in result records, not stderr, got %q", result.stderr)
	}

	results := decodeStdoutResultsNumbered(t, result.stdout)
	if len(results) != 5 {
		t.Fatalf("blank lines produce no records; expected 5 results for 7 physical lines, got %#v", results)
	}

	// Line 1: ok, literals preserved.
	if results[0]["line"] != json.Number("1") || results[0]["ok"] != true {
		t.Fatalf("physical line 1 must succeed: %#v", results[0])
	}
	firstExtra, ok := eventOf(t, results[0])["extra"].(map[string]any)
	if !ok {
		t.Fatalf("line 1 event must carry extra: %#v", results[0])
	}
	mustJSONNumber(t, firstExtra["big"], "9007199254740993")
	mustJSONNumber(t, firstExtra["precise"], "1.0000000000000000001")

	// Line 3: bare failure for the illegal JSON number, no event.
	if results[1]["line"] != json.Number("3") || results[1]["ok"] != false {
		t.Fatalf("the NaN line must fail as physical line 3: %#v", results[1])
	}
	if _, exists := results[1]["event"]; exists {
		t.Fatalf("line 3 failure must not carry an event: %#v", results[1])
	}
	if len(results[1]) != 3 {
		t.Fatalf("line 3 failure record carries exactly line, ok and error, got %#v", results[1])
	}
	if msg, _ := results[1]["error"].(string); msg == "" {
		t.Fatalf("line 3 failure must carry a reason: %#v", results[1])
	}

	// Line 4: bare failure naming the timestamp field and its string rule.
	if results[2]["line"] != json.Number("4") || results[2]["ok"] != false {
		t.Fatalf("the number-in-time line must fail as physical line 4: %#v", results[2])
	}
	if _, exists := results[2]["event"]; exists {
		t.Fatalf("line 4 failure must not carry an event: %#v", results[2])
	}
	if len(results[2]) != 3 {
		t.Fatalf("line 4 failure record carries exactly line, ok and error, got %#v", results[2])
	}
	msg, _ := results[2]["error"].(string)
	if !strings.Contains(msg, "timestamp") || !strings.Contains(msg, "string") {
		t.Fatalf("line 4 reason must demand a string for timestamp, got %q", msg)
	}

	// Line 5: ok — standard fields still normalized, nested evidence intact.
	if results[3]["line"] != json.Number("5") || results[3]["ok"] != true {
		t.Fatalf("physical line 5 must succeed after earlier failures: %#v", results[3])
	}
	fifthEvent := eventOf(t, results[3])
	if got := fifthEvent["timestamp"]; got != "2026-01-02T00:04:05Z" {
		t.Fatalf("line 5 timestamp must still convert to UTC, got %v", got)
	}
	if got := fifthEvent["action"]; got != "login" {
		t.Fatalf("line 5 action must still be trimmed, got %v", got)
	}
	fifthPayload, ok := fifthEvent["extra"].(map[string]any)["payload"].(map[string]any)
	if !ok {
		t.Fatalf("line 5 payload must be preserved: %#v", fifthEvent["extra"])
	}
	ids, ok := fifthPayload["ids"].([]any)
	if !ok || len(ids) != 5 {
		t.Fatalf("line 5 nested array must keep its length and order: %#v", fifthPayload["ids"])
	}
	mustJSONNumber(t, ids[0], "9007199254740993")
	if s, ok := ids[1].(string); !ok || s != "9007199254740993" {
		t.Fatalf("line 5 string-formed number must stay a string, got %T (%v)", ids[1], ids[1])
	}
	if ids[2] != true || ids[3] != nil {
		t.Fatalf("line 5 adjacent boolean/null must keep their types: %#v", ids)
	}
	mustJSONNumber(t, ids[4], "1e-400")

	// Line 7: ok — the input's own extra remains one nested field.
	if results[4]["line"] != json.Number("7") || results[4]["ok"] != true {
		t.Fatalf("physical line 7 must succeed in input order: %#v", results[4])
	}
	lastExtra, ok := eventOf(t, results[4])["extra"].(map[string]any)
	if !ok || len(lastExtra) != 2 {
		t.Fatalf("line 7 input extra must stay nested beside ratio, got %#v", eventOf(t, results[4])["extra"])
	}
	inner, ok := lastExtra["extra"].(map[string]any)
	if !ok {
		t.Fatalf("line 7 input extra must survive nested, got %#v", lastExtra["extra"])
	}
	mustJSONNumber(t, inner["balance"], "9007199254740993")
	mustJSONNumber(t, lastExtra["ratio"], "1.0000000000000000001")

	// Serialized bytes across the whole mixed stream: the exact literals
	// survive on the wire, with no float64 neighbor rounding or infinity.
	raw := result.stdout
	for _, want := range []string{"9007199254740993", "1.0000000000000000001", "1e-400"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("serialized stdout must contain the exact literal %s, got %s", want, raw)
		}
	}
	if strings.Contains(raw, "9007199254740992") {
		t.Fatalf("the big integer must not round to its float64 neighbor, got %s", raw)
	}
	if strings.Contains(raw, "Infinity") {
		t.Fatalf("failed or preserved exponents must never serialize as infinity, got %s", raw)
	}

	// The NaN token is invalid JSON; it must never be echoed as a serialized
	// value (the decoder's reason spells the offending character, not the
	// token, so a bare "NaN" substring in stdout means it leaked through).
	if strings.Contains(raw, "NaN") {
		t.Fatalf("illegal NaN token must never appear as a serialized value, got %s", raw)
	}
}

// Sanity check on the failure-record shape when extension numbers and a
// standard-field failure coexist in one otherwise-valid batch: the failure
// record bytes contain exactly "line", "ok" and "error" members, in that
// order, so log shippers can rely on the fixed minimal schema.
func TestNormalizeCLIFailureRecordShapeForNumericRejects(t *testing.T) {
	var input bytes.Buffer
	input.WriteString(`{"timestamp":"2026-01-02T00:00:00Z","action":"a","big":9007199254740993}` + "\n")
	input.WriteString(`{"time":9007199254740993,"action":"a"}` + "\n")

	result := runNormalizeCLI(t, &input)
	if result.exitCode != 1 || result.stderr != "" {
		t.Fatalf("expected exit 1 and empty stderr, got code %d stderr %q", result.exitCode, result.stderr)
	}

	lines := strings.Split(strings.TrimSuffix(result.stdout, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two record lines, got %q", result.stdout)
	}
	if !strings.Contains(lines[0], `"ok":true`) || !strings.Contains(lines[0], `"event"`) {
		t.Fatalf("the legal line must carry its event, got %s", lines[0])
	}
	failure := lines[1]
	if !strings.HasPrefix(failure, `{"line":2,"ok":false,"error":`) {
		t.Fatalf("failure record must open with fixed line/ok/error order, got %s", failure)
	}
	if strings.Contains(failure, `"event"`) {
		t.Fatalf("failure record must not contain an event member, got %s", failure)
	}
}
