package main

// CLI-level regression coverage for numeric evidence carried in unknown log
// fields. Detection rules treat extension numbers as evidence, so a value in
// extra must leave the process byte-for-byte with the spelling and the JSON
// type it arrived with: an integer beyond float64's exact-integer range must
// not be rounded to a neighbor, a long decimal fraction must not be truncated,
// an over-large exponent must not become Infinity, and an under-large exponent
// must not become zero. A numerically equal but textually different spelling
// (scientific notation, padding, a string) must never be substituted, and a
// number the source wrote as a string stays a string distinct from the real
// number. The guarantee reaches numbers nested inside unknown-field objects
// and arrays, and an input's own "extra" is just another unknown field: it is
// nested verbatim inside the output extra rather than merged into its siblings.
//
// Number retention applies to extension data only. A number handed straight to
// timestamp, source_ip or action (canonical name or existing alias) still
// fails the whole line with a "must be a string" reason, and an illegal JSON
// number token in an extension field (01, NaN) fails as invalid JSON rather
// than being stored.

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// rawResultLines splits stdout into its per-line JSON records without
// trailing empty segment after the final newline. Evidence assertions run
// against these raw bytes on purpose: decoding them into map[string]any
// parses every number through float64, which rounds 9007199254740993 to
// 9007199254740992 and turns 1e400 into +Inf — destroying exactly the
// evidence the normalizer is being pinned to preserve.
func rawResultLines(t *testing.T, stdout string) []string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

// decodeResultWithNumbers parses one result object keeping every JSON number
// as a json.Number (its raw literal text), so tests can assert both the JSON
// type and the extreme-number spellings that a float64 decode cannot carry.
func decodeResultWithNumbers(t *testing.T, raw string) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var record map[string]any
	if err := decoder.Decode(&record); err != nil {
		t.Fatalf("result line must decode with numbers intact: %v (%q)", err, raw)
	}
	return record
}

// decodeStdoutResultsWithNumbers parses the whole NDJSON stream keeping
// numbers as json.Number. The shared decodeStdoutResults helper routes every
// number through float64 and so cannot even read a line containing 1e400 —
// which is precisely the evidence this regression test exists to pin — so the
// evidence tests use this lossless decoder instead.
func decodeStdoutResultsWithNumbers(t *testing.T, stdout string) []map[string]any {
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

// requireContains fails unless line contains substr.
func requireContains(t *testing.T, line, substr string) {
	t.Helper()
	if !strings.Contains(line, substr) {
		t.Fatalf("output must preserve %s verbatim, got:\n%s", substr, line)
	}
}

// The all-valid evidence run. Two legal logs (the first through aliases and a
// timezone that must convert to UTC) carry the four edge numbers at the top of
// extra, inside a nested object, and inside an array, alongside string-written
// numbers, booleans and null, plus an input-owned extra object. Every number
// keeps its literal spelling and JSON number type, the string spellings stay
// strings, object/array order is untouched, the input's own extra stays nested
// as an ordinary unknown field, and standard-field normalization proceeds
// exactly as before. Exit 0 and an empty stderr.
func TestNormalizeCLIExtraNumbersPreserveLiteralEvidence(t *testing.T) {
	input := strings.Join([]string{
		`{"time":"2026-01-02T08:04:05+08:00","event_type":"  login  ","src_ip":"10.0.0.1",` +
			`"nested":{"big":9007199254740993,"dec":1.0000000000000000001,"huge":1e400,"tiny":1e-400,` +
			`"arr":[9007199254740993,1.0000000000000000001,1e400,1e-400,"9007199254740993","1e400",true,false,null]},` +
			`"extra":{"own":9007199254740993,"label":"kept"}}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"x",` +
			`"big":9007199254740993,"dec":1.0000000000000000001,"huge":1e400,"tiny":1e-400,` +
			`"asString":"1.0000000000000000001","flag":true,"missing":null}`,
	}, "\n") + "\n"

	result := runNormalizeCLI(t, strings.NewReader(input))

	if result.exitCode != 0 {
		t.Fatalf("an all-valid evidence batch must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("a clean run must not write to stderr, got %q", result.stderr)
	}

	records := decodeStdoutResultsWithNumbers(t, result.stdout)
	if len(records) != 2 {
		t.Fatalf("expected 2 success records, got %#v", records)
	}
	for i, r := range records {
		if r["ok"] != true {
			t.Fatalf("record %d must be ok:true: %#v", i, r)
		}
	}

	// Standard-field normalization must be unaffected by the extension data:
	// alias keys map to canonical names, the timestamp converts to UTC and the
	// action is trimmed.
	first := eventOf(t, records[0])
	if first["timestamp"] != "2026-01-02T00:04:05Z" {
		t.Fatalf("alias time must convert to UTC, got %v", first["timestamp"])
	}
	if first["source_ip"] != "10.0.0.1" || first["action"] != "login" {
		t.Fatalf("aliases must normalize as before: %#v", first)
	}
	second := eventOf(t, records[1])
	if second["timestamp"] != "2026-01-02T00:00:00Z" || second["action"] != "x" {
		t.Fatalf("canonical fields must round-trip: %#v", second)
	}
	if _, present := second["source_ip"]; present {
		t.Fatalf("an omitted source_ip must stay omitted: %#v", second)
	}

	lines := rawResultLines(t, result.stdout)
	if len(lines) != 2 {
		t.Fatalf("expected 2 raw output lines, got %d", len(lines))
	}

	// Raw textual pinning: the exact tokens must survive, in their original
	// object/array positions and adjacency, without re-notation.
	requireContains(t, lines[0],
		`"nested":{"big":9007199254740993,"dec":1.0000000000000000001,"huge":1e400,"tiny":1e-400,`+
			`"arr":[9007199254740993,1.0000000000000000001,1e400,1e-400,"9007199254740993","1e400",true,false,null]}`)
	requireContains(t, lines[0], `"extra":{"own":9007199254740993,"label":"kept"}`)
	requireContains(t, lines[1],
		`"extra":{"asString":"1.0000000000000000001","big":9007199254740993,`+
			`"dec":1.0000000000000000001,"flag":true,"huge":1e400,"missing":null,"tiny":1e-400}`)

	// The specific corruptions float-style re-serialization would introduce
	// must never appear anywhere in the output.
	for _, banned := range []string{
		"9007199254740992", // the rounded neighbor float64 would produce
		"1e+400",           // Go's float64 notation
		"Infinity",
		"Inf",
	} {
		if strings.Contains(result.stdout, banned) {
			t.Fatalf("output must not rewrite extension numbers into %q:\n%s", banned, result.stdout)
		}
	}

	// Type-level pinning, whitespace-insensitive: numbers decode as json.Number
	// carrying the exact literal; string-written numbers decode as strings.
	n1 := decodeResultWithNumbers(t, lines[0])
	ev1 := n1["event"].(map[string]any)
	extra1 := ev1["extra"].(map[string]any)

	ownExtra, ok := extra1["extra"].(map[string]any)
	if !ok {
		t.Fatalf("the input's own extra must nest under output extra, not merge: %#v", extra1)
	}
	if got := ownExtra["own"]; got != json.Number("9007199254740993") {
		t.Fatalf("number inside input-owned extra must keep type and spelling, got %#v", got)
	}
	if got := ownExtra["label"]; got != "kept" {
		t.Fatalf("string sibling inside input-owned extra must survive, got %#v", got)
	}
	if _, merged := extra1["own"]; merged {
		t.Fatalf("input-owned extra members must not be hoisted into the output extra: %#v", extra1)
	}

	nested, ok := extra1["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested unknown object must survive: %#v", extra1["nested"])
	}
	wantNested := map[string]json.Number{
		"big":  "9007199254740993",
		"dec":  "1.0000000000000000001",
		"huge": "1e400",
		"tiny": "1e-400",
	}
	for key, want := range wantNested {
		if got, ok := nested[key].(json.Number); !ok || string(got) != string(want) {
			t.Fatalf("nested %s must be JSON number %s, got %#v", key, want, nested[key])
		}
	}
	arr, ok := nested["arr"].([]any)
	if !ok || len(arr) != 9 {
		t.Fatalf("nested array must keep all nine elements in order, got %#v", nested["arr"])
	}
	wantArr := []struct {
		check func(any) bool
		label string
	}{
		{isNumber("9007199254740993"), "number 9007199254740993"},
		{isNumber("1.0000000000000000001"), "number 1.0000000000000000001"},
		{isNumber("1e400"), "number 1e400"},
		{isNumber("1e-400"), "number 1e-400"},
		{isString("9007199254740993"), "string \"9007199254740993\""},
		{isString("1e400"), "string \"1e400\""},
		{isBool(true), "boolean true"},
		{isBool(false), "boolean false"},
		{isNull(), "null"},
	}
	for i, w := range wantArr {
		if !w.check(arr[i]) {
			t.Fatalf("array element %d must be %s, got %#v (array: %#v)", i, w.label, arr[i], arr)
		}
	}

	n2 := decodeResultWithNumbers(t, lines[1])
	extra2 := n2["event"].(map[string]any)["extra"].(map[string]any)
	for key, want := range map[string]json.Number{
		"big":  "9007199254740993",
		"dec":  "1.0000000000000000001",
		"huge": "1e400",
		"tiny": "1e-400",
	} {
		if got, ok := extra2[key].(json.Number); !ok || string(got) != string(want) {
			t.Fatalf("top-level extra %s must be JSON number %s, got %#v", key, want, extra2[key])
		}
	}
	if got, ok := extra2["asString"].(string); !ok || got != "1.0000000000000000001" {
		t.Fatalf("a string-written number must remain a distinct string, got %#v", extra2["asString"])
	}
	if extra2["flag"] != true {
		t.Fatalf("boolean sibling must survive, got %#v", extra2["flag"])
	}
	if _, present := extra2["missing"]; !present || extra2["missing"] != nil {
		t.Fatalf("null sibling must survive as null, got %#v", extra2["missing"])
	}
}

func isNumber(want string) func(any) bool {
	return func(v any) bool {
		n, ok := v.(json.Number)
		return ok && string(n) == want
	}
}
func isString(want string) func(any) bool {
	return func(v any) bool {
		s, ok := v.(string)
		return ok && s == want
	}
}
func isBool(want bool) func(any) bool {
	return func(v any) bool {
		b, ok := v.(bool)
		return ok && b == want
	}
}
func isNull() func(any) bool {
	return func(v any) bool { return v == nil }
}

// A number given directly to a mapped field is a type error regardless of
// whether the canonical name or its alias carries it: the line fails with the
// canonical field's "must be a string, got number" reason, carries no event,
// and the run exits 1. This holds even when the number is a big integer or an
// extreme exponent that extra would otherwise preserve — extension-number
// retention never loosens the standard-field contract.
func TestNormalizeCLINumberInStandardFieldFails(t *testing.T) {
	const ts = `"2026-01-02T00:00:00Z"`
	cases := []struct {
		name      string
		line      string
		canonical string
	}{
		{"timestamp canonical", `{"timestamp":1700000000,"action":"a"}`, "timestamp"},
		{"timestamp alias big integer", `{"time":9007199254740993,"action":"a"}`, "timestamp"},
		{"source_ip canonical", `{"timestamp":` + ts + `,"action":"a","source_ip":12345}`, "source_ip"},
		{"source_ip alias exponent", `{"timestamp":` + ts + `,"action":"a","src_ip":1e400}`, "source_ip"},
		{"action canonical integer", `{"timestamp":` + ts + `,"action":42}`, "action"},
		{"action alias decimal", `{"timestamp":` + ts + `,"event_type":1.5}`, "action"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := runNormalizeCLI(t, strings.NewReader(tc.line+"\n"))
			if result.exitCode != 1 {
				t.Fatalf("a numeric standard field must exit 1, got %d (stderr: %q)", result.exitCode, result.stderr)
			}
			if result.stderr != "" {
				t.Fatalf("per-line failures belong in result records, not stderr, got %q", result.stderr)
			}
			records := decodeStdoutResults(t, result.stdout)
			if len(records) != 1 {
				t.Fatalf("expected exactly one failure record, got %#v", records)
			}
			r := records[0]
			if r["line"] != float64(1) || r["ok"] != false {
				t.Fatalf("the bad line must be line 1 ok=false: %#v", r)
			}
			if _, exists := r["event"]; exists {
				t.Fatalf("a type-invalid line must carry no event: %#v", r)
			}
			if len(r) != 3 {
				t.Fatalf("a failure record carries exactly line, ok and error, got %#v", r)
			}
			want := `field "` + tc.canonical + `": value must be a string, got number`
			if r["error"] != want {
				t.Fatalf("error must name canonical field %q and demand a string, got %q", tc.canonical, r["error"])
			}
		})
	}
}

// Extension numbers must be legal JSON number tokens to be preserved. Leading
// zeros (01) and bare NaN are JSON syntax errors, not valid values to store:
// the line fails as invalid JSON with no event. In the same batch, a legal
// evidence line, a number-into-standard-field line, a blank physical line,
// these two syntax failures, and a trailing legal evidence line must all be
// reported in input order with the blank only consuming a line number; the
// trailing valid line still succeeds, stderr stays empty and the run exits 1.
func TestNormalizeCLIIllegalJSONNumbersAndMixedBatch(t *testing.T) {
	input := bytes.Join([][]byte{
		[]byte(`{"timestamp":"2026-01-02T00:00:00Z","action":"a","big":9007199254740993}`), // 1: ok
		[]byte(`{"timestamp":1700000000,"action":"a"}`),                                    // 2: fail (number field)
		[]byte(``), // 3: blank, no record
		[]byte(`{"timestamp":"2026-01-02T00:00:00Z","action":"a","bad":01}`),      // 4: fail (invalid JSON)
		[]byte(`{"timestamp":"2026-01-02T00:00:00Z","action":"a","bad":NaN}`),     // 5: fail (invalid JSON)
		[]byte(`{"timestamp":"2026-01-02T00:00:00Z","action":"z","tiny":1e-400}`), // 6: ok
	}, []byte("\n"))

	result := runNormalizeCLI(t, bytes.NewReader(input))

	if result.exitCode != 1 {
		t.Fatalf("a batch containing failed logs must exit 1, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in result records, not stderr, got %q", result.stderr)
	}

	records := decodeStdoutResults(t, result.stdout)
	if len(records) != 5 {
		t.Fatalf("the blank line produces no record; expected 5, got %#v", records)
	}

	want := []struct {
		line float64
		ok   bool
	}{
		{1, true},
		{2, false},
		{4, false},
		{5, false},
		{6, true},
	}
	for i, w := range want {
		if records[i]["line"] != w.line || records[i]["ok"] != w.ok {
			t.Fatalf("record %d must be physical line %v ok=%v, got %#v", i, w.line, w.ok, records[i])
		}
	}

	if eventOf(t, records[0])["action"] != "a" {
		t.Fatalf("line 1 event mismatch: %#v", records[0])
	}
	if eventOf(t, records[4])["action"] != "z" {
		t.Fatalf("the trailing legal log must still normalize after failures: %#v", records[4])
	}

	// Failures carry only physical line number, ok:false and a reason.
	for _, i := range []int{1, 2, 3} {
		r := records[i]
		if _, exists := r["event"]; exists {
			t.Fatalf("failed line %v must carry no event: %#v", r["line"], r)
		}
		if len(r) != 3 {
			t.Fatalf("failed line %v must carry exactly line, ok and error: %#v", r["line"], r)
		}
	}
	if got := records[1]["error"]; got != `field "timestamp": value must be a string, got number` {
		t.Fatalf("line 2 must report the numeric timestamp, got %q", got)
	}
	for _, i := range []int{2, 3} {
		msg, _ := records[i]["error"].(string)
		if !strings.Contains(msg, "invalid JSON") {
			t.Fatalf("line %v must fail as invalid JSON, not be stored as a number; got %q", records[i]["line"], msg)
		}
	}

	// Evidence on the legal lines is intact, in raw text.
	lines := rawResultLines(t, result.stdout)
	requireContains(t, lines[0], `"big":9007199254740993`)
	requireContains(t, lines[4], `"tiny":1e-400`)
}
