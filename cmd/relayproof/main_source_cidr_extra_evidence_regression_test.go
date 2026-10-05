package main

// CLI-level regression coverage for extended-evidence preservation under the
// normalize --source-cidr filter. The filter decides only whether a
// successfully normalized event is emitted; it must never rewrite the event
// it lets through. A kept record's extra still carries the source log's
// evidence exactly as the unfiltered run would: unknown top-level fields are
// individual members of event.extra, an input-owned "extra" stays nested at
// event.extra.extra rather than being flattened into its siblings, nested
// objects and arrays keep their structure (including same-named action /
// timestamp members whose strings are evidence, not standard fields, and
// repeated inner members in source order), and extreme numbers keep their
// literal spelling and JSON number type while quoted spellings stay strings.
// Out-of-network valid logs vanish without a record and without a failure;
// invalid logs are reported with their physical line number and reason even
// when their address lies outside the network; and the records the filter
// keeps are byte-identical to what the same logs produce without the option.

import (
	"encoding/json"
	"strings"
	"testing"
)

// evidenceFilterInput builds the shared four-line batch used by the filtered
// and unfiltered runs below: two in-network hits carrying distinct evidence,
// one valid out-of-network log whose evidence must vanish with its record,
// and one invalid-timestamp log whose source address is also out-of-network.
// The first hit deliberately spells its nested object with extra whitespace
// so the existing structural-whitespace compaction is pinned as well.
func evidenceFilterInput() string {
	hitOne := `{"timestamp":"2026-01-02T00:00:00Z","action":"keep-one","source_ip":"192.0.2.10",` +
		`"nested":{ "action":"  raw action  ","timestamp":"not-a-time",` +
		`"big":9007199254740993,"dec":1.0000000000000000001,"huge":1e400,"dup":1,"dup":2 },` +
		`"extra":{"own":9007199254740993,"note":"  padded  "},` +
		`"arr":[9007199254740993,1.0000000000000000001,1e400,"9007199254740993","1e400",true,false,null]}`
	dropped := `{"timestamp":"2026-01-02T00:00:00Z","action":"drop","source_ip":"198.51.100.7",` +
		`"secret":"must-not-leak","nums":[9,9]}`
	broken := `{"timestamp":"2026-02-30T00:00:00Z","action":"broken","source_ip":"198.51.100.9","junk":1e400}`
	hitTwo := `{"timestamp":"2026-01-02T00:00:01Z","action":"keep-two","source_ip":"192.0.2.11",` +
		`"marker":"second","nums":[3,1e400]}`
	return strings.Join([]string{hitOne, dropped, broken, hitTwo}, "\n") + "\n"
}

// The mixed-batch filtered run: the two in-network hits come out in input
// order with their physical line numbers and their own complete evidence,
// the out-of-network valid log leaves no trace, and the invalid-timestamp
// line — even though its source is also outside the network — is still a
// failure record with its line number, an explicit timestamp reason and no
// event. Exit 1 reflects the one bad line; stderr stays empty.
func TestNormalizeCLISourceCIDRPreservesExtraEvidence(t *testing.T) {
	result := runNormalizeCLIArgs(t, strings.NewReader(evidenceFilterInput()),
		"--source-cidr", "192.0.2.0/24")

	if result.exitCode != 1 {
		t.Fatalf("one invalid log among filtered hits must exit 1, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line reasons belong in stdout records, not stderr, got %q", result.stderr)
	}

	// The dropped valid log's evidence must not leak into any emitted record.
	for _, gone := range []string{"must-not-leak", `"secret"`, `"drop"`} {
		if strings.Contains(result.stdout, gone) {
			t.Fatalf("filtered-out log content %s must not appear in output:\n%s", gone, result.stdout)
		}
	}

	records := decodeStdoutResultsWithNumbers(t, result.stdout)
	if len(records) != 3 {
		t.Fatalf("expected 2 kept hits + 1 failure, got %#v", records)
	}
	for i, wantLine := range []json.Number{"1", "3", "4"} {
		if records[i]["line"] != wantLine {
			t.Fatalf("record %d must carry physical line %s, got %#v", i, wantLine, records[i])
		}
		if _, exists := records[i]["filtered"]; exists {
			t.Fatalf("records must carry no filter marker: %#v", records[i])
		}
	}

	lines := rawResultLines(t, result.stdout)
	if len(lines) != 3 {
		t.Fatalf("expected 3 raw output lines, got %d", len(lines))
	}

	// The failure sits between the hits: physical line 3, an explicit
	// timestamp reason, no event, and exactly the three failure keys — even
	// though its source address is outside the selected network.
	bad := records[1]
	if bad["ok"] != false {
		t.Fatalf("the invalid-time line must be a failure record: %#v", bad)
	}
	if _, exists := bad["event"]; exists {
		t.Fatalf("the failure record must carry no event: %#v", bad)
	}
	if len(bad) != 3 {
		t.Fatalf("a failure record carries exactly line, ok and error, got %#v", bad)
	}
	if msg, _ := bad["error"].(string); !strings.Contains(msg, `field "timestamp"`) ||
		!strings.Contains(msg, "invalid RFC3339 timestamp") {
		t.Fatalf("the failure must keep its explicit timestamp reason, got %q", msg)
	}

	// First hit: standard fields normalize as usual, and the whole evidence
	// payload survives verbatim. The single raw-text assertion pins, in one
	// piece: extra top-level members sorted (arr < extra < nested), inner
	// whitespace compacted to the existing output form, the nested same-named
	// action/timestamp strings untrimmed and unconverted, the repeated inner
	// member kept twice in source order, the extreme numbers in their
	// original spelling as JSON numbers, the quoted spellings still strings,
	// the array's element order and member types, and the input-owned extra
	// nested as an ordinary unknown field rather than flattened.
	first := eventOf(t, records[0])
	if first["timestamp"] != "2026-01-02T00:00:00Z" ||
		first["source_ip"] != "192.0.2.10" || first["action"] != "keep-one" {
		t.Fatalf("first hit standard fields mismatch: %#v", first)
	}
	requireContains(t, lines[0],
		`"extra":{"arr":[9007199254740993,1.0000000000000000001,1e400,"9007199254740993","1e400",true,false,null],`+
			`"extra":{"own":9007199254740993,"note":"  padded  "},`+
			`"nested":{"action":"  raw action  ","timestamp":"not-a-time",`+
			`"big":9007199254740993,"dec":1.0000000000000000001,"huge":1e400,"dup":1,"dup":2}}`)

	// The corruptions a float-style re-serialization would introduce must
	// appear nowhere in the output.
	for _, banned := range []string{"9007199254740992", "1e+400", "Infinity", "Inf"} {
		if strings.Contains(result.stdout, banned) {
			t.Fatalf("evidence numbers must not be rewritten into %q:\n%s", banned, result.stdout)
		}
	}

	// Type-level pinning on the first hit: numbers decode as json.Number
	// carrying the exact literal, quoted spellings decode as strings, and
	// the nested same-named members are evidence strings, not normalized
	// standard-field values.
	ev1 := eventOf(t, decodeResultWithNumbers(t, lines[0]))
	extra1, ok := ev1["extra"].(map[string]any)
	if !ok {
		t.Fatalf("first hit must carry its extra object: %#v", ev1)
	}
	ownExtra, ok := extra1["extra"].(map[string]any)
	if !ok {
		t.Fatalf("input-owned extra must nest under event.extra, not merge: %#v", extra1)
	}
	if got := ownExtra["own"]; got != json.Number("9007199254740993") {
		t.Fatalf("number inside input-owned extra must keep type and spelling, got %#v", got)
	}
	if got := ownExtra["note"]; got != "  padded  " {
		t.Fatalf("string inside input-owned extra must stay untrimmed, got %#v", got)
	}
	if _, merged := extra1["own"]; merged {
		t.Fatalf("input-owned extra members must not be hoisted into event.extra: %#v", extra1)
	}
	nested, ok := extra1["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested evidence object must survive: %#v", extra1)
	}
	if got := nested["action"]; got != "  raw action  " {
		t.Fatalf("nested action is evidence and must stay untrimmed, got %#v", got)
	}
	if got := nested["timestamp"]; got != "not-a-time" {
		t.Fatalf("nested timestamp is evidence and must not be validated or converted, got %#v", got)
	}
	for key, want := range map[string]json.Number{
		"big":  "9007199254740993",
		"dec":  "1.0000000000000000001",
		"huge": "1e400",
	} {
		if got, ok := nested[key].(json.Number); !ok || got != want {
			t.Fatalf("nested %s must be JSON number %s, got %#v", key, want, nested[key])
		}
	}
	arr, ok := extra1["arr"].([]any)
	if !ok || len(arr) != 8 {
		t.Fatalf("evidence array must keep all eight elements in order, got %#v", extra1["arr"])
	}
	wantArr := []struct {
		check func(any) bool
		label string
	}{
		{isNumber("9007199254740993"), "number 9007199254740993"},
		{isNumber("1.0000000000000000001"), "number 1.0000000000000000001"},
		{isNumber("1e400"), "number 1e400"},
		{isString("9007199254740993"), `string "9007199254740993"`},
		{isString("1e400"), `string "1e400"`},
		{isBool(true), "boolean true"},
		{isBool(false), "boolean false"},
		{isNull(), "null"},
	}
	for i, w := range wantArr {
		if !w.check(arr[i]) {
			t.Fatalf("array element %d must be %s, got %#v", i, w.label, arr[i])
		}
	}

	// Second hit: its own evidence only — nothing from the first hit or the
	// dropped log may bleed across records.
	second := eventOf(t, records[2])
	if second["action"] != "keep-two" || second["source_ip"] != "192.0.2.11" {
		t.Fatalf("second hit standard fields mismatch: %#v", second)
	}
	requireContains(t, lines[2], `"extra":{"marker":"second","nums":[3,1e400]}`)
	for _, foreign := range []string{"keep-one", "raw action", `"own"`, "must-not-leak"} {
		if strings.Contains(lines[2], foreign) {
			t.Fatalf("second hit must not carry another record's evidence %q:\n%s", foreign, lines[2])
		}
	}
	if strings.Contains(lines[0], "keep-two") || strings.Contains(lines[0], `"marker"`) {
		t.Fatalf("first hit must not carry the second hit's evidence:\n%s", lines[0])
	}
}

// The same batch without the filter must produce, for every record the
// filtered run kept, byte-identical output: filtering selects records, it
// never rewrites them. The unfiltered run additionally emits the
// out-of-network valid log (with its evidence intact), which is exactly the
// record the filter removed.
func TestNormalizeCLISourceCIDRKeptRecordsMatchUnfilteredRun(t *testing.T) {
	input := evidenceFilterInput()

	filtered := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.2.0/24")
	plain := runNormalizeCLI(t, strings.NewReader(input))

	if filtered.exitCode != 1 || plain.exitCode != 1 {
		t.Fatalf("both runs must exit 1 on the invalid line, got %d and %d", filtered.exitCode, plain.exitCode)
	}
	if filtered.stderr != "" || plain.stderr != "" {
		t.Fatalf("both runs must keep stderr empty, got %q and %q", filtered.stderr, plain.stderr)
	}

	filteredLines := rawResultLines(t, filtered.stdout)
	plainLines := rawResultLines(t, plain.stdout)
	if len(filteredLines) != 3 || len(plainLines) != 4 {
		t.Fatalf("expected 3 filtered and 4 unfiltered records, got %d and %d",
			len(filteredLines), len(plainLines))
	}

	// Filtered records 0..2 are unfiltered records 0, 2, 3 (physical lines
	// 1, 3, 4); unfiltered record 1 is the dropped out-of-network success.
	for i, plainIndex := range []int{0, 2, 3} {
		if filteredLines[i] != plainLines[plainIndex] {
			t.Fatalf("kept record must be byte-identical to the unfiltered run.\nfiltered:   %s\nunfiltered: %s",
				filteredLines[i], plainLines[plainIndex])
		}
	}

	dropped := decodeResultWithNumbers(t, plainLines[1])
	if dropped["line"] != json.Number("2") || dropped["ok"] != true {
		t.Fatalf("the record the filter removed must be the line-2 success: %#v", dropped)
	}
	droppedExtra, ok := eventOf(t, dropped)["extra"].(map[string]any)
	if !ok || droppedExtra["secret"] != "must-not-leak" {
		t.Fatalf("unfiltered run must carry the dropped log's evidence: %#v", dropped)
	}
}

// When every legal log falls outside the selected network, the run still
// ends normally: no records, no failures, exit 0, and both streams empty —
// however rich the filtered-out evidence was.
func TestNormalizeCLISourceCIDREvidenceAllFilteredExitsZero(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.1","big":9007199254740993}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"b","source_ip":"2001:db8::1","huge":1e400}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"c","extra":{"own":1.0000000000000000001}}`,
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.2.0/24")

	if result.exitCode != 0 {
		t.Fatalf("all-valid-but-filtered input must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stdout != "" || result.stderr != "" {
		t.Fatalf("no surviving records means empty stdout/stderr, got %q / %q", result.stdout, result.stderr)
	}
}
