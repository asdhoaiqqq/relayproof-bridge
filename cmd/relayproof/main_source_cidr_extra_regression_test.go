package main

// CLI-level regression coverage for extension-evidence preservation under the
// normalize --source-cidr filter. The filter decides only which successful
// events are emitted; an emitted event must carry the source log's evidence
// exactly as an unfiltered run would: unknown top-level fields each become a
// member of event.extra, an input-owned "extra" stays nested as
// event.extra.extra, same-named fields inside nested objects are evidence
// (never trimmed or mapped onto standard values), arrays keep element order
// and types, duplicate members of an inner object keep source order, and the
// edge numbers 9007199254740993, 1.0000000000000000001 and 1e400 keep their
// literal JSON-number spelling while quoted spellings stay strings. Structural
// whitespace is compacted and extra's top-level members are sorted, exactly
// as without a filter. Dropped out-of-network logs leave no trace: they are
// not emitted, not counted as failures, and their fields never leak into a
// surviving record. A time-invalid line fails with its physical line number
// and reason even when its source lies outside the selected network.

import (
	"encoding/json"
	"strings"
	"testing"
)

// Evidence-rich in-network log line used by several tests: standard fields
// arrive through aliases (and a mapped ::ffff: source), while the unknown
// fields carry a nested object with same-named "standard" keys, a duplicate
// inner member, an order-sensitive array of mixed types, the three edge
// numbers, an input-owned extra, and out-of-order siblings. Structural
// whitespace inside the nested object and array is deliberate: the output
// must compact it without touching string contents.
const cidrEvidenceHit1 = `{"time":"2026-01-02T08:04:05+08:00","event_type":"  login  ","src_ip":"::ffff:192.0.2.7",` +
	`"zeta":"z","nested":{ "action" : "  raw action  " , "timestamp" : "not-a-time" , "source_ip" : "10.9.9.9",` +
	`"big":9007199254740993,"dec":1.0000000000000000001,"huge":1e400,"dup":"first","dup":"second",` +
	`"arr":[ 9007199254740993 , "9007199254740993" , 1.0000000000000000001 , 1e400 , "1e400" , true , false , null ]},` +
	`"extra":{"own":9007199254740993,"label":"kept"},"alpha":"a"}`

// The exact extra object the filtered run must emit for cidrEvidenceHit1:
// top-level members sorted, structural whitespace compacted, every nested
// byte — including both "dup" members in source order and the untrimmed
// strings — verbatim.
const cidrEvidenceHit1Extra = `"extra":{"alpha":"a","extra":{"own":9007199254740993,"label":"kept"},` +
	`"nested":{"action":"  raw action  ","timestamp":"not-a-time","source_ip":"10.9.9.9",` +
	`"big":9007199254740993,"dec":1.0000000000000000001,"huge":1e400,"dup":"first","dup":"second",` +
	`"arr":[9007199254740993,"9007199254740993",1.0000000000000000001,1e400,"1e400",true,false,null]},"zeta":"z"}`

// A second, simpler in-network hit carrying the edge numbers at the top of
// extra next to a string-written number.
const cidrEvidenceHit2 = `{"timestamp":"2026-01-02T00:00:00Z","action":"hit2","source_ip":"192.0.2.8",` +
	`"big":9007199254740993,"dec":1.0000000000000000001,"huge":1e400,"asString":"1.0000000000000000001"}`

// An all-valid filtered run: both in-network hits survive in input order with
// their physical line numbers, the standard fields normalize exactly as
// without a filter, and every piece of extension evidence — nested object
// with same-named keys, duplicate inner members, ordered mixed-type array,
// input-owned extra, edge numbers and string-written numbers — arrives
// byte-for-byte. Exit 0 with an empty stderr.
func TestNormalizeCLISourceCIDRKeepsExtraEvidence(t *testing.T) {
	input := cidrEvidenceHit1 + "\n" + cidrEvidenceHit2 + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.2.0/24")

	if result.exitCode != 0 {
		t.Fatalf("an all-valid filtered batch must exit 0, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("a clean filtered run must not write to stderr, got %q", result.stderr)
	}

	lines := rawResultLines(t, result.stdout)
	if len(lines) != 2 {
		t.Fatalf("both in-network hits must survive, got %d records: %q", len(lines), result.stdout)
	}

	// Standard-field normalization is unaffected by the filter or the
	// evidence: aliases map, the timestamp converts to UTC, the action is
	// trimmed, and the mapped source prints in dotted IPv4 form.
	records := decodeStdoutResultsWithNumbers(t, result.stdout)
	first := eventOf(t, records[0])
	if records[0]["line"] != json.Number("1") || records[0]["ok"] != true {
		t.Fatalf("first hit must be physical line 1 ok:true: %#v", records[0])
	}
	if first["timestamp"] != "2026-01-02T00:04:05Z" || first["action"] != "login" || first["source_ip"] != "192.0.2.7" {
		t.Fatalf("standard fields must normalize as without a filter: %#v", first)
	}
	second := eventOf(t, records[1])
	if records[1]["line"] != json.Number("2") || records[1]["ok"] != true {
		t.Fatalf("second hit must be physical line 2 ok:true: %#v", records[1])
	}
	if second["timestamp"] != "2026-01-02T00:00:00Z" || second["action"] != "hit2" || second["source_ip"] != "192.0.2.8" {
		t.Fatalf("second hit standard fields mismatch: %#v", second)
	}

	// Raw textual pinning of the whole extra object: sorted top-level
	// members, compacted structural whitespace, verbatim nested content.
	requireContains(t, lines[0], cidrEvidenceHit1Extra)
	requireContains(t, lines[1],
		`"extra":{"asString":"1.0000000000000000001","big":9007199254740993,`+
			`"dec":1.0000000000000000001,"huge":1e400}`)

	// The corruptions a lossy pipeline would introduce must never appear.
	for _, banned := range []string{
		"9007199254740992", // float64's rounded neighbor
		"1e+400",           // Go float64 notation
		"Infinity", "Inf",
	} {
		if strings.Contains(result.stdout, banned) {
			t.Fatalf("filtered output must not rewrite evidence numbers into %q:\n%s", banned, result.stdout)
		}
	}

	// Type-level pinning: the nested same-named fields are evidence strings,
	// not mapped standard values; the input-owned extra nests under the
	// output extra; edge numbers decode as json.Number with exact spellings.
	extra1 := first["extra"].(map[string]any)
	nested, ok := extra1["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested evidence object must survive the filter: %#v", extra1)
	}
	if nested["action"] != "  raw action  " {
		t.Fatalf("a nested action is evidence and must stay untrimmed, got %#v", nested["action"])
	}
	if nested["timestamp"] != "not-a-time" {
		t.Fatalf("a nested timestamp is evidence and must not be parsed, got %#v", nested["timestamp"])
	}
	if nested["source_ip"] != "10.9.9.9" {
		t.Fatalf("a nested source_ip is evidence and must not be normalized, got %#v", nested["source_ip"])
	}
	for key, want := range map[string]string{
		"big":  "9007199254740993",
		"dec":  "1.0000000000000000001",
		"huge": "1e400",
	} {
		if got, ok := nested[key].(json.Number); !ok || string(got) != want {
			t.Fatalf("nested %s must be JSON number %s, got %#v", key, want, nested[key])
		}
	}
	arr, ok := nested["arr"].([]any)
	if !ok || len(arr) != 8 {
		t.Fatalf("the nested array must keep all eight elements in order, got %#v", nested["arr"])
	}
	wantArr := []struct {
		check func(any) bool
		label string
	}{
		{isNumber("9007199254740993"), "number 9007199254740993"},
		{isString("9007199254740993"), "string \"9007199254740993\""},
		{isNumber("1.0000000000000000001"), "number 1.0000000000000000001"},
		{isNumber("1e400"), "number 1e400"},
		{isString("1e400"), "string \"1e400\""},
		{isBool(true), "boolean true"},
		{isBool(false), "boolean false"},
		{isNull(), "null"},
	}
	for i, w := range wantArr {
		if !w.check(arr[i]) {
			t.Fatalf("array element %d must be %s, got %#v", i, w.label, arr[i])
		}
	}

	ownExtra, ok := extra1["extra"].(map[string]any)
	if !ok {
		t.Fatalf("the input's own extra must nest under the output extra, not merge: %#v", extra1)
	}
	if got := ownExtra["own"]; got != json.Number("9007199254740993") {
		t.Fatalf("number inside the input-owned extra must keep type and spelling, got %#v", got)
	}
	if _, hoisted := extra1["own"]; hoisted {
		t.Fatalf("input-owned extra members must not be hoisted next to their siblings: %#v", extra1)
	}

	extra2 := second["extra"].(map[string]any)
	if got, ok := extra2["asString"].(string); !ok || got != "1.0000000000000000001" {
		t.Fatalf("a string-written number must remain a distinct string, got %#v", extra2["asString"])
	}
	if got, ok := extra2["huge"].(json.Number); !ok || string(got) != "1e400" {
		t.Fatalf("top-level extra huge must be JSON number 1e400, got %#v", extra2["huge"])
	}
}

// A mixed batch: in-network hits interleaved with an out-of-network valid
// log, a blank line, and a time-invalid log whose source lies outside the
// selected network. The hits come out in input order with their physical
// line numbers and their own evidence — nothing from a dropped or failed
// line leaks into them — the out-of-network valid log produces no record
// and no failure, and the invalid line still fails with its line number, a
// timestamp reason and no event. Exit 1, stderr empty.
func TestNormalizeCLISourceCIDRMixedBatchEvidenceIsolation(t *testing.T) {
	input := strings.Join([]string{
		cidrEvidenceHit1, // line 1: kept
		`{"timestamp":"2026-01-02T00:00:01Z","action":"outside","source_ip":"198.51.100.9","secret":"must-not-leak"}`, // line 2: dropped, no failure
		`{"timestamp":"not-a-time","action":"broken","source_ip":"198.51.100.9"}`,                                     // line 3: failure despite out-of-network source
		"",               // line 4: blank, only consumes a line number
		cidrEvidenceHit2, // line 5: kept
	}, "\n") + "\n"

	result := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.2.0/24")

	if result.exitCode != 1 {
		t.Fatalf("the time-invalid line must force exit 1 even though its source is out-of-network, got %d", result.exitCode)
	}
	if result.stderr != "" {
		t.Fatalf("per-line reasons belong in stdout records, not stderr, got %q", result.stderr)
	}

	lines := rawResultLines(t, result.stdout)
	if len(lines) != 3 {
		t.Fatalf("expected 2 kept hits + 1 failure record, got %d: %q", len(lines), result.stdout)
	}
	records := decodeStdoutResultsWithNumbers(t, result.stdout)

	// Input order and physical line numbers survive filtering and failure.
	if records[0]["line"] != json.Number("1") || records[0]["ok"] != true {
		t.Fatalf("record 0 must be the line-1 hit: %#v", records[0])
	}
	if records[1]["line"] != json.Number("3") || records[1]["ok"] != false {
		t.Fatalf("record 1 must be the line-3 failure: %#v", records[1])
	}
	if records[2]["line"] != json.Number("5") || records[2]["ok"] != true {
		t.Fatalf("record 2 must be the line-5 hit: %#v", records[2])
	}

	// The failure record: original line number, explicit timestamp reason,
	// no event — the out-of-network source does not hide it.
	failure := records[1]
	if _, exists := failure["event"]; exists {
		t.Fatalf("the time-invalid line must carry no event: %#v", failure)
	}
	msg, _ := failure["error"].(string)
	if !strings.Contains(msg, `"timestamp"`) || !strings.Contains(msg, "invalid RFC3339 timestamp") {
		t.Fatalf("the failure must name the timestamp problem, got %q", msg)
	}

	// Each kept hit carries exactly its own evidence: the dropped line's
	// fields and the failed line's fields appear nowhere, and the second
	// hit's extra holds only its own four members.
	for _, leaked := range []string{"must-not-leak", "secret", "outside", "broken"} {
		if strings.Contains(result.stdout, leaked) {
			t.Fatalf("dropped/failed line content %q must not appear in the output:\n%s", leaked, result.stdout)
		}
	}
	requireContains(t, lines[0], cidrEvidenceHit1Extra)
	extra2 := eventOf(t, records[2])["extra"].(map[string]any)
	if len(extra2) != 4 {
		t.Fatalf("the line-5 hit must carry only its own extra members, not line 1's: %#v", extra2)
	}
	for _, foreign := range []string{"nested", "alpha", "zeta", "extra"} {
		if _, leaked := extra2[foreign]; leaked {
			t.Fatalf("line 1's extra member %q must not leak into line 5's event: %#v", foreign, extra2)
		}
	}
	if got := extra2["big"]; got != json.Number("9007199254740993") {
		t.Fatalf("line 5's own evidence must survive the mixed batch, got %#v", got)
	}
}

// Filtering is selection only: the same hit logs produce byte-identical
// result records whether or not --source-cidr is given, and a run in which
// every valid log falls outside the network is a clean empty run (exit 0,
// empty stdout and stderr).
func TestNormalizeCLISourceCIDRFilteredOutputMatchesUnfiltered(t *testing.T) {
	input := cidrEvidenceHit1 + "\n" + cidrEvidenceHit2 + "\n"

	filtered := runNormalizeCLIArgs(t, strings.NewReader(input), "--source-cidr", "192.0.2.0/24")
	unfiltered := runNormalizeCLI(t, strings.NewReader(input))

	if filtered.exitCode != 0 || unfiltered.exitCode != 0 {
		t.Fatalf("both runs of an all-valid batch must exit 0, got %d and %d", filtered.exitCode, unfiltered.exitCode)
	}
	if filtered.stdout != unfiltered.stdout {
		t.Fatalf("kept records must be identical with and without the filter:\nfiltered:   %s\nunfiltered: %s",
			filtered.stdout, unfiltered.stdout)
	}

	droppedOnly := `{"timestamp":"2026-01-02T00:00:01Z","action":"outside","source_ip":"198.51.100.9","big":9007199254740993}` + "\n"
	allDropped := runNormalizeCLIArgs(t, strings.NewReader(droppedOnly), "--source-cidr", "192.0.2.0/24")
	if allDropped.exitCode != 0 {
		t.Fatalf("an all-valid, fully filtered run must exit 0, got %d (stderr: %q)", allDropped.exitCode, allDropped.stderr)
	}
	if allDropped.stdout != "" || allDropped.stderr != "" {
		t.Fatalf("no surviving records means empty stdout/stderr, got %q / %q", allDropped.stdout, allDropped.stderr)
	}
}
