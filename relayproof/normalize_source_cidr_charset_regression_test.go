package relayproof

// Regression coverage for character corruption meeting the IPv4 source
// network filter. The filter may only drop successful events whose
// normalized source_ip falls outside the selected network; it must never
// make a corrupted log disappear:
//
//   - With 192.0.2.0/24 selected, a line whose source_ip is 198.51.100.9 —
//     or that carries no source address at all — still fails when an unknown
//     field's string, or a string inside its nested objects and arrays, is
//     corrupted. The failure record keeps the original physical line number,
//     ok:false and exactly one error, and carries no event.
//   - The two corruption classes stay distinguishable under the filter:
//     raw bytes that are not legal UTF-8 versus an unpaired \uXXXX surrogate
//     escape inside a JSON string. Corrupted content is never repaired into
//     legal characters and then processed.
//   - The filter does not change error precedence: a line holding both an
//     unpaired escape and invalid UTF-8 bytes reports the byte encoding
//     problem even when the escape sits earlier in the text; a line with
//     legal bytes, an unpaired escape in an unknown field and an invalid
//     timestamp reports the escape, not the time. Each corrupted line's
//     error is byte-for-byte the error the unfiltered run reports.
//   - In a mixed stream the failure records survive alongside dropped
//     out-of-network successes, blank lines and later in-network hits, with
//     physical line numbers intact.
//   - Legal lookalikes — a correctly paired surrogate escape and the plain
//     text "uD800" behind an escaped backslash — are never flagged; their
//     logs are still selected by the network alone, and an all-valid batch
//     that misses the network entirely produces no output and no failures.

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// runFilteredCharset feeds input through NormalizeReaderFiltered under the
// 192.0.2.0/24 network and returns the decoded records, the failure count
// and the raw output bytes, so tests can also inspect the output's own
// encoding.
func runFilteredCharset(t *testing.T, input string) ([]map[string]any, int, []byte) {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReaderFiltered(strings.NewReader(input), &out, mustSourceFilter(t, "192.0.2.0/24"))
	if err != nil {
		t.Fatalf("a bad log line is not a stream error, got %v", err)
	}
	results := decodeResults(t, out.Bytes())
	if got := countFailures(results); got != failures {
		t.Fatalf("NormalizeReaderFiltered returned %d failures but output shows %d", failures, got)
	}
	return results, failures, out.Bytes()
}

// expectFilteredCorruption asserts that one corrupted line whose source lies
// outside the selected network (or is absent) still produces exactly one
// failure record under the filter: physical line 1, ok:false, exactly the
// keys line/ok/error, no event, and an error containing every marker in
// contains and none in excludes. The emitted record must be valid UTF-8 and
// must not gain a U+FFFD the user did not write: corruption is reported,
// never repaired into legal characters.
func expectFilteredCorruption(t *testing.T, input string, contains, excludes []string) string {
	t.Helper()
	results, failures, raw := runFilteredCharset(t, input)
	if failures != 1 {
		t.Fatalf("the corrupted line must count as one failure even though no event survives the filter, got %d", failures)
	}
	if !utf8.Valid(raw) {
		t.Fatalf("output must be valid UTF-8 even for corrupted input: %q", raw)
	}
	if bytes.Contains(raw, []byte("�")) {
		t.Fatalf("corrupted input must not be rewritten with replacement characters: %q", raw)
	}
	if len(results) != 1 {
		t.Fatalf("a filtered-out corrupted line still emits its failure record, got %#v", results)
	}
	r := results[0]
	if r["line"] != float64(1) || r["ok"] != false {
		t.Fatalf("the corrupted line must fail as physical line 1: %#v", r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("a failed line must not carry an event: %#v", r)
	}
	if len(r) != 3 {
		t.Fatalf("a failure record carries exactly line, ok and one error, got %#v", r)
	}
	msg, _ := r["error"].(string)
	if msg == "" {
		t.Fatalf("a failed line must explain itself: %#v", r)
	}
	for _, marker := range contains {
		if !strings.Contains(msg, marker) {
			t.Fatalf("error %q must contain %q", msg, marker)
		}
	}
	for _, marker := range excludes {
		if strings.Contains(msg, marker) {
			t.Fatalf("error %q must not contain %q", msg, marker)
		}
	}
	return msg
}

// Corruption hiding in an unknown field — at the top level or inside its
// nested objects and arrays — must surface even though the line's
// out-of-network source (198.51.100.9 against 192.0.2.0/24) means no success
// event could ever be emitted, and even when the line has no source address
// at all. Each line fails with its own class of reason: invalid UTF-8 bytes
// versus an unpaired surrogate escape.
func TestSourceCIDRFilterCorruptionOutsideNetworkStillFails(t *testing.T) {
	const outside = `"source_ip":"198.51.100.9",`
	cases := []struct {
		name     string
		input    string
		contains []string
		excludes []string
	}{
		{"invalid UTF-8 in unknown field string",
			`{"timestamp":` + validTS + `,"action":"a",` + outside + `"note":"` + "\xff" + `"}`,
			[]string{"UTF-8"}, []string{"surrogate"}},
		{"invalid UTF-8 in nested object string",
			`{"timestamp":` + validTS + `,"action":"a",` + outside + `"meta":{"deep":"` + "\xc3\x28" + `"}}`,
			[]string{"UTF-8"}, []string{"surrogate"}},
		{"invalid UTF-8 in nested array string",
			`{"timestamp":` + validTS + `,"action":"a",` + outside + `"list":["ok","` + "\xed\xa0\x80" + `"]}`,
			[]string{"UTF-8"}, []string{"surrogate"}},
		{"unpaired high surrogate in unknown field string",
			`{"timestamp":` + validTS + `,"action":"a",` + outside + `"note":"\uD800"}`,
			[]string{"unpaired", "surrogate"}, []string{"UTF-8"}},
		{"unpaired low surrogate in nested object string",
			`{"timestamp":` + validTS + `,"action":"a",` + outside + `"meta":{"deep":"\uDC00"}}`,
			[]string{"unpaired", "surrogate"}, []string{"UTF-8"}},
		{"unpaired high surrogate in nested array string",
			`{"timestamp":` + validTS + `,"action":"a",` + outside + `"list":["\uDBFF"]}`,
			[]string{"unpaired", "surrogate"}, []string{"UTF-8"}},
		{"invalid UTF-8 with source address absent",
			`{"timestamp":` + validTS + `,"action":"a","note":"` + "\xff" + `"}`,
			[]string{"UTF-8"}, []string{"surrogate"}},
		{"unpaired surrogate with source address absent",
			`{"timestamp":` + validTS + `,"action":"a","note":"\uD800"}`,
			[]string{"unpaired", "surrogate"}, []string{"UTF-8"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectFilteredCorruption(t, tc.input, tc.contains, tc.excludes)
		})
	}
}

// The filter must not change which problem is reported when one line holds
// several: invalid UTF-8 bytes outrank an unpaired escape even when the
// escape sits earlier in the text, and an unpaired escape in an unknown
// field outranks an invalid timestamp. Each corrupted line's error category
// and reason are exactly what the unfiltered run reports for the same line.
func TestSourceCIDRFilterKeepsCharsetPrecedence(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		contains []string
		excludes []string
	}{
		{"unpaired escape before invalid byte",
			`{"timestamp":` + validTS + `,"action":"a","source_ip":"198.51.100.9","note":"\uD800` + "\xff" + `"}`,
			[]string{"UTF-8"}, []string{"surrogate", "escape"}},
		{"unpaired escape in unknown field with invalid timestamp",
			`{"timestamp":"not-a-time","action":"a","source_ip":"198.51.100.9","note":"\uD800"}`,
			[]string{"unpaired", "surrogate"}, []string{"UTF-8", "timestamp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filteredMsg := expectFilteredCorruption(t, tc.input, tc.contains, tc.excludes)

			unfiltered := runNormalize(t, tc.input)
			if len(unfiltered) != 1 || unfiltered[0]["ok"] != false {
				t.Fatalf("the same line must fail without the filter too: %#v", unfiltered)
			}
			if got := unfiltered[0]["error"]; got != filteredMsg {
				t.Fatalf("the filter must not change the failure reason:\nfiltered:   %v\nunfiltered: %v", filteredMsg, got)
			}
		})
	}
}

// A mixed stream: corrupted logs interleaved with a valid out-of-network
// log, a blank line and later in-network hits. The failure records are kept
// with their original physical line numbers, the valid out-of-network event
// is neither emitted nor counted as a failure, the blank line only consumes
// a line number, and the later hits come out in input order without
// renumbering.
func TestSourceCIDRFilterMixedStreamKeepsCorruptionFailures(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":` + validTS + `,"action":"hit-1","source_ip":"192.0.2.7"}`,                // line 1 admitted
		`{"timestamp":` + validTS + `,"action":"x","source_ip":"198.51.100.9","note":"\uD800"}`, // line 2 failure, out-of-network source
		`{"timestamp":` + validTS + `,"action":"outside","source_ip":"198.51.100.1"}`,           // line 3 valid, dropped silently
		"   ", // line 4 blank
		`{"timestamp":` + validTS + `,"action":"y","note":"` + "\xff" + `"}`, // line 5 failure, no source
		`{"timestamp":` + validTS + `,"action":"hit-2","source_ip":"192.0.2.8"}`, // line 6 admitted
	}, "\n") + "\n"

	results, failures, _ := runFilteredCharset(t, input)
	if failures != 2 {
		t.Fatalf("the two corrupted lines must count as failures, got %d", failures)
	}
	if len(results) != 4 {
		t.Fatalf("expected 2 admitted hits + 2 failures, got %#v", results)
	}

	wantLines := []float64{1, 2, 5, 6}
	wantOK := []bool{true, false, false, true}
	for i := range wantLines {
		if results[i]["line"] != wantLines[i] || results[i]["ok"] != wantOK[i] {
			t.Fatalf("record %d must be line %v ok:%v: %#v", i, wantLines[i], wantOK[i], results[i])
		}
	}

	if msg, _ := results[1]["error"].(string); !strings.Contains(msg, "surrogate") || strings.Contains(msg, "UTF-8") {
		t.Fatalf("line 2 must report the unpaired escape, got %q", msg)
	}
	if _, exists := results[1]["event"]; exists {
		t.Fatalf("the corrupted line 2 must carry no event: %#v", results[1])
	}
	if msg, _ := results[2]["error"].(string); !strings.Contains(msg, "UTF-8") || strings.Contains(msg, "surrogate") {
		t.Fatalf("line 5 must report the invalid bytes, got %q", msg)
	}
	if _, exists := results[2]["event"]; exists {
		t.Fatalf("the corrupted line 5 must carry no event: %#v", results[2])
	}

	if got := eventOf(t, results[0])["action"]; got != "hit-1" {
		t.Fatalf("the leading hit must survive in order, got %v", got)
	}
	if got := eventOf(t, results[3])["action"]; got != "hit-2" {
		t.Fatalf("the trailing hit must survive after the failures and the dropped line, got %v", got)
	}
}

// Legal lookalikes are never mistaken for corruption, and the filter still
// decides purely by network: an in-network log carrying a correctly paired
// surrogate escape and the plain text "uD800" behind an escaped backslash is
// emitted with its string meanings intact, while the same content from an
// out-of-network source is dropped without a failure. A batch of valid logs
// that all miss the network produces no output and no failures.
func TestSourceCIDRFilterLegalLookalikesFilteredByNetworkOnly(t *testing.T) {
	inNetwork := `{"timestamp":` + validTS + `,"action":"login","source_ip":"192.0.2.7",` +
		`"pair":"` + escGrinning + `","note":"\\uD800"}`

	results, failures, _ := runFilteredCharset(t, inNetwork+"\n")
	if failures != 0 || len(results) != 1 {
		t.Fatalf("legal lookalikes from inside the network must be admitted, got %#v failures=%d", results, failures)
	}
	extra := extraOf(t, results[0])
	if extra["pair"] != "😀" {
		t.Fatalf("the paired escape must decode to the emoji, got %v", extra["pair"])
	}
	if extra["note"] != `\uD800` {
		t.Fatalf(`escaped-backslash text must stay the plain text \uD800, got %v`, extra["note"])
	}

	outOfNetwork := strings.Replace(inNetwork, "192.0.2.7", "198.51.100.9", 1)
	results, failures, raw := runFilteredCharset(t, outOfNetwork+"\n")
	if failures != 0 || len(results) != 0 || len(raw) != 0 {
		t.Fatalf("the same legal content from outside the network must be dropped silently, got %#v failures=%d", results, failures)
	}

	allFiltered := outOfNetwork + "\n" +
		`{"timestamp":` + validTS + `,"action":"other","source_ip":"203.0.113.4","pair":"` + escGrinning + `"}` + "\n"
	results, failures, raw = runFilteredCharset(t, allFiltered)
	if failures != 0 || len(results) != 0 || len(raw) != 0 {
		t.Fatalf("an all-valid batch that misses the network must end with empty output and zero failures, got %#v failures=%d", results, failures)
	}
}
