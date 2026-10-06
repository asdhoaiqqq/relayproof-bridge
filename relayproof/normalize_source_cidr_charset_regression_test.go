package relayproof

// Regression coverage for character integrity under the source-network
// filter. The filter decides only which *successful* events are emitted; it
// must never silence a character-corrupted log. With --source-cidr set to
// 192.0.2.0/24 and a line whose source_ip is 198.51.100.9 (or whose source
// address is absent), corruption in an unknown top-level string, or in a
// string nested inside that unknown field's object/array, still yields one
// failure record carrying the original physical line number, ok:false and an
// error, with no event. The two defect classes stay distinguishable — raw
// bytes that are not valid UTF-8 vs. an unpaired \uXXXX surrogate escape —
// and corrupted bytes are never repaired into legal characters and processed
// further.
//
// The filter must not move the existing precedence ladder: on one line that
// has both an unpaired escape earlier in the text and invalid UTF-8 bytes
// later, the byte-encoding problem is still reported; with legal bytes and an
// unpaired escape in an unknown field plus an invalid timestamp, the escape
// problem wins. The category and reason for the same corrupted line must be
// identical to what an unfiltered run reports.
//
// In a mixed stream the failed rows are retained, a valid out-of-network
// event is neither output nor counted as a failure, blank lines only consume
// a physical line number, and later hits keep their input order and physical
// line numbers (no renumbering). A run ends normally with corrupted rows
// present still returns the failure count; the per-line reason lives only in
// the stdout failure record.
//
// On the legal-character boundary: a correctly paired surrogate escape and a
// uD800 that is ordinary text behind an escaped backslash must not be flagged
// as corruption; such a legal log is still admitted or dropped solely by its
// normalized source network, and an admitted event keeps the string's original
// meaning. Only legal-but-all-miss input leaves stdout empty with zero
// failures.

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// filteredCharsetFilter is the network every test in this file selects:
// 192.0.2.0/24, so 198.51.100.9 and an absent source both miss it.
func filteredCharsetFilter(t *testing.T) *SourceCIDRFilter {
	t.Helper()
	f, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatalf("test setup: ParseSourceCIDRFilter: %v", err)
	}
	return &f
}

// runCharsetFiltered drives one stream through the /24 filter and returns
// the raw emitted bytes plus the returned failure count.
func runCharsetFiltered(t *testing.T, input string) ([]byte, int) {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReaderFiltered(strings.NewReader(input), &out, filteredCharsetFilter(t))
	if err != nil {
		t.Fatalf("a bad log line is not a stream error under a filter, got %v", err)
	}
	return out.Bytes(), failures
}

// expectFilteredCharFailure feeds a single line (plus trailing newline)
// through the /24 filter, asserts it comes back as one failure — physical
// line N (default 1), ok:false, one error containing every marker, no event
// — and that the emitted record itself is valid UTF-8 with no unwritten
// replacement character. Returns the full result map and the raw output
// bytes for further inspection.
func expectFilteredCharFailure(t *testing.T, line string, markers ...string) (map[string]any, []byte) {
	t.Helper()
	out, failures := runCharsetFiltered(t, line+"\n")
	if failures != 1 {
		t.Fatalf("the corrupted line must count as one failure even with no successful hit, got %d", failures)
	}
	if !utf8.Valid(out) {
		t.Fatalf("output must be valid UTF-8 even for corrupted input: %q", out)
	}
	if bytes.Contains(out, []byte("�")) {
		t.Fatalf("corrupted input must not be repaired into replacement characters: %q", out)
	}
	results := decodeResults(t, out)
	if len(results) != 1 {
		t.Fatalf("a corrupted line must emit exactly one record even though it misses the network, got %#v", results)
	}
	r := results[0]
	if r["line"] != float64(1) || r["ok"] != false {
		t.Fatalf("corrupted line must fail as line 1 with ok:false: %#v", r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("corrupted line must not emit an event despite the filter: %#v", r)
	}
	if len(r) != 3 {
		t.Fatalf("a failure record carries exactly line, ok and one error, got %#v", r)
	}
	msg, _ := r["error"].(string)
	if msg == "" {
		t.Fatalf("corrupted line must explain itself: %#v", r)
	}
	if !utf8.ValidString(msg) {
		t.Fatalf("error message must be valid UTF-8, got %q", msg)
	}
	for _, marker := range markers {
		if !strings.Contains(msg, marker) {
			t.Fatalf("error %q must contain %q", msg, marker)
		}
	}
	return r, out
}

// invalidByte is a byte sequence that cannot be valid UTF-8: 0xC3 starts a
// two-byte sequence whose continuation must be 0x80-0xBF but 0x28 is '('.
const invalidByte = "\xc3\x28"

// expectUnfilteredReason runs the same single corrupted line without a
// filter and returns its error text, so a filtered run's reason can be pinned
// byte-identical to the unfiltered category and reason.
func expectUnfilteredReason(t *testing.T, line string) string {
	t.Helper()
	results := runNormalize(t, line+"\n")
	if len(results) != 1 || results[0]["ok"] != false {
		t.Fatalf("test setup: unfiltered run must fail the same line: %#v", results)
	}
	msg, _ := results[0]["error"].(string)
	if msg == "" {
		t.Fatalf("test setup: unfiltered failure must carry a reason: %#v", results[0])
	}
	return msg
}

// A corrupted log whose source is outside 192.0.2.0/24 (198.51.100.9) or
// absent must not be dropped the way a valid out-of-network event is: each
// corruption site — unknown top-level string, nested object string, nested
// array string — produces one ok:false record with a distinguishable reason
// and no event, even though no successful event in the batch hits.
func TestSourceCIDRFilterCorruptionOutsideNetworkStillFails(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		markers []string
	}{
		{
			name:    "invalid UTF-8 in unknown top-level string, outside source",
			line:    `{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","note":"` + invalidByte + `"}`,
			markers: []string{"UTF-8"},
		},
		{
			name: "invalid UTF-8 in a nested object string, outside source",
			line: `{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9",` +
				`"payload":{"k":"` + invalidByte + `"}}`,
			markers: []string{"UTF-8"},
		},
		{
			name: "invalid UTF-8 in a nested array string, outside source",
			line: `{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9",` +
				`"payload":["ok","` + invalidByte + `"]}`,
			markers: []string{"UTF-8"},
		},
		{
			name:    "invalid UTF-8 with no source address",
			line:    `{"timestamp":"2026-01-02T00:00:00Z","action":"a","note":"` + invalidByte + `"}`,
			markers: []string{"UTF-8"},
		},
		{
			name:    "unpaired high surrogate in unknown string, outside source",
			line:    `{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","note":"\uD800"}`,
			markers: []string{"unpaired", "surrogate"},
		},
		{
			name: "unpaired low surrogate in a nested object string, outside source",
			line: `{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9",` +
				`"payload":{"k":"\uDC00"}}`,
			markers: []string{"unpaired", "surrogate"},
		},
		{
			name: "unpaired high surrogate in a nested array string, outside source",
			line: `{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9",` +
				`"payload":["ok","\uDBFF"]}`,
			markers: []string{"unpaired", "surrogate"},
		},
		{
			name:    "unpaired surrogate with no source address",
			line:    `{"timestamp":"2026-01-02T00:00:00Z","action":"a","note":"\uD800"}`,
			markers: []string{"unpaired", "surrogate"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := expectFilteredCharFailure(t, tc.line, tc.markers...)
			msg := r["error"].(string)
			// The two defect classes must never be confused for each other.
			if bytesMarkers := tc.markers[0] == "UTF-8"; bytesMarkers {
				if strings.Contains(msg, "surrogate") || strings.Contains(msg, "escape") {
					t.Fatalf("UTF-8 corruption must not be reported as an escape problem, got %q", msg)
				}
			} else {
				if strings.Contains(msg, "UTF-8") {
					t.Fatalf("unpaired escape must not be reported as UTF-8 corruption, got %q", msg)
				}
			}
			// Same corrupted line, same category and reason as without the
			// filter — filtering changes selection, not validation.
			if got, want := msg, expectUnfilteredReason(t, tc.line); got != want {
				t.Fatalf("filtered reason %q must equal unfiltered reason %q", got, want)
			}
		})
	}
}

// Filtering must not move the precedence ladder:
//
//   - One line carrying both an unpaired escape earlier and invalid bytes
//     later still reports the byte-encoding problem (UTF-8 outranks escapes
//     regardless of textual position).
//   - With legal raw bytes, an unpaired escape in an unknown field plus an
//     invalid timestamp still reports the escape problem (escapes outrank
//     timestamp validation).
//
// Each reason is byte-identical to the unfiltered run's reason.
func TestSourceCIDRFilterCharsetPrecedenceUnchanged(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		contains []string
		excludes []string
	}{
		{
			name:     "escape earlier in text, invalid bytes later",
			line:     `{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800` + invalidByte + `","source_ip":"198.51.100.9"}`,
			contains: []string{"UTF-8"},
			excludes: []string{"surrogate", "escape", "timestamp"},
		},
		{
			name:     "invalid bytes earlier, escape later",
			line:     `{"timestamp":"2026-01-02T00:00:00Z","action":"` + invalidByte + `\uD800","source_ip":"198.51.100.9"}`,
			contains: []string{"UTF-8"},
			excludes: []string{"surrogate", "escape", "timestamp"},
		},
		{
			name: "legal bytes, unpaired escape in unknown field with invalid timestamp",
			line: `{"timestamp":"not-a-time","action":"a","source_ip":"198.51.100.9",` +
				`"payload":{"k":"\uDC00"}}`,
			contains: []string{"unpaired", "surrogate"},
			excludes: []string{"UTF-8", "timestamp"},
		},
		{
			name: "legal bytes, unpaired high in nested array and invalid timestamp",
			line: `{"timestamp":"not-a-time","action":"a","source_ip":"198.51.100.9",` +
				`"payload":["ok","\uDBFF"]}`,
			contains: []string{"unpaired", "surrogate"},
			excludes: []string{"UTF-8", "timestamp"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := expectFilteredCharFailure(t, tc.line, tc.contains...)
			msg := r["error"].(string)
			for _, bad := range tc.excludes {
				if strings.Contains(msg, bad) {
					t.Fatalf("error %q must not contain %q", msg, bad)
				}
			}
			if got, want := msg, expectUnfilteredReason(t, tc.line); got != want {
				t.Fatalf("filtered reason %q must equal unfiltered reason %q", got, want)
			}
		})
	}
}

// A mixed stream under the /24 filter: corrupted rows are retained with
// their physical line numbers (invalid-UTF-8 and unpaired-escape variants,
// each outside the network or source-less), a valid out-of-network event is
// dropped silently, a blank line only advances the counter, and a later
// in-network hit keeps its physical line number and content. Failure count
// and the returned stream error (nil) are exactly what drives exit status 1.
func TestSourceCIDRFilterCharsetMixedStream(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"hit-first","source_ip":"192.0.2.7"}`,                        // line 1 admitted
		`{"timestamp":"2026-01-02T00:00:00Z","action":"outside-valid","source_ip":"198.51.100.9"}`,                 // line 2 dropped (valid, misses)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","note":"` + "\xc3\x28" + `"}`, // line 3 failure (invalid UTF-8)
		"", // line 4 blank
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","payload":["ok","\uD800"]}`, // line 5 failure (unpaired, nested array)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","note":"\uDC00"}`,                                      // line 6 failure (no source)
		`{"timestamp":"2026-01-02T00:00:00Z","action":"outside-valid-2","source_ip":"198.51.100.10"}`,            // line 7 dropped (valid, misses)
		`{"timestamp":"2026-01-02T00:00:02Z","action":"hit-last","source_ip":"192.0.2.8","keep":true}`,           // line 8 admitted
	}, "\n") + "\n"

	out, failures := runCharsetFiltered(t, input)
	if failures != 3 {
		t.Fatalf("exactly the three corrupted lines must count, got %d", failures)
	}
	if !utf8.Valid(out) {
		t.Fatalf("stdout must be valid UTF-8: %q", out)
	}
	results := decodeResults(t, out)
	// 2 admitted successes + 3 failures; dropped valid and blank lines add none.
	if len(results) != 5 {
		t.Fatalf("expected 2 hits + 3 failures = 5 records, got %d: %#v", len(results), results)
	}
	want := []struct {
		line    float64
		ok      bool
		markers string
		action  string
	}{
		{1, true, "", "hit-first"},
		{3, false, "UTF-8", ""},
		{5, false, "surrogate", ""},
		{6, false, "surrogate", ""},
		{8, true, "", "hit-last"},
	}
	for i, w := range want {
		got := results[i]
		if got["line"] != w.line || got["ok"] != w.ok {
			t.Fatalf("record %d mismatch: want line=%v ok=%v, got %#v", i, w.line, w.ok, got)
		}
		if !w.ok {
			if _, exists := got["event"]; exists {
				t.Fatalf("failed record %d must carry no event: %#v", i, got)
			}
			if len(got) != 3 {
				t.Fatalf("failed record %d carries exactly line/ok/error, got %#v", i, got)
			}
			msg, _ := got["error"].(string)
			if !strings.Contains(msg, w.markers) {
				t.Fatalf("record %d reason must contain %q, got %q", i, w.markers, msg)
			}
		} else {
			if eventOf(t, got)["action"] != w.action {
				t.Fatalf("record %d action mismatch: %#v", i, got)
			}
		}
	}
	// A valid out-of-network event and its fields leave no trace at all.
	for _, marker := range []string{"outside-valid", "198.51.100.9", "outside-valid-2"} {
		if bytes.Contains(out, []byte(marker)) {
			t.Fatalf("dropped valid out-of-network content %q must not appear: %q", marker, out)
		}
	}
}

// A batch of corrupted lines with no successful hit anywhere still ends
// normally (no stream error) and reports every corrupted line; the failure
// count is what would drive exit status 1.
func TestSourceCIDRFilterCharsetNoHitsStillDetected(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","note":"` + invalidByte + `"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","note":"\uD800"}`,
	}, "\n") + "\n"

	out, failures := runCharsetFiltered(t, input)
	if failures != 2 {
		t.Fatalf("both corrupted lines must be found even with zero successful hits, got %d", failures)
	}
	results := decodeResults(t, out)
	if len(results) != 2 {
		t.Fatalf("both corrupted lines must emit a record, got %#v", results)
	}
	for i, marker := range []string{"UTF-8", "surrogate"} {
		if results[i]["line"] != float64(i+1) || results[i]["ok"] != false {
			t.Fatalf("corrupted line %d must fail with its physical number: %#v", i+1, results[i])
		}
		if _, exists := results[i]["event"]; exists {
			t.Fatalf("corrupted line %d must not emit an event: %#v", i+1, results[i])
		}
		if msg, _ := results[i]["error"].(string); !strings.Contains(msg, marker) {
			t.Fatalf("line %d must report %s corruption, got %q", i+1, marker, msg)
		}
	}
}

// Legal-character boundary: a correctly paired surrogate escape and a uD800
// that is plain text behind an escaped backslash must not be flagged; such a
// legal log is admitted/dropped solely by its normalized source, and an
// admitted event keeps the string's original meaning.
func TestSourceCIDRFilterCharsetLegalLookalikesNotCorruption(t *testing.T) {
	// Two legal lines, both outside the network: one with a paired surrogate
	// escape, one with an escaped-backslash uD800. They are valid events, so
	// under the filter they are dropped silently — zero records, zero
	// failures — and must never be mistaken for corruption.
	outside := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"paired-outside","source_ip":"198.51.100.9","note":"` + escGrinning + `"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"plain-uD800-outside","source_ip":"198.51.100.9","note":"\\uD800"}`,
	}, "\n") + "\n"
	out, failures := runCharsetFiltered(t, outside)
	if failures != 0 {
		t.Fatalf("legal lookalikes must not count as failures, got %d", failures)
	}
	if len(out) != 0 {
		t.Fatalf("legal out-of-network lookalikes must be dropped like any valid miss, got %q", out)
	}

	// Same two legal lines, but admitted by source: they must succeed and
	// preserve meaning — paired escape decodes to the astral character, and
	// the escaped-backslash uD800 stays the literal text \uD800.
	inside := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"paired-hit","source_ip":"192.0.2.7","note":"` + escGrinning + `"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"plain-uD800-hit","source_ip":"192.0.2.7","note":"\\uD800"}`,
	}, "\n") + "\n"
	results, failures := runNormalizeFiltered(t, inside, filteredCharsetFilter(t))
	if failures != 0 || len(results) != 2 {
		t.Fatalf("legal lookalikes inside the network must succeed: %#v failures=%d", results, failures)
	}
	for i, w := range []struct {
		line   float64
		action string
		note   string
	}{
		{1, "paired-hit", "😀"},
		{2, "plain-uD800-hit", `\uD800`},
	} {
		got := results[i]
		if got["line"] != w.line || got["ok"] != true {
			t.Fatalf("record %d must be line %v ok:true: %#v", i, w.line, got)
		}
		event := eventOf(t, got)
		if event["action"] != w.action {
			t.Fatalf("record %d action mismatch: %#v", i, event)
		}
		if note := extraOf(t, got)["note"]; note != w.note {
			t.Fatalf("record %d note must keep its original meaning, got %q want %q", i, note, w.note)
		}
	}
}

// Only-legal-but-all-miss input leaves stdout empty with zero failures and no
// stream error — a clean exit-0 run, distinct from a corrupted batch which
// would emit failure records (and drive exit 1).
func TestSourceCIDRFilterCharsetAllLegalMissesCleanEmpty(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"paired-miss","source_ip":"198.51.100.9","note":"` + escGrinning + `"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"plain-miss","source_ip":"198.51.100.9","note":"\\uD800"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"plain","source_ip":"10.0.0.1"}`,
	}, "\n") + "\n"
	out, failures := runCharsetFiltered(t, input)
	if failures != 0 {
		t.Fatalf("an all-legal all-miss batch must have zero failures, got %d", failures)
	}
	if len(out) != 0 {
		t.Fatalf("every valid log missed the network, so no record may be emitted, got %q", out)
	}
}
