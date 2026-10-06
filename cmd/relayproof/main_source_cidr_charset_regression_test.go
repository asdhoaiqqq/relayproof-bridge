package main

// CLI-level regression coverage for character corruption under the
// normalize --source-cidr filter. The filter may only omit successful
// out-of-network events; it must never let a corrupted log vanish. With
// 192.0.2.0/24 selected, a line sourced from 198.51.100.9 — or carrying no
// source address at all — still fails when an unknown field's string (or a
// string nested in its objects and arrays) holds invalid UTF-8 bytes or an
// unpaired \uXXXX surrogate escape: one ok:false record with the original
// physical line number and a single error, no event. The two corruption
// classes stay distinguishable, precedence between competing problems is
// exactly the unfiltered run's, failure records sit among dropped valid
// lines, blank lines and later hits without renumbering, the process exits
// 1 with stderr empty, and legal lookalikes (paired escapes, escaped
// backslash before uD800) are never flagged.

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// A mixed stream under --source-cidr 192.0.2.0/24: corrupted out-of-network
// and source-less logs interleaved with a valid out-of-network log, a blank
// line and in-network hits. The corrupted lines keep their failure records
// with physical line numbers and their own error class, the valid
// out-of-network log produces no record and no failure, the blank line only
// consumes a line number, and the hits come out in input order. Exit status
// is 1, stderr stays empty, and the per-line reasons live only in the
// stdout records.
func TestNormalizeCLISourceCIDRCorruptionStillReported(t *testing.T) {
	input := []byte(`{"timestamp":"2026-01-02T00:00:00Z","action":"hit-1","source_ip":"192.0.2.7"}` + "\n" +
		// Line 2: unpaired escape in an unknown field's nested array, source out of network.
		`{"timestamp":"2026-01-02T00:00:00Z","action":"x","source_ip":"198.51.100.9","meta":{"list":["ok","\uD800"]}}` + "\n" +
		// Line 3: valid but out of network — no record, no failure.
		`{"timestamp":"2026-01-02T00:00:00Z","action":"outside","source_ip":"198.51.100.1"}` + "\n" +
		"\n" +
		// Line 5: invalid UTF-8 byte in an unknown field, no source address.
		`{"timestamp":"2026-01-02T00:00:00Z","action":"y","note":"` + "\xff" + `"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"hit-2","source_ip":"192.0.2.8"}` + "\n")

	result := runNormalizeCLIArgs(t, bytes.NewReader(input), "--source-cidr", "192.0.2.0/24")

	if result.exitCode != 1 {
		t.Fatalf("corrupted lines must set exit status 1 even though their sources are filtered out, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in result records, not stderr, got %q", result.stderr)
	}
	if !utf8.ValidString(result.stdout) {
		t.Fatalf("stdout must be valid UTF-8 even for corrupted input, got %q", result.stdout)
	}
	if strings.Contains(result.stdout, "�") {
		t.Fatalf("corrupted input must not be rewritten with replacement characters: %q", result.stdout)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 4 {
		t.Fatalf("expected 2 hits + 2 failures; the valid out-of-network log and the blank line produce nothing, got %#v", results)
	}

	wantLines := []float64{1, 2, 5, 6}
	for i, line := range wantLines {
		if results[i]["line"] != line {
			t.Fatalf("record %d must carry physical line %v: %#v", i, line, results[i])
		}
	}

	if results[0]["ok"] != true || eventOf(t, results[0])["action"] != "hit-1" {
		t.Fatalf("the leading in-network hit must survive on line 1: %#v", results[0])
	}

	// Each failure record is exactly line, ok:false and one error — no event.
	failures := []struct {
		index    int
		contains []string
		excludes []string
	}{
		{1, []string{"unpaired", "surrogate"}, []string{"UTF-8"}},
		{2, []string{"UTF-8"}, []string{"surrogate"}},
	}
	for _, f := range failures {
		r := results[f.index]
		if r["ok"] != false {
			t.Fatalf("record %d must be a failure: %#v", f.index, r)
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
		for _, marker := range f.contains {
			if !strings.Contains(msg, marker) {
				t.Fatalf("record %d error %q must contain %q", f.index, msg, marker)
			}
		}
		for _, marker := range f.excludes {
			if strings.Contains(msg, marker) {
				t.Fatalf("record %d error %q must not contain %q", f.index, msg, marker)
			}
		}
	}

	if results[3]["ok"] != true || eventOf(t, results[3])["action"] != "hit-2" {
		t.Fatalf("the trailing in-network hit must survive on line 6: %#v", results[3])
	}
}

// The filter must not change which problem a corrupted line reports: an
// unpaired escape earlier in the text than an invalid UTF-8 byte still loses
// to the byte encoding problem, and an unpaired escape in an unknown field
// still outranks an invalid timestamp. Each line's error under the filter is
// byte-for-byte the error the unfiltered run reports.
func TestNormalizeCLISourceCIDRKeepsCharsetPrecedence(t *testing.T) {
	lines := []string{
		// Unpaired escape first, invalid byte later: position must not let
		// the escape win.
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","note":"\uD800` + "\xff" + `"}`,
		// Legal bytes, unpaired escape in an unknown field, invalid
		// timestamp: the escape is reported, not the time.
		`{"timestamp":"not-a-time","action":"a","source_ip":"198.51.100.9","note":"\uD800"}`,
	}
	markers := []struct {
		contains []string
		excludes []string
	}{
		{[]string{"UTF-8"}, []string{"surrogate", "escape"}},
		{[]string{"unpaired", "surrogate"}, []string{"UTF-8", "timestamp"}},
	}

	for i, line := range lines {
		filtered := runNormalizeCLIArgs(t, strings.NewReader(line+"\n"), "--source-cidr", "192.0.2.0/24")
		unfiltered := runNormalizeCLI(t, strings.NewReader(line+"\n"))

		if filtered.exitCode != 1 || unfiltered.exitCode != 1 {
			t.Fatalf("line %d must exit 1 with and without the filter, got %d and %d", i+1, filtered.exitCode, unfiltered.exitCode)
		}
		if filtered.stderr != "" || unfiltered.stderr != "" {
			t.Fatalf("line %d reasons belong in stdout records, got stderr %q / %q", i+1, filtered.stderr, unfiltered.stderr)
		}

		filteredResults := decodeStdoutResults(t, filtered.stdout)
		unfilteredResults := decodeStdoutResults(t, unfiltered.stdout)
		if len(filteredResults) != 1 || len(unfilteredResults) != 1 {
			t.Fatalf("line %d must produce exactly one failure record in both runs: %#v / %#v", i+1, filteredResults, unfilteredResults)
		}
		filteredMsg, _ := filteredResults[0]["error"].(string)
		unfilteredMsg, _ := unfilteredResults[0]["error"].(string)
		if filteredMsg == "" || filteredMsg != unfilteredMsg {
			t.Fatalf("line %d error must be identical with and without the filter:\nfiltered:   %q\nunfiltered: %q", i+1, filteredMsg, unfilteredMsg)
		}
		for _, marker := range markers[i].contains {
			if !strings.Contains(filteredMsg, marker) {
				t.Fatalf("line %d error %q must contain %q", i+1, filteredMsg, marker)
			}
		}
		for _, marker := range markers[i].excludes {
			if strings.Contains(filteredMsg, marker) {
				t.Fatalf("line %d error %q must not contain %q", i+1, filteredMsg, marker)
			}
		}
	}
}

// Legal lookalikes are never flagged as corruption, and the filter still
// decides purely by network: an in-network log carrying a correctly paired
// surrogate escape and the plain text "uD800" behind an escaped backslash is
// emitted with its string meanings intact, while an all-valid batch whose
// sources all miss the network ends with empty stdout and exit status 0.
func TestNormalizeCLISourceCIDRLegalLookalikesFilteredByNetworkOnly(t *testing.T) {
	inNetwork := `{"timestamp":"2026-01-02T00:00:00Z","action":"login","source_ip":"192.0.2.7",` +
		`"pair":"😀","note":"\\uD800"}`
	outOfNetwork := `{"timestamp":"2026-01-02T00:00:00Z","action":"other","source_ip":"198.51.100.9",` +
		`"pair":"😀","note":"\\uD800"}`

	hit := runNormalizeCLIArgs(t, strings.NewReader(inNetwork+"\n"), "--source-cidr", "192.0.2.0/24")
	if hit.exitCode != 0 || hit.stderr != "" {
		t.Fatalf("a legal in-network log must exit 0 with empty stderr, got %d / %q", hit.exitCode, hit.stderr)
	}
	results := decodeStdoutResults(t, hit.stdout)
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("legal lookalikes from inside the network must be admitted, got %#v", results)
	}
	extra, ok := eventOf(t, results[0])["extra"].(map[string]any)
	if !ok {
		t.Fatalf("the unknown fields must land in extra: %#v", results[0])
	}
	if extra["pair"] != "😀" {
		t.Fatalf("the paired escape must decode to the emoji, got %v", extra["pair"])
	}
	if extra["note"] != `\uD800` {
		t.Fatalf(`escaped-backslash text must stay the plain text \uD800, got %v`, extra["note"])
	}

	allFiltered := runNormalizeCLIArgs(t, strings.NewReader(outOfNetwork+"\n"+outOfNetwork+"\n"),
		"--source-cidr", "192.0.2.0/24")
	if allFiltered.exitCode != 0 {
		t.Fatalf("an all-valid batch that misses the network must exit 0, got %d (stderr: %q)", allFiltered.exitCode, allFiltered.stderr)
	}
	if allFiltered.stdout != "" || allFiltered.stderr != "" {
		t.Fatalf("no surviving records means empty stdout/stderr, got %q / %q", allFiltered.stdout, allFiltered.stderr)
	}
}
