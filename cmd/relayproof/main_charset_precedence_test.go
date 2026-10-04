package main

// CLI-level regression coverage for lines where character corruption meets
// other problems: the failure reason is decided by the normalizer's check
// order (invalid UTF-8 bytes, then unpaired surrogate escapes, then JSON and
// field rules), not by where the problems sit in the line. In a mixed stream
// each such failure is one ok:false record with its original physical line
// number and a single error, valid lines around them keep coming out in
// input order, stderr stays empty, and the process exits 1.

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizeCLICompetingProblemsKeepTheirCategory(t *testing.T) {
	input := []byte(`{"timestamp":"2026-01-02T00:00:00Z","action":"first"}` + "\n" +
		// Line 2: unpaired escape first, invalid byte later, bad timestamp too.
		`{"timestamp":"not-a-time","action":"\uD800` + "\xff" + `"}` + "\n" +
		"\n" +
		// Line 4: unpaired low surrogate plus a duplicate top-level key.
		`{"timestamp":"2026-01-02T00:00:00Z","action":"\uDC00","action":"b"}` + "\n" +
		// Line 5: characters clean, duplicate top-level key.
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","action":"a"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:02Z","action":"last"}` + "\n")

	result := runNormalizeCLI(t, bytes.NewReader(input))

	if result.exitCode != 1 {
		t.Fatalf("per-line failures must set exit status 1, got %d (stderr: %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line failures belong in result records, not stderr, got %q", result.stderr)
	}
	if !utf8.ValidString(result.stdout) {
		t.Fatalf("stdout must be valid UTF-8 even for corrupted input, got %q", result.stdout)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 5 {
		t.Fatalf("blank lines produce no output; expected 5 results, got %#v", results)
	}

	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("the leading valid log must succeed on line 1: %#v", results[0])
	}
	if eventOf(t, results[0])["action"] != "first" {
		t.Fatalf("line 1 event content mismatch: %#v", results[0])
	}

	// Each failure record is exactly line, ok:false and one error — no event.
	failures := []struct {
		index    int
		line     float64
		contains []string
		excludes []string
	}{
		{1, 2, []string{"UTF-8"}, []string{"surrogate", "timestamp"}},
		{2, 4, []string{"surrogate"}, []string{"UTF-8", "duplicate"}},
		{3, 5, []string{"duplicate", "action"}, []string{"UTF-8", "surrogate"}},
	}
	for _, f := range failures {
		r := results[f.index]
		if r["line"] != f.line || r["ok"] != false {
			t.Fatalf("result %d must fail on physical line %v: %#v", f.index, f.line, r)
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
				t.Fatalf("line %v error %q must contain %q", f.line, msg, marker)
			}
		}
		for _, marker := range f.excludes {
			if strings.Contains(msg, marker) {
				t.Fatalf("line %v error %q must not contain %q", f.line, msg, marker)
			}
		}
	}

	if results[4]["line"] != float64(6) || results[4]["ok"] != true {
		t.Fatalf("the trailing valid log must still succeed on line 6: %#v", results[4])
	}
	if eventOf(t, results[4])["action"] != "last" {
		t.Fatalf("line 6 event content must survive in order: %#v", results[4])
	}
}
