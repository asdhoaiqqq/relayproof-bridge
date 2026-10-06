package main

// CLI-level regression coverage for character integrity under the normalize
// --source-cidr option, exercised against the real compiled binary. The
// option selects only successful events; it must never let a
// character-corrupted log vanish. With --source-cidr 192.0.2.0/24 and a log
// whose source_ip is 198.51.100.9 (outside) or absent, corruption sitting in
// an unknown field's string — or in a string nested inside that unknown
// field's own object or array — still produces one failure record with the
// original physical line number, ok:false and an error, and no event. The
// two defect classes stay distinguishable: raw bytes that are not legal
// UTF-8 vs. an unpaired \uXXXX surrogate escape; corrupted bytes are never
// replaced with legal characters and processed further.
//
// The option does not change the error precedence: a line with an unpaired
// escape earlier in the text plus invalid UTF-8 bytes later still reports the
// byte-encoding problem, while legal bytes with an unpaired escape in an
// unknown field plus an invalid timestamp still report the escape problem;
// the failure category and reason are byte-identical to a run without the
// option.
//
// Mixed input keeps every existing invariant: failure rows survive, a valid
// out-of-network event is neither written nor counted as a failure, blank
// lines only occupy a physical line number, and later in-network hits keep
// their input order and physical line numbers. The run ends normally yet
// exits 1 when corrupted rows exist, with an empty stderr — per-line reasons
// live only in the stdout failure records.
//
// Legal-character boundaries stay legal: a correctly paired surrogate escape
// and a uD800 that is ordinary text behind an escaped backslash are not
// corruption; those logs are admitted or dropped solely by source network,
// admitted strings keep their meaning, and only-legal, all-miss input exits 0
// with empty stdout.

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// escPair is JSON escape text for the grinning emoji 😀 as a surrogate pair.
const escPair = "\\uD83D\\uDE00"

// badUTF8Byte is a byte sequence that is not valid UTF-8 (0xC3 starts a
// two-byte sequence but 0x28 is not a continuation byte).
const badUTF8Byte = "\xc3\x28"

// charsetFilterArg is the network every test here selects: 192.0.2.0/24, so
// 198.51.100.9 and an absent source miss it.
const charsetFilterArg = "192.0.2.0/24"

// assertCharsetFailureRecord asserts one decoded result is a charset failure:
// the given physical line, ok:false, no event, exactly line/ok/error, and an
// error message containing marker but none of the opposite-class words.
func assertCharsetFailureRecord(t *testing.T, r map[string]any, line float64, marker string) string {
	t.Helper()
	if r["line"] != line || r["ok"] != false {
		t.Fatalf("line %v must be reported with ok:false: %#v", line, r)
	}
	if _, exists := r["event"]; exists {
		t.Fatalf("corrupted line %v must carry no event: %#v", line, r)
	}
	if len(r) != 3 {
		t.Fatalf("failure on line %v carries exactly line/ok/error, got %#v", line, r)
	}
	msg, _ := r["error"].(string)
	if msg == "" {
		t.Fatalf("corrupted line %v must explain itself: %#v", line, r)
	}
	if !utf8.ValidString(msg) {
		t.Fatalf("error on line %v must be valid UTF-8, got %q", line, msg)
	}
	if !strings.Contains(msg, marker) {
		t.Fatalf("error on line %v must contain %q, got %q", line, marker, msg)
	}
	switch marker {
	case "UTF-8":
		if strings.Contains(msg, "surrogate") || strings.Contains(msg, "escape") {
			t.Fatalf("UTF-8 corruption must not be reported as an escape problem (line %v): %q", line, msg)
		}
	default: // surrogate class
		if strings.Contains(msg, "UTF-8") {
			t.Fatalf("unpaired escape must not be reported as UTF-8 corruption (line %v): %q", line, msg)
		}
	}
	return msg
}

// Even when no successful event in the batch hits the network, every
// corrupted log is found: corruption in an unknown string, in a nested object
// string, or in a nested array string — with an outside source or no source
// at all — yields one failure record per line, exit 1, empty stderr, and
// valid-UTF-8 stdout that never echoes or repairs the bad bytes.
func TestNormalizeCLISourceCIDRCharsetCorruptionStillReported(t *testing.T) {
	input := []byte(strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","note":"` + badUTF8Byte + `"}`,           // 1: invalid UTF-8, unknown string, outside
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","payload":{"k":"` + badUTF8Byte + `"}}`,  // 2: invalid UTF-8, nested object
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","payload":["ok","` + badUTF8Byte + `"]}`, // 3: invalid UTF-8, nested array
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","note":"` + badUTF8Byte + `"}`,                                      // 4: invalid UTF-8, no source
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","note":"\uD800"}`,                        // 5: unpaired high, unknown string, outside
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","payload":{"k":"\uDC00"}}`,               // 6: unpaired low, nested object
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","payload":["ok","\uDBFF"]}`,              // 7: unpaired high, nested array
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","note":"\uD800"}`,                                                   // 8: unpaired high, no source
	}, "\n") + "\n")

	result := runNormalizeCLIArgs(t, bytes.NewReader(input), "--source-cidr", charsetFilterArg)

	if result.exitCode != 1 {
		t.Fatalf("corrupted lines must force exit 1 even with zero successful hits, got %d (stderr %q)",
			result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line reasons belong only in stdout records, got stderr %q", result.stderr)
	}
	if !utf8.ValidString(result.stdout) {
		t.Fatalf("stdout must be valid UTF-8 even for corrupted input: %q", result.stdout)
	}
	if strings.Contains(result.stdout, "�") {
		t.Fatalf("corrupted bytes must not be repaired into replacement characters: %q", result.stdout)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 8 {
		t.Fatalf("all eight corrupted lines must be reported despite missing the network, got %#v", results)
	}
	for i := 0; i < 4; i++ {
		assertCharsetFailureRecord(t, results[i], float64(i+1), "UTF-8")
	}
	for i := 4; i < 8; i++ {
		assertCharsetFailureRecord(t, results[i], float64(i+1), "surrogate")
	}
}

// The filter must not move the precedence ladder. One line has the unpaired
// escape earlier in the text and invalid UTF-8 bytes later: the
// byte-encoding problem is still what is reported. Another line has legal
// raw bytes, an unpaired escape nested in an unknown field, and an invalid
// timestamp: the escape problem is reported, not the time error.
func TestNormalizeCLISourceCIDRCharsetPrecedenceUnchanged(t *testing.T) {
	input := []byte(strings.Join([]string{
		// escape first, invalid byte later — position must not let the escape win
		`{"timestamp":"2026-01-02T00:00:00Z","action":"\uD800` + badUTF8Byte + `","source_ip":"198.51.100.9"}`,
		// legal bytes, unpaired escape deep in an unknown field, bad timestamp
		`{"timestamp":"not-a-time","action":"a","source_ip":"198.51.100.9","payload":{"k":"\uDC00"}}`,
	}, "\n") + "\n")

	result := runNormalizeCLIArgs(t, bytes.NewReader(input), "--source-cidr", charsetFilterArg)
	if result.exitCode != 1 || result.stderr != "" {
		t.Fatalf("want exit 1 and empty stderr, got exit=%d stderr=%q", result.exitCode, result.stderr)
	}
	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 2 {
		t.Fatalf("both corrupted lines must be reported, got %#v", results)
	}
	msg1 := assertCharsetFailureRecord(t, results[0], 1, "UTF-8")
	if strings.Contains(msg1, "timestamp") {
		t.Fatalf("byte encoding must outrank the timestamp problem too, got %q", msg1)
	}
	msg2 := assertCharsetFailureRecord(t, results[1], 2, "surrogate")
	if strings.Contains(msg2, "timestamp") {
		t.Fatalf("unpaired escape must outrank an invalid timestamp, got %q", msg2)
	}
}

// For the same corrupted-only input, a filtered run and an unfiltered run
// must emit byte-identical stdout (same category and same reason per line)
// and both exit 1 with empty stderr: filtering changes only which successes
// are selected, never how corruption is reported.
func TestNormalizeCLISourceCIDRCharsetReasonMatchesUnfiltered(t *testing.T) {
	input := []byte(strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","note":"` + badUTF8Byte + `"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","note":"\uD800"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","payload":["x","` + badUTF8Byte + `"]}`,
	}, "\n") + "\n")

	filtered := runNormalizeCLIArgs(t, bytes.NewReader(input), "--source-cidr", charsetFilterArg)
	unfiltered := runNormalizeCLI(t, bytes.NewReader(input))

	if filtered.exitCode != 1 || unfiltered.exitCode != 1 {
		t.Fatalf("both runs must exit 1, got %d and %d", filtered.exitCode, unfiltered.exitCode)
	}
	if filtered.stderr != "" || unfiltered.stderr != "" {
		t.Fatalf("neither run may write stderr: %q / %q", filtered.stderr, unfiltered.stderr)
	}
	if filtered.stdout != unfiltered.stdout {
		t.Fatalf("filtered and unfiltered failure records must be byte-identical\nfiltered:   %s\nunfiltered: %s",
			filtered.stdout, unfiltered.stdout)
	}
}

// The full mixed stream: in-network hits, a valid out-of-network event,
// corrupted rows (outside or source-less), a blank line, and a later
// in-network hit. Failures keep their physical line numbers and reasons; the
// valid out-of-network event and the blank line leave no record and no
// failure yet still consume a physical line number; later hits continue in
// input order without renumbering. Exit 1, stderr empty.
func TestNormalizeCLISourceCIDRCharsetMixedStream(t *testing.T) {
	input := []byte(strings.Join([]string{
		validCIDRSource("hit-first", "192.0.2.7"),                                                                   // 1: hit
		validCIDRSource("outside-valid", "198.51.100.9"),                                                            // 2: valid, dropped
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","note":"` + badUTF8Byte + `"}`, // 3: failure, UTF-8
		"", // 4: blank
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","source_ip":"198.51.100.9","payload":["ok","\uD800"]}`, // 5: failure, surrogate in array
		`{"timestamp":"2026-01-02T00:00:00Z","action":"a","note":"\uDC00"}`,                                      // 6: failure, surrogate, no source
		validCIDRSource("outside-valid-2", "198.51.100.10"),                                                      // 7: valid, dropped
		`{"timestamp":"2026-01-02T00:00:02Z","action":"hit-last","source_ip":"192.0.2.8","keep":true}`,           // 8: hit
	}, "\n") + "\n")

	result := runNormalizeCLIArgs(t, bytes.NewReader(input), "--source-cidr", charsetFilterArg)
	if result.exitCode != 1 {
		t.Fatalf("the three corrupted rows must force exit 1, got %d (stderr %q)", result.exitCode, result.stderr)
	}
	if result.stderr != "" {
		t.Fatalf("per-line reasons belong only in stdout records, got stderr %q", result.stderr)
	}
	if !utf8.ValidString(result.stdout) {
		t.Fatalf("stdout must be valid UTF-8: %q", result.stdout)
	}

	results := decodeStdoutResults(t, result.stdout)
	if len(results) != 5 {
		t.Fatalf("expected 2 hits + 3 failures = 5 records, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true || eventOf(t, results[0])["action"] != "hit-first" {
		t.Fatalf("record 0 must be the line-1 hit: %#v", results[0])
	}
	assertCharsetFailureRecord(t, results[1], 3, "UTF-8")
	assertCharsetFailureRecord(t, results[2], 5, "surrogate")
	assertCharsetFailureRecord(t, results[3], 6, "surrogate")
	if results[4]["line"] != float64(8) || results[4]["ok"] != true {
		t.Fatalf("the later hit must keep physical line 8 past dropped, blank and failed rows: %#v", results[4])
	}
	if eventOf(t, results[4])["action"] != "hit-last" {
		t.Fatalf("later hits must continue in input order: %#v", results[4])
	}
	// Valid out-of-network events leave no trace at all (not output, and
	// their fields never leak into a surviving record).
	for _, marker := range []string{"outside-valid", "198.51.100.9", "198.51.100.10"} {
		if strings.Contains(result.stdout, marker) {
			t.Fatalf("dropped valid out-of-network content %q must not appear in stdout: %q", marker, result.stdout)
		}
	}
}

// Legal lookalikes are not corruption, and selection is still decided solely
// by source network. A batch of legal out-of-network logs carrying a paired
// surrogate escape and an escaped-backslash uD800 exits 0 with completely
// empty stdout/stderr; the same logs from inside the network are admitted,
// succeed, and keep each string's original meaning.
func TestNormalizeCLISourceCIDRCharsetLegalLookalikes(t *testing.T) {
	outside := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"paired-miss","source_ip":"198.51.100.9","note":"` + escPair + `"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"plain-miss","source_ip":"198.51.100.9","note":"\\uD800"}`,
	}, "\n") + "\n"
	miss := runNormalizeCLIArgs(t, strings.NewReader(outside), "--source-cidr", charsetFilterArg)
	if miss.exitCode != 0 {
		t.Fatalf("legal lookalikes that all miss the network must exit 0, got %d (stderr %q)", miss.exitCode, miss.stderr)
	}
	if miss.stdout != "" || miss.stderr != "" {
		t.Fatalf("legal all-miss lookalikes must be dropped like any valid miss, got %q / %q", miss.stdout, miss.stderr)
	}

	inside := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"paired-hit","source_ip":"192.0.2.7","note":"` + escPair + `"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"plain-hit","source_ip":"192.0.2.7","note":"\\uD800"}`,
	}, "\n") + "\n"
	hit := runNormalizeCLIArgs(t, strings.NewReader(inside), "--source-cidr", charsetFilterArg)
	if hit.exitCode != 0 || hit.stderr != "" {
		t.Fatalf("legal lookalikes inside the network must succeed: exit=%d stderr=%q", hit.exitCode, hit.stderr)
	}
	results := decodeStdoutResults(t, hit.stdout)
	if len(results) != 2 {
		t.Fatalf("both in-network lookalikes must be admitted, got %#v", results)
	}
	for i, w := range []struct {
		line   float64
		action string
		note   string
	}{
		{1, "paired-hit", "😀"},
		{2, "plain-hit", `\uD800`},
	} {
		r := results[i]
		if r["line"] != w.line || r["ok"] != true {
			t.Fatalf("record %d must be line %v ok:true: %#v", i, w.line, r)
		}
		event := eventOf(t, r)
		if event["action"] != w.action {
			t.Fatalf("record %d action mismatch: %#v", i, event)
		}
		extra := event["extra"].(map[string]any)
		if extra["note"] != w.note {
			t.Fatalf("record %d note must keep its original meaning, got %q want %q", i, extra["note"], w.note)
		}
	}
}
