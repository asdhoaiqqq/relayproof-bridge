package relayproof

// Regression coverage for chunked input delivery while the IPv4 source
// network filter is active. normalize_chunked_test.go pins the same
// delivery-shape invariants for the unfiltered entry point; this file pins
// them for NormalizeReaderFiltered with a non-nil filter, so the read
// pattern can never change what the filter admits:
//
//   - The same logs with the same network must produce byte-for-byte the
//     same records, in the same order, with the same physical line numbers
//     and the same failure count, whether the input arrives as one piece,
//     one byte at a time, or alternating short and long chunks.
//   - Membership is decided on the fully normalized source_ip: 192.0.2.7 and
//     ::ffff:192.0.2.7 admit identically (also via the src_ip alias, and a
//     canonical name plus an alias spelling of the same address merge into
//     one success record), while ::192.0.2.7 stays IPv6 — valid but dropped.
//     Out-of-network and source-less valid logs are dropped without
//     failing, and dropped or blank lines never renumber later records.
//   - The filter never hides bad logs and never rewrites hits: a failed
//     line keeps its physical number and original reason, and admitted
//     records are exactly the records the unfiltered run would emit.
//   - A partial delivery (a read fault with an unterminated fragment)
//     must not turn the fragment into an extra record or an extra failure.
//
// All inputs are built in-process and replayed through chunkReader and
// scriptReader, so every case reproduces deterministically offline.

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// mustSourceFilter parses a filter argument or fails the test.
func mustSourceFilter(t *testing.T, cidr string) *SourceCIDRFilter {
	t.Helper()
	f, err := ParseSourceCIDRFilter(cidr)
	if err != nil {
		t.Fatalf("test setup: ParseSourceCIDRFilter(%q): %v", cidr, err)
	}
	return &f
}

// normalizeFilteredChunked runs NormalizeReaderFiltered over input delivered
// in the given chunk-size pattern and returns the exact output bytes and
// failure count.
func normalizeFilteredChunked(t *testing.T, input string, filter *SourceCIDRFilter, sizes []int) (string, int) {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReaderFiltered(&chunkReader{data: []byte(input), sizes: sizes}, &out, filter)
	if err != nil {
		t.Fatalf("chunked delivery must not turn into a stream error, got %v", err)
	}
	return out.String(), failures
}

// assertFilteredChunkingInvariant verifies that every delivery pattern
// produces byte-for-byte the same output and the same failure count as
// reading the whole filtered input at once, and that no chunk boundary
// introduced replacement characters into the emitted records.
func assertFilteredChunkingInvariant(t *testing.T, input string, filter *SourceCIDRFilter) (string, int) {
	t.Helper()
	var whole bytes.Buffer
	baseFailures, err := NormalizeReaderFiltered(strings.NewReader(input), &whole, filter)
	if err != nil {
		t.Fatalf("whole-input filtered baseline must not fail, got %v", err)
	}
	base := whole.String()
	for _, pattern := range chunkPatterns {
		t.Run(pattern.name, func(t *testing.T) {
			got, failures := normalizeFilteredChunked(t, input, filter, pattern.sizes)
			if got != base {
				t.Fatalf("chunking changed the filtered output\nwhole:   %q\nchunked: %q", base, got)
			}
			if failures != baseFailures {
				t.Fatalf("chunking changed the failure count: got %d, want %d", failures, baseFailures)
			}
		})
	}
	if strings.Contains(base, "�") {
		t.Fatalf("filtered output must not contain replacement characters: %q", base)
	}
	return base, baseFailures
}

// filteredChunkedFixtureInput is one stream exercising every filtered-read
// hazard at once under 192.0.2.0/24:
//
//	line 1:  hit via aliases, Chinese/emoji extras, JSON escapes
//	line 2:  blank
//	line 3:  hit via the IPv4-mapped spelling ::ffff:192.0.2.7
//	line 4:  valid but out of network                    -> dropped
//	line 5:  valid genuine IPv6 ::192.0.2.7              -> dropped
//	line 6:  valid without any source address            -> dropped
//	line 7:  whitespace-only blank
//	line 8:  canonical name and alias give equivalent spellings -> one hit
//	line 9:  out-of-network source, invalid timestamp    -> failure
//	line 10: hit via the src_ip alias, CRLF terminated
//	line 11: hit, final line without a trailing newline
func filteredChunkedFixtureInput() string {
	return `{"time":"2026-01-02T08:04:05+08:00","src_ip":"192.0.2.7","event_type":" 登录 ","user":" 爱丽丝 ","note":"换行\n与\"引号\"和中文","emoji":"🚀🙂"}` + "\n" +
		"\n" +
		`{"timestamp":"2026-01-02T00:00:00.5Z","action":"mapped","source_ip":"::ffff:192.0.2.7"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"out-dropped","source_ip":"198.51.100.9"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"compat-v6","source_ip":"::192.0.2.7"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source"}` + "\n" +
		"   \t \n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"merged-alias","source_ip":"192.0.2.7","src_ip":"::ffff:192.0.2.7"}` + "\n" +
		`{"timestamp":"not-a-time","action":"bad-time-outside","source_ip":"198.51.100.30"}` + "\n" +
		`{"timestamp":"2026-12-31T23:59:59-01:00","action":"收尾","msg":"结束🚀","src_ip":"192.0.2.7"}` + "\r\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"tail-hit","source_ip":"192.0.2.7"}`
}

// The fixture's business results must hold under every chunking: the six
// visible records are the hits on physical lines 1, 3, 8, 10, 11 plus the
// failure on line 9; dropped and blank lines leave no record and never
// renumber anything; exactly the invalid-timestamp log counts as a failure.
func TestNormalizeFilteredChunkedFixtureBusinessResults(t *testing.T) {
	filter := mustSourceFilter(t, "192.0.2.0/24")
	input := filteredChunkedFixtureInput()
	base, failures := assertFilteredChunkingInvariant(t, input, filter)
	if failures != 1 {
		t.Fatalf("only the invalid-timestamp log may count as a failure, got %d", failures)
	}

	results := decodeResults(t, []byte(base))
	wantLines := []float64{1, 3, 8, 9, 10, 11}
	wantOK := []bool{true, true, true, false, true, true}
	if len(results) != len(wantLines) {
		t.Fatalf("expected %d records (5 hits + 1 failure), got %d: %#v", len(wantLines), len(results), results)
	}
	for i := range wantLines {
		if results[i]["line"] != wantLines[i] || results[i]["ok"] != wantOK[i] {
			t.Fatalf("record %d must be line %v ok=%v, got %#v", i, wantLines[i], wantOK[i], results[i])
		}
	}

	// Line 1: aliases map to canonical fields, the timestamp converts to
	// UTC, the action is trimmed, and extra text keeps its exact characters
	// even when chunk boundaries fell inside multi-byte UTF-8 or escapes.
	first := eventOf(t, results[0])
	if first["timestamp"] != "2026-01-02T00:04:05Z" {
		t.Fatalf("alias timestamp must convert to UTC, got %v", first["timestamp"])
	}
	if first["source_ip"] != "192.0.2.7" {
		t.Fatalf("alias source_ip mismatch: %v", first["source_ip"])
	}
	if first["action"] != "登录" {
		t.Fatalf("action must be trimmed of surrounding whitespace, got %q", first["action"])
	}
	extra := extraOf(t, results[0])
	if extra["user"] != " 爱丽丝 " {
		t.Fatalf("extra text must keep its exact characters and spacing, got %q", extra["user"])
	}
	if extra["note"] != "换行\n与\"引号\"和中文" {
		t.Fatalf("extra text with escapes must decode intact, got %q", extra["note"])
	}
	if extra["emoji"] != "🚀🙂" {
		t.Fatalf("emoji must survive chunk boundaries inside UTF-8 sequences, got %q", extra["emoji"])
	}

	// Line 3: the mapped spelling normalizes to the same dotted address the
	// filter matched on; the fractional timestamp is preserved.
	mapped := eventOf(t, results[1])
	if mapped["source_ip"] != "192.0.2.7" {
		t.Fatalf("::ffff:192.0.2.7 must normalize to 192.0.2.7, got %v", mapped["source_ip"])
	}
	if mapped["timestamp"] != "2026-01-02T00:00:00.5Z" {
		t.Fatalf("line 3 timestamp mismatch: %v", mapped["timestamp"])
	}

	// Line 8: the canonical name and its alias spelled the same address two
	// equivalent ways; they merge into exactly one success record.
	merged := eventOf(t, results[2])
	if merged["source_ip"] != "192.0.2.7" || merged["action"] != "merged-alias" {
		t.Fatalf("equivalent canonical/alias spellings must merge into one hit: %#v", merged)
	}

	// Line 9: the filter never hides a bad log — the out-of-network source
	// with an invalid timestamp fails with its physical number and the
	// timestamp reason, carries no event, and counts as the one failure.
	if _, exists := results[3]["event"]; exists {
		t.Fatalf("failed log must not carry an event: %#v", results[3])
	}
	msg, _ := results[3]["error"].(string)
	if !strings.Contains(msg, FieldTimestamp) || !strings.Contains(msg, "invalid RFC3339") {
		t.Fatalf("failure must keep the timestamp-specific reason, got %q", msg)
	}

	// Line 10: CRLF termination and the src_ip alias; the timestamp
	// converts across the date boundary and the emoji extra survives.
	tenth := eventOf(t, results[4])
	if tenth["timestamp"] != "2027-01-01T00:59:59Z" {
		t.Fatalf("line 10 timestamp must convert to UTC, got %v", tenth["timestamp"])
	}
	if extraOf(t, results[4])["msg"] != "结束🚀" {
		t.Fatalf("line 10 extra mismatch: %#v", extraOf(t, results[4])["msg"])
	}

	// Line 11: the final complete JSON without a trailing newline is
	// processed exactly once, as a hit.
	if eventOf(t, results[5])["action"] != "tail-hit" {
		t.Fatalf("final newline-less line must be emitted once as a hit: %#v", results[5])
	}

	// Dropped valid logs leave no trace in the output at all.
	for _, marker := range []string{"out-dropped", "compat-v6", "no-source"} {
		if strings.Contains(base, marker) {
			t.Fatalf("dropped line %q must produce no record: %q", marker, base)
		}
	}
}

// Filtering must only remove records, never rewrite them: the filtered
// output is exactly the subsequence of the unfiltered results consisting of
// every failure plus every admitted success, with identical content.
func TestNormalizeFilteredChunkedRecordsAreUnfilteredSubsequence(t *testing.T) {
	filter := mustSourceFilter(t, "192.0.2.0/24")
	input := filteredChunkedFixtureInput()
	base, _ := assertFilteredChunkingInvariant(t, input, filter)
	filtered := decodeResults(t, []byte(base))

	var plain bytes.Buffer
	if _, err := NormalizeReader(strings.NewReader(input), &plain); err != nil {
		t.Fatalf("unfiltered reference run must not fail, got %v", err)
	}
	unfiltered := decodeResults(t, plain.Bytes())
	var want []map[string]any
	for _, r := range unfiltered {
		if r["ok"] != true {
			want = append(want, r) // failures are always kept
			continue
		}
		event, _ := r["event"].(map[string]any)
		source, _ := event["source_ip"].(string)
		if filter.admits(source) {
			want = append(want, r)
		}
	}
	if !reflect.DeepEqual(filtered, want) {
		t.Fatalf("filtered records must be the exact unfiltered subsequence\nfiltered:   %#v\nwant: %#v", filtered, want)
	}
}

// Splitting the filtered input into exactly two pieces at every possible
// byte offset — inside multi-byte characters, inside escape sequences,
// between CR and LF — must always reproduce the whole-input filtered output
// and failure count.
func TestNormalizeFilteredChunkedEveryTwoPieceSplit(t *testing.T) {
	filter := mustSourceFilter(t, "192.0.2.0/24")
	input := `{"time":"2026-01-02T08:04:05+08:00","src_ip":"::ffff:192.0.2.7","event_type":" 登录 ","note":"a\nb\"c\\d中文🚀"}` + "\r\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"dropped","source_ip":"198.51.100.9"}` + "\n" +
		`{"timestamp":"bad","action":"bad-time","source_ip":"192.0.2.7"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"尾","source_ip":"192.0.2.7","x":"🙂"}`
	var whole bytes.Buffer
	baseFailures, err := NormalizeReaderFiltered(strings.NewReader(input), &whole, filter)
	if err != nil {
		t.Fatalf("filtered baseline must not fail, got %v", err)
	}
	for i := 0; i <= len(input); i++ {
		out, failures := normalizeFilteredChunked(t, input, filter, []int{i, len(input) - i})
		if out != whole.String() || failures != baseFailures {
			t.Fatalf("split at byte %d changed the filtered result\nwhole:   %q (%d failures)\nchunked: %q (%d failures)",
				i, whole.String(), baseFailures, out, failures)
		}
	}
}

// A single valid log larger than 64 KiB needs several reads to assemble;
// under the filter it is still processed whole: the hit's long unknown
// string is preserved verbatim, the dropped line after it stays invisible,
// and the following hit keeps its physical line number.
func TestNormalizeFilteredChunkedOversizedLine(t *testing.T) {
	filter := mustSourceFilter(t, "192.0.2.0/24")
	blob := strings.Repeat("长", 20000) + strings.Repeat("x", 40000) + "🚀"
	line := `{"timestamp":"2026-01-02T00:00:00Z","action":"big","source_ip":"192.0.2.7","blob":` + jsonString(blob) + `}`
	if len(line) <= 64*1024 {
		t.Fatalf("test setup: oversized log must exceed 64 KiB, got %d bytes", len(line))
	}
	input := line + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"dropped","source_ip":"198.51.100.9"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"after","source_ip":"192.0.2.7"}` + "\n"

	base, failures := assertFilteredChunkingInvariant(t, input, filter)
	if failures != 0 {
		t.Fatalf("valid logs must report zero failures, got %d", failures)
	}
	results := decodeResults(t, []byte(base))
	if len(results) != 2 {
		t.Fatalf("expected the oversized hit and the trailing hit only, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("oversized line 1 must succeed: %#v", results[0])
	}
	if got := extraOf(t, results[0])["blob"]; got != blob {
		t.Fatalf("long unknown string must be preserved verbatim (got %d chars, want %d)",
			len(got.(string)), len(blob))
	}
	if results[1]["line"] != float64(3) || results[1]["ok"] != true {
		t.Fatalf("hit after the dropped line must keep physical line 3: %#v", results[1])
	}
	if eventOf(t, results[1])["action"] != "after" {
		t.Fatalf("hit after the dropped line must keep its content: %#v", results[1])
	}
}

// At clean end of input the final complete JSON log is processed exactly
// once even without a trailing newline: an admittable tail is emitted, a
// dropped tail (out of network, IPv6, or source-less) adds nothing, and a
// failing tail counts as one failure — under every chunking.
func TestNormalizeFilteredChunkedInputTail(t *testing.T) {
	filter := mustSourceFilter(t, "192.0.2.0/24")
	head := `{"timestamp":"2026-01-02T00:00:00Z","action":"head","source_ip":"192.0.2.7"}` + "\n"
	cases := []struct {
		name         string
		tail         string
		wantResults  int
		wantFailures int
		wantLastOK   bool // meaning of the last record when wantResults == 2
	}{
		{"admittable tail", `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-hit","source_ip":"192.0.2.7"}`, 2, 0, true},
		{"out-of-network tail", `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-out","source_ip":"198.51.100.9"}`, 1, 0, true},
		{"genuine IPv6 tail", `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-v6","source_ip":"::192.0.2.7"}`, 1, 0, true},
		{"source-less tail", `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-none"}`, 1, 0, true},
		{"invalid-timestamp tail", `{"timestamp":"not-a-time","action":"tail-bad","source_ip":"192.0.2.7"}`, 2, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, failures := assertFilteredChunkingInvariant(t, head+tc.tail, filter)
			if failures != tc.wantFailures {
				t.Fatalf("want %d failures, got %d", tc.wantFailures, failures)
			}
			results := decodeResults(t, []byte(base))
			if len(results) != tc.wantResults {
				t.Fatalf("expected %d results, got %#v", tc.wantResults, results)
			}
			last := results[len(results)-1]
			if tc.wantResults == 2 {
				// The tail is physical line 2 whenever it produces a record.
				if last["line"] != float64(2) || last["ok"] != tc.wantLastOK {
					t.Fatalf("tail record must be line 2 with ok=%v: %#v", tc.wantLastOK, last)
				}
			}
			if tc.wantResults == 1 && eventOf(t, last)["action"] != "head" {
				t.Fatalf("dropped tail must leave the head record untouched: %#v", last)
			}
		})
	}
}

// A read fault that delivers only part of the stream must not turn the
// unterminated fragment into a record or a failure, no matter how the
// complete lines before it were chunked. The emitted prefix equals a
// healthy filtered read of exactly the complete lines, and the caller still
// receives ErrLogRead wrapping the original cause.
func TestNormalizeFilteredChunkedPartialReadFault(t *testing.T) {
	filter := mustSourceFilter(t, "192.0.2.0/24")
	complete := strings.Join([]string{
		`{"timestamp":"2026-01-02T00:00:00Z","action":"in-allowed","source_ip":"192.0.2.7"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","action":"out-dropped","source_ip":"198.51.100.9"}`,
		``,
		`{"timestamp":"not-a-time","action":"bad-time-outside","source_ip":"198.51.100.30"}`,
	}, "\n") + "\n"
	fragments := []struct {
		name     string
		fragment string
		marker   string
	}{
		{"fragment is a complete admittable object", `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-in-allowed","source_ip":"192.0.2.7"}`, "tail-in-allowed"},
		{"fragment carries an invalid timestamp", `{"timestamp":"not-a-time","action":"tail-bad-time","source_ip":"192.0.2.7"}`, "tail-bad-time"},
	}
	patterns := [][]int{{1}, {7, 4096, 3, 64}, {len(complete)}}

	var healthy bytes.Buffer
	healthyFailures, healthyErr := NormalizeReaderFiltered(strings.NewReader(complete), &healthy, filter)
	if healthyErr != nil || healthyFailures != 1 {
		t.Fatalf("test setup: healthy reference read failed: failures=%d err=%v", healthyFailures, healthyErr)
	}

	for _, tc := range fragments {
		for pi, sizes := range patterns {
			t.Run(fmt.Sprintf("%s/chunk pattern %d", tc.name, pi), func(t *testing.T) {
				// Deliver the complete lines in the chunk pattern, then the
				// unterminated fragment together with the read fault.
				var steps []scriptStep
				for pos, step := 0, 0; pos < len(complete); step++ {
					n := sizes[step%len(sizes)]
					if n <= 0 {
						continue
					}
					if rem := len(complete) - pos; n > rem {
						n = rem
					}
					steps = append(steps, scriptStep{data: []byte(complete[pos : pos+n])})
					pos += n
				}
				steps = append(steps, scriptStep{data: []byte(tc.fragment), err: errSimulatedRead})

				var out bytes.Buffer
				failures, err := NormalizeReaderFiltered(&scriptReader{steps: steps}, &out, filter)
				if !errors.Is(err, ErrLogRead) || !errors.Is(err, errSimulatedRead) {
					t.Fatalf("want ErrLogRead wrapping the read cause, got %v", err)
				}
				if failures != healthyFailures {
					t.Fatalf("the failed-read fragment must not add failures: got %d, want %d", failures, healthyFailures)
				}
				if !bytes.Equal(out.Bytes(), healthy.Bytes()) {
					t.Fatalf("output must equal a healthy filtered read of the complete lines:\nfault:   %q\nhealthy: %q", out.String(), healthy.String())
				}
				if bytes.Contains(out.Bytes(), []byte(tc.marker)) {
					t.Fatalf("the unterminated fragment belongs to the failed read and must leave no record: %q", out.String())
				}
			})
		}
	}
}
