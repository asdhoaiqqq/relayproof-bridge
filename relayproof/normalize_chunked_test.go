package relayproof

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// Regression coverage for chunked input delivery: the bytes a source hands
// over per Read are not aligned to log lines, so the same complete input may
// arrive as single bytes, as alternating short and long pieces, or as one
// piece spanning several records. Chunking must never change the normalized
// events, their order, the physical line numbers, or the failure count, and
// a partial chunk must never be mistaken for a whole log line. All inputs
// are built in-process, so every case reproduces deterministically offline.

// chunkReader replays data in pieces whose sizes cycle through the given
// pattern, mirroring a source that delivers arbitrary byte counts per Read.
// It never returns (0, nil): once data is exhausted every Read is io.EOF.
type chunkReader struct {
	data  []byte
	sizes []int
	pos   int
	step  int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n := c.sizes[c.step%len(c.sizes)]
	c.step++
	if n <= 0 {
		// A zero-length piece delivers nothing; skip it rather than
		// returning (0, nil), which a Reader must not do while data remains.
		return c.Read(p)
	}
	if n > len(p) {
		n = len(p)
	}
	if rem := len(c.data) - c.pos; n > rem {
		n = rem
	}
	copy(p, c.data[c.pos:c.pos+n])
	c.pos += n
	return n, nil
}

// chunkPatterns are the delivery shapes every fixture must survive: byte at
// a time (every possible split point, including inside UTF-8 sequences,
// escape sequences, and CRLF pairs), irregular alternation of short and long
// pieces, and pieces large enough to carry several whole records at once.
var chunkPatterns = []struct {
	name  string
	sizes []int
}{
	{"single byte at a time", []int{1}},
	{"alternating short and long pieces", []int{1, 4096, 2, 7, 1024, 3, 64}},
	{"odd small sizes", []int{2, 3, 5, 7, 11, 13}},
	{"one piece spans many records", []int{1 << 20}},
}

// normalizeChunked runs NormalizeReader over input delivered in the given
// chunk-size pattern and returns the exact output bytes and failure count.
func normalizeChunked(t *testing.T, input string, sizes []int) (string, int) {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReader(&chunkReader{data: []byte(input), sizes: sizes}, &out)
	if err != nil {
		t.Fatalf("chunked delivery must not turn into a stream error, got %v", err)
	}
	return out.String(), failures
}

// assertChunkingInvariant verifies that every delivery pattern produces byte
// for byte the same output and the same failure count as reading the whole
// input at once, and that no chunk boundary introduced replacement
// characters into the emitted records.
func assertChunkingInvariant(t *testing.T, input string) (string, int) {
	t.Helper()
	var whole bytes.Buffer
	baseFailures, err := NormalizeReader(strings.NewReader(input), &whole)
	if err != nil {
		t.Fatalf("whole-input baseline must not fail, got %v", err)
	}
	base := whole.String()
	for _, pattern := range chunkPatterns {
		t.Run(pattern.name, func(t *testing.T) {
			got, failures := normalizeChunked(t, input, pattern.sizes)
			if got != base {
				t.Fatalf("chunking changed the output\nwhole:   %q\nchunked: %q", base, got)
			}
			if failures != baseFailures {
				t.Fatalf("chunking changed the failure count: got %d, want %d", failures, baseFailures)
			}
		})
	}
	if strings.Contains(base, "�") {
		t.Fatalf("output must not contain replacement characters: %q", base)
	}
	return base, baseFailures
}

// chunkedFixtureInput is one stream exercising every hazard at once: aliases,
// Chinese and emoji text (multi-byte UTF-8) in mapped and unmapped fields,
// JSON escape sequences inside strings, blank lines, an empty-action error
// line, a CRLF-terminated line, and a final complete line with no trailing
// newline.
func chunkedFixtureInput() string {
	return `{"time":"2026-01-02T08:04:05+08:00","src_ip":"2001:db8::1","event_type":" 登录 ","user":" 爱丽丝 ","note":"换行\n与\"引号\"和中文","emoji":"🚀🙂"}` + "\n" +
		"\n" +
		"   \t \n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":""}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00.5Z","action":"心跳","detail":"转义\\与中文字符"}` + "\r\n" +
		`{"timestamp":"2026-12-31T23:59:59-01:00","action":"收尾","msg":"结束🚀"}`
}

// The fixture's business results must hold under every chunking: aliases map
// to canonical fields with UTC timestamps and trimmed actions, unknown text
// keeps its exact characters in extra, blank lines only advance the physical
// line counter, the empty-action log fails on its own line without an event,
// and exactly that one log counts as the failure.
func TestNormalizeChunkedFixtureBusinessResults(t *testing.T) {
	input := chunkedFixtureInput()
	base, _ := assertChunkingInvariant(t, input)

	results := decodeResults(t, []byte(base))
	if len(results) != 4 {
		t.Fatalf("4 non-blank logs must yield exactly 4 results, got %d: %#v", len(results), results)
	}

	first := eventOf(t, results[0])
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 must succeed: %#v", results[0])
	}
	if first["timestamp"] != "2026-01-02T00:04:05Z" {
		t.Fatalf("alias timestamp must convert to UTC, got %v", first["timestamp"])
	}
	if first["source_ip"] != "2001:db8::1" {
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

	// Blank physical lines 2 and 3 only advance the counter: the empty-action
	// log reports its failure on line 4, carries no event, and is the only
	// counted failure.
	if results[1]["line"] != float64(4) || results[1]["ok"] != false {
		t.Fatalf("empty-action log must fail on physical line 4: %#v", results[1])
	}
	if _, exists := results[1]["event"]; exists {
		t.Fatalf("failed log must not carry an event: %#v", results[1])
	}
	msg, _ := results[1]["error"].(string)
	if !strings.Contains(msg, FieldAction) || !strings.Contains(msg, "must not be empty") {
		t.Fatalf("error must state the action must not be empty, got %q", msg)
	}

	if results[2]["line"] != float64(5) || results[2]["ok"] != true {
		t.Fatalf("CRLF-terminated line 5 must succeed: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "心跳" {
		t.Fatalf("line 5 action mismatch: %#v", results[2])
	}
	if extraOf(t, results[2])["detail"] != `转义\与中文`+"字符" {
		t.Fatalf("line 5 extra with escaped content mismatch: %#v", extraOf(t, results[2])["detail"])
	}

	if results[3]["line"] != float64(6) || results[3]["ok"] != true {
		t.Fatalf("final line without trailing newline must succeed on line 6: %#v", results[3])
	}
	if got := eventOf(t, results[3])["timestamp"]; got != "2027-01-01T00:59:59Z" {
		t.Fatalf("final line timestamp must convert to UTC, got %v", got)
	}
	if extraOf(t, results[3])["msg"] != "结束🚀" {
		t.Fatalf("final line extra mismatch: %#v", extraOf(t, results[3])["msg"])
	}
}

// The returned failure count covers only the empty-action log; temporarily
// incomplete content produced by chunking must never be counted as a failed
// log, and success/failure results keep input order.
func TestNormalizeChunkedFailureCount(t *testing.T) {
	input := chunkedFixtureInput()
	for _, pattern := range chunkPatterns {
		t.Run(pattern.name, func(t *testing.T) {
			out, failures := normalizeChunked(t, input, pattern.sizes)
			if failures != 1 {
				t.Fatalf("only the empty-action log may count as a failure, got %d", failures)
			}
			results := decodeResults(t, []byte(out))
			okPattern := make([]bool, len(results))
			for i, r := range results {
				okPattern[i] = r["ok"] == true
			}
			want := []bool{true, false, true, true}
			if len(okPattern) != len(want) {
				t.Fatalf("result count mismatch: %#v", results)
			}
			for i := range want {
				if okPattern[i] != want[i] {
					t.Fatalf("results must keep input order of successes and failures: %#v", results)
				}
			}
		})
	}
}

// Splitting the input into exactly two pieces at every possible byte offset
// — inside multi-byte characters, inside escape sequences, between CR and LF
// — must always reproduce the whole-input output.
func TestNormalizeChunkedEveryTwoPieceSplit(t *testing.T) {
	input := `{"time":"2026-01-02T08:04:05+08:00","event_type":" 登录 ","note":"a\nb\"c\\d中文🚀"}` + "\r\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":""}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"尾","x":"🙂"}`
	var whole bytes.Buffer
	baseFailures, err := NormalizeReader(strings.NewReader(input), &whole)
	if err != nil {
		t.Fatalf("baseline must not fail, got %v", err)
	}
	for i := 0; i <= len(input); i++ {
		out, failures := normalizeChunked(t, input, []int{i, len(input) - i})
		if out != whole.String() || failures != baseFailures {
			t.Fatalf("split at byte %d changed the result\nwhole:   %q (%d failures)\nchunked: %q (%d failures)",
				i, whole.String(), baseFailures, out, failures)
		}
	}
}

// A single valid log larger than 64 KiB is processed whole under every
// chunking: the long unknown string is preserved verbatim in extra, and the
// following record keeps its line number and content.
func TestNormalizeChunkedOversizedLine(t *testing.T) {
	blob := strings.Repeat("长", 20000) + strings.Repeat("x", 40000) + "🚀"
	line := `{"timestamp":"2026-01-02T00:00:00Z","action":"big","blob":` + jsonString(blob) + `}`
	if len(line) <= 64*1024 {
		t.Fatalf("test setup: oversized log must exceed 64 KiB, got %d bytes", len(line))
	}
	input := line + "\n" + validLog("after") + "\n"

	base, failures := assertChunkingInvariant(t, input)
	if failures != 0 {
		t.Fatalf("valid oversized log must not count as a failure, got %d", failures)
	}
	results := decodeResults(t, []byte(base))
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("oversized line 1 must succeed: %#v", results[0]["ok"])
	}
	if got := extraOf(t, results[0])["blob"]; got != blob {
		t.Fatalf("long unknown string must be preserved verbatim (got %d chars, want %d)",
			len(got.(string)), len(blob))
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != true {
		t.Fatalf("record after the oversized line must keep line number 2: %#v", results[1])
	}
	if eventOf(t, results[1])["action"] != "after" {
		t.Fatalf("record after the oversized line must keep its content: %#v", results[1])
	}
}

// At clean end of input the final complete JSON log yields exactly one
// result even without a trailing newline, while a trailing whitespace-only
// tail yields no extra result — under every chunking.
func TestNormalizeChunkedInputTail(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		wantResults int
		wantLast    string // action of the last result, "" when none
	}{
		{"final log without trailing newline", validLog("a") + "\n" + validLog("b"), 2, "b"},
		{"trailing whitespace without newline", validLog("a") + "\n" + "  \t ", 1, "a"},
		{"trailing blank lines", validLog("a") + "\n\n  \n", 1, "a"},
		{"only whitespace after final newline", validLog("a") + "\n" + " \r\n\t\n", 1, "a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, failures := assertChunkingInvariant(t, tc.input)
			if failures != 0 {
				t.Fatalf("valid logs must report zero failures, got %d", failures)
			}
			results := decodeResults(t, []byte(base))
			if len(results) != tc.wantResults {
				t.Fatalf("expected %d results, got %#v", tc.wantResults, results)
			}
			last := results[len(results)-1]
			if last["ok"] != true || eventOf(t, last)["action"] != tc.wantLast {
				t.Fatalf("last result mismatch: %#v", last)
			}
		})
	}
}
