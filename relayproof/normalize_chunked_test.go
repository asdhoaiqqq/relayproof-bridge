package relayproof

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

// Regression coverage for fragmented input delivery. A log source hands
// bytes to NormalizeReader through whatever chunk boundaries its transport
// produces: one byte at a time, irregularly sized pieces, or one piece
// carrying several records. Splits may land inside multi-byte UTF-8
// sequences (Chinese text, emoji, including the two code units of a flag
// sequence), inside JSON string escapes (\" \\ \t \uXXXX), or between the
// '\r' and '\n' of a CRLF line ending. None of that may change anything
// about the business result: for identical complete input, the normalized
// events, their order, physical line numbers, the per-line ok/error
// outcomes, and the returned failure count must be byte-for-byte identical
// no matter where the chunk boundaries fall. A temporarily incomplete
// fragment must never be mistaken for a log line (and therefore must never
// produce a result or a failure).
//
// Every chunking is generated in-process from fixed byte strings, so the
// checks reproduce deterministically with no network or device involvement.

// chunkReader serves the same fixed data with a scripted chunk shape: the
// (reads mod len(sizes))-th Read hands out at most that many bytes (clamped
// to what remains and to the caller's buffer), and Read returns io.EOF only
// once every byte has been delivered. With sizes {1} every byte arrives in
// its own Read; with a size past len(data) the whole input arrives at once,
// even when one chunk spans several complete records.
type chunkReader struct {
	data  []byte
	sizes []int
	pos   int
	reads int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n := c.sizes[c.reads%len(c.sizes)]
	c.reads++
	if remaining := len(c.data) - c.pos; n > remaining {
		n = remaining
	}
	if n > len(p) {
		n = len(p) // a source may have more bytes ready than the caller takes
	}
	copy(p, c.data[c.pos:c.pos+n])
	c.pos += n
	return n, nil
}

// chunkPlans builds scripted chunk shapes for data of total bytes. The set
// always includes single-byte delivery, one-shot delivery (a single chunk
// spanning every record), a Fibonacci-ish irregular alternation, coprime
// and prime sizes (their cycling boundaries land on different record
// offsets), power-of-two sizes, and a few lopsided large/small
// alternations. With exhaustive, every byte offset 1..total-1 is used as a
// two-chunk cut in two ways, so every possible split point — including
// every byte inside every multi-byte character, escape sequence, and CRLF
// pair — is exercised at least once.
func chunkPlans(total int, exhaustive bool) [][]int {
	base := [][]int{
		{1},
		{total*2 + 1},
		{1, 1, 2, 3, 5, 8, 13},
		{2, 3, 5, 7, 11, 13, 17, 31},
		{3, 7, 13, 31},
		{2, 4, 8, 16, 32, 64, 128},
		{total/2 + 1, total/3 + 2, 5},
		{total/4 + 1, total - total/4},
	}
	seen := map[string]bool{}
	out := make([][]int, 0, len(base)+2*total)
	add := func(p []int) {
		key := fmt.Sprint(p)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, p)
	}
	for _, p := range base {
		add(p)
	}
	if exhaustive {
		for cut := 1; cut < total; cut++ {
			add([]int{cut, total})       // first chunk ends exactly at cut
			add([]int{cut, total - cut}) // second chunk is exactly the remainder
		}
	}
	return out
}

// normalizeChunked runs NormalizeReader over one scripted fragmentation.
func normalizeChunked(t *testing.T, data []byte, plan []int) (int, []byte) {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReader(&chunkReader{data: data, sizes: plan}, &out)
	if err != nil {
		t.Fatalf("clean fragmented input must not be a stream error (plan %v): %v", plan, err)
	}
	return failures, out.Bytes()
}

// normalizeGolden is the reference produced when the same input arrives in
// one ordinary read; every fragmented run must match it exactly.
func normalizeGolden(t *testing.T, data []byte) (int, []byte) {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReader(bytes.NewReader(data), &out)
	if err != nil {
		t.Fatalf("golden run failed: %v", err)
	}
	return failures, out.Bytes()
}

// assertChunkingsInvariant runs every plan and requires identical failure
// counts and byte-identical output to the golden run.
func assertChunkingsInvariant(t *testing.T, data []byte, plans [][]int) {
	t.Helper()
	wantFailures, wantOutput := normalizeGolden(t, data)
	for _, plan := range plans {
		gotFailures, gotOutput := normalizeChunked(t, data, plan)
		if gotFailures != wantFailures {
			t.Fatalf("plan %v changed the failure count: got %d, want %d", plan, gotFailures, wantFailures)
		}
		if !bytes.Equal(gotOutput, wantOutput) {
			t.Fatalf("plan %v changed the output.\nwant: %q\n got: %q", plan, wantOutput, gotOutput)
		}
	}
}

// The richest stream: aliased fields converted to canonical fields
// (timestamp to UTC, action trimmed), Chinese text and emoji (including a
// flag made of two scalars) both inside mapped values and unknown fields,
// JSON string escapes (\n \" \\ \t \/ and a é escape), a CRLF ending,
// blank physical lines, a log whose action is empty, and a syntactically
// invalid log — finished by a valid line without a trailing newline. Every
// possible split point is tried, including every byte of every multi-byte
// character, every escape byte, and the gap of the CRLF pair.
func TestNormalizeChunkedDeliveryMatchesWholeInput(t *testing.T) {
	line1 := "{\"time\":\"2026-01-02T08:30:00+08:00\",\"src_ip\":\"2001:db8::1\"," +
		"\"event_type\":\"\\t登录 🚀  \",\"user\":\" 张三 \"," +
		"\"msg\":\"换行\\n引号\\\"反斜杠\\\\ emoji😀\",\"note\":\"a\\tb\"}\r\n"
	blank1 := "\n"
	emptyAction := "{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"   \"}\n"
	line4 := "{\"timestamp\":\"2026-01-02T01:02:03.123456789Z\",\"action\":\"x\"," +
		"\"quote\":\"he said \\\"hi\\\" \\\\ end\\t\\r\\n\\b\\f\\/\\u00e9\"," +
		"\"japan\":\"カタカナ\",\"emoji_flag\":\"🇺🇳\"}\n"
	invalid := "{not json\n"
	blank2 := "  \t \r\n"
	line7 := "{\"timestamp\":\"2026-01-02T00:00:02Z\",\"action\":\"done\",\"n\":42}" // no trailing newline

	data := []byte(line1 + blank1 + emptyAction + line4 + invalid + blank2 + line7)
	if bytes.Count(data, []byte("\n")) < 6 {
		t.Fatalf("test setup: expected at least 6 physical lines")
	}

	wantFailures, golden := normalizeGolden(t, data)
	if wantFailures != 2 {
		t.Fatalf("only the empty-action log and the invalid JSON must fail, got %d", wantFailures)
	}
	if bytes.ContainsRune(golden, '�') {
		t.Fatalf("output must never contain a Unicode replacement char: %q", golden)
	}
	// The original multibyte text must survive literally, not be lost or
	// re-escaped into replacement bytes.
	for _, marker := range []string{"张三", "😀", "🚀", "カタカナ", "🇺🇳"} {
		if !bytes.Contains(golden, []byte(marker)) {
			t.Fatalf("output must preserve %q verbatim: %q", marker, golden)
		}
	}

	results := decodeResults(t, golden)
	if len(results) != 5 {
		t.Fatalf("each of the 5 non-blank logs must yield exactly one result, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 mismatch: %#v", results[0])
	}
	ev1 := eventOf(t, results[0])
	if ev1["timestamp"] != "2026-01-02T00:30:00Z" {
		t.Fatalf("alias time must convert to UTC: %v", ev1["timestamp"])
	}
	if ev1["source_ip"] != "2001:db8::1" {
		t.Fatalf("alias src_ip mismatch: %v", ev1["source_ip"])
	}
	if ev1["action"] != "登录 🚀" {
		t.Fatalf("action must trim surrounding whitespace but keep inner text: %v", ev1["action"])
	}
	extra1 := ev1["extra"].(map[string]any)
	if extra1["user"] != " 张三 " {
		t.Fatalf("unknown text field must keep original characters and spaces, got %v", extra1["user"])
	}
	if extra1["msg"] != "换行\n引号\"反斜杠\\ emoji😀" {
		t.Fatalf("escaped JSON content must decode once and stay intact, got %v", extra1["msg"])
	}
	if extra1["note"] != "a\tb" {
		t.Fatalf("tab escape in unknown field must be preserved, got %v", extra1["note"])
	}

	bad := results[1]
	if bad["line"] != float64(3) || bad["ok"] != false {
		t.Fatalf("empty-action log must fail on its physical line 3: %#v", bad)
	}
	if _, exists := bad["event"]; exists {
		t.Fatalf("the empty-action failure must not carry an event: %#v", bad)
	}
	msg, _ := bad["error"].(string)
	if !strings.Contains(msg, FieldAction) || !strings.Contains(msg, "must not be empty") {
		t.Fatalf("error must explain that the action must not be empty, got %q", msg)
	}

	ev4 := eventOf(t, results[2])
	if results[2]["line"] != float64(4) || results[2]["ok"] != true {
		t.Fatalf("line 4 mismatch: %#v", results[2])
	}
	extra4 := ev4["extra"].(map[string]any)
	if extra4["quote"] != "he said \"hi\" \\ end\t\r\n\b\f/é" {
		t.Fatalf("split-prone JSON escapes must survive every chunking, got %v", extra4["quote"])
	}
	if extra4["japan"] != "カタカナ" || extra4["emoji_flag"] != "🇺🇳" {
		t.Fatalf("multibyte unknown fields must survive, got %#v", extra4)
	}

	if results[3]["line"] != float64(5) || results[3]["ok"] != false {
		t.Fatalf("invalid JSON must fail on physical line 5: %#v", results[3])
	}
	if _, exists := results[3]["event"]; exists {
		t.Fatalf("invalid JSON must not carry an event: %#v", results[3])
	}
	if results[4]["line"] != float64(7) || results[4]["ok"] != true {
		t.Fatalf("the final newline-less log must be physical line 7 and succeed: %#v", results[4])
	}
	if eventOf(t, results[4])["action"] != "done" {
		t.Fatalf("final log content mismatch: %#v", results[4])
	}

	// Every possible cut through this multi-byte/escape/CRLF-heavy input.
	assertChunkingsInvariant(t, data, chunkPlans(len(data), true))
}

// One chunk may carry several records at once, or arrive after a single
// leading byte. Neither the many-newlines chunk nor the lone-byte chunk may
// be mistaken for a log of its own.
func TestNormalizeChunkSpanningMultipleRecords(t *testing.T) {
	logA := `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}` + "\n"
	logBad := `{"timestamp":"not-a-time","action":"b"}` + "\n"
	blank := "\n"
	logD := `{"timestamp":"2026-01-02T00:00:02Z","action":"d"}` + "\n"
	data := []byte(logA + logBad + blank + logD)

	firstSpansTwoRecordsAndBlank := len(logA) + len(logBad) + len(blank) + 2
	plans := [][]int{
		{len(data)}, // the whole stream in a single Read
		{1, len(data) - 1},
		{3, len(data)},
		{firstSpansTwoRecordsAndBlank, len(data)}, // chunk 1 ends mid-record D
		{len(data) / 2, len(data)/2 + 1, 1, 7},
		{1, 1, 2, 3, 5},
	}

	wantFailures, golden := normalizeGolden(t, data)
	if wantFailures != 1 {
		t.Fatalf("only the invalid log must count, got %d", wantFailures)
	}
	results := decodeResults(t, golden)
	if len(results) != 3 {
		t.Fatalf("one result per non-blank log, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true ||
		results[1]["line"] != float64(2) || results[1]["ok"] != false ||
		results[2]["line"] != float64(4) || results[2]["ok"] != true {
		t.Fatalf("order, line numbers, and outcomes mismatch: %#v", results)
	}
	assertChunkingsInvariant(t, data, plans)
}

// A single valid log longer than 64 KiB must be processed whole (bufio's
// line accumulation keeps growing instead of truncating or splitting it),
// its long unknown string must be preserved verbatim, and the line number
// and content of following records must be unaffected.
func TestNormalizeChunkedOversizeLine(t *testing.T) {
	blob := strings.Repeat("ab", 35000) // 70000 bytes of unknown string
	blobJSON, err := json.Marshal(blob)
	if err != nil {
		t.Fatal(err)
	}
	line1 := `{"timestamp":"2026-01-02T00:00:00Z","action":"big","city":"北京😀","blob":` +
		string(blobJSON) + "}"
	if len(line1) <= 64*1024 {
		t.Fatalf("test setup: the log must exceed 64 KiB, got %d bytes", len(line1))
	}
	line3 := "{\"timestamp\":\"2026-01-02T00:00:01Z\",\"action\":\"下一条 🎉\",\"seq\":2}\n"
	data := []byte(line1 + "\n\n" + line3) // physical lines: big, blank, next

	plans := chunkPlans(len(data), false)
	plans = append(plans,
		// Long steady refills (clamped by bufio to its 4096-byte Read buffer)
		// interrupted by one-byte reads: the 64 KiB line boundary is crossed
		// mid-accumulation, never mid-record from the normalizer's view.
		[]int{4096, 1, 4096, 5},
		[]int{4095, 4097, 4096, 7}, // offsets just off the refill grid
		[]int{len(line1) + 2, 3},   // chunk 1 ends right at line 3
		[]int{len(line1) + 1, 1, 999},
	)

	wantFailures, golden := normalizeGolden(t, data)
	if wantFailures != 0 {
		t.Fatalf("oversize valid logs must not fail, got %d failures", wantFailures)
	}
	if bytes.Contains(golden, []byte("�")) {
		t.Fatalf("oversize output must not contain replacement characters")
	}
	results := decodeResults(t, golden)
	if len(results) != 2 {
		t.Fatalf("expected results on line 1 and line 3, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("the >64 KiB log must succeed on line 1: %#v", results[0])
	}
	extra := eventOf(t, results[0])["extra"].(map[string]any)
	if got := extra["blob"].(string); got != blob {
		t.Fatalf("long unknown string changed: got length %d, want %d", len(got), len(blob))
	}
	if extra["city"] != "北京😀" {
		t.Fatalf("multibyte field on the oversize line must survive, got %v", extra["city"])
	}
	if results[1]["line"] != float64(3) || results[1]["ok"] != true {
		t.Fatalf("the record after the oversize log must keep physical line 3: %#v", results[1])
	}
	if eventOf(t, results[1])["action"] != "下一条 🎉" {
		t.Fatalf("later record content must be unaffected by the long line: %#v", results[1])
	}

	assertChunkingsInvariant(t, data, plans)
}

// Tail behavior must be independent of chunking: a final complete JSON log
// without a trailing newline is emitted exactly once at clean EOF; a tail
// holding only whitespace (including a bare '\r' left over from CRLF)
// produces no extra result.
func TestNormalizeChunkedTailBehavior(t *testing.T) {
	logA := `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}`
	logB := `{"timestamp":"2026-01-02T00:00:01Z","action":"b"}`
	cases := []struct {
		name        string
		input       string
		wantResults int
	}{
		{"final line without newline", logA + "\n" + logB, 2},
		{"whitespace-only tail after newline", logA + "\n" + logB + "\n  \t \r", 2},
		{"ordinary trailing newline", logA + "\n" + logB + "\n", 2},
		{"single line with newline", logA + "\n", 1},
		{"blank bytes only", "\n  \t\r", 0},
		{"CRLF endings without trailing newline", logA + "\r\n" + logB, 2},
		{"empty input", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.input)
			_, golden := normalizeGolden(t, data)
			if len(decodeResults(t, golden)) != tc.wantResults {
				t.Fatalf("%s: expected %d results, got %q", tc.name, tc.wantResults, golden)
			}
			assertChunkingsInvariant(t, data, chunkPlans(len(data), true))
		})
	}
}
