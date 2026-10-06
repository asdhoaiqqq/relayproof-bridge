package relayproof

// Regression coverage for chunked input delivery WHILE the 192.0.2.0/24
// source filter is active on the streaming entry point. normalize_chunked_test.go
// pins chunking on the unfiltered entry point; this file closes the gap for
// NormalizeReaderFiltered. The same complete log submitted with the same
// network must produce identical output whether it arrives many lines per
// Read, one byte per Read, or in alternating short and long pieces: the exact
// emitted bytes, record order, physical line numbers, and the failure count.
//
// The fixtures exercise every hazard at once:
//
//   - A plain 192.0.2.7 and ::ffff:192.0.2.7 (also via the src_ip alias, also
//     with canonical name and alias spelling the equivalent address together)
//     normalize to the same dotted source and yield one hit each, while
//     ::192.0.2.7 stays genuine IPv6, is legal, and leaves no record.
//   - Out-of-network and address-less legal logs leave no record and do not
//     count as failures; blank and dropped lines never renumber later hits.
//   - A complete log whose source is outside the network but whose timestamp
//     is invalid is still a counted failure carrying its physical line number
//     and timestamp reason and no event, even under byte-at-a-time delivery.
//   - Chunk boundaries fall inside Chinese and emoji UTF-8 sequences, inside
//     JSON escapes, and between CR and LF; a single log larger than the
//     64 KiB read buffer needs many Reads, and a clean EOF still processes a
//     final newline-less JSON exactly once (whether it hits or fails).
//   - A newline-less fragment seen mid-stream is only a partial input chunk:
//     it is never mistaken for a complete log, so it adds neither a record
//     nor a failure.
//
// Filtering only removes records: every emitted record is byte-for-byte the
// JSON the unfiltered run writes for the same physical line, with no added
// marker. Everything is built in-process, so all cases reproduce
// deterministically offline.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// normalizeChunkedFiltered runs NormalizeReaderFiltered over input delivered
// in the given chunk-size pattern and returns the exact output bytes and
// failure count.
func normalizeChunkedFiltered(t *testing.T, input string, sizes []int, filter *SourceCIDRFilter) (string, int) {
	t.Helper()
	var out bytes.Buffer
	failures, err := NormalizeReaderFiltered(&chunkReader{data: []byte(input), sizes: sizes}, &out, filter)
	if err != nil {
		t.Fatalf("chunked delivery under a filter must not turn into a stream error, got %v", err)
	}
	return out.String(), failures
}

// assertFilteredChunkingInvariant verifies that every delivery pattern
// produces byte-for-byte the same output and failure count as reading the
// whole filtered input at once, and that no chunk boundary introduced
// replacement characters.
func assertFilteredChunkingInvariant(t *testing.T, input string, filter *SourceCIDRFilter) (string, int) {
	t.Helper()
	var whole bytes.Buffer
	baseFailures, err := NormalizeReaderFiltered(strings.NewReader(input), &whole, filter)
	if err != nil {
		t.Fatalf("whole-input baseline must not fail, got %v", err)
	}
	base := whole.String()
	for _, pattern := range chunkPatterns {
		t.Run(pattern.name, func(t *testing.T) {
			got, failures := normalizeChunkedFiltered(t, input, pattern.sizes, filter)
			if got != base {
				t.Fatalf("chunking under a filter changed the output\nwhole:   %q\nchunked: %q", base, got)
			}
			if failures != baseFailures {
				t.Fatalf("chunking under a filter changed the failure count: got %d, want %d", failures, baseFailures)
			}
		})
	}
	if strings.Contains(base, "�") {
		t.Fatalf("output must not contain replacement characters: %q", base)
	}
	return base, baseFailures
}

// assertFilteredOnlyRemovesRecords proves the filter adds nothing and rewrites
// nothing: each record the filtered run emits must be byte-for-byte the same
// JSON line the unfiltered run emits for that physical line. The encoder is
// the same in both runs, so raw identity is an exact check.
func assertFilteredOnlyRemovesRecords(t *testing.T, input, filteredOutput string) {
	t.Helper()
	var plain bytes.Buffer
	if _, err := NormalizeReader(strings.NewReader(input), &plain); err != nil {
		t.Fatalf("unfiltered reference run must not fail: %v", err)
	}
	unfiltered := map[int]string{}
	for _, raw := range strings.Split(strings.TrimSuffix(plain.String(), "\n"), "\n") {
		if raw == "" {
			continue
		}
		var head struct {
			Line int `json:"line"`
		}
		if err := json.Unmarshal([]byte(raw), &head); err != nil {
			t.Fatalf("unfiltered output line must decode: %v: %q", err, raw)
		}
		unfiltered[head.Line] = raw
	}
	for _, raw := range strings.Split(strings.TrimSuffix(filteredOutput, "\n"), "\n") {
		if raw == "" {
			continue
		}
		var head struct {
			Line int `json:"line"`
		}
		if err := json.Unmarshal([]byte(raw), &head); err != nil {
			t.Fatalf("filtered output line must decode: %v: %q", err, raw)
		}
		if want, ok := unfiltered[head.Line]; !ok {
			t.Fatalf("filtered output has a record for physical line %d that the unfiltered run never wrote", head.Line)
		} else if want != raw {
			t.Fatalf("filtering rewrote physical line %d:\nunfiltered: %q\nfiltered:   %q", head.Line, want, raw)
		}
	}
}

// filteredChunkedFixture is one batch under 192.0.2.0/24 that mixes hits with
// every drop and failure shape, blank lines, CRLF, UTF-8, escapes, mapped
// aliases, and a newline-less tail:
//
//	line  1: hit, plain 192.0.2.7, Chinese action, emoji/Chinese/escaped extra
//	line  2: blank
//	line  3: whitespace-only blank
//	line  4: hit via src_ip alias spelling ::ffff:192.0.2.7 (same source as 1)
//	line  5: dropped, outside network
//	line  6: dropped, ::192.0.2.7 is genuine IPv6 despite the trailing bits
//	line  7: dropped, plain IPv6
//	line  8: dropped, no source address
//	line  9: blank
//	line 10: hit, canonical and alias both spell the equivalent mapped address
//	line 11: FAILURE, outside source with an invalid timestamp
//	line 12: hit, CRLF-terminated, Chinese action with an escaped backslash
//	line 13: hit, final complete JSON with no trailing newline
func filteredChunkedFixture() string {
	return `{"timestamp":"2026-01-02T08:04:05+08:00","source_ip":"192.0.2.7","action":" 登录 ","user":" 爱丽丝 ","note":"换行\n与\"引号\"和中文\\斜杠","emoji":"🚀🙂"}` + "\n" +
		"\n" +
		"   \t \n" +
		`{"time":"2026-01-02T00:00:00Z","src_ip":"::ffff:192.0.2.7","event_type":"via-alias-mapped"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"out-of-net","source_ip":"198.51.100.9"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"compat-v6","source_ip":"::192.0.2.7"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"plain-v6","source_ip":"2001:db8::7"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"no-source","trace":1}` + "\n" +
		"\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"both-spellings","source_ip":"192.0.2.9","src_ip":"::ffff:192.0.2.9","keep":{"n":2}}` + "\n" +
		`{"timestamp":"not-a-time","action":"bad-time-outside","source_ip":"198.51.100.77"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00.5Z","action":"心跳","source_ip":"192.0.2.7","detail":"转义\\与中文🙂"}` + "\r\n" +
		`{"timestamp":"2026-12-31T23:59:59-01:00","action":"tail-hit","source_ip":"192.0.2.50","msg":"结束🚀"}`
}

// The whole fixture must come out identically under whole-read,
// many-lines-per-read, byte-at-a-time, and long/short alternation, and the
// business results must hold in every case.
func TestNormalizeReaderFilteredChunkedFixture(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	input := filteredChunkedFixture()
	base, failures := assertFilteredChunkingInvariant(t, input, &filter)

	if failures != 1 {
		t.Fatalf("only the invalid-timestamp line may count as a failure, got %d", failures)
	}
	results := decodeResults(t, []byte(base))
	if len(results) != 6 {
		t.Fatalf("expected hits on lines 1,4,10,12,13 plus the line-11 failure = 6 records, got %d: %#v", len(results), results)
	}

	// Line numbers are the ORIGINAL physical numbers: blank lines 2/3/9 and
	// silently dropped lines 5-8 must not compress or renumber anything.
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 hit must keep physical number 1: %#v", results[0])
	}
	first := eventOf(t, results[0])
	if first["timestamp"] != "2026-01-02T00:04:05Z" {
		t.Fatalf("line 1 timestamp must normalize to UTC, got %v", first["timestamp"])
	}
	if first["source_ip"] != "192.0.2.7" {
		t.Fatalf("line 1 source mismatch: %v", first["source_ip"])
	}
	if first["action"] != "登录" {
		t.Fatalf("line 1 action must be trimmed, got %q", first["action"])
	}
	firstExtra := extraOf(t, results[0])
	if firstExtra["user"] != " 爱丽丝 " {
		t.Fatalf("line 1 extra must keep exact spacing, got %q", firstExtra["user"])
	}
	if firstExtra["note"] != `换行
与"引号"和中文\斜杠` {
		t.Fatalf("line 1 escaped extra must decode intact across chunk boundaries, got %q", firstExtra["note"])
	}
	if firstExtra["emoji"] != "🚀🙂" {
		t.Fatalf("line 1 emoji must survive chunk boundaries inside UTF-8, got %q", firstExtra["emoji"])
	}

	// ::ffff:192.0.2.7 arriving through src_ip is the same normalized source
	// as line 1 and hits on its own physical line.
	if results[1]["line"] != float64(4) || results[1]["ok"] != true {
		t.Fatalf("mapped alias hit must keep physical number 4: %#v", results[1])
	}
	if got := eventOf(t, results[1])["source_ip"]; got != "192.0.2.7" {
		t.Fatalf("mapped alias must print the dotted source, got %v", got)
	}
	if got := eventOf(t, results[1])["action"]; got != "via-alias-mapped" {
		t.Fatalf("line 4 action mismatch: %v", got)
	}

	// Canonical name and alias together spelling the equivalent mapped
	// address merge into exactly one successful record.
	if results[2]["line"] != float64(10) || results[2]["ok"] != true {
		t.Fatalf("dual-spelling hit must keep physical number 10: %#v", results[2])
	}
	tenth := eventOf(t, results[2])
	if tenth["source_ip"] != "192.0.2.9" || tenth["action"] != "both-spellings" {
		t.Fatalf("line 10 event mismatch: %#v", tenth)
	}
	if got := extraOf(t, results[2])["keep"].(map[string]any)["n"]; got != float64(2) {
		t.Fatalf("line 10 nested extra must survive, got %v", got)
	}

	// The out-of-network invalid-time line is a visible, counted failure with
	// its physical number and timestamp reason and no event -- filtering
	// never hides bad logs.
	if results[3]["line"] != float64(11) || results[3]["ok"] != false {
		t.Fatalf("outside-source invalid-time log must fail on physical line 11: %#v", results[3])
	}
	if _, exists := results[3]["event"]; exists {
		t.Fatalf("failed record must not carry an event: %#v", results[3])
	}
	if msg, _ := results[3]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("failure must keep its timestamp-specific reason, got %q", msg)
	}

	// The CRLF-terminated line keeps number 12 and its Chinese content.
	if results[4]["line"] != float64(12) || results[4]["ok"] != true {
		t.Fatalf("CRLF hit must keep physical number 12: %#v", results[4])
	}
	twelfth := eventOf(t, results[4])
	if twelfth["action"] != "心跳" || twelfth["source_ip"] != "192.0.2.7" {
		t.Fatalf("line 12 event mismatch: %#v", twelfth)
	}
	if got := extraOf(t, results[4])["detail"]; got != `转义\与中文🙂` {
		t.Fatalf("line 12 escaped content mismatch: %v", got)
	}

	// The newline-less tail is processed exactly once at clean EOF.
	if results[5]["line"] != float64(13) || results[5]["ok"] != true {
		t.Fatalf("newline-less tail hit must be processed once as line 13: %#v", results[5])
	}
	thirteenth := eventOf(t, results[5])
	if thirteenth["timestamp"] != "2027-01-01T00:59:59Z" {
		t.Fatalf("line 13 timestamp must normalize to UTC, got %v", thirteenth["timestamp"])
	}
	if thirteenth["action"] != "tail-hit" || thirteenth["source_ip"] != "192.0.2.50" {
		t.Fatalf("line 13 event mismatch: %#v", thirteenth)
	}
	if got := extraOf(t, results[5])["msg"]; got != "结束🚀" {
		t.Fatalf("line 13 emoji extra mismatch: %v", got)
	}

	for i, r := range results {
		if _, marked := r["filtered"]; marked {
			t.Fatalf("record %d must carry no filter marker: %#v", i, r)
		}
		if r["ok"] == true {
			for _, marker := range []string{"filter", "matched", "cidr"} {
				if _, present := eventOf(t, r)[marker]; present {
					t.Fatalf("record %d event must carry no %q marker: %#v", i, marker, r)
				}
			}
		}
	}

	// The filtered run only removes the unfiltered run's records; every byte
	// it does emit is evidence unchanged.
	assertFilteredOnlyRemovesRecords(t, input, base)
}

// Splitting the filtered input into exactly two pieces at every possible byte
// offset -- inside multi-byte Chinese and emoji characters, inside JSON
// escapes, between CR and LF, mid-line with no newline -- must always
// reproduce the whole-input output, records, and failure count. Each split
// also delivers a partial first chunk that must never be mistaken for a
// complete log.
func TestNormalizeReaderFilteredChunkedEveryTwoPieceSplit(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	input := `{"time":"2026-01-02T08:04:05+08:00","src_ip":"192.0.2.7","event_type":" 登录 ","note":"a\nb\"c\\d中文🚀"}` + "\r\n" +
		`{"timestamp":"not-a-time","action":"bad-outside","source_ip":"198.51.100.5"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"dropped-outside","source_ip":"198.51.100.6"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"dropped-compat-v6","source_ip":"::192.0.2.7"}` + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"尾","source_ip":"192.0.2.66","x":"🙂"}`

	var whole bytes.Buffer
	baseFailures, err := NormalizeReaderFiltered(strings.NewReader(input), &whole, &filter)
	if err != nil {
		t.Fatalf("baseline must not fail, got %v", err)
	}
	if baseFailures != 1 {
		t.Fatalf("test setup: only the outside-source bad-time log may fail, got %d", baseFailures)
	}
	for i := 0; i <= len(input); i++ {
		out, failures := normalizeChunkedFiltered(t, input, []int{i, len(input) - i}, &filter)
		if out != whole.String() || failures != baseFailures {
			t.Fatalf("split at byte %d changed the filtered result\nwhole:   %q (%d failures)\nchunked: %q (%d failures)",
				i, whole.String(), baseFailures, out, failures)
		}
	}

	// Independent of delivery: line 1 hit, line 2 failure, line 5 hit, with
	// the two dropped legal lines invisible and no renumbering.
	results := decodeResults(t, whole.Bytes())
	if len(results) != 3 {
		t.Fatalf("expected 3 records, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 mismatch: %#v", results[0])
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != false {
		t.Fatalf("outside-source invalid-time line must keep number 2 and fail: %#v", results[1])
	}
	if results[2]["line"] != float64(5) || results[2]["ok"] != true {
		t.Fatalf("newline-less tail hit must keep number 5: %#v", results[2])
	}
	if got := extraOf(t, results[2])["x"]; got != "🙂" {
		t.Fatalf("tail emoji extra mismatch: %v", got)
	}
}

// Logs larger than the 64 KiB internal read buffer need several Reads to
// collect; that must not change filter decisions, content, numbering, or the
// failure count for an oversized hit, an oversized dropped log, and the
// ordinary records around them.
func TestNormalizeReaderFilteredChunkedOversizedLines(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	hitBlob := strings.Repeat("长", 20000) + strings.Repeat("x", 40000) + "🚀"
	bigHit := `{"timestamp":"2026-01-02T00:00:00Z","action":"big-hit","source_ip":"192.0.2.7","blob":` + jsonString(hitBlob) + `}`
	if len(bigHit) <= 64*1024 {
		t.Fatalf("test setup: oversized hit must exceed 64 KiB, got %d bytes", len(bigHit))
	}
	dropBlob := strings.Repeat("y", 70000)
	bigDrop := `{"timestamp":"2026-01-02T00:00:00Z","action":"big-drop","source_ip":"198.51.100.9","blob":` + jsonString(dropBlob) + `}`
	if len(bigDrop) <= 64*1024 {
		t.Fatalf("test setup: oversized dropped log must exceed 64 KiB, got %d bytes", len(bigDrop))
	}
	input := strings.Join([]string{
		bigHit,  // line 1: admitted, needs many Reads
		bigDrop, // line 2: valid but out of network, silently dropped
		"",      // line 3: blank
		`{"timestamp":"not-a-time","action":"bad-outside","source_ip":"198.51.100.77"}`, // line 4: failure
		`{"timestamp":"2026-01-02T00:00:00Z","action":"after","source_ip":"192.0.2.8"}`, // line 5: hit
	}, "\n") + "\n" +
		`{"timestamp":"2026-01-02T00:00:00Z","action":"tail-hit","source_ip":"192.0.2.9"}` // line 6: hit, no newline

	base, failures := assertFilteredChunkingInvariant(t, input, &filter)
	if failures != 1 {
		t.Fatalf("only the line-4 invalid log may count as a failure, got %d", failures)
	}
	results := decodeResults(t, []byte(base))
	if len(results) != 4 {
		t.Fatalf("expected records for lines 1,4,5,6, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("oversized hit on line 1 must succeed: %#v", results[0])
	}
	if got := extraOf(t, results[0])["blob"]; got != hitBlob {
		t.Fatalf("oversized hit blob must be preserved verbatim (got %d chars, want %d)",
			len(got.(string)), len(hitBlob))
	}
	if results[1]["line"] != float64(4) || results[1]["ok"] != false {
		t.Fatalf("failure must keep physical number 4 after the oversized dropped line: %#v", results[1])
	}
	if _, exists := results[1]["event"]; exists {
		t.Fatalf("line 4 failure must not carry an event: %#v", results[1])
	}
	if msg, _ := results[1]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("line 4 must keep the timestamp reason, got %q", msg)
	}
	if results[2]["line"] != float64(5) || results[2]["ok"] != true {
		t.Fatalf("hit after the oversized lines must keep number 5: %#v", results[2])
	}
	if eventOf(t, results[2])["action"] != "after" {
		t.Fatalf("line 5 content mismatch: %#v", results[2])
	}
	if results[3]["line"] != float64(6) || results[3]["ok"] != true {
		t.Fatalf("newline-less tail hit must be processed once as line 6: %#v", results[3])
	}
	assertFilteredOnlyRemovesRecords(t, input, base)
}

// At clean EOF the final complete JSON without a trailing newline is handled
// exactly once under every chunking: a hit appends one success, a valid
// out-of-network log appends nothing and no failure, an invalid log appends
// one counted failure, and a whitespace tail appends nothing.
func TestNormalizeReaderFilteredChunkedNewlineLessTail(t *testing.T) {
	filter, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	head := `{"timestamp":"2026-01-02T00:00:00Z","action":"head-hit","source_ip":"192.0.2.1"}` + "\n"
	cases := []struct {
		name         string
		tail         string
		wantRecords  int
		wantFailures int
		tailLine     float64 // physical line number of the result the tail yields
		tailOK       bool
		tailAction   string
	}{
		{
			name:         "admitted tail without newline",
			tail:         `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-hit","source_ip":"192.0.2.2"}`,
			wantRecords:  2,
			wantFailures: 0,
			tailLine:     2,
			tailOK:       true,
			tailAction:   "tail-hit",
		},
		{
			name:         "valid out-of-network tail without newline",
			tail:         `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-dropped","source_ip":"198.51.100.3"}`,
			wantRecords:  1,
			wantFailures: 0,
		},
		{
			name:         "genuine IPv6 tail without newline",
			tail:         `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-v6","source_ip":"::192.0.2.2"}`,
			wantRecords:  1,
			wantFailures: 0,
		},
		{
			name:         "invalid-timestamp tail outside the network",
			tail:         `{"timestamp":"not-a-time","action":"tail-bad","source_ip":"198.51.100.4"}`,
			wantRecords:  2,
			wantFailures: 1,
			tailLine:     2,
			tailOK:       false,
		},
		{
			name:         "whitespace-only tail",
			tail:         "  \t \r",
			wantRecords:  1,
			wantFailures: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := head + tc.tail
			base, failures := assertFilteredChunkingInvariant(t, input, &filter)
			if failures != tc.wantFailures {
				t.Fatalf("want %d failures, got %d", tc.wantFailures, failures)
			}
			results := decodeResults(t, []byte(base))
			if len(results) != tc.wantRecords {
				t.Fatalf("want %d records, got %#v", tc.wantRecords, results)
			}
			if results[0]["line"] != float64(1) || eventOf(t, results[0])["action"] != "head-hit" {
				t.Fatalf("head record mismatch: %#v", results[0])
			}
			if tc.wantRecords == 2 {
				tail := results[1]
				if tail["line"] != tc.tailLine || tail["ok"] != tc.tailOK {
					t.Fatalf("tail result must be line %v with ok=%v: %#v", tc.tailLine, tc.tailOK, tail)
				}
				if tc.tailOK {
					if eventOf(t, tail)["action"] != tc.tailAction {
						t.Fatalf("tail event mismatch: %#v", tail)
					}
				} else {
					if _, exists := tail["event"]; exists {
						t.Fatalf("tail failure must not carry an event: %#v", tail)
					}
					if msg, _ := tail["error"].(string); !strings.Contains(msg, FieldTimestamp) {
						t.Fatalf("tail failure must keep the timestamp reason, got %q", msg)
					}
				}
			}
			assertFilteredOnlyRemovesRecords(t, input, base)
		})
	}
}
