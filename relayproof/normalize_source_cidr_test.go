package relayproof

// Coverage for the optional --source-cidr filter: strict IPv4 network
// parsing, host-bit handling, IPv4-mapped versus other IPv6 sources, the
// "successful out-of-net event is suppressed, bad log line is not" rule,
// physical line numbering across suppressed and blank lines, and byte-for
// -byte compatibility when no filter is configured.

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
)

func mustParseSourceCIDR(t *testing.T, text string) *SourceCIDR {
	t.Helper()
	filter, err := ParseSourceCIDR(text)
	if err != nil {
		t.Fatalf("ParseSourceCIDR(%q) returned unexpected error: %v", text, err)
	}
	return filter
}

func mustParseIP(t *testing.T, text string) net.IP {
	t.Helper()
	ip := net.ParseIP(text)
	if ip == nil {
		t.Fatalf("net.ParseIP(%q) failed in test data", text)
	}
	return ip
}

func TestParseSourceCIDRHostBitsAndEndpoints(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"192.0.2.123/24", "192.0.2.0/24"}, // host bits discarded
		{"192.0.2.0/24", "192.0.2.0/24"},
		{"10.20.30.40/8", "10.0.0.0/8"},
		{"0.0.0.0/0", "0.0.0.0/0"},
		{"255.255.255.255/0", "0.0.0.0/0"},
		{"192.0.2.1/32", "192.0.2.1/32"},
		{"192.0.2.1/31", "192.0.2.0/31"},
		{"128.0.0.0/1", "128.0.0.0/1"},
	}
	for _, tc := range cases {
		filter := mustParseSourceCIDR(t, tc.in)
		if got := filter.String(); got != tc.want {
			t.Errorf("ParseSourceCIDR(%q).String() = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseSourceCIDRRejectsNonCanonicalAndIPv6(t *testing.T) {
	bad := []string{
		"",
		"192.0.2.0",          // no slash/prefix
		"192.0.2.0/",         // empty prefix
		"/24",                // empty address
		"192.0.2.0/24/",      // trailing slash
		"192.0.2.1/24/extra", // two slashes
		"192.0.2.0/33",       // prefix too large
		"192.0.2.0/100",
		"192.0.2.0/-1", // signed prefix
		"192.0.2.0/+1",
		"192.0.2.0/01",   // leading-zero prefix
		"192.0.2/24",     // missing octet
		"192.0.2.0.1/24", // five segments
		"999.0.0.1/24",   // octet out of range
		"192.0.2.256/24",
		"192.168.001.001/24", // leading-zero octets
		"0x7f.0.0.1/8",       // hex octets
		"1...1/32",           // empty octets
		"192.0.2.x/24",
		"::ffff:192.0.2.0/120", // IPv6 network
		"2001:db8::/32",
		"::/0",
		"192.0.2.0:80/24", // port-like tail
		" 192.0.2.0/24",   // surrounding whitespace
		"192.0.2.0/24 ",
	}
	for _, in := range bad {
		if _, err := ParseSourceCIDR(in); err == nil {
			t.Errorf("ParseSourceCIDR(%q) must fail", in)
		}
	}
}

func TestSourceCIDRContains(t *testing.T) {
	filter := mustParseSourceCIDR(t, "192.0.2.123/24")
	inside := []string{"192.0.2.0", "192.0.2.1", "192.0.2.255", "::ffff:192.0.2.1", "::FFFF:C000:0201"}
	outside := []string{
		"192.0.1.255", "192.0.3.0", "10.0.0.1", "0.0.0.0", "255.255.255.255",
		"::192.0.2.1",        // IPv4-compatible: still IPv6
		"::ffff:192.0.3.1",   // mapped but outside
		"2001:db8::1", "::1", // ordinary IPv6
	}
	for _, s := range inside {
		if !filter.Contains(mustParseIP(t, s)) {
			t.Errorf("%s must be inside %s", s, filter)
		}
	}
	for _, s := range outside {
		if filter.Contains(mustParseIP(t, s)) {
			t.Errorf("%s must not be inside %s", s, filter)
		}
	}

	all := mustParseSourceCIDR(t, "10.0.0.1/0")
	for _, s := range []string{"0.0.0.0", "192.0.2.1", "255.255.255.255", "::ffff:1.2.3.4"} {
		if !all.Contains(mustParseIP(t, s)) {
			t.Errorf("/0 must contain IPv4 source %s", s)
		}
	}
	if all.Contains(mustParseIP(t, "2001:db8::1")) {
		t.Errorf("/0 IPv4 network must not contain plain IPv6")
	}

	one := mustParseSourceCIDR(t, "192.0.2.1/32")
	if !one.Contains(mustParseIP(t, "::ffff:192.0.2.1")) {
		t.Errorf("/32 must contain the mapped spelling of its address")
	}
	for _, s := range []string{"192.0.2.0", "192.0.2.2"} {
		if one.Contains(mustParseIP(t, s)) {
			t.Errorf("/32 must not contain neighboring %s", s)
		}
	}
}

func TestSourceCIDRMatchesCanonicalEvents(t *testing.T) {
	filter := mustParseSourceCIDR(t, "192.0.2.0/24")
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"plain ipv4 in", "192.0.2.5", true},
		{"mapped ipv6 in", "::ffff:192.0.2.5", true},
		{"plain ipv4 out", "198.51.100.5", false},
		{"mapped ipv6 out", "::ffff:198.51.100.5", false},
		{"ipv4-compatible never matches", "::192.0.2.5", false},
		{"plain ipv6 never matches", "2001:db8::5", false},
		{"loopback ipv6 never matches", "::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := &NormalizedEvent{SourceIP: tc.ip}
			if got := filter.MatchesEvent(event); got != tc.want {
				t.Fatalf("MatchesEvent(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
	if filter.MatchesEvent(nil) {
		t.Fatalf("a nil event must not match")
	}
	if filter.MatchesEvent(&NormalizedEvent{}) {
		t.Fatalf("an event without a source must not match")
	}
}

// runNormalizeFiltered is the filtered counterpart of runNormalize, also
// returning the failure count so tests can assert suppressed successes were
// not counted as failures.
func runNormalizeFiltered(t *testing.T, input, cidr string) ([]map[string]any, int) {
	t.Helper()
	filter := mustParseSourceCIDR(t, cidr)
	var out bytes.Buffer
	failures, err := NormalizeReaderOptions(strings.NewReader(input), &out, NormalizeOptions{SourceFilter: filter})
	if err != nil {
		t.Fatalf("NormalizeReaderOptions returned error: %v", err)
	}
	results := []map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decoding result: %v", err)
		}
		results = append(results, m)
	}
	if got := countFailures(results); got != failures {
		t.Fatalf("NormalizeReaderOptions returned %d failures but output shows %d", failures, got)
	}
	return results, failures
}

// TestNormalizeFilterKeepsOnlyInNetSuccesses is the core stream scenario:
// /24 matches plain and mapped spellings; out-of-net IPv4, IPv6,
// IPv4-compatible, and sourceless successes disappear without a failure
// marker; bad lines still come through.
func TestNormalizeFilterKeepsOnlyInNetSuccesses(t *testing.T) {
	lines := []string{
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"192.0.2.5","user":"a"}`,
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"src_ip":"198.51.100.7"}`,
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"::ffff:192.0.2.1"}`,
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"::192.0.2.1"}`,
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"2001:db8::1"}`,
		`{"timestamp":` + validTS + `,"action":` + validAction + `}`,
		`{"timestamp":"not-a-time","action":` + validAction + `,"source_ip":"198.51.100.9"}`,
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"198.51.100.200"}`,
	}
	input := strings.Join(lines, "\n") + "\n"

	results, failures := runNormalizeFiltered(t, input, "192.0.2.123/24")
	if failures != 1 {
		t.Fatalf("only the genuinely bad line counts as a failure, got %d", failures)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 records (2 kept successes + 1 failure), got %d: %#v", len(results), results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 in-net success must be kept: %#v", results[0])
	}
	if got := eventOf(t, results[0])["source_ip"]; got != "192.0.2.5" {
		t.Fatalf("line 1 source_ip = %v", got)
	}
	if results[1]["line"] != float64(3) || results[1]["ok"] != true {
		t.Fatalf("line 3 mapped-IPv6 in-net success must be kept: %#v", results[1])
	}
	if got := eventOf(t, results[1])["source_ip"]; got != "192.0.2.1" {
		t.Fatalf("mapped IPv6 must be normalized to its IPv4 canonical form, got %v", got)
	}
	bad := results[2]
	if bad["line"] != float64(7) || bad["ok"] != false {
		t.Fatalf("the out-of-net bad line must still be reported as line 7: %#v", bad)
	}
	if _, exists := bad["event"]; exists {
		t.Fatalf("a failure record must never carry an event: %#v", bad)
	}
	if !strings.Contains(bad["error"].(string), FieldTimestamp) {
		t.Fatalf("the failure must keep its original cause, got %v", bad["error"])
	}
}

// TestNormalizeFilterLineNumbering proves suppressed lines and blank lines
// do not renumber later physical lines.
func TestNormalizeFilterLineNumbering(t *testing.T) {
	input := `{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"10.0.0.1"}` + "\n" +
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"192.0.2.1"}` + "\n" +
		"\n" +
		"   \n" +
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"192.0.2.2"}` + "\n" +
		`not json` + "\n" +
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"192.0.2.3"}` // no trailing newline

	results, failures := runNormalizeFiltered(t, input, "192.0.2.0/24")
	if failures != 1 {
		t.Fatalf("only physical line 6 fails, got %d failures", failures)
	}
	if len(results) != 4 {
		t.Fatalf("expected 4 records: kept lines 2,5,7 and bad line 6, got %#v", results)
	}
	wantLines := []float64{2, 5, 6, 7}
	for i, want := range wantLines {
		if results[i]["line"] != want {
			t.Fatalf("record %d must carry physical line %v, got %v: %#v", i, want, results[i]["line"], results[i])
		}
	}
	if results[2]["ok"] != false || results[3]["ok"] != true {
		t.Fatalf("line 6 must be a failure and the unnewlined line 7 a success: %#v", results)
	}
	if eventOf(t, results[3])["action"] != "login" {
		t.Fatalf("input order and content must be preserved")
	}
}

// TestNormalizeFilterZeroAndHostPrefixes pins the prefix endpoints: /0
// keeps every IPv4 source including mapped IPv6 spellings while plain IPv6
// and sourceless events are dropped; /32 keeps exactly one address.
func TestNormalizeFilterZeroAndHostPrefixes(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":` + validTS + `,"action":"a","source_ip":"0.0.0.0"}`,
		`{"timestamp":` + validTS + `,"action":"a","source_ip":"255.255.255.255"}`,
		`{"timestamp":` + validTS + `,"action":"a","source_ip":"::ffff:10.20.30.40"}`,
		`{"timestamp":` + validTS + `,"action":"a","source_ip":"::1"}`,
		`{"timestamp":` + validTS + `,"action":"a","source_ip":"2001:db8::9"}`,
		`{"timestamp":` + validTS + `,"action":"a"}`,
	}, "\n") + "\n"

	all, failures := runNormalizeFiltered(t, input, "192.0.2.123/0")
	if failures != 0 {
		t.Fatalf("all lines are legal, failures = %d", failures)
	}
	if len(all) != 3 {
		t.Fatalf("/0 must keep exactly the three IPv4 sources, got %#v", all)
	}
	for i, want := range []string{"0.0.0.0", "255.255.255.255", "10.20.30.40"} {
		if got := eventOf(t, all[i])["source_ip"]; got != want {
			t.Fatalf("record %d source_ip = %v, want %s", i, got, want)
		}
	}

	one, _ := runNormalizeFiltered(t, input, "10.20.30.40/32")
	if len(one) != 1 || eventOf(t, one[0])["source_ip"] != "10.20.30.40" {
		t.Fatalf("/32 must keep exactly 10.20.30.40 (mapped spelling), got %#v", one)
	}
}

// TestNormalizeFilterBadLineOutsideNetStillFails proves filtering cannot
// hide bad logs for every failure shape, including a line whose source is
// missing, IPv6, or outside the network.
func TestNormalizeFilterBadLineOutsideNetStillFails(t *testing.T) {
	lines := []string{
		`{"timestamp":` + validTS + `,"action":` + validAction + `}`,
		`{"timestamp":"bad","action":` + validAction + `}`,
		`{"timestamp":"bad","action":` + validAction + `,"source_ip":"2001:db8::1"}`,
		`{"timestamp":"bad","action":` + validAction + `,"source_ip":"10.0.0.1"}`,
		`{"timestamp":` + validTS + `,"action":""}`,
		`{"timestamp":` + validTS + `,"source_ip":"10.0.0.1"}`, // missing action
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"999.1.1.1"}`,
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"192.0.2.9","src_ip":"10.0.0.9"}`, // alias conflict
		`not json`,
		`{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"192.0.2.7"}`,
	}
	input := strings.Join(lines, "\n") + "\n"
	results, failures := runNormalizeFiltered(t, input, "192.0.2.0/24")
	if failures != 8 {
		t.Fatalf("lines 2-9 all fail (8 failures), got %d: %#v", failures, results)
	}
	// Line 1 (sourceless success) is suppressed; lines 2..9 are failures,
	// line 10 is the sole kept success.
	if len(results) != 9 {
		t.Fatalf("expected the 8 failures plus the in-net line 10, got %d: %#v", len(results), results)
	}
	for i := 0; i < 8; i++ {
		rec := results[i]
		if rec["ok"] != false {
			t.Fatalf("record %d must be a failure: %#v", i, rec)
		}
		if _, exists := rec["event"]; exists {
			t.Fatalf("failure record %d must not carry an event: %#v", i, rec)
		}
		if rec["line"] != float64(i+2) {
			t.Fatalf("failure %d must keep physical line %d, got %v", i, i+2, rec["line"])
		}
		if rec["error"] == "" {
			t.Fatalf("failure %d must keep its original error cause", i)
		}
	}
	if results[8]["line"] != float64(10) || results[8]["ok"] != true {
		t.Fatalf("the trailing in-net success must still be processed: %#v", results[8])
	}
}

// TestNormalizeFilterKeepsEventShapeAndContent verifies a kept record is
// byte-for-byte the same record the unfiltered run produces: no filter
// marker is added, extra boundaries and number spellings are untouched.
func TestNormalizeFilterKeepsEventShapeAndContent(t *testing.T) {
	line := `{"time":"2026-01-02T08:04:05+08:00","src_ip":"  ::ffff:192.0.2.1  ","event_type":" login ","user":"alice","big":9007199254740993}`
	var unfiltered bytes.Buffer
	if _, err := NormalizeReader(strings.NewReader(line+"\n"), &unfiltered); err != nil {
		t.Fatal(err)
	}
	results, _ := runNormalizeFiltered(t, line+"\n", "192.0.2.0/24")
	if len(results) != 1 {
		t.Fatalf("the event must be kept, got %#v", results)
	}
	var filtered bytes.Buffer
	filter := mustParseSourceCIDR(t, "192.0.2.0/24")
	if _, err := NormalizeReaderOptions(strings.NewReader(line+"\n"), &filtered, NormalizeOptions{SourceFilter: filter}); err != nil {
		t.Fatal(err)
	}
	if filtered.String() != unfiltered.String() {
		t.Fatalf("kept record must be byte-identical to the unfiltered output:\nfiltered: %q\nunfiltered: %q",
			filtered.String(), unfiltered.String())
	}
	event := eventOf(t, results[0])
	for _, key := range []string{"line", "ok", "event"} {
		if _, exists := results[0][key]; !exists {
			t.Fatalf("kept record must keep the %q key", key)
		}
	}
	for _, extraKey := range []string{"matched", "filter", "source_cidr", "cidr"} {
		if _, exists := event[extraKey]; exists {
			t.Fatalf("filtering must not add a %q marker to the event", extraKey)
		}
	}
	if event["source_ip"] != "192.0.2.1" || event["action"] != "login" || event["timestamp"] != "2026-01-02T00:04:05Z" {
		t.Fatalf("normalized event content mismatch: %#v", event)
	}
}

// TestNormalizeNoFilterCompatible verifies the options entry with a nil
// filter is exactly the public NormalizeReader behavior.
func TestNormalizeNoFilterCompatible(t *testing.T) {
	input := `{"timestamp":` + validTS + `,"action":` + validAction + `,"source_ip":"10.0.0.1"}` + "\n" +
		`{"timestamp":"bad","action":"x"}` + "\n" +
		"\n" +
		`{"timestamp":` + validTS + `,"action":"y"}`
	var a, b bytes.Buffer
	f1, err1 := NormalizeReader(strings.NewReader(input), &a)
	f2, err2 := NormalizeReaderOptions(strings.NewReader(input), &b, NormalizeOptions{})
	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: %v %v", err1, err2)
	}
	if f1 != f2 || f1 != 1 {
		t.Fatalf("failure counts must match and equal 1, got %d %d", f1, f2)
	}
	if a.String() != b.String() {
		t.Fatalf("nil filter must reproduce NormalizeReader output:\n%q\n%q", a.String(), b.String())
	}

	// Explicit nil pointer inside options is the same default.
	var c bytes.Buffer
	if _, err := NormalizeReaderOptions(strings.NewReader(input), &c, NormalizeOptions{SourceFilter: nil}); err != nil {
		t.Fatal(err)
	}
	if c.String() != a.String() {
		t.Fatalf("nil SourceFilter must reproduce NormalizeReader output")
	}
}

// TestNormalizeFilterAllSuppressedExitsClean covers "no success records at
// all": the stream ends normally with zero failures, which drives CLI exit
// status 0 even though stdout is empty.
func TestNormalizeFilterAllSuppressedExitsClean(t *testing.T) {
	for _, input := range []string{
		`{"timestamp":` + validTS + `,"action":"a","source_ip":"10.0.0.1"}` + "\n",
		`{"timestamp":` + validTS + `,"action":"a"}` + "\n",
		`{"timestamp":` + validTS + `,"action":"a","source_ip":"2001:db8::1"}` + "\n",
		"",
	} {
		var out bytes.Buffer
		filter := mustParseSourceCIDR(t, "192.0.2.0/24")
		failures, err := NormalizeReaderOptions(strings.NewReader(input), &out, NormalizeOptions{SourceFilter: filter})
		if err != nil {
			t.Fatalf("filtered run must not be a stream error: %v", err)
		}
		if failures != 0 {
			t.Fatalf("suppressed successes are not failures, got %d", failures)
		}
		if out.Len() != 0 {
			t.Fatalf("nothing matched, stdout must be empty, got %q", out.String())
		}
	}
}
