package relayproof

import (
	"encoding/json"
	"strings"
	"testing"
)

func normalizeOK(t *testing.T, line string) *Event {
	t.Helper()
	event, err := NormalizeLog(line)
	if err != nil {
		t.Fatalf("NormalizeLog(%q) unexpected error: %v", line, err)
	}
	return event
}

func normalizeFail(t *testing.T, line string) string {
	t.Helper()
	event, err := NormalizeLog(line)
	if err == nil {
		t.Fatalf("NormalizeLog(%q) expected error, got event %+v", line, event)
	}
	if event != nil {
		t.Fatalf("NormalizeLog(%q) returned event alongside error: %+v", line, event)
	}
	return err.Error()
}

func TestNormalizeMinimal(t *testing.T) {
	event := normalizeOK(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"login"}`)
	if event.Timestamp != "2024-01-01T00:00:00Z" {
		t.Errorf("timestamp = %q", event.Timestamp)
	}
	if event.Action != "login" {
		t.Errorf("action = %q", event.Action)
	}
	if event.SourceIP != "" {
		t.Errorf("source_ip = %q, want empty", event.SourceIP)
	}
	if event.Extra != nil {
		t.Errorf("extra = %v, want nil", event.Extra)
	}
}

func TestNormalizeAliases(t *testing.T) {
	event := normalizeOK(t, `{"time":"2024-01-01T08:00:00+08:00","event_type":"login","src_ip":"1.2.3.4"}`)
	if event.Timestamp != "2024-01-01T00:00:00Z" {
		t.Errorf("timestamp = %q", event.Timestamp)
	}
	if event.Action != "login" {
		t.Errorf("action = %q", event.Action)
	}
	if event.SourceIP != "1.2.3.4" {
		t.Errorf("source_ip = %q", event.SourceIP)
	}
}

func TestNormalizeTimeUTC(t *testing.T) {
	cases := map[string]string{
		"2024-01-01T08:00:00+08:00":      "2024-01-01T00:00:00Z",
		"2024-01-01T00:00:00-05:00":      "2024-01-01T05:00:00Z",
		"2024-01-01T00:00:00.123456789Z": "2024-01-01T00:00:00.123456789Z",
		"2024-01-01T00:00:00.100Z":       "2024-01-01T00:00:00.1Z",
		"2024-01-01T00:00:00.120Z":       "2024-01-01T00:00:00.12Z",
	}
	for in, want := range cases {
		event := normalizeOK(t, `{"timestamp":`+jsonString(in)+`,"action":"a"}`)
		if event.Timestamp != want {
			t.Errorf("timestamp(%s) = %q, want %q", in, event.Timestamp, want)
		}
	}
}

func TestNormalizeTimeFractionTooLong(t *testing.T) {
	err := normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00.1234567890Z","action":"a"}`)
	if !strings.Contains(err, "timestamp") {
		t.Errorf("error %q does not name timestamp", err)
	}
}

func TestNormalizeTimeRejectsNaive(t *testing.T) {
	normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00","action":"a"}`)
}

func TestNormalizeIPCanonical(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4": "1.2.3.4",
		"2001:0db8:0000:0000:0000:0000:0000:0001": "2001:db8::1",
		"2001:db8::1":      "2001:db8::1",
		"::ffff:1.2.3.4":   "1.2.3.4",
		"::ffff:0102:0304": "1.2.3.4",
		"0:0:0:0:0:0:0:1":  "::1",
	}
	for in, want := range cases {
		event := normalizeOK(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"a","source_ip":`+jsonString(in)+`}`)
		if event.SourceIP != want {
			t.Errorf("source_ip(%s) = %q, want %q", in, event.SourceIP, want)
		}
	}
}

func TestNormalizeIPRejectsPort(t *testing.T) {
	for _, in := range []string{"1.2.3.4:80", "[2001:db8::1]:80", "1.2.3.4:0"} {
		err := normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"a","source_ip":`+jsonString(in)+`}`)
		if !strings.Contains(err, "source_ip") {
			t.Errorf("error %q does not name source_ip", err)
		}
	}
}

func TestNormalizeIPRejectsGarbage(t *testing.T) {
	normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"a","source_ip":"not-an-ip"}`)
	normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"a","source_ip":""}`)
	// Go's net.ParseIP deliberately rejects leading-zero IPv4 octets.
	normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"a","source_ip":"001.002.003.004"}`)
}

func TestNormalizeTrimsStrings(t *testing.T) {
	event := normalizeOK(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"  login  ","source_ip":" 1.2.3.4 "}`)
	if event.Action != "login" {
		t.Errorf("action = %q", event.Action)
	}
	if event.SourceIP != "1.2.3.4" {
		t.Errorf("source_ip = %q", event.SourceIP)
	}
}

func TestNormalizeActionEmpty(t *testing.T) {
	err := normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"   "}`)
	if !strings.Contains(err, "action") {
		t.Errorf("error %q does not name action", err)
	}
}

func TestNormalizeNullNotMissing(t *testing.T) {
	for _, line := range []string{
		`{"timestamp":null,"action":"a"}`,
		`{"timestamp":"2024-01-01T00:00:00Z","action":null}`,
		`{"timestamp":"2024-01-01T00:00:00Z","action":"a","source_ip":null}`,
		`{"time":null,"event_type":"a"}`,
	} {
		normalizeFail(t, line)
	}
}

func TestNormalizeWrongType(t *testing.T) {
	for _, line := range []string{
		`{"timestamp":1700000000,"action":"a"}`,
		`{"timestamp":"2024-01-01T00:00:00Z","action":123}`,
		`{"timestamp":"2024-01-01T00:00:00Z","action":"a","source_ip":42}`,
		`{"timestamp":"2024-01-01T00:00:00Z","action":true}`,
	} {
		normalizeFail(t, line)
	}
}

func TestNormalizeMissingRequired(t *testing.T) {
	err := normalizeFail(t, `{"action":"a"}`)
	if !strings.Contains(err, "timestamp") {
		t.Errorf("error %q does not name timestamp", err)
	}
	err = normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z"}`)
	if !strings.Contains(err, "action") {
		t.Errorf("error %q does not name action", err)
	}
}

func TestNormalizeConflict(t *testing.T) {
	err := normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z","time":"2024-01-02T00:00:00Z","action":"a"}`)
	if !strings.Contains(err, "timestamp") {
		t.Errorf("error %q does not name timestamp", err)
	}
	err = normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"a","event_type":"b"}`)
	if !strings.Contains(err, "action") {
		t.Errorf("error %q does not name action", err)
	}
	err = normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"a","source_ip":"1.2.3.4","src_ip":"5.6.7.8"}`)
	if !strings.Contains(err, "source_ip") {
		t.Errorf("error %q does not name source_ip", err)
	}
}

func TestNormalizeConflictEqualMerges(t *testing.T) {
	event := normalizeOK(t, `{"timestamp":"2024-01-01T00:00:00Z","time":"2024-01-01T08:00:00+08:00","action":"a","event_type":"a"}`)
	if event.Timestamp != "2024-01-01T00:00:00Z" {
		t.Errorf("timestamp = %q", event.Timestamp)
	}
	if event.Action != "a" {
		t.Errorf("action = %q", event.Action)
	}
	if event.Extra != nil {
		t.Errorf("extra = %v, want nil (aliases consumed)", event.Extra)
	}
}

func TestNormalizeAllCandidatesMustBeValid(t *testing.T) {
	// One valid candidate must not excuse an invalid alias.
	normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z","time":"not-a-time","action":"a"}`)
	normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"a","event_type":""}`)
	normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"a","source_ip":"1.2.3.4","src_ip":null}`)
}

func TestNormalizeDuplicateTopLevelKey(t *testing.T) {
	normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z","timestamp":"2024-01-01T00:00:00Z","action":"a"}`)
	normalizeFail(t, `{"action":"a","action":"a","timestamp":"2024-01-01T00:00:00Z"}`)
}

func TestNormalizeExtraPreserved(t *testing.T) {
	event := normalizeOK(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"a","foo":"bar","nested":{"x":[1,2,{"y":true}],"z":null},"num":3.5,"flag":false}`)
	if event.Extra == nil {
		t.Fatal("extra is nil")
	}
	want := map[string]string{
		"foo":    `"bar"`,
		"nested": `{"x":[1,2,{"y":true}],"z":null}`,
		"num":    `3.5`,
		"flag":   `false`,
	}
	for key, wantRaw := range want {
		got, ok := event.Extra[key]
		if !ok {
			t.Errorf("extra missing key %q", key)
			continue
		}
		if string(got) != wantRaw {
			t.Errorf("extra[%s] = %s, want %s", key, got, wantRaw)
		}
	}
}

func TestNormalizeInputExtraKeptAsField(t *testing.T) {
	event := normalizeOK(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"a","extra":{"kept":true}}`)
	got, ok := event.Extra["extra"]
	if !ok {
		t.Fatal("input extra was not preserved as an ordinary field")
	}
	if string(got) != `{"kept":true}` {
		t.Errorf("extra[extra] = %s", got)
	}
}

func TestNormalizeNotAnObject(t *testing.T) {
	normalizeFail(t, `[1,2,3]`)
	normalizeFail(t, `"a string"`)
	normalizeFail(t, `42`)
	normalizeFail(t, `null`)
}

func TestNormalizeInvalidJSON(t *testing.T) {
	normalizeFail(t, `{not json`)
	normalizeFail(t, `{"timestamp":"2024-01-01T00:00:00Z","action":"a"} trailing`)
	normalizeFail(t, ``)
}

func TestNormalizeDeterministic(t *testing.T) {
	line := `{"time":"2024-01-01T08:00:00+08:00","event_type":"login","src_ip":"2001:0db8::1","foo":{"bar":1}}`
	first := normalizeOK(t, line)
	second := normalizeOK(t, line)
	if first.Timestamp != second.Timestamp || first.Action != second.Action ||
		first.SourceIP != second.SourceIP || string(mustMarshal(t, first.Extra)) != string(mustMarshal(t, second.Extra)) {
		t.Errorf("non-deterministic normalization: %+v vs %+v", first, second)
	}
}

func TestNormalizeLineResult(t *testing.T) {
	res := NormalizeLine(`{"timestamp":"2024-01-01T00:00:00Z","action":"a"}`, 7)
	if !res.OK || res.Line != 7 || res.Event == nil || res.Error != "" {
		t.Errorf("unexpected result: %+v", res)
	}
	res = NormalizeLine(`{"action":"a"}`, 8)
	if res.OK || res.Line != 8 || res.Event != nil || res.Error == "" {
		t.Errorf("unexpected result: %+v", res)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
