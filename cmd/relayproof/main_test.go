package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func runStream(t *testing.T, input string) (string, bool, error) {
	t.Helper()
	var out bytes.Buffer
	failed, err := normalizeStream(strings.NewReader(input), &out)
	return out.String(), failed, err
}

func TestNormalizeStreamAllValid(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":"2024-01-01T00:00:00Z","action":"a"}`,
		`{"time":"2024-01-01T08:00:00+08:00","event_type":"b","src_ip":"::1"}`,
	}, "\n") + "\n"
	out, failed, err := runStream(t, input)
	if err != nil || failed {
		t.Fatalf("err=%v failed=%v", err, failed)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d output lines: %q", len(lines), out)
	}
	if !strings.Contains(lines[0], `"line":1`) || !strings.Contains(lines[0], `"ok":true`) {
		t.Errorf("line 1: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"line":2`) || !strings.Contains(lines[1], `"source_ip":"::1"`) {
		t.Errorf("line 2: %s", lines[1])
	}
}

func TestNormalizeStreamEmpty(t *testing.T) {
	out, failed, err := runStream(t, "")
	if err != nil || failed {
		t.Fatalf("err=%v failed=%v", err, failed)
	}
	if out != "" {
		t.Errorf("expected no output, got %q", out)
	}
}

func TestNormalizeStreamBlankLinesCounted(t *testing.T) {
	input := "\n   \n\n{\"timestamp\":\"2024-01-01T00:00:00Z\",\"action\":\"a\"}\n\n"
	out, failed, err := runStream(t, input)
	if err != nil || failed {
		t.Fatalf("err=%v failed=%v", err, failed)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d output lines: %q", len(lines), out)
	}
	if !strings.Contains(lines[0], `"line":4`) {
		t.Errorf("blank lines not counted, got %s", lines[0])
	}
}

func TestNormalizeStreamFailuresKeepOrder(t *testing.T) {
	input := strings.Join([]string{
		`{"timestamp":"2024-01-01T00:00:00Z","action":"a"}`,
		`not json`,
		`{"action":"a"}`,
		`{"timestamp":"2024-01-01T00:00:00Z","action":"b"}`,
	}, "\n") + "\n"
	out, failed, err := runStream(t, input)
	if err != nil || !failed {
		t.Fatalf("err=%v failed=%v", err, failed)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d output lines: %q", len(lines), out)
	}
	for i, want := range []string{`"ok":true`, `"ok":false`, `"ok":false`, `"ok":true`} {
		if !strings.Contains(lines[i], want) {
			t.Errorf("line %d: want %s, got %s", i+1, want, lines[i])
		}
		if !strings.Contains(lines[i], `"line":`) {
			t.Errorf("line %d missing line number: %s", i+1, lines[i])
		}
	}
	if !strings.Contains(lines[1], `"error":`) || !strings.Contains(lines[2], `"error":`) {
		t.Errorf("failure lines must carry errors: %q / %q", lines[1], lines[2])
	}
	if strings.Contains(lines[1], `"event":`) {
		t.Errorf("failure line must not carry an event: %s", lines[1])
	}
}

func TestNormalizeStreamFailureNamesField(t *testing.T) {
	input := `{"timestamp":"2024-01-01T00:00:00Z","action":"a","source_ip":"nope"}` + "\n"
	out, failed, err := runStream(t, input)
	if err != nil || !failed {
		t.Fatalf("err=%v failed=%v", err, failed)
	}
	if !strings.Contains(out, `"ok":false`) || !strings.Contains(out, `source_ip`) {
		t.Errorf("output = %s", out)
	}
}

func TestNormalizeStreamDeterministic(t *testing.T) {
	input := strings.Join([]string{
		`{"time":"2024-01-01T08:00:00+08:00","event_type":"a","src_ip":"2001:db8::1","x":1}`,
		`{"timestamp":"2024-01-01T00:00:00Z","action":"a"}`,
	}, "\n") + "\n"
	first, _, _ := runStream(t, input)
	second, _, _ := runStream(t, input)
	if first != second {
		t.Errorf("non-deterministic output:\n%s\nvs\n%s", first, second)
	}
}

func TestUsageContainsNormalize(t *testing.T) {
	// usage must mention the new subcommand.
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	usage()
	os.Stdout = orig
	w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "normalize") {
		t.Errorf("usage %q does not mention normalize", buf.String())
	}
}
