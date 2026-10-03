package relayproof

import (
	"strings"
	"testing"
)

// Only space, tab, CR, and LF may surround a log object. Any other
// whitespace-like character at either edge of a non-blank line is not legal
// JSON separation and must fail the line as invalid JSON — it must not be
// trimmed away before parsing.
func TestNormalizeNonJSONSeparatorWhitespaceFails(t *testing.T) {
	object := `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}`
	cases := map[string]string{
		"leading vertical tab":    "\v" + object,
		"trailing vertical tab":   object + "\v",
		"leading form feed":       "\f" + object,
		"trailing form feed":      object + "\f",
		"leading no-break space":  "\u00a0" + object,
		"trailing no-break space": object + "\u00a0",
		"both sides":              "\v" + object + "\f",
		"mixed with legal space":  " \t\v " + object + " \f\t ",
		"between legal padding":   " \f " + object,
	}
	for name, in := range cases {
		results := runNormalize(t, in)
		if len(results) != 1 || results[0]["ok"] != false {
			t.Fatalf("%s: expected one failed result, got %#v", name, results)
		}
		if _, hasEvent := results[0]["event"]; hasEvent {
			t.Fatalf("%s: failed line must not carry an event: %#v", name, results[0])
		}
		errText, _ := results[0]["error"].(string)
		if !strings.Contains(errText, "invalid JSON") {
			t.Fatalf("%s: error must report the JSON syntax problem, got %q", name, errText)
		}
	}
}

// The syntax failure from illegal edge whitespace is reported before any
// field-level problem inside the object.
func TestNormalizeIllegalEdgeWhitespacePrecedesFieldErrors(t *testing.T) {
	// Missing timestamp, empty action, and conflicting aliases inside; the
	// leading vertical tab must still be the reported problem.
	in := "\v{\"event_type\":\" \",\"action\":\"\"}"
	results := runNormalize(t, in)
	if len(results) != 1 || results[0]["ok"] != false {
		t.Fatalf("expected one failed result, got %#v", results)
	}
	errText, _ := results[0]["error"].(string)
	if !strings.Contains(errText, "invalid JSON") {
		t.Fatalf("edge whitespace must fail as invalid JSON before field errors, got %q", errText)
	}
}

// A bad line fails in place; surrounding valid lines still process in input
// order with their physical line numbers.
func TestNormalizeIllegalWhitespaceLineNumbering(t *testing.T) {
	input := "{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"a\"}\n" +
		"\f{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"b\"}\n" +
		"\n" +
		"{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"c\"}\n"
	results := runNormalize(t, input)
	if len(results) != 3 {
		t.Fatalf("expected 3 results for 4 physical lines, got %#v", results)
	}
	if results[0]["line"] != float64(1) || results[0]["ok"] != true {
		t.Fatalf("line 1 mismatch: %#v", results[0])
	}
	if results[1]["line"] != float64(2) || results[1]["ok"] != false {
		t.Fatalf("line 2 must fail: %#v", results[1])
	}
	if results[2]["line"] != float64(4) || results[2]["ok"] != true {
		t.Fatalf("line 4 must still succeed: %#v", results[2])
	}
}

// NormalizeLine must make the same syntax judgment as the streaming path.
func TestNormalizeLineIllegalWhitespaceParity(t *testing.T) {
	object := `{"timestamp":"2026-01-02T00:00:00Z","action":"a"}`
	for _, in := range []string{"\v" + object, object + "\f", "\u00a0" + object} {
		result := NormalizeLine(7, []byte(in+"\n"))
		if result.OK {
			t.Fatalf("NormalizeLine must reject non-JSON edge whitespace: %q", in)
		}
		if result.Line != 7 {
			t.Fatalf("line number must echo through, got %d", result.Line)
		}
		if !strings.Contains(result.Error, "invalid JSON") {
			t.Fatalf("NormalizeLine error must report invalid JSON, got %q", result.Error)
		}
	}
	ok := NormalizeLine(3, []byte(" \t"+object+" \r\n"))
	if !ok.OK {
		t.Fatalf("legal JSON whitespace around the object must still pass: %v", ok.Error)
	}
}

// Whitespace-like characters inside the JSON document stay legal: no-break
// spaces and non-ASCII text in string values, escaped tab/form feed, and
// unknown-field content preserved in extra.
func TestNormalizeWhitespaceInsideStringsUnaffected(t *testing.T) {
	in := `{"timestamp":"2026-01-02T00:00:00Z","action":"\u00a0登录\u00a0","note":"\u00a0😀\t\f","tag":"x"}`
	results := runNormalize(t, in)
	if len(results) != 1 || results[0]["ok"] != true {
		t.Fatalf("whitespace inside strings must stay legal: %#v", results)
	}
	event := eventOf(t, results[0])
	if event["action"] != "登录" {
		t.Fatalf("mapped action keeps its existing trim behavior, got %q", event["action"])
	}
	extra := event["extra"].(map[string]any)
	if extra["note"] != "\u00a0😀\t\f" {
		t.Fatalf("extra string content must be preserved verbatim, got %q", extra["note"])
	}
}
