package main

// End-to-end behaviour when an existing state directory's queue.log carries a
// complete, checksummed submit record that names BOTH payload forms — a plain
// "payload" and a "payloadB64" — including the previously accepted shape
// "payload":"" together with a payloadB64 that decodes to byte 0xFF. Such a
// record is on-disk corruption (ErrCorrupt), not a live same-id content
// conflict: opening the directory must fail with the corrupt exit code 12, say
// plainly that the message content carried both representations, print no
// query results, and leave queue.log byte-for-byte untouched — even when the
// offending record is the final frame (a complete record is never treated as
// a torn tail) and even when normal records precede it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// assertPayloadCorruptExit12 pins the corruption surface of a dual-payload
// record: exit code 12 (never the 13 content-conflict code), no stdout query
// output, a stderr explanation naming the two message-content representations,
// and an unchanged queue.log.
func assertPayloadCorruptExit12(t *testing.T, r cliResult, state string, wantLog []byte) {
	t.Helper()
	if r.code != 12 {
		t.Fatalf("want corrupt exit code 12, got %d (stdout=%q stderr=%q)", r.code, r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a corrupt directory must print no query results: %q", r.stdout)
	}
	for _, want := range []string{"corrupt", "both payload and payloadB64"} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("stderr missing %q:\n%s", want, r.stderr)
		}
	}
	if strings.Contains(r.stderr, "message id conflict") {
		t.Fatalf("dual-payload on-disk corruption must not be reported as a live content conflict:\n%s", r.stderr)
	}
	got, err := os.ReadFile(filepath.Join(state, "queue.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wantLog) {
		t.Fatalf("queue.log changed on rejected open: want %d bytes, got %d bytes", len(wantLog), len(got))
	}
}

// A complete submit record at the end of the log carrying both "payload":""
// and a payloadB64 of 0xFF rejects the directory on open: `queue query` (the
// listing and a single-id lookup alike) exits 12 without output and names both
// payload forms; even a fresh `queue submit` cannot open or append to the
// directory (so no frame is added), and a repeated open keeps failing with the
// file untouched — the complete record is never dropped as an unwritten torn
// tail.
func TestCLIQueryDualPayloadSubmitCorruptExit12(t *testing.T) {
	state := t.TempDir()
	var raw []byte
	raw = append(raw, cliLogMagic...)
	raw = append(raw, cliFrame([]byte(`{"t":"version","v":1}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10,"payload":"","payloadB64":"/w=="}`))...)
	writeCLIStateLog(t, state, raw)

	assertPayloadCorruptExit12(t, queueCLI(t, state, "query"), state, raw)

	// A single-id lookup opens the same directory and must fail identically.
	assertPayloadCorruptExit12(t, queueCLI(t, state, "query", "--id", "m"), state, raw)

	// Any other command that opens the queue fails the same way and must not
	// have appended a frame before the error surfaced.
	r := queueCLI(t, state, "submit",
		"--id", "other", "--from", "a", "--to", "b",
		"--nonce", "2", "--proof-at", "10", "--payload", "fresh")
	assertPayloadCorruptExit12(t, r, state, raw)

	// The directory stays unopenable and byte-identical on a further attempt.
	assertPayloadCorruptExit12(t, queueCLI(t, state, "query"), state, raw)
}

// The dual-payload record is corruption even when perfectly good records
// precede it: the listing surfaces none of the normal messages already
// stored, proving the whole open is refused rather than partially served.
func TestCLIQueryDualPayloadSubmitHidesNormalResults(t *testing.T) {
	state := t.TempDir()

	// Lay down one normal, accepted message through the real CLI.
	submitMsg(t, state, "m1", "x", "y", 1, 90)

	// Append the corrupt dual-payload submit as the final, complete frame. Its
	// declared seq 1 follows the real message's seq 0; it still fails on the
	// conflicting content representations before any record is restored.
	path := filepath.Join(state, "queue.log")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, cliFrame([]byte(
		`{"t":"submit","seq":1,"id":"bad","from":"x","to":"y","nonce":2,"proofAt":90,"payload":"","payloadB64":"/w=="}`))...)
	writeCLIStateLog(t, state, raw)

	r := queueCLI(t, state, "query")
	assertPayloadCorruptExit12(t, r, state, raw)
	if strings.Contains(r.stdout, "m1") {
		t.Fatalf("normal message must not be served from a corrupt directory: %q", r.stdout)
	}
}

// Field-name casing cannot smuggle a second payload representation past the
// recovery check: a complete final record mixing cased spellings — here an
// uppercase plain key together with an uppercase base64 key — still opens with
// exit 12, prints nothing, names both representations and leaves every byte in
// place, for both the listing and a single-id lookup. An all-caps base64
// spelling whose value does not decode is the same refusal but with the
// undecodable wording rather than the both-representations wording.
func TestCLIQueryCasedPayloadKeysCorruptExit12(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"cased both representations",
			`{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10,"PAYLOAD":"","PAYLOADB64":"/w=="}`,
			"both payload and payloadB64",
		},
		{
			"cased undecodable base64",
			`{"t":"submit","seq":0,"id":"m","from":"a","to":"b","nonce":1,"proofAt":10,"PAYLOADB64":"!!!not-base64!!!"}`,
			"undecodable payloadB64",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := t.TempDir()
			var raw []byte
			raw = append(raw, cliLogMagic...)
			raw = append(raw, cliFrame([]byte(`{"t":"version","v":1}`))...)
			raw = append(raw, cliFrame([]byte(tc.body))...)
			writeCLIStateLog(t, state, raw)

			for _, r := range []cliResult{
				queueCLI(t, state, "query"),
				queueCLI(t, state, "query", "--id", "m"),
			} {
				if r.code != 12 {
					t.Fatalf("want corrupt exit code 12, got %d (stdout=%q stderr=%q)",
						r.code, r.stdout, r.stderr)
				}
				if r.stdout != "" {
					t.Fatalf("a corrupt directory must print no query results: %q", r.stdout)
				}
				if !strings.Contains(r.stderr, "corrupt") || !strings.Contains(r.stderr, tc.want) {
					t.Fatalf("stderr must name the verdict %q:\n%s", tc.want, r.stderr)
				}
				if strings.Contains(r.stderr, "message id conflict") {
					t.Fatalf("on-disk corruption must not read as a live content conflict:\n%s", r.stderr)
				}
			}

			got, err := os.ReadFile(filepath.Join(state, "queue.log"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(raw) {
				t.Fatalf("queue.log changed on rejected open: want %d bytes, got %d bytes",
					len(raw), len(got))
			}
		})
	}
}
