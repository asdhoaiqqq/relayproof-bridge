package main

// End-to-end behaviour when an existing state directory's queue.log carries
// a complete, checksum-valid header record that names BOTH root forms. Such a
// record is on-disk corruption (ErrCorrupt), not the live ErrHeaderConflict a
// user gets for same-height/different-root saves: opening the directory must
// fail with the corrupt exit code 12, say plainly that the header root carried
// both representations, print no query results, and leave queue.log
// byte-for-byte untouched — even when the offending record is the final frame
// (a complete record is never treated as a torn tail).

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cliLogMagic = "RELAYPROOF-QUEUE-V1\n"

// cliFrame wraps a JSON payload exactly as the queue log stores records:
// uint32-be length, payload, uint32-be CRC32-IEEE.
func cliFrame(payload []byte) []byte {
	frame := make([]byte, 0, 4+len(payload)+4)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	frame = append(frame, hdr[:]...)
	frame = append(frame, payload...)
	var crc [4]byte
	binary.BigEndian.PutUint32(crc[:], crc32.ChecksumIEEE(payload))
	frame = append(frame, crc[:]...)
	return frame
}

// cliLogWithCorruptHeader builds the smallest corrupt log: a valid leading
// version record followed by one complete trusted header naming both "root":""
// and a rootB64 that decodes to byte 0xFF — the exact gap the fix closes.
func cliLogWithCorruptHeader() []byte {
	var raw []byte
	raw = append(raw, cliLogMagic...)
	raw = append(raw, cliFrame([]byte(`{"t":"version","v":1}`))...)
	raw = append(raw, cliFrame([]byte(
		`{"t":"header","chain":"x","height":100,"trusted":true,"root":"","rootB64":"/w=="}`))...)
	return raw
}

func writeCLIStateLog(t *testing.T, state string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(state, "queue.log"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// assertCorruptExit12 opens the directory via the given CLI result and pins
// the corruption surface: exit code 12 (never the 16 header-conflict code),
// no stdout query output, a stderr explanation that names the two root
// representations, and an unchanged queue.log.
func assertCorruptExit12(t *testing.T, r cliResult, state string, wantLog []byte) {
	t.Helper()
	if r.code != 12 {
		t.Fatalf("want corrupt exit code 12, got %d (stdout=%q stderr=%q)", r.code, r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a corrupt directory must print no query results: %q", r.stdout)
	}
	for _, want := range []string{"corrupt", "both root and rootB64"} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("stderr missing %q:\n%s", want, r.stderr)
		}
	}
	if strings.Contains(r.stderr, "trusted header conflict") {
		t.Fatalf("on-disk dual-root corruption must not be reported as a live header conflict:\n%s", r.stderr)
	}
	got, err := os.ReadFile(filepath.Join(state, "queue.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wantLog) {
		t.Fatalf("queue.log changed on rejected open: want %d bytes, got %d bytes", len(wantLog), len(got))
	}
}

// A complete trusted header at the end of the log carrying both "root":"" and
// rootB64 rejects the directory on open: `queue query` (both the listing and a
// single-id lookup) exits 12 without output, names both root forms, and a
// repeated open keeps failing with the file untouched — it is never dropped as
// an unwritten torn tail.
func TestCLIQueryDualRootHeaderCorruptExit12(t *testing.T) {
	state := t.TempDir()
	raw := cliLogWithCorruptHeader()
	writeCLIStateLog(t, state, raw)

	assertCorruptExit12(t, queueCLI(t, state, "query"), state, raw)

	// Single-id lookup opens the same directory and must fail identically.
	assertCorruptExit12(t, queueCLI(t, state, "query", "--id", "anything"), state, raw)

	// The directory stays unopenable and byte-identical on a further attempt.
	assertCorruptExit12(t, queueCLI(t, state, "query"), state, raw)
}

// The dual-root record is corruption even when perfectly good records precede
// it: the listing must surface none of the normal messages already stored,
// proving the whole open is refused rather than partially served.
func TestCLIQueryDualRootHeaderHidesNormalResults(t *testing.T) {
	state := t.TempDir()

	// Lay down normal, accepted state through the real CLI: a registered
	// source, a trusted header covering height 90, and a deliverable message.
	registerSource(t, state, "x")
	if r := storeHeader(t, state, "x", 100, "0xaaa", true); r.code != 0 {
		t.Fatalf("store initial header: %v", r)
	}
	submitMsg(t, state, "m1", "x", "y", 1, 90)

	// Append the corrupt dual-root header as the final, complete frame.
	path := filepath.Join(state, "queue.log")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, cliFrame([]byte(
		`{"t":"header","chain":"x","height":200,"trusted":true,"root":"","rootB64":"/w=="}`))...)
	writeCLIStateLog(t, state, raw)

	r := queueCLI(t, state, "query")
	assertCorruptExit12(t, r, state, raw)
	if strings.Contains(r.stdout, "m1") {
		t.Fatalf("normal message must not be served from a corrupt directory: %q", r.stdout)
	}
}
