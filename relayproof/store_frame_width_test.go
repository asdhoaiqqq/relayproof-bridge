package relayproof

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests pin down the architecture-independent framing rule: the log's
// uint32 declared length is read as a full unsigned value and the frame end is
// computed without integer overflow, so a 32-bit build judges a huge declared
// length exactly like a 64-bit one. A declared length a narrow int cannot hold
// (2^31, 2^32-1) — or one whose sum with its position would overflow it — must
// never wrap the record range back inside the file: the leading version record
// so declared is corrupt (ErrCorrupt, file untouched), while the same shape as
// the final record after a valid version record is the ordinary torn tail and
// is truncated, preserving every acknowledged record before it.

// hugeLengthHeader returns the four-byte big-endian frame length header
// declaring a payload of n bytes.
func hugeLengthHeader(n uint32) []byte {
	var hdr [frameHeaderSize]byte
	binary.BigEndian.PutUint32(hdr[:], n)
	return hdr[:]
}

// A first record whose declared body/checksum bytes are not all present is
// corrupt no matter how large the declared length is: the open must fail with
// ErrCorrupt, return no usable queue, and leave every byte of the log in
// place — never truncate the log to a magic-only shell or fabricate a version
// record. This holds for lengths that turn negative in a 32-bit int and for
// lengths whose end offset would overflow one.
func TestHugeDeclaredVersionLengthIsCorrupt(t *testing.T) {
	cases := map[string]uint32{
		"2^31 (negative as int32)":           1 << 31,
		"2^32-1 (max uint32)":                math.MaxUint32,
		"positive but end overflows int32":   0x7FFFFFF0,
		"positive, position pushes end over": 0x7FFFFF00,
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			data := append([]byte(logMagic), hugeLengthHeader(n)...)
			// Only a token of the declared body is present.
			data = append(data, '{')
			writeRawLog(t, dir, data)

			q, err := Open(dir)
			if !errors.Is(err, ErrCorrupt) {
				if q != nil {
					q.Close()
				}
				t.Fatalf("want ErrCorrupt, got %v (queue=%v)", err, q != nil)
			}
			if q != nil {
				q.Close()
				t.Fatalf("corrupt open must not return a usable queue")
			}
			if !strings.Contains(err.Error(), "incomplete version record") {
				t.Fatalf("error must name the incomplete version record, got %q", err)
			}
			assertLogUntouched(t, dir, data)

			// A repeated open keeps failing and still alters nothing.
			q2, err2 := Open(dir)
			if !errors.Is(err2, ErrCorrupt) || q2 != nil {
				if q2 != nil {
					q2.Close()
				}
				t.Fatalf("repeated open must keep failing with ErrCorrupt, got %v", err2)
			}
			assertLogUntouched(t, dir, data)
		})
	}
}

// assertLogUntouched requires queue.log in dir to equal want byte for byte.
func assertLogUntouched(t *testing.T, dir string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("log was modified: want %d bytes, got %d bytes", len(want), len(got))
	}
}

// With an intact, checksum-valid version record, a final record whose declared
// length runs far past the end of the file is the ordinary torn tail of an
// unacknowledged write — however huge the declaration. Only that record is
// dropped: every complete record before it is recovered, the saved success and
// its nonce consumption survive, the never-written message does not appear,
// and the queue keeps working. The declared length must not be misjudged just
// because a 32-bit int cannot hold it.
func TestHugeDeclaredTailLengthStillTruncates(t *testing.T) {
	for _, n := range []uint32{1 << 31, math.MaxUint32, 0x7FFFFFF0} {
		t.Run(fmt.Sprintf("declared length %d", n), func(t *testing.T) {
			dir := t.TempDir()
			q, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := q.RegisterSource("a"); err != nil {
				t.Fatal(err)
			}
			if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: "0x100", Trusted: true}); err != nil {
				t.Fatal(err)
			}
			if _, err := q.Submit(env("m1", "a", "b", 1, 10, 0)); err != nil {
				t.Fatal(err)
			}
			if _, err := q.Advance(1000); err != nil {
				t.Fatal(err)
			}
			if err := q.Close(); err != nil {
				t.Fatal(err)
			}

			raw, err := os.ReadFile(filepath.Join(dir, logName))
			if err != nil {
				t.Fatal(err)
			}

			// A final record declares an enormous body that never arrives.
			d := t.TempDir()
			torn := append(append([]byte(nil), raw...), hugeLengthHeader(n)...)
			torn = append(torn, 'x')
			writeRawLog(t, d, torn)

			qt, err := Open(d)
			if err != nil {
				t.Fatalf("huge declared tail length must truncate and open: %v", err)
			}
			defer qt.Close()
			if r := statusOf(t, qt, "m1"); r.Status != StatusSuccess {
				t.Fatalf("acknowledged success lost: %+v", r)
			}
			if winner := qt.consumed[newConsumeToken("a", "b", 1)]; winner != "m1" {
				t.Fatalf("consumed nonce not restored: %q", winner)
			}
			if qt.nextSeq != 1 {
				t.Fatalf("nextSeq must resume after the last intact submit, got %d", qt.nextSeq)
			}
			// The log was cut back to exactly the acknowledged prefix.
			assertLogUntouched(t, d, raw)
			// The recovered queue stays fully usable.
			if _, err := qt.Submit(env("m2", "a", "b", 2, 10, 0)); err != nil {
				t.Fatalf("recovered queue must accept new submits: %v", err)
			}
			if _, err := qt.Advance(2000); err != nil {
				t.Fatal(err)
			}
			if r := statusOf(t, qt, "m2"); r.Status != StatusSuccess {
				t.Fatalf("new message should deliver on recovered queue: %+v", r)
			}
		})
	}
}
