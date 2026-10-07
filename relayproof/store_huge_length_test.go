package relayproof

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// These tests pin the recovery rules for record frames whose declared payload
// length is enormous: the four-byte length header is an unsigned 32-bit value,
// and recovery must judge it the same way on 32-bit and 64-bit builds. A
// declared length must never go negative or overflow the frame-extent
// computation (which used to panic with a slice out of range on 32-bit), and
// the verdict must come from the actual file contents:
//
//   - as the FIRST record after the magic, a version record whose declared
//     body/checksum bytes are not all present is corrupt: Open fails with
//     ErrCorrupt, returns no usable queue, and leaves every byte of the log
//     untouched — it is never truncated to a magic-only shell and no version
//     record is fabricated;
//   - as the LAST record after a complete, checksum-valid version record and
//     good records, a frame whose declared content runs past end of file is
//     the torn tail of an unacknowledged write: only that frame is dropped,
//     every earlier record is recovered, and the queue stays usable.
//
// The declared lengths exercised are 2147483647 (positive everywhere, but the
// frame extent overflows a 32-bit int), 2147483648 and 4294967295 (negative
// when narrowed to a 32-bit int).

// hugeLengths are the declared payload lengths under test: the largest
// positive int32, the smallest value that goes negative in 32 bits, and the
// largest uint32.
var hugeLengths = []uint32{2147483647, 2147483648, 4294967295}

// logWithHugeFirstLength builds a log whose first record after the magic
// declares a payload of declared bytes while only bodyBytes of body/checksum
// content actually follow.
func logWithHugeFirstLength(declared uint32, bodyBytes int) []byte {
	raw := append([]byte(logMagic), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(raw[len(logMagic):], declared)
	return append(raw, make([]byte, bodyBytes)...)
}

// A first record declaring a huge length the file does not contain is a
// corrupt log, never a truncatable tail and never a crash: Open returns
// ErrCorrupt with no queue, and the log keeps its exact length and bytes —
// even when the declared length cannot be represented as a positive 32-bit
// int, and even when the file holds only the length header itself.
func TestHugeVersionRecordLengthRejectedUntouched(t *testing.T) {
	for _, declared := range hugeLengths {
		for _, bodyBytes := range []int{0, 3, 16} {
			dir := t.TempDir()
			data := logWithHugeFirstLength(declared, bodyBytes)
			path := writeRawLog(t, dir, data)

			assertCorruptAndUntouched(t, dir, data)
			// A repeated open keeps failing and still changes nothing.
			assertCorruptAndUntouched(t, dir, data)

			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(data) {
				t.Fatalf("declared %d, body %d: log length changed: %d -> %d",
					declared, bodyBytes, len(data), len(got))
			}
		}
	}
}

// A log whose first record declares a huge length must not be "repaired" into
// a fresh log on a later open either: the corrupt bytes stay in place for
// diagnosis and no version record is ever fabricated over them.
func TestHugeVersionRecordLengthNeverReplaced(t *testing.T) {
	dir := t.TempDir()
	data := logWithHugeFirstLength(4294967295, 8)
	writeRawLog(t, dir, data)

	assertCorruptAndUntouched(t, dir, data)
	assertCorruptAndUntouched(t, dir, data)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != logName && e.Name() != "lock" {
			t.Fatalf("failed open left unexpected file %q", e.Name())
		}
	}
}

// With an intact version record and good records behind it, a final record
// whose declared huge length runs past end of file is the torn tail of an
// unacknowledged write: only that frame is truncated, the acknowledged prefix
// — including the delivered message and its nonce consumption — is recovered,
// and the queue keeps working. The declared length must not change the
// verdict no matter how large it is.
func TestHugeFinalRecordLengthTornTailRecovery(t *testing.T) {
	for _, declared := range hugeLengths {
		t.Run(strconv.FormatUint(uint64(declared), 10), func(t *testing.T) {
			dir := t.TempDir()
			q, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := q.RegisterSource("a"); err != nil {
				t.Fatal(err)
			}
			if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true}); err != nil {
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

			path := filepath.Join(dir, logName)
			good, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			// Append a torn final frame: a huge declared length with only a
			// few body bytes actually written.
			torn := append(good[:len(good):len(good)], 0, 0, 0, 0)
			binary.BigEndian.PutUint32(torn[len(good):], declared)
			torn = append(torn, 1, 2, 3)
			writeRawLog(t, dir, torn)

			qt, err := Open(dir)
			if err != nil {
				t.Fatalf("declared %d: torn tail must truncate and open: %v", declared, err)
			}
			defer qt.Close()

			// The acknowledged prefix is fully recovered.
			if !qt.sources["a"] {
				t.Fatalf("declared %d: acknowledged source registration lost", declared)
			}
			if r := statusOf(t, qt, "m1"); r.Status != StatusSuccess {
				t.Fatalf("declared %d: acknowledged success lost: %+v", declared, r)
			}
			if winner := qt.consumed[newConsumeToken("a", "b", 1)]; winner != "m1" {
				t.Fatalf("declared %d: consumed nonce not restored: %q", declared, winner)
			}
			if qt.nextSeq != 1 {
				t.Fatalf("declared %d: nextSeq must resume after the last intact submit, got %d", declared, qt.nextSeq)
			}

			// Only the torn frame was removed; the prefix is byte-identical.
			repaired, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(repaired) != string(good) {
				t.Fatalf("declared %d: recovery must drop only the torn frame: want %d bytes, got %d",
					declared, len(good), len(repaired))
			}

			// The recovered queue is fully usable: a new submit takes the seq
			// the torn record never acquired and delivers normally.
			rec, err := qt.Submit(env("m2", "a", "b", 2, 10, 0))
			if err != nil {
				t.Fatalf("declared %d: recovered queue must accept new submits: %v", declared, err)
			}
			if rec.Seq != 1 {
				t.Fatalf("declared %d: new submit should reuse seq 1, got %d", declared, rec.Seq)
			}
			if _, err := qt.Advance(2000); err != nil {
				t.Fatal(err)
			}
			if r := statusOf(t, qt, "m2"); r.Status != StatusSuccess {
				t.Fatalf("declared %d: new message should deliver on recovered queue: %+v", declared, r)
			}
		})
	}
}

// A huge declared length is always the log's last record — the frame format
// is self-delimiting, so a length that reaches past end of file claims every
// remaining byte and recovery treats it as the torn tail. A complete frame
// with a bad checksum in the MIDDLE of the log stays corrupt, and so does a
// zero-length record anywhere; those rules are unchanged by the huge-length
// handling and are pinned here against the same overflow-prone offsets.
func TestCompleteMidLogCorruptionStillRejectedAfterHugeLengthFix(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("m1", "a", "b", 1, 10, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(env("m2", "a", "b", 2, 10, 0)); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, logName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a payload byte of the first (source) record after the version
	// record: a complete, checksum-bad frame in the middle of the log.
	bad := append([]byte(nil), raw...)
	pos := len(logMagic)
	vn := int(binary.BigEndian.Uint32(bad[pos:]))
	pos += frameHeaderSize + vn + frameCRCsSize
	bad[pos+frameHeaderSize] ^= 0xFF
	writeRawLog(t, dir, bad)

	assertCorruptAndUntouched(t, dir, bad)
}

// A zero-length record is corrupt in every context — as the version record
// and as a later record — and the log is preserved byte-for-byte.
func TestZeroLengthRecordStillRejected(t *testing.T) {
	t.Run("as version record", func(t *testing.T) {
		dir := t.TempDir()
		data := append([]byte(logMagic), 0, 0, 0, 0)
		writeRawLog(t, dir, data)
		assertCorruptAndUntouched(t, dir, data)
	})

	t.Run("after good records", func(t *testing.T) {
		dir := t.TempDir()
		q, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := q.RegisterSource("a"); err != nil {
			t.Fatal(err)
		}
		if err := q.Close(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, logName)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		bad := append(raw[:len(raw):len(raw)], 0, 0, 0, 0)
		writeRawLog(t, dir, bad)
		assertCorruptAndUntouched(t, dir, bad)
	})
}
