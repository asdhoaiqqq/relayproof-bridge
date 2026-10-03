package relayproof

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeRawLog creates queue.log in dir with exactly the given bytes.
func writeRawLog(t *testing.T, dir string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, logName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// assertCorruptAndUntouched opens dir, requires ErrCorrupt with no usable
// queue, and requires queue.log to remain byte-for-byte as written.
func assertCorruptAndUntouched(t *testing.T, dir string, want []byte) {
	t.Helper()
	path := filepath.Join(dir, logName)
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
	got, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != string(want) {
		t.Fatalf("corrupt log was modified: want %d bytes, got %d bytes", len(want), len(got))
	}
}

// A log that contains the magic but no intact, checksum-valid, supported
// version record as its first record must be rejected as corrupt on the very
// first open, never truncated down to a magic-only shell that later appends
// could turn into a headerless log. None of these failures may alter the
// file, and a repeated open must keep failing rather than replacing the log.
func TestHeadVersionRecordMustBeIntact(t *testing.T) {
	versionFrame := encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))

	cases := map[string][]byte{
		"magic only": []byte(logMagic),
		// One to three of the four length bytes survived.
		"one length byte":    append([]byte(logMagic), versionFrame[:1]...),
		"two length bytes":   append([]byte(logMagic), versionFrame[:2]...),
		"three length bytes": append([]byte(logMagic), versionFrame[:3]...),
		// Full length saved but body/checksum missing or cut short.
		"length without body":    append([]byte(logMagic), versionFrame[:frameHeaderSize]...),
		"partial body":           append([]byte(logMagic), versionFrame[:frameHeaderSize+2]...),
		"body without crc":       append([]byte(logMagic), versionFrame[:len(versionFrame)-frameCRCsSize]...),
		"frame missing one crc":  append([]byte(logMagic), versionFrame[:len(versionFrame)-1]...),
		"complete frame bad crc": append(append([]byte(logMagic), versionFrame[:len(versionFrame)-1]...), versionFrame[len(versionFrame)-1]^0xFF),
	}
	// A complete frame whose payload byte is flipped fails its checksum while
	// sitting exactly at EOF.
	badBody := append([]byte(nil), versionFrame...)
	badBody[frameHeaderSize+2] ^= 0xFF
	cases["complete frame bad body"] = append([]byte(logMagic), badBody...)
	// A complete, checksum-valid first record that is not a version record.
	cases["first record is source"] = append([]byte(logMagic),
		encodeFrame(mustMarshal(&logEntry{T: kindSource, Chain: "a"}))...)
	// A complete version record naming an unsupported version.
	cases["unsupported version"] = append([]byte(logMagic),
		encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV + 1}))...)

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeRawLog(t, dir, data)

			assertCorruptAndUntouched(t, dir, data)

			// A corrupt head must not be auto-replaced with a fresh log on a
			// later open: the user's bytes stay in place for diagnosis.
			assertCorruptAndUntouched(t, dir, data)

			// No stray replacement or temp log was written beside the original.
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if e.Name() != logName && e.Name() != "lock" {
					t.Fatalf("failed open left unexpected file %q", e.Name())
				}
			}
		})
	}
}

// Directories with no queue.log at all (never created, or just created) still
// initialize a fresh queue normally — they are distinct from an existing but
// incomplete magic-only log, which is corrupt data and must not be replaced.
func TestAbsentLogStillInitializes(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T) string{
		"nonexistent dir": func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "nested", "queue-state")
		},
		"empty dir": func(t *testing.T) string {
			return t.TempDir()
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := setup(t)
			q, err := Open(dir)
			if err != nil {
				t.Fatalf("fresh directory must initialize: %v", err)
			}
			if err := q.RegisterSource("a"); err != nil {
				t.Fatal(err)
			}
			if err := q.Close(); err != nil {
				t.Fatal(err)
			}
			// Reopen restores the registered source.
			q2, err := Open(dir)
			if err != nil {
				t.Fatalf("reopen fresh queue: %v", err)
			}
			defer q2.Close()
			if !q2.sources["a"] {
				t.Fatal("registered source not persisted")
			}
		})
	}

	// Same directory, but with a magic-only queue.log present, must fail even
	// though the surrounding directory setup is identical.
	dir := t.TempDir()
	data := []byte(logMagic)
	writeRawLog(t, dir, data)
	assertCorruptAndUntouched(t, dir, data)
}

// With an intact leading version record, torn-tail recovery keeps working
// exactly as before: the acknowledged prefix is restored and the queue stays
// usable, whether the last record is partial or complete-but-bad-CRC.
func TestValidVersionPreservesTailRecovery(t *testing.T) {
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
	m2 := encodeFrame(mustMarshal(&logEntry{
		T: kindSubmit, Seq: 1, ID: "m2", From: "a", To: "b", Nonce: 2, ProofAt: 10,
	}))
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	base := append([]byte(nil), raw...)

	t.Run("partial final record", func(t *testing.T) {
		d := t.TempDir()
		torn := append(base[:len(base):len(base)], m2[:len(m2)-3]...)
		writeRawLog(t, d, torn)
		qt, err := Open(d)
		if err != nil {
			t.Fatalf("torn tail must truncate and open: %v", err)
		}
		assertRecoveredPrefixUsable(t, qt, "m2")
	})

	t.Run("complete final record bad crc", func(t *testing.T) {
		d := t.TempDir()
		badTail := append(base[:len(base):len(base)], m2...)
		badTail[len(badTail)-1] ^= 0xFF // corrupt only the final record's CRC
		writeRawLog(t, d, badTail)
		qt, err := Open(d)
		if err != nil {
			t.Fatalf("checksum-bad final record must be dropped: %v", err)
		}
		assertRecoveredPrefixUsable(t, qt, "m2")
	})
}

// assertRecoveredPrefixUsable verifies the acknowledged prefix (source a,
// delivered m1) is restored, the dropped final submit for missingID never
// existed, and the reopened queue accepts new operations.
func assertRecoveredPrefixUsable(t *testing.T, q *Queue, missingID string) {
	t.Helper()
	defer q.Close()
	if !q.sources["a"] {
		t.Fatal("acknowledged source registration lost")
	}
	if r := statusOf(t, q, "m1"); r.Status != StatusSuccess {
		t.Fatalf("acknowledged success lost: %+v", r)
	}
	if winner := q.consumed[newConsumeToken("a", "b", 1)]; winner != "m1" {
		t.Fatalf("consumed nonce not restored: %q", winner)
	}
	if _, ok := q.Query(missingID); ok {
		t.Fatalf("unacknowledged torn record %q must not exist", missingID)
	}
	if q.nextSeq != 1 {
		t.Fatalf("nextSeq must resume after the last intact submit, got %d", q.nextSeq)
	}
	// The recovered queue is fully writable and the new submit gets the seq
	// that the dropped tail record never acquired.
	rec, err := q.Submit(env("m3", "a", "b", 3, 10, 0))
	if err != nil {
		t.Fatalf("recovered queue must accept new submits: %v", err)
	}
	if rec.Seq != 1 {
		t.Fatalf("new submit should reuse seq 1, got %d", rec.Seq)
	}
	if _, err := q.Advance(2000); err != nil {
		t.Fatal(err)
	}
	if r := statusOf(t, q, "m3"); r.Status != StatusSuccess {
		t.Fatalf("new message should deliver on recovered queue: %+v", r)
	}
}

// Corruption strictly after a valid version record (i.e. in the middle) must
// still reject the directory and preserve every byte.
func TestMidLogCorruptionStillRejectedAndUntouched(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	q.RegisterSource("a")
	q.Submit(env("m1", "a", "b", 1, 10, 0))
	q.Submit(env("m2", "a", "b", 2, 10, 0))
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	// The first frame is the version record; flip a byte in the second frame
	// (the source entry) so its checksum fails before EOF.
	bad := append([]byte(nil), raw...)
	pos := len(logMagic)
	// Skip the whole version frame to land on the record after it.
	vn := int(binary.BigEndian.Uint32(bad[pos:]))
	pos += frameHeaderSize + vn + frameCRCsSize
	bad[pos+frameHeaderSize+1] ^= 0xFF

	d := t.TempDir()
	writeRawLog(t, d, bad)
	assertCorruptAndUntouched(t, d, bad)
}
