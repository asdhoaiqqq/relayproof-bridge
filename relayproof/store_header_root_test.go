package relayproof

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Header roots are arbitrary byte strings compared byte for byte. A root
// holding invalid UTF-8 bytes must survive saving, reopening and log
// compaction exactly: JSON string encoding would otherwise silently rewrite
// such bytes to U+FFFD, making the resubmitted original root conflict with
// its own saved value while the replacement character is wrongly accepted.

const replacementCharRoot = "�"

// requireHeaderAccepted requires a trusted same-height save of root to be
// accepted against the currently accepted trusted root.
func requireHeaderAccepted(t *testing.T, q *Queue, chain string, height int64, root string) {
	t.Helper()
	if err := q.UpsertHeader(Header{Chain: chain, Height: height, Root: root, Trusted: true}); err != nil {
		t.Fatalf("same root at trusted height %d must be accepted: %v", height, err)
	}
}

// requireHeaderConflict requires a trusted same-height save of root to fail
// with ErrHeaderConflict, and the accepted trusted root to stay wantAccepted.
func requireHeaderConflict(t *testing.T, q *Queue, chain string, height int64, root, wantAccepted string) {
	t.Helper()
	err := q.UpsertHeader(Header{Chain: chain, Height: height, Root: root, Trusted: true})
	if !errors.Is(err, ErrHeaderConflict) {
		t.Fatalf("different root at trusted height %d: want ErrHeaderConflict, got %v", height, err)
	}
	hs := q.headers[chain]
	if hs == nil || hs.trusted == nil || hs.trusted.Root != wantAccepted || hs.trusted.Height != height {
		t.Fatalf("accepted trusted header changed after conflict: %+v", hs.trusted)
	}
}

func reopen(t *testing.T, dir string) *Queue {
	t.Helper()
	q, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	return q
}

// An invalid-UTF-8 root is preserved byte-for-byte through save, close,
// reopen and compaction: the identical byte sequence stays an idempotent
// accept at the trusted height, while a root differing in any byte — and the
// legal character U+FFFD, which must never be merged with invalid bytes —
// conflicts, before and after every persistence boundary.
func TestHeaderRootInvalidUTF8PreservedAcrossReopenAndCompaction(t *testing.T) {
	rootFF := string([]byte{0xFF})
	rootFE := string([]byte{0xFE})
	mixed := "pre" + string([]byte{0xFF}) + "post"

	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: rootFF, Trusted: true}); err != nil {
		t.Fatalf("save invalid-UTF-8 root: %v", err)
	}
	if err := q.UpsertHeader(Header{Chain: "b", Height: 7, Root: mixed, Trusted: true}); err != nil {
		t.Fatalf("save partially invalid root: %v", err)
	}

	check := func(t *testing.T, q *Queue) {
		t.Helper()
		// The exact same bytes are accepted idempotently.
		requireHeaderAccepted(t, q, "a", 100, rootFF)
		requireHeaderAccepted(t, q, "b", 7, mixed)
		// Any single-byte difference is a conflict, and U+FFFD is a distinct
		// root, never the canonical form of invalid bytes.
		requireHeaderConflict(t, q, "a", 100, rootFE, rootFF)
		requireHeaderConflict(t, q, "a", 100, replacementCharRoot, rootFF)
		requireHeaderConflict(t, q, "b", 7, replacementCharRoot, mixed)
	}
	t.Run("same instance", func(t *testing.T) { check(t, q) })
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	t.Run("after reopen", func(t *testing.T) { check(t, q) })

	// A higher untrusted header and a lower trusted header with different
	// roots are recorded but never displace the accepted trusted root.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 200, Root: rootFE, Trusted: false}); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 50, Root: rootFE, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	check(t, q)

	// Force a compaction cycle; the snapshot must carry the exact bytes too.
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q = reopen(t, dir)
	t.Run("after compaction and reopen", func(t *testing.T) { check(t, q) })
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// The persisted log holds the raw bytes base64-encoded and never the
	// replacement character.
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"rootB64":"`)) {
		t.Fatalf("invalid-UTF-8 root not stored byte-exactly: %s", raw)
	}
	if bytes.Contains(raw, []byte(replacementCharRoot)) {
		t.Fatalf("log contains U+FFFD: a root was silently rewritten: %s", raw)
	}
}

// Valid-UTF-8 roots — plain text, empty, whitespace, U+FFFD itself — keep the
// historical plain "root" field, so logs written by older builds and this
// build remain byte-identical and existing state directories keep working.
func TestHeaderRootValidUTF8KeepsHistoricalEncoding(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	roots := []string{"0xaaa", "", " spaced ", replacementCharRoot}
	for i, root := range roots {
		chain := string(rune('c' + i))
		if err := q.UpsertHeader(Header{Chain: chain, Height: 5, Root: root, Trusted: true}); err != nil {
			t.Fatalf("save root %q: %v", root, err)
		}
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("rootB64")) {
		t.Fatalf("valid-UTF-8 roots must keep the plain root field: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"root":"0xaaa"`)) {
		t.Fatalf("plain root missing from log: %s", raw)
	}

	// Reopen: every root means exactly what it meant before, including the
	// empty root and U+FFFD as an ordinary legal character.
	q = reopen(t, dir)
	defer q.Close()
	for i, root := range roots {
		requireHeaderAccepted(t, q, string(rune('c'+i)), 5, root)
	}
	requireHeaderConflict(t, q, "c", 5, "0xAAA", "0xaaa")
	requireHeaderConflict(t, q, "d", 5, "other", "")
	requireHeaderConflict(t, q, "f", 5, string([]byte{0xFF}), replacementCharRoot)
}

// A state directory written by an older build may already hold a root that
// was silently rewritten to U+FFFD. Replay takes the saved characters at face
// value — the lost bytes are never guessed — so the replacement character is
// the accepted root and the original invalid bytes conflict with it.
func TestHeaderRootLegacyReplacementCharTakenAtFaceValue(t *testing.T) {
	dir := t.TempDir()
	var raw []byte
	raw = append(raw, logMagic...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
	raw = append(raw, encodeFrame(mustMarshal(&logEntry{
		T: kindHeader, Chain: "a", Height: 100, Root: replacementCharRoot, Trusted: true,
	}))...)
	writeRawLog(t, dir, raw)

	q := reopen(t, dir)
	defer q.Close()
	requireHeaderAccepted(t, q, "a", 100, replacementCharRoot)
	requireHeaderConflict(t, q, "a", 100, string([]byte{0xFF}), replacementCharRoot)
}

// A rootB64 entry must decode unambiguously: an entry carrying both root and
// rootB64, or an undecodable rootB64, is an inconsistent record no build
// writes and rejects the directory as corrupt, leaving every byte untouched.
func TestHeaderRootB64InconsistentRecordsRejected(t *testing.T) {
	for name, e := range map[string]*logEntry{
		"both root and rootB64": {T: kindHeader, Chain: "a", Height: 1, Root: "x", RootB64: "eA==", Trusted: true},
		"undecodable rootB64":   {T: kindHeader, Chain: "a", Height: 1, RootB64: "!!!not-base64!!!", Trusted: true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var raw []byte
			raw = append(raw, logMagic...)
			raw = append(raw, encodeFrame(mustMarshal(&logEntry{T: kindVersion, V: currentLogV}))...)
			raw = append(raw, encodeFrame(mustMarshal(e))...)
			writeRawLog(t, dir, raw)
			assertCorruptAndUntouched(t, dir, raw)
		})
	}
}

// A conflict error still names the submitted and accepted roots distinctly
// when invalid bytes are involved, so the two sides of the conflict stay
// distinguishable in diagnostics.
func TestHeaderConflictErrorDistinguishesInvalidByteRoots(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	rootFF := string([]byte{0xFF})
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: rootFF, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	err = q.UpsertHeader(Header{Chain: "a", Height: 100, Root: string([]byte{0xFE}), Trusted: true})
	if !errors.Is(err, ErrHeaderConflict) {
		t.Fatalf("want ErrHeaderConflict, got %v", err)
	}
	if !strings.Contains(err.Error(), `\xfe`) || !strings.Contains(err.Error(), `\xff`) {
		t.Fatalf("conflict error must name both roots distinctly: %v", err)
	}
}
