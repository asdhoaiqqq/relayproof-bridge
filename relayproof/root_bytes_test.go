package relayproof

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// Header roots are Go strings compared and persisted byte for byte. A root
// submitted through the Go API may contain bytes that are not valid UTF-8;
// json.Marshal silently rewrites every such byte to U+FFFD, so persisting the
// root as a plain JSON string used to accept the raw bytes in memory while
// saving them as a replacement character. After a reopen (or an automatic
// compaction, which rewrites the log from live state) a byte-identical resave
// then conflicted and the mangled replacement root was accepted. These tests
// pin the byte-exact round trip and the conflict distinctions that depend on
// it. Roots that only the Go API can carry (invalid UTF-8, NUL) are exercised
// directly; the command-line surface has its own regression test.

// rawRootFF/FE are single invalid-UTF-8 bytes; replacementRoot is the legal
// three-byte encoding of U+FFFD. The three must never collapse into one root.
var (
	rawRootFF       = string([]byte{0xFF})
	rawRootFE       = string([]byte{0xFE})
	replacementRoot = "�"
)

// reopenQueue closes q and opens the same state directory again.
func reopenQueue(t *testing.T, q *Queue, dir string) *Queue {
	t.Helper()
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen state directory: %v", err)
	}
	return q2
}

// assertSameRootAccepts requires a trusted resave at the current highest
// trusted height with the identical root bytes to be accepted normally.
func assertSameRootAccepts(t *testing.T, q *Queue, chain string, height int64, root string) {
	t.Helper()
	if err := q.UpsertHeader(Header{Chain: chain, Height: height, Root: root, Trusted: true}); err != nil {
		t.Fatalf("same-height resave with identical root bytes must succeed: %v", err)
	}
	if got := q.headers[chain].trusted; got == nil || got.Root != root {
		t.Fatalf("accepted trusted root changed: want %q, got %+v", root, got)
	}
}

// assertRootConflict requires a trusted save at height with submitted to be an
// ErrHeaderConflict that still names both roots, and leaves the accepted root
// untouched.
func assertRootConflict(t *testing.T, q *Queue, chain string, height int64, submitted, accepted string) {
	t.Helper()
	err := q.UpsertHeader(Header{Chain: chain, Height: height, Root: submitted, Trusted: true})
	if !errors.Is(err, ErrHeaderConflict) {
		t.Fatalf("root %q vs accepted %q: want ErrHeaderConflict, got %v", submitted, accepted, err)
	}
	msg := err.Error()
	for _, want := range []string{
		"submitted root " + strconv.Quote(submitted),
		"conflicts with accepted root " + strconv.Quote(accepted),
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("conflict error %q must distinguish %q", msg, want)
		}
	}
	if got := q.headers[chain].trusted; got == nil || got.Root != accepted {
		t.Fatalf("conflict must keep accepted root %q, got %+v", accepted, got)
	}
}

// The exact byte sequence of an invalid-UTF-8 root survives saving, closing and
// reopening the state directory: the same bytes resave idempotently, while one
// different byte and the legal U+FFFD character each conflict, instead of all
// comparing equal to the replacement character the old JSON encoding stored.
func TestHeaderRootInvalidUTF8SurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: rawRootFF, Trusted: true}); err != nil {
		t.Fatal(err)
	}

	// Within the same instance the bytes were always compared literally.
	assertSameRootAccepts(t, q, "a", 100, rawRootFF)
	assertRootConflict(t, q, "a", 100, rawRootFE, rawRootFF)
	assertRootConflict(t, q, "a", 100, replacementRoot, rawRootFF)

	q = reopenQueue(t, q, dir)
	defer q.Close()

	// After a reopen the persisted root must still be the original 0xFF byte.
	if got := q.headers["a"].trusted; got == nil || got.Root != rawRootFF {
		t.Fatalf("reopen rewrote trusted root: want %q, got %+v", rawRootFF, got)
	}
	assertSameRootAccepts(t, q, "a", 100, rawRootFF)
	assertRootConflict(t, q, "a", 100, rawRootFE, rawRootFF)
	assertRootConflict(t, q, "a", 100, replacementRoot, rawRootFF)
}

// The same distinctions must hold after the queue automatically rewrites the
// log as a compaction snapshot — compaction serializes headers again, so it
// used to mangle the root a second time.
func TestHeaderRootInvalidUTF8SurvivesForcedCompaction(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: rawRootFF, Trusted: true}); err != nil {
		t.Fatal(err)
	}

	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatal(err)
	}
	if got := q.headers["a"].trusted; got == nil || got.Root != rawRootFF {
		t.Fatalf("compaction rewrote trusted root in memory: want %q, got %+v", rawRootFF, got)
	}
	assertSameRootAccepts(t, q, "a", 100, rawRootFF)
	assertRootConflict(t, q, "a", 100, rawRootFE, rawRootFF)
	assertRootConflict(t, q, "a", 100, replacementRoot, rawRootFF)

	q = reopenQueue(t, q, dir)
	defer q.Close()
	if got := q.headers["a"].trusted; got == nil || got.Root != rawRootFF {
		t.Fatalf("reopen after compaction rewrote trusted root: want %q, got %+v", rawRootFF, got)
	}
	assertSameRootAccepts(t, q, "a", 100, rawRootFF)
	assertRootConflict(t, q, "a", 100, rawRootFE, rawRootFF)
	assertRootConflict(t, q, "a", 100, replacementRoot, rawRootFF)
}

// The automatic compaction triggered by an ordinary write crossing the 4 MiB
// threshold must preserve the byte-exact root as well; the triggering write
// returns success only once the rewritten snapshot already carries that root.
// Crossing honestly but cheaply: a large payload pads most of the log, then
// repeated equal-time advance checkpoints (legal while time stands still) cross
// the boundary; each is excluded from the following snapshot, so compaction
// shrinks the log back below the threshold.
func TestHeaderRootInvalidUTF8SurvivesAutomaticCompaction(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: rawRootFF, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit(Envelope{Message: Message{
		ID: "filler", From: "a", To: "b", Nonce: 1,
		Payload: strings.Repeat("x", compactThreshold-8192), ProofAt: 100,
	}}); err != nil {
		t.Fatal(err)
	}

	// Equal-time advances append small checkpoints until one crosses the
	// threshold; that advance's own maybeCompact rewrites the snapshot before
	// Advance returns, observable as a sudden size drop.
	prev := q.store.size
	compacted := false
	for i := 0; i < 1000; i++ {
		if _, err := q.Advance(1000); err != nil {
			t.Fatal(err)
		}
		if q.store.size < prev {
			compacted = true
			break
		}
		prev = q.store.size
	}
	if !compacted {
		t.Fatalf("an automatic compaction never fired: size=%d", q.store.size)
	}
	if q.store.size >= compactThreshold {
		t.Fatalf("compacted snapshot must sit below the threshold: size=%d", q.store.size)
	}

	q = reopenQueue(t, q, dir)
	defer q.Close()
	if got := q.headers["a"].trusted; got == nil || got.Root != rawRootFF {
		t.Fatalf("automatic compaction rewrote trusted root: want %q, got %+v", rawRootFF, got)
	}
	assertSameRootAccepts(t, q, "a", 100, rawRootFF)
	assertRootConflict(t, q, "a", 100, rawRootFE, rawRootFF)
	assertRootConflict(t, q, "a", 100, replacementRoot, rawRootFF)
}

// 0xFF, 0xFE and the legal U+FFFD stay three distinct roots at the same
// height, in memory and after a reopen and a compaction: no later save may
// merge them into one value, and only the original byte sequence resaves.
func TestHeaderRootByteSequencesNeverMerged(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: rawRootFF, Trusted: true}); err != nil {
		t.Fatal(err)
	}

	for _, other := range []string{rawRootFE, replacementRoot, "", "f", "F", " f"} {
		assertRootConflict(t, q, "a", 100, other, rawRootFF)
	}

	q = reopenQueue(t, q, dir)
	for _, other := range []string{rawRootFE, replacementRoot, "", "f", "F", " f"} {
		assertRootConflict(t, q, "a", 100, other, rawRootFF)
	}
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatal(err)
	}
	q = reopenQueue(t, q, dir)
	defer q.Close()
	for _, other := range []string{rawRootFE, replacementRoot, "", "f", "F", " f"} {
		assertRootConflict(t, q, "a", 100, other, rawRootFF)
	}
	assertSameRootAccepts(t, q, "a", 100, rawRootFF)
}

// Whitespace, case, NUL bytes and empty roots keep comparing as raw content,
// including through a reopen and a compaction.
func TestHeaderRootRawContentDistinctionsPersist(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	root := "root\x00with\xffnul"
	if err := q.UpsertHeader(Header{Chain: "a", Height: 7, Root: root, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	for _, other := range []string{"root\x00with\xfenul", "root with\xffnul", "ROOT\x00WITH\xffNUL"} {
		assertRootConflict(t, q, "a", 7, other, root)
	}

	// Empty root is legal and stays empty, distinct from any non-empty root.
	if err := q.RegisterSource("b"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "b", Height: 1, Root: "", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	assertSameRootAccepts(t, q, "b", 1, "")
	assertRootConflict(t, q, "b", 1, rawRootFF, "")

	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatal(err)
	}
	q = reopenQueue(t, q, dir)
	defer q.Close()
	assertSameRootAccepts(t, q, "a", 7, root)
	assertRootConflict(t, q, "a", 7, "root\x00with\xfenul", root)
	assertSameRootAccepts(t, q, "b", 1, "")
	assertRootConflict(t, q, "b", 1, rawRootFF, "")
}

// After the accepted trusted root is established with raw bytes, a higher
// untrusted header and a lower trusted header carrying different bytes must
// neither overwrite it nor change coverage. The original bytes still resave at
// the accepted height; different bytes still conflict; the queue keeps
// processing messages under the original coverage. This must remain true after
// a reopen and a compaction.
func TestHeaderRawRootKeptAcrossUntrustedHigherAndLowerTrusted(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: rawRootFF, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	// A waiting message, scheduled before the later header saves.
	if _, err := q.Submit(env("w", "a", "b", 9, 101, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(1000); err != nil {
		t.Fatal(err)
	}
	waiting := statusOf(t, q, "w")
	if waiting.Status != StatusWaiting || waiting.Attempts != 1 || waiting.NextRetry != 2000 {
		t.Fatalf("setup waiting record wrong: %+v", waiting)
	}

	// Higher untrusted header with different bytes: saves, changes nothing.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 120, Root: rawRootFE, Trusted: false}); err != nil {
		t.Fatal(err)
	}
	// Lower trusted header with different bytes: saves as well, no conflict.
	if err := q.UpsertHeader(Header{Chain: "a", Height: 50, Root: replacementRoot, Trusted: true}); err != nil {
		t.Fatal(err)
	}

	// Header saves alone neither deliver nor reschedule the waiting message.
	if got := statusOf(t, q, "w"); got != waiting {
		t.Fatalf("header saves changed the waiting record: %+v", got)
	}

	// Original root resaves at the accepted height; a different root conflicts.
	assertSameRootAccepts(t, q, "a", 100, rawRootFF)
	assertRootConflict(t, q, "a", 100, rawRootFE, rawRootFF)

	// Coverage is still 100 and the queue still processes under it.
	if _, err := q.Submit(env("m100", "a", "b", 10, 100, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(2000); err != nil {
		t.Fatal(err)
	}
	if r := statusOf(t, q, "m100"); r.Status != StatusSuccess ||
		r.Reason != "delivered; proof verified by trusted header at height 100" {
		t.Fatalf("covered message must deliver under trusted height 100: %+v", r)
	}
	if r := statusOf(t, q, "w"); r.Status != StatusWaiting {
		t.Fatalf("proof-at-101 must still wait on coverage 100: %+v", r)
	}

	// Same expectations after compaction and a fresh open.
	if err := q.store.compact(q.snapshot()); err != nil {
		t.Fatal(err)
	}
	q = reopenQueue(t, q, dir)
	defer q.Close()
	if got := q.headers["a"].trusted; got == nil || got.Height != 100 || got.Root != rawRootFF {
		t.Fatalf("accepted trusted header not restored: %+v", got)
	}
	assertSameRootAccepts(t, q, "a", 100, rawRootFF)
	assertRootConflict(t, q, "a", 100, rawRootFE, rawRootFF)
	assertRootConflict(t, q, "a", 100, replacementRoot, rawRootFF)
	if _, err := q.Submit(env("m99", "a", "b", 11, 99, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Advance(3000); err != nil {
		t.Fatal(err)
	}
	if r := statusOf(t, q, "m99"); r.Status != StatusSuccess {
		t.Fatalf("reopened queue must still process under coverage 100: %+v", r)
	}
}

// Byte-exact roots are maintained independently per source chain: the same raw
// root bytes at the same height on two chains never collide, and a different
// root on one chain does not conflict against the other.
func TestHeaderRawRootsPerChainIndependent(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	if err := q.RegisterSource("a"); err != nil {
		t.Fatal(err)
	}
	if err := q.RegisterSource("b"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "a", Height: 100, Root: rawRootFF, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertHeader(Header{Chain: "b", Height: 100, Root: rawRootFE, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	assertSameRootAccepts(t, q, "a", 100, rawRootFF)
	assertRootConflict(t, q, "a", 100, rawRootFE, rawRootFF)
	assertSameRootAccepts(t, q, "b", 100, rawRootFE)
	assertRootConflict(t, q, "b", 100, rawRootFF, rawRootFE)
}

// Existing state directories open directly. Logs written by older builds only
// have the plain JSON root string; those bytes are replayed verbatim, and an
// old build that already stored a U+FFFD replacement character is treated as
// exactly that character — the lost invalid bytes are never guessed back.
func TestLegacyHeaderRootFieldReplayedVerbatim(t *testing.T) {
	t.Run("plain ASCII root", func(t *testing.T) {
		dir := t.TempDir()
		writeLegacyLog(t, dir,
			&logEntry{T: kindSource, Chain: "a"},
			&logEntry{T: kindHeader, Chain: "a", Height: 100, Root: "0xaaa", Trusted: true},
		)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("existing state directory must open directly: %v", err)
		}
		defer q.Close()
		if got := q.headers["a"].trusted; got == nil || got.Root != "0xaaa" {
			t.Fatalf("legacy root not replayed verbatim: %+v", got)
		}
		assertSameRootAccepts(t, q, "a", 100, "0xaaa")
		assertRootConflict(t, q, "a", 100, "0xbbb", "0xaaa")

		// A resave upgrades the record to the byte-exact encoding, which keeps
		// surviving compaction.
		if err := q.store.compact(q.snapshot()); err != nil {
			t.Fatal(err)
		}
		q2 := reopenQueue(t, q, dir)
		defer q2.Close()
		if got := q2.headers["a"].trusted; got == nil || got.Root != "0xaaa" {
			t.Fatalf("legacy root lost after compaction: %+v", got)
		}
	})

	t.Run("old replacement-character root", func(t *testing.T) {
		dir := t.TempDir()
		writeLegacyLog(t, dir,
			&logEntry{T: kindSource, Chain: "a"},
			&logEntry{T: kindHeader, Chain: "a", Height: 100, Root: replacementRoot, Trusted: true},
		)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("existing state directory must open directly: %v", err)
		}
		defer q.Close()
		// The accepted root is the actual U+FFFD character the old build saved.
		if got := q.headers["a"].trusted; got == nil || got.Root != replacementRoot {
			t.Fatalf("legacy replacement root must be kept as saved: %+v", got)
		}
		// The raw 0xFF byte that an old build may have lost is a different root
		// now — it conflicts rather than being silently treated as the same
		// value; resaving the stored character accepts.
		assertRootConflict(t, q, "a", 100, rawRootFF, replacementRoot)
		assertSameRootAccepts(t, q, "a", 100, replacementRoot)
	})

	t.Run("rootBytes wins over the legacy string field", func(t *testing.T) {
		dir := t.TempDir()
		writeLegacyLog(t, dir,
			&logEntry{T: kindSource, Chain: "a"},
			&logEntry{
				T: kindHeader, Chain: "a", Height: 100,
				Root: replacementRoot, RootBytes: []byte(rawRootFF), Trusted: true,
			},
		)
		q, err := Open(dir)
		if err != nil {
			t.Fatalf("state directory must open: %v", err)
		}
		defer q.Close()
		if got := q.headers["a"].trusted; got == nil || got.Root != rawRootFF {
			t.Fatalf("rootBytes must be authoritative: %+v", got)
		}
	})
}
