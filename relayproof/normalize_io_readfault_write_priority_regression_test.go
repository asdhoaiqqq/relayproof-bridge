package relayproof

// Regression coverage for the read/write priority boundary where the output
// breaks WHILE the batch delivered together with a non-EOF read fault is
// still being encoded — earlier than the shutdown flush the existing
// scenarios fault. A Reader is allowed to hand back log bytes and a non-EOF
// error in the SAME Read call. When those bytes contain newline-ended
// complete logs and their results are long (a result larger than the 4096
// byte buffering writer goes straight to the underlying Writer) or results
// already buffered need a flush, the output can fail in the middle of
// processing that batch. The read fault was already delivered with the
// bytes, so it must stay the primary failure of the call: the returned
// error keeps matching ErrLogRead and the reader's original cause via
// errors.Is, while the later write failure is shown in the message text
// only — it must not also match ErrLogWrite, io.ErrShortWrite, or the
// writer's concrete cause.
//
// The rest of the contract is pinned here as well: processing stops at the
// write failure, bytes already accepted stay the unmodified prefix of the
// healthy output (an incomplete final JSON is allowed, no fabricated log
// failure record), the failure count freezes at the invalid logs already
// normalized (the fault's newline-less tail fragment and never-reached
// lines do not count, legal logs do not become illegal), and a zero-failure
// run still reports the read interruption. A write failure before any read
// fault is reported as a write failure without reading ahead for priority,
// and a clean EOF — even arriving with the final bytes — is not a read
// fault. The source-CIDR filter obeys the same rules without changing
// hits, per-line errors, physical line numbers, or the public signatures.
//
// Every scenario is scripted in-process with scriptReader/failWriter and
// the long-log helpers, so it reproduces deterministically without real
// pipes, networks, or device failures.

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// expectReadPrimaryOverWrite asserts the dual-fault reporting shape: read
// marker and read cause stay in the error chain, every write-side failure
// is visible in the message text but absent from the chain.
func expectReadPrimaryOverWrite(t *testing.T, err error, readCause, writeText error, wantFailures, failures int) {
	t.Helper()
	if err == nil {
		t.Fatalf("a read fault already delivered with bytes must not end as normal completion (failures=%d)", failures)
	}
	if !errors.Is(err, ErrLogRead) {
		t.Fatalf("caller must recognize the interruption via errors.Is(err, ErrLogRead), got %v", err)
	}
	if !errors.Is(err, readCause) {
		t.Fatalf("the reader's original cause must stay reachable, got %v", err)
	}
	if errors.Is(err, ErrLogWrite) {
		t.Fatalf("the later write failure must not reclassify the call as ErrLogWrite: %v", err)
	}
	if errors.Is(err, writeText) {
		t.Fatalf("the later write cause must be text-only, not reachable via errors.Is: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, readCause.Error()) {
		t.Fatalf("message must name the read cause, got %q", msg)
	}
	if !strings.Contains(msg, writeText.Error()) {
		t.Fatalf("message must still describe the later write failure, got %q", msg)
	}
	if failures != wantFailures {
		t.Fatalf("failure count must freeze at already-normalized invalid logs, got %d, want %d", failures, wantFailures)
	}
}

// replayReader replays fixed (data, err) steps while tolerating a caller
// whose scratch buffer is smaller than a step (bufio refills a shrunk
// window after consuming part of a full buffer): a step's leftover bytes
// carry into later Read calls, and the step's error is returned only with
// the call that delivers its final bytes — the error still arrives together
// with data, just split across as many offers as the sink asked for.
type replayReader struct {
	steps []scriptStep
	i     int
	off   int
}

func (r *replayReader) Read(p []byte) (int, error) {
	if r.i >= len(r.steps) {
		return 0, io.EOF
	}
	step := r.steps[r.i]
	n := copy(p, step.data[r.off:])
	r.off += n
	if r.off < len(step.data) {
		return n, nil
	}
	r.i++
	r.off = 0
	return n, step.err
}

// newlineAlignedChunks cuts input into script steps no larger than max
// bytes, splitting only at newline boundaries, so each step's data fits the
// reader's 4096-byte scratch buffer while the streamed byte content is
// unchanged.
func newlineAlignedChunks(t *testing.T, input string, max int) []scriptStep {
	t.Helper()
	var steps []scriptStep
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			steps = append(steps, scriptStep{data: []byte(cur.String())})
			cur.Reset()
		}
	}
	for _, line := range strings.SplitAfter(input, "\n") {
		if len(line) > max {
			t.Fatalf("test setup: single physical line %d bytes exceeds chunk limit %d", len(line), max)
		}
		if cur.Len()+len(line) > max {
			flush()
		}
		cur.WriteString(line)
	}
	flush()
	return steps
}

// A complete log longer than the 4096-byte buffer is delivered across two
// reads: the second read also carries a newline-less tail fragment and a
// non-EOF fault. Encoding the long result writes straight through the
// buffer and fails on the output end. The read fault must still be the
// primary error, whether the output reports a concrete error or a
// nil-error short acknowledgement, and whatever prefix it accepted stays
// the prefix of the healthy output.
func TestNormalizeIOReadFaultWithBytesWinsOverLongResultWrite(t *testing.T) {
	longLine := bigSourcedLog("long-under-fault", "")
	full := longLine + "\n"
	rec := encodedRecord(t, 1, longLine)
	if len(rec) <= 4096 {
		t.Fatalf("test setup: encoded result must exceed the 4096-byte buffer, got %d", len(rec))
	}
	if len(full) <= 4096+256 {
		t.Fatalf("test setup: need a tail beyond the first read buffer, got %d bytes", len(full))
	}
	fragment := `{"timestamp":"2026-01-02T00:00:00Z","action":"frag-must-vanish"}`
	buildSrc := func() *replayReader {
		return &replayReader{steps: []scriptStep{
			{data: []byte(full[:4096])},
			{data: []byte(full[4096:] + fragment), err: errSimulatedRead},
		}}
	}

	var healthy bytes.Buffer
	if _, err := NormalizeReader(strings.NewReader(full), &healthy); err != nil {
		t.Fatalf("test setup: healthy reference run failed: %v", err)
	}

	t.Run("concrete write error, nothing accepted", func(t *testing.T) {
		w := &failWriter{err: errSimulatedWrite}
		failures, err := NormalizeReader(buildSrc(), w)
		expectReadPrimaryOverWrite(t, err, errSimulatedRead, errSimulatedWrite, 0, failures)
		if w.buf.Len() != 0 {
			t.Fatalf("rejecting writer must leave no output, got %q", w.buf.String())
		}
		if bytes.Contains(w.buf.Bytes(), []byte("frag-must-vanish")) {
			t.Fatalf("the fault's tail fragment must never be emitted: %q", w.buf.String())
		}
	})

	t.Run("concrete write error, prefix accepted", func(t *testing.T) {
		w := &failWriter{partial: 120, err: errSimulatedWrite}
		failures, err := NormalizeReader(buildSrc(), w)
		expectReadPrimaryOverWrite(t, err, errSimulatedRead, errSimulatedWrite, 0, failures)
		if w.buf.Len() != 120 {
			t.Fatalf("exactly the acknowledged prefix must remain, got %d", w.buf.Len())
		}
		if !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
			t.Fatalf("accepted bytes must be the unmodified healthy prefix:\nkept:    %q\nhealthy: %q", w.buf.String(), healthy.String())
		}
		for _, r := range decodeAvailable(t, w.buf.Bytes()) {
			if r["ok"] == false {
				t.Fatalf("write failure must not fabricate a log failure record: %#v", r)
			}
		}
	})

	t.Run("nil-error short write, nothing accepted", func(t *testing.T) {
		w := &nilErrorPrefixWriter{allowBytes: 0}
		failures, err := NormalizeReader(buildSrc(), w)
		expectReadPrimaryOverWrite(t, err, errSimulatedRead, io.ErrShortWrite, 0, failures)
		if w.writes != 1 {
			t.Fatalf("processing must stop on the first broken acknowledgement, got %d writes", w.writes)
		}
		if w.buf.Len() != 0 {
			t.Fatalf("zero acknowledged bytes must leave no output, got %q", w.buf.String())
		}
	})

	t.Run("nil-error short write, prefix accepted", func(t *testing.T) {
		w := &nilErrorPrefixWriter{allowBytes: 120}
		failures, err := NormalizeReader(buildSrc(), w)
		expectReadPrimaryOverWrite(t, err, errSimulatedRead, io.ErrShortWrite, 0, failures)
		if w.writes != 1 {
			t.Fatalf("processing must stop on the first broken acknowledgement, got %d writes", w.writes)
		}
		if w.buf.Len() != 120 || !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
			t.Fatalf("the 120 acknowledged bytes must be the healthy prefix, got %q", w.buf.String())
		}
	})
}

// Small results already buffered in the output writer must trigger the same
// rule: healthy reads fill the buffer to within a record of its limit, then
// a complete log and a tail fragment arrive together with the read fault,
// and the forced flush fails while that fault-batch log is encoded.
func TestNormalizeIOReadFaultWithBytesWinsOverBufferFlush(t *testing.T) {
	line := validLog("fill")
	faultLine := validLog("fault-line") + "\n"
	fragment := `{"timestamp":"2026-01-02T00:00:00Z","action":"frag-must-vanish"}`

	// Pick a healthy batch whose encoded size leaves fewer than one fault
	// record of space in the buffering writer, so encoding the fault-batch
	// log must flush into the already-full physical write budget.
	var healthyInput string
	var healthy bytes.Buffer
	faultRecLen := 0
	chosen := false
	for n := 80; n <= 160; n++ {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			sb.WriteString(line)
			sb.WriteByte('\n')
		}
		var buf bytes.Buffer
		fl, err := NormalizeReader(strings.NewReader(sb.String()), &buf)
		if err != nil || fl != 0 {
			t.Fatalf("test setup: healthy fill run failed: %d %v", fl, err)
		}
		recLen := len(encodedRecord(t, n+1, validLog("fault-line")))
		if rem := buf.Len() % 4096; buf.Len() > 4096 && rem+recLen > 4096 {
			healthyInput = sb.String()
			healthy = buf
			faultRecLen = recLen
			chosen = true
			break
		}
	}
	if !chosen {
		t.Fatal("test setup: could not size the healthy batch near the flush boundary")
	}
	budget := (healthy.Len() / 4096) * 4096
	if faultRecLen == 0 || budget == 0 {
		t.Fatal("test setup: healthy batch must span a physical write and the fault record fit")
	}

	buildSrc := func() *replayReader {
		steps := newlineAlignedChunks(t, healthyInput, 4096)
		steps = append(steps, scriptStep{data: []byte(faultLine + fragment), err: errSimulatedRead})
		return &replayReader{steps: steps}
	}

	t.Run("concrete write error on the forced flush", func(t *testing.T) {
		w := &failWriter{allowBytes: budget, err: errSimulatedWrite}
		failures, err := NormalizeReader(buildSrc(), w)
		expectReadPrimaryOverWrite(t, err, errSimulatedRead, errSimulatedWrite, 0, failures)
		if w.buf.Len() != budget {
			t.Fatalf("only the bytes accepted before the failing flush remain, got %d, want %d", w.buf.Len(), budget)
		}
		if !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
			t.Fatalf("accepted bytes must be the unmodified prefix of healthy output:\nkept: %q\nhealthy: %q", w.buf.String(), healthy.String())
		}
		if bytes.Contains(w.buf.Bytes(), []byte("fault-line")) || bytes.Contains(w.buf.Bytes(), []byte("frag-must-vanish")) {
			t.Fatalf("the fault batch and its fragment must leave no trace: %q", w.buf.String())
		}
	})

	t.Run("nil-error short acknowledgement on the forced flush", func(t *testing.T) {
		w := &nilErrorPrefixWriter{allowBytes: budget}
		failures, err := NormalizeReader(buildSrc(), w)
		expectReadPrimaryOverWrite(t, err, errSimulatedRead, io.ErrShortWrite, 0, failures)
		if w.buf.Len() != budget || !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
			t.Fatalf("accepted bytes must be the healthy prefix of length %d, got %d", budget, w.buf.Len())
		}
	})
}

// The failure count counts only invalid logs fully normalized before the
// output stopped: an invalid line ahead of the failing long result counts
// even though nothing more can be delivered; the legal long log is not
// turned into a failure, and neither the unprocessed tail nor later lines
// count. With no invalid line the count is zero but the read interruption
// is still returned.
func TestNormalizeIOReadFaultWritePriorityFailureCount(t *testing.T) {
	invalid := `{"timestamp":"not-a-time","action":"bad-ahead"}` + "\n"
	longLine := bigSourcedLog("long-under-fault", "")
	fragment := `{"timestamp":"2026-01-02T00:00:00Z","action":"frag-must-vanish"}`

	input := invalid + longLine + "\n" + fragment
	if len(input) > 2*4096 {
		t.Fatalf("test setup: script supports at most two reads, got %d bytes", len(input))
	}
	steps := []scriptStep{
		{data: []byte(input[:4096])},
		{data: []byte(input[4096:]), err: errSimulatedRead},
	}

	t.Run("invalid ahead counts once", func(t *testing.T) {
		w := &failWriter{err: errSimulatedWrite}
		failures, err := NormalizeReader(&replayReader{steps: steps}, w)
		expectReadPrimaryOverWrite(t, err, errSimulatedRead, errSimulatedWrite, 1, failures)
	})

	t.Run("zero failures still reports the interruption", func(t *testing.T) {
		allValid := longLine + "\n" + fragment
		validSteps := []scriptStep{
			{data: []byte(allValid[:4096])},
			{data: []byte(allValid[4096:]), err: errSimulatedRead},
		}
		w := &failWriter{err: errSimulatedWrite}
		failures, err := NormalizeReader(&replayReader{steps: validSteps}, w)
		expectReadPrimaryOverWrite(t, err, errSimulatedRead, errSimulatedWrite, 0, failures)
	})
}

// noReadAheadReader fails the test if Read is called after its script is
// exhausted: when the output breaks before any read fault, processing must
// stop with the write failure rather than reading further to decide which
// side has priority.
type noReadAheadReader struct {
	steps      []scriptStep
	i          int
	extraReads int
}

func (r *noReadAheadReader) Read(p []byte) (int, error) {
	if r.i >= len(r.steps) {
		r.extraReads++
		return 0, errors.New("input must not be read after the write failure")
	}
	step := r.steps[r.i]
	r.i++
	n := copy(p, step.data)
	if n < len(step.data) {
		panic("noReadAheadReader step larger than the caller's buffer")
	}
	return n, step.err
}

// A write failure before the reader has returned any fault is reported as a
// write failure, and the reader is not consulted again to settle priority —
// even though no EOF has been seen yet.
func TestNormalizeIOWriteFaultWithoutReadFaultDoesNotReadAhead(t *testing.T) {
	longLine := bigSourcedLog("long-write-only", "")
	full := longLine + "\n"
	src := &noReadAheadReader{steps: []scriptStep{
		{data: []byte(full[:4096])},
		{data: []byte(full[4096:])}, // healthy chunk, deliberately no EOF
	}}
	w := &failWriter{err: errSimulatedWrite}
	failures, err := NormalizeReader(src, w)
	if !errors.Is(err, ErrLogWrite) || !errors.Is(err, errSimulatedWrite) {
		t.Fatalf("want ErrLogWrite wrapping the write cause, got %v", err)
	}
	if errors.Is(err, ErrLogRead) {
		t.Fatalf("no read fault has occurred, so the failure must not classify as one: %v", err)
	}
	if failures != 0 {
		t.Fatalf("the legal long log must not become a failure, got %d", failures)
	}
	if src.extraReads != 0 {
		t.Fatalf("processing must stop without reading ahead for priority, got %d extra reads", src.extraReads)
	}
}

// A clean EOF arriving together with the bytes that complete a long log is
// normal input completion on the read side: an output failure encoding it
// is a write failure, never a read failure.
func TestNormalizeIOCleanEOFWithLongBytesWriteFailsIsWriteFault(t *testing.T) {
	longLine := bigSourcedLog("long-eof", "")
	full := longLine + "\n"
	src := &replayReader{steps: []scriptStep{
		{data: []byte(full[:4096])},
		{data: []byte(full[4096:]), err: io.EOF},
	}}
	w := &failWriter{err: errSimulatedWrite}
	failures, err := NormalizeReader(src, w)
	if !errors.Is(err, ErrLogWrite) || !errors.Is(err, errSimulatedWrite) {
		t.Fatalf("clean EOF with bytes is not a read fault; want the write failure, got %v", err)
	}
	if errors.Is(err, ErrLogRead) {
		t.Fatalf("clean EOF must never classify as ErrLogRead: %v", err)
	}
	if failures != 0 {
		t.Fatalf("legal logs must not count as failures, got %d", failures)
	}
}

// Under the source-CIDR filter the same priority rules hold: the admitted
// long event is attempted (its failed write must not mask the read fault),
// an out-of-network complete line stays silently filtered, the fault's
// newline-less in-network tail vanishes with the read, physical line
// numbering is unchanged, and an invalid line (even from an outside
// source) still counts once when it was normalized before the stop.
func TestNormalizeIOFilteredReadFaultWithBytesWinsOverWrite(t *testing.T) {
	f, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	filter := &f

	inNetLong := bigSourcedLog("in-long-under-fault", "192.0.2.10") + "\n"
	outSmall := `{"timestamp":"2026-01-02T00:00:00Z","action":"out-small","source_ip":"198.51.100.20"}` + "\n"
	tailAdmitted := `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-admitted","source_ip":"192.0.2.77"}`

	var healthy bytes.Buffer
	if _, err := NormalizeReaderFiltered(strings.NewReader(inNetLong), &healthy, filter); err != nil {
		t.Fatalf("test setup: healthy filtered reference failed: %v", err)
	}

	t.Run("admitted long write fails, out-of-network line and tail vanish", func(t *testing.T) {
		input := inNetLong + outSmall + tailAdmitted
		steps := []scriptStep{
			{data: []byte(input[:4096])},
			{data: []byte(input[4096:]), err: errSimulatedRead},
		}
		w := &failWriter{partial: 120, err: errSimulatedWrite}
		failures, err := NormalizeReaderFiltered(&replayReader{steps: steps}, w, filter)
		expectReadPrimaryOverWrite(t, err, errSimulatedRead, errSimulatedWrite, 0, failures)
		if w.buf.Len() != 120 || !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
			t.Fatalf("accepted bytes must be the prefix of the healthy filtered long record, got %d bytes: %q", w.buf.Len(), w.buf.String())
		}
		if bytes.Contains(w.buf.Bytes(), []byte("out-small")) {
			t.Fatalf("out-of-network line must leave no record: %q", w.buf.String())
		}
		if bytes.Contains(w.buf.Bytes(), []byte("tail-admitted")) {
			t.Fatalf("the fault's newline-less tail must vanish with the read: %q", w.buf.String())
		}
	})

	t.Run("invalid outside-source line normalized before the stop counts once", func(t *testing.T) {
		invalidOutside := `{"timestamp":"not-a-time","action":"bad-outside","source_ip":"198.51.100.30"}` + "\n"
		input := invalidOutside + inNetLong + tailAdmitted
		if len(input) > 2*4096 {
			t.Fatalf("test setup: script supports at most two reads, got %d bytes", len(input))
		}
		steps := []scriptStep{
			{data: []byte(input[:4096])},
			{data: []byte(input[4096:]), err: errSimulatedRead},
		}
		w := &failWriter{err: errSimulatedWrite}
		failures, err := NormalizeReaderFiltered(&replayReader{steps: steps}, w, filter)
		expectReadPrimaryOverWrite(t, err, errSimulatedRead, errSimulatedWrite, 1, failures)
	})

	t.Run("nil-error short write obeys the same priority", func(t *testing.T) {
		input := inNetLong + outSmall + tailAdmitted
		steps := []scriptStep{
			{data: []byte(input[:4096])},
			{data: []byte(input[4096:]), err: errSimulatedRead},
		}
		w := &nilErrorPrefixWriter{allowBytes: 0}
		failures, err := NormalizeReaderFiltered(&replayReader{steps: steps}, w, filter)
		expectReadPrimaryOverWrite(t, err, errSimulatedRead, io.ErrShortWrite, 0, failures)
		if w.buf.Len() != 0 || w.writes != 1 {
			t.Fatalf("want one stopped write attempt and no output, got writes=%d bytes=%d", w.writes, w.buf.Len())
		}
	})

	t.Run("healthy filtered delivery is byte-for-byte unchanged", func(t *testing.T) {
		input := outSmall + inNetLong
		var want bytes.Buffer
		if _, err := NormalizeReaderFiltered(strings.NewReader(input), &want, filter); err != nil {
			t.Fatalf("test setup: healthy filtered reference failed: %v", err)
		}
		var out bytes.Buffer
		failures, err := NormalizeReaderFiltered(strings.NewReader(input), &out, filter)
		if err != nil {
			t.Fatalf("healthy filtered delivery must succeed, got %v", err)
		}
		if failures != 0 {
			t.Fatalf("both logs are legal and filtering counts no failures, got %d", failures)
		}
		results := decodeResults(t, out.Bytes())
		if len(results) != 1 || results[0]["line"] != float64(2) || results[0]["ok"] != true {
			t.Fatalf("only the admitted physical line 2 must be emitted: %#v", results)
		}
		if eventOf(t, results[0])["action"] != "in-long-under-fault" {
			t.Fatalf("admitted event mismatch: %#v", results[0])
		}
		if !bytes.Equal(out.Bytes(), want.Bytes()) {
			t.Fatalf("filtered output must match the reference:\ngot:    %q\nwanted: %q", out.String(), want.String())
		}
	})
}

// (no trailing scaffold helpers)
