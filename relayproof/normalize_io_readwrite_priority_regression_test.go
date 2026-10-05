package relayproof

// Regression coverage for the read/write priority boundary where the read
// fault and its bytes arrive in the SAME underlying Read call. A buffering
// reader latches an error delivered together with a delimiter-ended chunk:
// the complete line is handed up with a nil error and the fault surfaces only
// on the next line read, so an output fault fired while emitting the
// just-completed line's result previously masked the already-delivered read
// cause and callers mistook an interrupted input for a write-only failure.
//
// The fixed contract asserted here:
//   - a non-EOF read fault delivered with complete newline-ended logs stays
//     the primary failure even when the output fails while emitting those very
//     results, whether the failing write is the long result itself or only the
//     flush of earlier buffered results it forces; errors.Is must match
//     ErrLogRead and the reader's original cause, and must NOT match
//     ErrLogWrite or the write cause, while both causes still show in the text;
//   - processing stops without another Read; accepted bytes stay the normal
//     prefix (a final JSON may be cut open), no log-failure record is
//     fabricated, legal logs never become illegal, and neither unprocessed
//     lines nor the fault's newline-less tail count — so failures may be zero
//     while the read interruption is still returned;
//   - the same rules hold under the source-CIDR filter with its physical line
//     numbers and per-line error content.
//
// Everything is scripted in-process with failWriter from normalize_io_test.go,
// so the boundary reproduces deterministically offline.

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// faultWithBatchReader serves data, copying no more than the caller's buffer,
// and returns faultErr on the Read whose copied bytes reach faultAt (the
// newline that completes the last whole log in the batch); every later Read
// returns the same persistent fault with no more bytes. This models a device
// that delivers a final batch and stays broken. Unlike scriptReader it never
// panics on a small caller buffer, so it reproduces the error-latching boundary
// against a buffering reader of any internal size.
type faultWithBatchReader struct {
	data           []byte
	faultAt        int
	faultErr       error
	pos            int
	faulted        bool
	reads          int
	postFaultReads int // Read calls after the fault-delivering batch
}

func (r *faultWithBatchReader) Read(p []byte) (int, error) {
	r.reads++
	if r.faulted {
		r.postFaultReads++
		return 0, r.faultErr
	}
	n := copy(p, r.data[r.pos:])
	end := r.pos + n
	r.pos = end
	if end > r.faultAt { // the batch's terminating newline went out with these bytes
		r.faulted = true
		return n, r.faultErr
	}
	return n, nil
}

// newFaultWithBatchReader builds a stream of prefix + lastCompleteLine + "\n" +
// tail, where the Read that delivers lastCompleteLine's newline also delivers
// the fault; the newline-less tail rides along inside that same batch.
func newFaultWithBatchReader(prefix, lastCompleteLine, tail string) *faultWithBatchReader {
	data := prefix + lastCompleteLine + "\n" + tail
	return &faultWithBatchReader{
		data:     []byte(data),
		faultAt:  len(prefix) + len(lastCompleteLine), // index of the '\n'
		faultErr: errSimulatedRead,
	}
}

// expectReadPrimaryOverWrite is the shared error-classification contract for a
// read fault that is already in hand when an output fault fires.
func expectReadPrimaryOverWrite(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("a read fault must be returned even with a later write fault, got nil")
	}
	if !errors.Is(err, ErrLogRead) {
		t.Fatalf("error must classify as the read failure, got %v", err)
	}
	if !errors.Is(err, errSimulatedRead) {
		t.Fatalf("the reader's original cause must stay reachable, got %v", err)
	}
	if errors.Is(err, ErrLogWrite) {
		t.Fatalf("the later write fault must not tag the error as a write failure: %v", err)
	}
	if errors.Is(err, errSimulatedWrite) {
		t.Fatalf("the later write cause must not join the error chain: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, errSimulatedRead.Error()) {
		t.Fatalf("message must name the read cause, got %q", msg)
	}
	if !strings.Contains(msg, errSimulatedWrite.Error()) {
		t.Fatalf("the write fault must stay visible in the message text, got %q", msg)
	}
}

// A small invalid complete log is buffered, then a long valid complete log and
// a newline-less tail arrive with the read fault. Emitting the long log forces
// a physical write (of the buffered failure result, then of the long result)
// that fails: the read cause must still win, with only the invalid line
// counted and the accepted bytes kept as a normal-output prefix.
func TestNormalizeIOReadFaultWithBytesWinsOverMidStreamWriteFault(t *testing.T) {
	invalid := `{"timestamp":"not-a-time","action":"bad"}`
	big := bigValidLog("big")
	if len(encodedRecord(t, 2, big)) <= 4096 {
		t.Fatalf("test setup: encoded long line must exceed the 4096-byte write buffer")
	}
	prefix := invalid + "\n"
	complete := prefix + big + "\n"
	fragment := `{"timestamp":"2026-01-02T00:00:00Z","action":"fault-tail"}`

	var healthy bytes.Buffer
	healthyFailures, healthyErr := NormalizeReader(strings.NewReader(complete), &healthy)
	if healthyErr != nil || healthyFailures != 1 {
		t.Fatalf("test setup: healthy reference read failed: failures=%d err=%v", healthyFailures, healthyErr)
	}
	firstRecord := encodedRecord(t, 1, invalid)

	cases := []struct {
		name       string
		allowBytes int // bytes the writer accepts before the failing write
		partial    int // bytes accepted by the failing write itself
		wantKept   int // total bytes that must remain
		whole      int // whole records the kept prefix must decode to
	}{
		{
			// The flush of the already-buffered failure result is the first
			// physical write and fails immediately: nothing is kept.
			name:       "flush of prior buffered result fails first",
			allowBytes: 0,
			partial:    0,
			wantKept:   0,
			whole:      0,
		},
		{
			// The buffered failure result flushes whole; the direct write of
			// the long result accepts 120 bytes and then fails.
			name:       "long result write fails after the buffered result",
			allowBytes: len(firstRecord),
			partial:    120,
			wantKept:   len(firstRecord) + 120,
			whole:      1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := newFaultWithBatchReader(prefix, big, fragment)
			w := &failWriter{allowBytes: tc.allowBytes, partial: tc.partial, err: errSimulatedWrite}
			failures, err := NormalizeReader(src, w)
			expectReadPrimaryOverWrite(t, err)
			if failures != 1 {
				t.Fatalf("only the invalid complete line counts; the legal long line and fault tail add nothing, got %d", failures)
			}
			if src.postFaultReads != 0 {
				t.Fatalf("processing must stop on the write fault without another Read, got %d post-fault reads", src.postFaultReads)
			}
			if w.buf.Len() != tc.wantKept {
				t.Fatalf("accepted bytes must total %d, got %d", tc.wantKept, w.buf.Len())
			}
			if !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
				t.Fatalf("accepted bytes must be the unmodified prefix of a healthy read of the complete lines:\nkept:    %q\nhealthy: %q",
					w.buf.String(), healthy.String())
			}
			var whole []map[string]any
			if w.buf.Len() > 0 {
				whole = decodePrefix(t, w.buf.Bytes())
			}
			if len(whole) != tc.whole {
				t.Fatalf("kept prefix must decode to %d whole record(s), got %#v", tc.whole, whole)
			}
			if tc.whole == 1 {
				if whole[0]["line"] != float64(1) || whole[0]["ok"] != false {
					t.Fatalf("the single whole record must be the line-1 failure: %#v", whole[0])
				}
				if msg, _ := whole[0]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
					t.Fatalf("line 1 must keep its timestamp-specific reason, got %q", msg)
				}
			}
			if bytes.Contains(w.buf.Bytes(), []byte("fault-tail")) {
				t.Fatalf("the fault's newline-less tail must leave no record: %q", w.buf.String())
			}
		})
	}
}

// When every complete line is legal, a long result whose very first write
// fails after a prefix still reports the read interruption with a zero
// failure count: zero failures must never look like normal completion.
func TestNormalizeIOReadFaultLongWriteFaultZeroFailuresStillInterrupted(t *testing.T) {
	big := bigValidLog("only-long")
	if len(encodedRecord(t, 1, big)) <= 4096 {
		t.Fatalf("test setup: encoded long line must exceed the 4096-byte write buffer")
	}
	complete := big + "\n"
	fragment := `{"timestamp":"2026-01-02T00:00:00Z","action":"fault-tail"}`

	var healthy bytes.Buffer
	if _, err := NormalizeReader(strings.NewReader(complete), &healthy); err != nil {
		t.Fatalf("test setup: healthy reference read failed: %v", err)
	}

	src := newFaultWithBatchReader("", big, fragment)
	// Empty output buffer: the long result is offered directly in one write,
	// which accepts 120 bytes and then fails.
	w := &failWriter{partial: 120, err: errSimulatedWrite}
	failures, err := NormalizeReader(src, w)
	expectReadPrimaryOverWrite(t, err)
	if failures != 0 {
		t.Fatalf("legal logs and an uncounted fault tail must leave zero failures, got %d", failures)
	}
	if src.postFaultReads != 0 {
		t.Fatalf("processing must stop without reading more input, got %d post-fault reads", src.postFaultReads)
	}
	if w.buf.Len() != 120 {
		t.Fatalf("exactly the 120 acknowledged bytes must remain, got %d", w.buf.Len())
	}
	if !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
		t.Fatalf("accepted bytes must be the healthy output prefix:\nkept:    %q\nhealthy: %q",
			w.buf.String(), healthy.String())
	}
	if len(decodePrefix(t, w.buf.Bytes())) != 0 {
		t.Fatalf("a 120-byte prefix of one long record must contain no whole record")
	}
	if bytes.Contains(w.buf.Bytes(), []byte("fault-tail")) {
		t.Fatalf("the fault's newline-less tail must leave no record: %q", w.buf.String())
	}
}

// Under the source-CIDR filter the same priority holds: an out-of-network
// invalid complete line still counts and is emitted first, the long admitted
// line's interrupted write keeps the read fault primary, and the in-network
// newline-less tail riding the failed read leaves no record.
func TestNormalizeReaderFilteredReadFaultWinsOverMidStreamWriteFault(t *testing.T) {
	f, err := ParseSourceCIDRFilter("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	filter := &f
	invalidOutside := `{"timestamp":"not-a-time","action":"bad-outside","source_ip":"198.51.100.30"}`
	inBig := bigSourcedLog("in-big", "192.0.2.10")
	if len(encodedRecord(t, 2, inBig)) <= 4096 {
		t.Fatalf("test setup: encoded long event must exceed the 4096-byte write buffer")
	}
	prefix := invalidOutside + "\n"
	complete := prefix + inBig + "\n"
	fragment := `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-in-allowed","source_ip":"192.0.2.77"}`

	var healthy bytes.Buffer
	healthyFailures, healthyErr := NormalizeReaderFiltered(strings.NewReader(complete), &healthy, filter)
	if healthyErr != nil || healthyFailures != 1 {
		t.Fatalf("test setup: healthy filtered reference read failed: failures=%d err=%v", healthyFailures, healthyErr)
	}
	firstRecord := encodedRecord(t, 1, invalidOutside)

	src := newFaultWithBatchReader(prefix, inBig, fragment)
	w := &failWriter{allowBytes: len(firstRecord), partial: 120, err: errSimulatedWrite}
	failures, err := NormalizeReaderFiltered(src, w, filter)
	expectReadPrimaryOverWrite(t, err)
	if failures != 1 {
		t.Fatalf("only the invalid complete line 1 counts; the fault tail adds nothing, got %d", failures)
	}
	if src.postFaultReads != 0 {
		t.Fatalf("processing must stop without another Read, got %d post-fault reads", src.postFaultReads)
	}
	if w.buf.Len() != len(firstRecord)+120 {
		t.Fatalf("accepted bytes must be the line-1 failure record plus 120 bytes of the long event, got %d", w.buf.Len())
	}
	if !bytes.HasPrefix(healthy.Bytes(), w.buf.Bytes()) {
		t.Fatalf("accepted bytes must equal the healthy filtered output prefix:\nkept:    %q\nhealthy: %q",
			w.buf.String(), healthy.String())
	}
	whole := decodePrefix(t, w.buf.Bytes())
	if len(whole) != 1 || whole[0]["line"] != float64(1) || whole[0]["ok"] != false {
		t.Fatalf("only the line-1 failure record may decode whole: %#v", whole)
	}
	if msg, _ := whole[0]["error"].(string); !strings.Contains(msg, FieldTimestamp) {
		t.Fatalf("line 1 must keep its timestamp-specific reason, got %q", msg)
	}
	if bytes.Contains(w.buf.Bytes(), []byte("tail-in-allowed")) {
		t.Fatalf("the fault's newline-less tail must leave no record: %q", w.buf.String())
	}
}
