// Command normalizeeof is a self-contained, offline demo of how
// relayproof.NormalizeReader tells a normal end of input apart from a read
// interruption, including combined errors that carry io.EOF together with
// another independent cause, and how read/write faults that arrive together
// are attributed.
//
// Run it with no network and no third-party dependencies:
//
//	go run ./examples/normalizeeof
//
// It uses in-memory readers/writers that script faults deterministically; the
// same code against an os.File or net.Conn follows the same io.Reader/io.Writer
// contract.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/asdhoaiqqq/relayproof-bridge/relayproof"
)

// errDeviceLost and errSinkBroken stand in for the concrete causes a real
// upstream reader and downstream writer might return.
var (
	errDeviceLost = errors.New("upstream device lost")
	errSinkBroken = errors.New("downstream sink broken")
)

// oneShotReader hands back all of data together with err on its first Read,
// modeling a device that delivers a final batch and reports its state in the
// same call (a file read at the last block, a connection half-closing with an
// error, ...). Every later Read returns io.EOF.
type oneShotReader struct {
	data      []byte
	err       error
	delivered bool
}

func (r *oneShotReader) Read(p []byte) (int, error) {
	if r.delivered {
		return 0, io.EOF
	}
	r.delivered = true
	n := copy(p, r.data)
	if n < len(r.data) {
		panic("oneShotReader: data larger than the caller's buffer")
	}
	return n, r.err
}

// failingWriter accepts allowBytes bytes in total and then fails; the failing
// Write itself still accepts up to partial bytes, modeling an output that is
// cut off mid-record. Everything accepted is retained for inspection.
type failingWriter struct {
	buf        bytes.Buffer
	allowBytes int
	partial    int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	accepted := 0
	if w.allowBytes > 0 {
		n := min(len(p), w.allowBytes)
		w.buf.Write(p[:n])
		w.allowBytes -= n
		accepted, p = n, p[n:]
		if len(p) == 0 {
			return accepted, nil
		}
	}
	m := min(w.partial, len(p))
	w.buf.Write(p[:m])
	return accepted + m, errSinkBroken
}

// batch is the same input for the main scenarios — one batch containing:
//
//	line 1: a valid log, newline-ended
//	line 2: a log with an invalid timestamp, newline-ended
//	line 3: a valid log WITHOUT a trailing newline
const batch = "" +
	`{"timestamp":"2026-01-02T00:00:00Z","action":"ok-1"}` + "\n" +
	`{"timestamp":"not-a-time","action":"bad-2"}` + "\n" +
	`{"timestamp":"2026-01-02T00:00:00Z","action":"tail-3"}`

func main() {
	cleanCompletionVariants()
	combinedFaultIsInterruption()
	fragmentOnlyCanStillBeInterruption()
	readFaultStaysPrimaryWhenFlushFails()
	writeFaultWithHealthyReadIsWriteFailure()
}

// 1. Every error that is io.EOF and nothing else — plain, wrapped, or a join
// of only EOF markers — is normal completion. The newline-less final line is
// processed, the invalid line counts as a failure but err stays nil.
func cleanCompletionVariants() {
	cases := []struct {
		name string
		err  error
	}{
		{"plain io.EOF", io.EOF},
		{"%w-wrapped io.EOF", fmt.Errorf("connection closed: %w", io.EOF)},
		{"errors.Join of only io.EOF", errors.Join(io.EOF, io.EOF)},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		failures, err := relayproof.NormalizeReader(
			&oneShotReader{data: []byte(batch), err: tc.err}, &out)
		records := bytes.Count(out.Bytes(), []byte("\n"))
		fmt.Printf("=== normal completion: %s ===\n", tc.name)
		fmt.Printf("%s", out.Bytes())
		fmt.Printf("records=%d failures=%d err=%v\n\n", records, failures, err)
	}
}

// 2. io.EOF combined with an independent read cause is an interruption even
// behind %w wrapping and even though errors.Is(err, io.EOF) matches. The
// newline-ended logs are processed in order; the newline-less tail vanishes.
func combinedFaultIsInterruption() {
	combined := fmt.Errorf("upstream closed mid-batch: %w",
		errors.Join(io.EOF, errDeviceLost))
	var out bytes.Buffer
	failures, err := relayproof.NormalizeReader(
		&oneShotReader{data: []byte(batch), err: combined}, &out)

	fmt.Printf("=== interruption: wrapped errors.Join(io.EOF, device cause) ===\n")
	fmt.Printf("%s", out.Bytes()) // lines 1 and 2 only; line 3 leaves no record
	fmt.Printf("failures=%d\n", failures)
	fmt.Printf("err=%v\n", err)
	fmt.Printf("errors.Is(err, io.EOF)=%v (matches, but is not enough)\n",
		errors.Is(err, io.EOF))
	fmt.Printf("errors.Is(err, ErrLogRead)=%v\n", errors.Is(err, relayproof.ErrLogRead))
	fmt.Printf("errors.Is(err, errDeviceLost)=%v\n", errors.Is(err, errDeviceLost))
	fmt.Printf("errors.Is(err, ErrLogWrite)=%v\n\n", errors.Is(err, relayproof.ErrLogWrite))
}

// 3. When the combined fault carries only a newline-less fragment — itself a
// perfectly legal log — the output is empty and the failure count zero, yet
// the interruption is still returned. Empty output plus zero failures is not
// proof of success: err must be checked first.
func fragmentOnlyCanStillBeInterruption() {
	fragment := `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-3"}`
	var out bytes.Buffer
	failures, err := relayproof.NormalizeReader(
		&oneShotReader{data: []byte(fragment), err: errors.Join(io.EOF, errDeviceLost)},
		&out)

	fmt.Printf("=== interruption: only a newline-less legal fragment rides the fault ===\n")
	fmt.Printf("output empty: %v\n", out.Len() == 0)
	fmt.Printf("failures=%d\n", failures)
	fmt.Printf("errors.Is(err, ErrLogRead)=%v\n", errors.Is(err, relayproof.ErrLogRead))
	fmt.Printf("errors.Is(err, errDeviceLost)=%v\n\n", errors.Is(err, errDeviceLost))
}

// 4. The read fault is recorded at the exact Read that returns it, together
// with its complete newline-ended logs. When writing those results fails —
// here the shutdown flush rejects every byte — the read fault stays the
// primary cause: ErrLogRead and the reader's cause are errors.Is-reachable,
// while the write cause appears only in the message text.
func readFaultStaysPrimaryWhenFlushFails() {
	w := &failingWriter{} // records are small, so the first physical write is the final flush
	failures, err := relayproof.NormalizeReader(
		&oneShotReader{data: []byte(batch), err: errors.Join(io.EOF, errDeviceLost)}, w)

	fmt.Printf("=== read fault already in hand, shutdown flush then fails ===\n")
	fmt.Printf("output bytes kept: %d (the failed flush accepted nothing)\n", w.buf.Len())
	fmt.Printf("failures=%d\n", failures)
	fmt.Printf("err=%v\n", err)
	fmt.Printf("errors.Is(err, ErrLogRead)=%v\n", errors.Is(err, relayproof.ErrLogRead))
	fmt.Printf("errors.Is(err, errDeviceLost)=%v\n", errors.Is(err, errDeviceLost))
	fmt.Printf("errors.Is(err, ErrLogWrite)=%v\n", errors.Is(err, relayproof.ErrLogWrite))
	fmt.Printf("errors.Is(err, errSinkBroken)=%v (only the text above names it)\n\n",
		errors.Is(err, errSinkBroken))
}

// 5. If the writer fails while no read fault has been received, the run ends
// as a write failure immediately — processing does not read on to look for a
// read cause. Per-line failures counted earlier remain counted.
func writeFaultWithHealthyReadIsWriteFailure() {
	w := &failingWriter{} // healthy input; the final flush fails
	failures, err := relayproof.NormalizeReader(strings.NewReader(batch), w)

	fmt.Printf("=== healthy input, shutdown flush fails ===\n")
	fmt.Printf("failures=%d (line 2 is still a bad log)\n", failures)
	fmt.Printf("err=%v\n", err)
	fmt.Printf("errors.Is(err, ErrLogWrite)=%v\n", errors.Is(err, relayproof.ErrLogWrite))
	fmt.Printf("errors.Is(err, errSinkBroken)=%v\n", errors.Is(err, errSinkBroken))
	fmt.Printf("errors.Is(err, ErrLogRead)=%v\n", errors.Is(err, relayproof.ErrLogRead))
}
