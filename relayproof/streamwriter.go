// Whole-stream processing for normalize: byte receipt and physical-line
// division live here, separate from the single-line normalization in
// normalize.go. A streamSink turns one io.Reader of newline-delimited JSON
// logs into one NormalizeResult JSON object per non-blank physical line on one
// io.Writer. NormalizeReader/NormalizeReaderFiltered only decide whether a
// source filter is attached; every fact about how the byte stream is read,
// divided, classified at end of input, selected, written, and finalized is
// stated in this file once.
package relayproof

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// isCleanEndOfInput reports whether err denotes nothing but the end of the
// input: io.EOF itself, or wrappers — a single %w chain or an errors.Join
// combination — whose every underlying cause is io.EOF. A combined error
// that carries io.EOF together with any other independent cause is NOT a
// clean end: errors.Is(err, io.EOF) matches it, but the accompanying cause
// is a genuine read fault. Treating such a combination as normal completion
// would silently drop the real cause and mistake the newline-less fragment
// delivered with it for a complete final line.
func isCleanEndOfInput(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		causes := multi.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !isCleanEndOfInput(cause) {
				return false
			}
		}
		return true
	}
	if single, ok := err.(interface{ Unwrap() error }); ok {
		return isCleanEndOfInput(single.Unwrap())
	}
	return false
}

// shortWriteDetectingWriter enforces the io.Writer contract at the output
// boundary: a Write that acknowledges fewer bytes than it was offered while
// reporting a nil error becomes io.ErrShortWrite. The guard matters for
// results larger than the buffering writer's 4 KiB buffer: those bypass the
// buffer and are handed to the underlying Writer in one call, and bufio
// retries a nil-error short acknowledgement forever (a (0, nil) answer loops
// without making progress), so without the normalization the sink would never
// return. Turning the broken acknowledgement into an ordinary error makes
// bufio stop on the first short write and lets the failure surface as
// ErrLogWrite wrapping io.ErrShortWrite. A Write that already reports a concrete
// error passes it through untouched: that error stays the write failure's
// original cause and is never replaced by io.ErrShortWrite.
type shortWriteDetectingWriter struct {
	w io.Writer
}

func (w shortWriteDetectingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if err == nil && n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, err
}

// streamSink drives one normalize run end to end. Reading (byte receipt,
// empty-read guarding, and the clean-EOF-versus-fault decision) is the input
// concern; result encoding/selection and the read-over-write precedence on
// failure are the output concern. The two meet only through processLine and
// writeFailure, so changing line division cannot alter how a result is
// written and changing selection cannot alter how the stream ends.
type streamSink struct {
	r      io.Reader
	filter *SourceCIDRFilter // nil means every successful event is emitted

	bw      *bufio.Writer
	encoder *json.Encoder

	// readErr is the first stream read error and is always the primary
	// failure: it is latched at the exact Read call that returns it, before
	// the bytes delivered in that same call are touched.
	readErr error

	// Physical-line bookkeeping. pending holds bytes not yet divided into a
	// complete line; scanned counts pending's leading bytes already known to
	// contain no newline, so only newly appended bytes are searched.
	pending []byte
	scanned int
	lineNo  int

	// emptyReads bounds consecutive (0, nil) Read answers instead of
	// spinning without progress the way bufio does.
	emptyReads int

	failures int
}

// processLine normalizes and emits one complete physical line (including its
// trailing newline). Blank lines only advance the physical line counter: they
// produce no result. A non-blank line is fully normalized first; only then
// may the CIDR filter suppress a *successful* event, so a failed line is
// always emitted with its reason and counted no matter where its (raw)
// address would fall. It reports only an output failure; per-line
// normalization failures are counted and emitted as results instead.
func (s *streamSink) processLine(raw []byte) error {
	s.lineNo++
	if strings.TrimSpace(string(raw)) == "" {
		return nil
	}
	result := NormalizeLine(s.lineNo, raw)
	emit := true
	if !result.OK {
		s.failures++
	} else if s.filter != nil && !s.filter.admits(result.Event.SourceIP) {
		// A valid event whose normalized source is outside the selected
		// network (or absent, or still IPv6) is filtered out: no result and
		// no failure. The filter never runs on failed lines, so a bad
		// address outside the network is still reported as a failure.
		emit = false
	}
	if !emit {
		return nil
	}
	return s.encoder.Encode(result)
}

// drainCompleteLines processes every newline-ended line in pending, in
// physical order, starting the newline search at the first not-yet-examined
// byte. It returns the first output failure; the bytes of the line whose
// result failed have already been handed to the writer.
func (s *streamSink) drainCompleteLines() error {
	for {
		i := bytes.IndexByte(s.pending[s.scanned:], '\n')
		if i < 0 {
			s.scanned = len(s.pending)
			return nil
		}
		i += s.scanned
		raw := s.pending[:i+1]
		werr := s.processLine(raw)
		s.pending = s.pending[i+1:]
		// The bytes after the consumed newline have not been examined yet, so
		// the next search starts from the new front.
		s.scanned = 0
		if werr != nil {
			return werr
		}
	}
}

// readErrorWins reports a write fault after a read fault has already been
// delivered: the read failure and its original cause stay the only error
// chain (both reachable via errors.Is), while the later write fault only
// contributes its message text and must not replace or join the chain.
func (s *streamSink) readErrorWins(writeErr error) error {
	wrapped := fmt.Errorf("%w: %w", ErrLogRead, s.readErr)
	if writeErr != nil {
		wrapped = fmt.Errorf("%w: %v", wrapped, writeErr)
	}
	return wrapped
}

// writeFailure classifies an output fault: once a read fault is in hand it
// stays primary even though the write fired first in time; otherwise this is
// the ordinary write-failure report and the caller stops without reading any
// further input to decide precedence.
func (s *streamSink) writeFailure(werr error) error {
	if s.readErr != nil {
		return s.readErrorWins(werr)
	}
	return fmt.Errorf("%w: %w", ErrLogWrite, werr)
}

// run is the read loop. A read fault is latched before the bytes that came
// with it are processed, so it survives an output failure while emitting the
// complete lines of that very delivery. It returns only an output fault met
// during the loop; a read fault (including the no-progress stall) leaves the
// loop with a nil return so finalize can still flush and can classify the
// shutdown write against the latched readErr, exactly as the original flow.
func (s *streamSink) run() error {
	chunk := make([]byte, 64*1024)
	for {
		n, rerr := s.r.Read(chunk)
		if n > 0 {
			s.pending = append(s.pending, chunk[:n]...)
			s.emptyReads = 0
		} else if rerr == nil {
			// A well-behaved Reader never returns (0, nil); bound the
			// retries instead of spinning without progress, matching bufio.
			s.emptyReads++
			if s.emptyReads > 100 {
				// Latch the stall like any other read fault; return with no
				// loop error so finalize flushes and classifies against it.
				s.readErr = io.ErrNoProgress
				return nil
			}
			continue
		}
		// Only an error that is io.EOF and nothing else is a clean end of
		// input. A combined error that joins io.EOF with another independent
		// cause (even behind ordinary %w wrapping) still matches
		// errors.Is(err, io.EOF), but the other cause is a real read fault:
		// it must be recorded as such, not vanish into normal completion.
		eof := isCleanEndOfInput(rerr)
		fault := rerr != nil && !eof
		if fault {
			// The fault is recorded before the bytes delivered with it are
			// touched, so it survives even if pushing their results out fails.
			s.readErr = rerr
		}

		if werr := s.drainCompleteLines(); werr != nil {
			return s.writeFailure(werr)
		}
		if len(s.pending) == 0 {
			// Release the grown accumulator once every delivered byte is a
			// processed complete line, so retention tracks the longest line
			// rather than the whole stream.
			s.pending = nil
			s.scanned = 0
		}

		switch {
		case fault:
			// The newline-less remainder belongs to the failed read: it is
			// neither normalized nor counted and gets no result of its own.
			// Leave the loop with no loop error; finalize flushes and
			// classifies any shutdown write fault against the latched
			// readErr, and no further input is read to set precedence.
			return nil
		case eof:
			// A clean EOF is normal completion: any remaining bytes are the
			// final complete line without a trailing newline.
			if len(s.pending) > 0 {
				if werr := s.processLine(s.pending); werr != nil {
					return s.writeFailure(werr)
				}
			}
			return nil
		}
	}
}

// finalize flushes buffered output once the read loop has ended, exactly as
// the original deferred shutdown did: the flush itself always runs (it retries
// whatever the loop's failure left buffered at the writer), but its result only
// matters when the loop returned no error of its own. With a read fault
// already in hand (including a stall), a flush failure only adds text; with no
// read fault, a flush failure is the run's write failure.
func (s *streamSink) finalize(runErr error) error {
	flushErr := s.bw.Flush()
	if runErr != nil {
		// The read loop already classified its error; the flush still ran,
		// but its outcome is decided against the latched readErr only when the
		// loop itself did not fail: a mid-loop write fault is final.
		return runErr
	}
	switch {
	case s.readErr != nil:
		// The original read failure must survive a write failure during
		// shutdown: both the read marker and the underlying cause stay
		// reachable via errors.Is, while the later flush failure only
		// contributes its text (it must not mask the original cause).
		return s.readErrorWins(flushErr)
	case flushErr != nil:
		return fmt.Errorf("%w: %w", ErrLogWrite, flushErr)
	}
	return nil
}

// NormalizeReader streams newline-delimited JSON logs from r and writes one
// NormalizeResult JSON object per non-blank physical line to w. Blank lines
// produce no output but still advance the physical line counter. It returns
// the number of complete lines that failed normalization; processing of
// later lines continues after any per-line failure.
//
// Stream-level failures are distinct from bad log lines: a read error stops
// processing and is returned wrapped with ErrLogRead, after every complete
// line already read has been processed in order; any unterminated fragment
// delivered together with the read error is part of the failed read rather
// than a complete log line, so it is neither normalized nor counted and gets
// no result of its own. A read error is recorded at the exact Read call that
// returns it, including when that call hands back complete newline-ended
// logs in the same delivery, so it stays the primary failure even when the
// output later fails while emitting those very results: the write failure is
// shown in the message text but is not wrapped, and neither ErrLogWrite nor
// the write's cause matches via errors.Is. Conversely, a write failure with
// no read error in hand is reported as such immediately, without reading any
// further input to decide precedence. A write error is returned wrapped with
// ErrLogWrite and leaves the failure count unchanged: an output end that
// acknowledges fewer bytes than offered with a nil error (an io.Writer
// contract violation) ends the run the same way, with io.ErrShortWrite kept
// in the error chain instead of retried until it recovers; bytes already
// accepted remain as the prefix of the would-be output, including an
// incomplete final JSON record. A clean EOF is not an error, including when
// the final complete line has no trailing newline. Clean means the error is
// io.EOF and nothing else: a combined error that carries io.EOF together
// with another independent cause — even behind ordinary error wrapping — is
// a read failure, handled exactly like any other non-EOF read fault.
func NormalizeReader(r io.Reader, w io.Writer) (failures int, err error) {
	return NormalizeReaderFiltered(r, w, nil)
}

// NormalizeReaderFiltered behaves like NormalizeReader, except that when
// filter is non-nil a successfully normalized event is written only when its
// normalized source_ip is admitted by the filter. Filtered-out successes are
// not written and are not failures: they leave both the failure count and
// the exit status unchanged. The filter never hides bad logs: a line that
// fails normalization is still emitted with its physical line number and
// original error reason and carries no event, whether or not its raw address
// was inside, outside, or absent from the network, and later lines keep
// processing. A nil filter reproduces NormalizeReader exactly.
func NormalizeReaderFiltered(r io.Reader, w io.Writer, filter *SourceCIDRFilter) (failures int, err error) {
	sink := &streamSink{r: r, filter: filter}
	// Guard the output end before buffering: a result that exceeds the
	// 4 KiB buffer is forwarded straight to the underlying Writer, so the
	// Flush path alone cannot catch a nil-error short acknowledgement there.
	sink.bw = bufio.NewWriter(shortWriteDetectingWriter{w: w})
	sink.encoder = json.NewEncoder(sink.bw)
	sink.encoder.SetEscapeHTML(false)

	runErr := sink.run()
	// Return the failure count frozen at loop exit alongside the finalized
	// error: the shutdown flush must never reset or add to it.
	defer func() {
		err = sink.finalize(runErr)
	}()
	return sink.failures, runErr
}
