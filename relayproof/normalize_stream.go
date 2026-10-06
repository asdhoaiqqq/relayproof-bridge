// Stream plumbing for log normalization: turning the input byte stream into
// physical lines, emitting one result record per line, and classifying
// stream-level read/write faults. Per-line normalization itself lives in
// normalize.go; this file owns everything between the raw Reader and the
// result records.
package relayproof

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrLogRead and ErrLogWrite let callers tell stream-level I/O failures
// apart from per-line normalization failures: NormalizeReader wraps the
// underlying error with the matching sentinel, and a single invalid log
// line never carries either.
var (
	ErrLogRead  = errors.New("log stream read failure")
	ErrLogWrite = errors.New("log stream write failure")
)

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
	// Guard the output end before buffering: a result that exceeds the
	// 4 KiB buffer is forwarded straight to the underlying Writer, so the
	// Flush path alone cannot catch a nil-error short acknowledgement there.
	bw := bufio.NewWriter(shortWriteDetectingWriter{w: w})
	var readErr error // first stream read error, always the primary failure
	defer func() {
		flushErr := bw.Flush()
		if err != nil {
			// A mid-stream error was already wrapped below; a write fault met
			// there was classified against readErr at the instant it fired.
			return
		}
		switch {
		case readErr != nil:
			// The original read failure must survive a write failure during
			// shutdown: both the read marker and the underlying cause stay
			// reachable via errors.Is, while the later flush failure only
			// contributes its text (it must not mask the original cause).
			err = wrapReadFault(readErr, flushErr)
		case flushErr != nil:
			err = fmt.Errorf("%w: %w", ErrLogWrite, flushErr)
		}
	}()

	sink := newNormalizeSink(bw, filter)
	splitter := newPhysicalLineSplitter(r)
	readErr, emitErr := splitter.forEachLine(sink.emitLine)
	if emitErr != nil {
		// An output fault stops the run at once, without reading any further
		// input to decide precedence; the recorded read fault, if any, stays
		// primary even though the write fired first in processing order.
		return sink.failures, classifyWriteFault(readErr, emitErr)
	}
	return sink.failures, nil
}

// physicalLineSplitter turns the byte stream of one Reader into complete
// physical lines. It owns the read loop and the accumulator that assembles
// lines delivered in arbitrary pieces; it knows nothing about what a line
// means or where results go.
type physicalLineSplitter struct {
	r       io.Reader
	chunk   []byte
	pending []byte
	// scanned counts the leading bytes of pending already known to contain no
	// newline. Only bytes appended since the last scan are searched, so a long
	// line delivered in many small pieces is assembled without re-examining
	// the bytes every earlier piece already ruled out.
	scanned    int
	emptyReads int
}

func newPhysicalLineSplitter(r io.Reader) *physicalLineSplitter {
	return &physicalLineSplitter{r: r, chunk: make([]byte, 64*1024)}
}

// forEachLine reads the stream to its end, invoking emit once per complete
// physical line in input order. Lines delivered with a trailing newline are
// emitted including that newline; on a clean EOF a final newline-less
// remainder is emitted as the last complete line, while a remainder that
// arrives together with a read fault belongs to the failed read and is
// dropped unemitted.
//
// The first return value is the first non-EOF read fault, recorded at the
// exact Read call that delivered it — before the bytes that came with it are
// emitted — so it can never be reclassified by an emit failure that follows
// in processing order. Only an error that is io.EOF and nothing else is a
// clean end of input; a combined error that joins io.EOF with another
// independent cause is a fault like any other. A Reader stuck returning
// (0, nil) is bounded and reported as io.ErrNoProgress. If emit itself
// fails, streaming stops immediately without another Read and the emit
// error is returned as the second value.
func (s *physicalLineSplitter) forEachLine(emit func(raw []byte) error) (readErr, emitErr error) {
	// Drive the upstream Reader directly instead of bufio.Reader.ReadBytes.
	// ReadBytes latches an error that arrives together with a
	// delimiter-ended chunk: the complete line comes back with a nil error and
	// the fault is only returned on the NEXT call. Emitting that line could
	// then fail on the output first, and the plain write return would mask the
	// already-delivered read cause. Owning the loop makes every (bytes, err)
	// pair observable at the exact call it arrives.
	for {
		n, rerr := s.r.Read(s.chunk)
		if n > 0 {
			s.pending = append(s.pending, s.chunk[:n]...)
			s.emptyReads = 0
		} else if rerr == nil {
			// A well-behaved Reader never returns (0, nil); bound the
			// retries instead of spinning without progress, matching bufio.
			s.emptyReads++
			if s.emptyReads > 100 {
				return io.ErrNoProgress, nil
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
			readErr = rerr
		}

		// Emit every newline-ended line the delivered bytes complete.
		// pending[:scanned] holds no newline, so the search starts at the
		// first not-yet-examined byte instead of re-scanning the whole
		// accumulator on every delivery.
		for {
			i := bytes.IndexByte(s.pending[s.scanned:], '\n')
			if i < 0 {
				s.scanned = len(s.pending)
				break
			}
			i += s.scanned
			if emitErr = emit(s.pending[:i+1]); emitErr != nil {
				return readErr, emitErr
			}
			s.pending = s.pending[i+1:]
			// The bytes after the consumed newline have not been examined
			// yet, so the next search starts from the new front.
			s.scanned = 0
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
			// neither emitted nor counted and gets no result of its own.
			// Stop immediately; no further input is read to set precedence.
			return readErr, nil
		case eof:
			// A clean EOF is normal completion: any remaining bytes are the
			// final complete line without a trailing newline.
			if len(s.pending) > 0 {
				if emitErr = emit(s.pending); emitErr != nil {
					return readErr, emitErr
				}
			}
			return nil, nil
		}
	}
}

// normalizeSink turns complete physical lines into NormalizeResult records
// on the output stream. It owns the physical line counter, the failure
// count, the optional source filter, and the JSON encoder; it knows nothing
// about how lines were read or how output faults are classified.
type normalizeSink struct {
	encoder  *json.Encoder
	filter   *SourceCIDRFilter
	lineNo   int
	failures int
}

func newNormalizeSink(w io.Writer, filter *SourceCIDRFilter) *normalizeSink {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return &normalizeSink{encoder: encoder, filter: filter}
}

// emitLine normalizes and emits one complete physical line (including its
// trailing newline). It reports only an output failure; per-line
// normalization failures are counted and emitted as results instead.
func (s *normalizeSink) emitLine(raw []byte) error {
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

// wrapReadFault reports a write fault after a read fault has already been
// delivered: the read failure and its original cause stay the only error
// chain (both reachable via errors.Is), while the later write fault only
// contributes its message text and must not replace or join the chain.
func wrapReadFault(readErr, writeErr error) error {
	wrapped := fmt.Errorf("%w: %w", ErrLogRead, readErr)
	if writeErr != nil {
		wrapped = fmt.Errorf("%w: %v", wrapped, writeErr)
	}
	return wrapped
}

// classifyWriteFault classifies an output fault: once a read fault is in
// hand it stays primary even though the write fired first in time;
// otherwise this is the ordinary write-failure report.
func classifyWriteFault(readErr, writeErr error) error {
	if readErr != nil {
		return wrapReadFault(readErr, writeErr)
	}
	return fmt.Errorf("%w: %w", ErrLogWrite, writeErr)
}

// shortWriteDetectingWriter enforces the io.Writer contract at the output
// boundary: a Write that acknowledges fewer bytes than it was offered while
// reporting a nil error becomes io.ErrShortWrite. The guard matters for
// results larger than the buffering writer's 4 KiB buffer: those bypass the
// buffer and are handed to the underlying Writer in one call, and bufio
// retries a nil-error short acknowledgement forever (a (0, nil) answer loops
// without making progress), so without the normalization NormalizeReader
// would never return. Turning the broken acknowledgement into an ordinary
// error makes bufio stop on the first short write and lets the failure
// surface as ErrLogWrite wrapping io.ErrShortWrite. A Write that already
// reports a concrete error passes it through untouched: that error stays the
// write failure's original cause and is never replaced by io.ErrShortWrite.
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
