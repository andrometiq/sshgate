package hosted

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

var ErrAuditBusy = errors.New("hosted: audit writer busy")

// ProcessAuditSink serializes complete frames on a process-owned blocking writer.
// Cancellation stops the caller's wait, never the outstanding write. Server must
// not close this transport: late completion is replayed by the durable outbox.
type ProcessAuditSink struct {
	writer       io.Writer
	requests     chan auditFrame
	joined       chan struct{}
	mu           sync.Mutex
	busy         bool
	auditPending *auditFrame
	auditBusy    bool
	diagnostics  [][]byte
	dropped      uint64
	dirty        bool // accessed only by the outstanding writer
}

// NewProcessAuditSink is constructed by main before logging starts. Route log
// output and HTTP ErrorLog through Write. It changes no flags or deadlines.
func NewProcessAuditSink(file *os.File) (*ProcessAuditSink, error) {
	if file == nil {
		return nil, errors.New("hosted: audit file required")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	dirty := false
	if info.Mode().IsRegular() && info.Size() > 0 {
		var tail [1]byte
		_, err = file.ReadAt(tail[:], info.Size()-1)
		if err != nil {
			// Redirected stderr is commonly write-only. Read its tail through a separate
			// descriptor without moving the append stream's offset.
			reader, openErr := os.Open(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
			if openErr == nil {
				_, err = reader.ReadAt(tail[:], info.Size()-1)
				reader.Close()
			}
		}
		// An inherited writable log need not be readable after privilege drop.
		dirty = err != nil || tail[0] != '\n'
	}
	return newProcessAuditSink(file, dirty), nil
}

type auditFrame struct {
	body   []byte
	result chan error
}

func newProcessAuditSink(writer io.Writer, dirty bool) *ProcessAuditSink {
	s := &ProcessAuditSink{writer: writer, dirty: dirty, requests: make(chan auditFrame, 1), joined: make(chan struct{})}
	go func() {
		defer close(s.joined)
		for frame := range s.requests {
			s.deliver(frame.body, frame.result)
		}
	}()
	return s
}

func (s *ProcessAuditSink) Call(ctx context.Context, call signerkit.AuditCall) error {
	var frame bytes.Buffer
	if err := signerkit.NewAppendOnlySink(&frame).Call(ctx, call); err != nil {
		return err
	}
	return s.submit(ctx, frame.Bytes())
}
func (s *ProcessAuditSink) Verdict(ctx context.Context, verdict signerkit.AuditVerdict) error {
	var frame bytes.Buffer
	if err := signerkit.NewAppendOnlySink(&frame).Verdict(ctx, verdict); err != nil {
		return err
	}
	return s.submit(ctx, frame.Bytes())
}

func (s *ProcessAuditSink) submit(ctx context.Context, frame []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	result := make(chan error, 1)
	request := auditFrame{frame, result}
	s.mu.Lock()
	if s.auditBusy {
		s.mu.Unlock()
		return ErrAuditBusy
	}
	s.auditBusy = true
	if s.busy {
		// Reserve the next write ahead of every queued diagnostic.
		s.auditPending = &request
	} else {
		s.busy = true
		s.requests <- request
	}
	s.mu.Unlock()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Write is the bounded, non-blocking diagnostic path for log and HTTP ErrorLog.
// Oversize lines are dropped whole so they cannot exhaust memory or split frames.
func (s *ProcessAuditSink) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(p) > 64*1024 || len(s.diagnostics) >= 64 {
		s.dropped += diagnosticLineCount(p)
		return len(p), nil
	}
	frame := append([]byte(nil), p...)
	if len(frame) == 0 || frame[len(frame)-1] != '\n' {
		frame = append(frame, '\n')
	}
	if s.busy {
		s.diagnostics = append(s.diagnostics, frame)
	} else {
		s.busy = true
		s.requests <- auditFrame{frame, nil}
	}
	return len(p), nil
}

func (s *ProcessAuditSink) DroppedDiagnostics() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

func (s *ProcessAuditSink) deliver(frame []byte, result chan error) {
	for {
		err := s.writeFrame(frame)
		s.mu.Lock()
		if result == nil && err != nil {
			s.dropped += diagnosticLineCount(frame)
		}
		if result != nil {
			s.auditBusy = false
			result <- err
			result = nil
		}
		if s.auditPending != nil {
			frame, result = s.auditPending.body, s.auditPending.result
			s.auditPending = nil
			s.mu.Unlock()
			continue
		}
		if len(s.diagnostics) == 0 {
			s.busy = false
			s.mu.Unlock()
			return
		}
		frame = s.diagnostics[0]
		s.diagnostics[0] = nil
		s.diagnostics = s.diagnostics[1:]
		s.mu.Unlock()
	}
}

func (s *ProcessAuditSink) writeFrame(frame []byte) error {
	if s.dirty {
		if err := s.writeAll([]byte{'\n'}); err != nil {
			return err
		}
		s.dirty = false
	}
	return s.writeAll(frame)
}

func (s *ProcessAuditSink) writeAll(frame []byte) error {
	for len(frame) > 0 {
		n, err := s.writer.Write(frame)
		if n < 0 || n > len(frame) {
			s.dirty = true
			return io.ErrShortWrite
		}
		if n > 0 {
			s.dirty = frame[n-1] != '\n'
			frame = frame[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func diagnosticLineCount(frame []byte) uint64 {
	count := uint64(bytes.Count(frame, []byte{'\n'}))
	if len(frame) > 0 && frame[len(frame)-1] != '\n' {
		count++
	}
	return count
}
