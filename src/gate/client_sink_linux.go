package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"golang.org/x/sys/unix"
)

// TransportMetadata separates delivery and cleanup from the command's outcome.
type TransportMetadata struct {
	Abandoned         bool                 `json:"abandoned"`
	DroppedBytes      int64                `json:"dropped_bytes"`
	SourceTruncated   string               `json:"source_truncated"`
	SourceBytesRead   int64                `json:"source_bytes_read"`
	DeliveryError     string               `json:"delivery_error"`
	OutputDestination string               `json:"output_destination"`
	CleanupError      string               `json:"cleanup_error"`
	WorkerStatus      confine.WorkerStatus `json:"worker_status"`
}

// CatchSIGPIPE catches rather than ignores SIGPIPE so exec restores its default.
func CatchSIGPIPE() func() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGPIPE)
	return func() { signal.Stop(signals) }
}

// ClientSink owns delivery to both client streams. Finish is a writer barrier;
// callers must join producers and offer their final diagnostics before calling it.
type ClientSink struct {
	mu          sync.Mutex
	streams     [2]*ClientStream
	wake        int
	done        chan struct{}
	watched     chan struct{}
	finishOnce  sync.Once
	closeOnce   sync.Once
	stopSignals func()
	finished    bool
	metadata    TransportMetadata
}

// ClientStream serializes writes to one destination, discarding after failure.
type ClientStream struct {
	mu     sync.Mutex
	sink   *ClientSink
	fd     int
	flags  int
	name   string
	failed bool
}

func NewClientSink(ctx context.Context, stdout, stderr *os.File) (*ClientSink, error) {
	wake, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return nil, err
	}
	s := &ClientSink{wake: wake, done: make(chan struct{}), watched: make(chan struct{}), stopSignals: CatchSIGPIPE()}
	s.metadata.OutputDestination, err = ClientOutputDestination(stdout, stderr)
	if err != nil {
		unix.Close(wake)
		s.stopSignals()
		return nil, err
	}
	for i, f := range []*os.File{stdout, stderr} {
		var fd int
		fd, err = unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			break
		}
		var flags int
		flags, err = unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil {
			unix.Close(fd)
			break
		}
		stream := &ClientStream{sink: s, fd: fd, flags: flags, name: []string{"stdout", "stderr"}[i]}
		s.streams[i] = stream
	}
	if err == nil {
		for _, stream := range s.streams {
			if err = unix.SetNonblock(stream.fd, true); err != nil {
				break
			}
		}
	}
	if err != nil {
		for _, stream := range s.streams {
			if stream != nil {
				unix.FcntlInt(uintptr(stream.fd), unix.F_SETFL, stream.flags)
				unix.Close(stream.fd)
			}
		}
		unix.Close(wake)
		s.stopSignals()
		return nil, fmt.Errorf("client sink: %w", err)
	}
	go func() {
		defer close(s.watched)
		select {
		case <-s.done:
			return
		case <-ctx.Done():
		}
		timer := time.NewTimer(500 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-s.done:
			return
		case <-timer.C:
		}
		s.mu.Lock()
		if !s.finished {
			s.metadata.Abandoned = true
			// Keep the event readable until both stream writers have left poll.
			_, _ = unix.Write(s.wake, []byte{1, 0, 0, 0, 0, 0, 0, 0})
		}
		s.mu.Unlock()
	}()
	return s, nil
}

func (s *ClientSink) Stdout() *ClientStream { return s.streams[0] }
func (s *ClientSink) Stderr() *ClientStream { return s.streams[1] }

func (w *ClientStream) Write(p []byte) (int, error) {
	_, err := w.WriteDelivered(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteDelivered consumes all input, returning only the prefix actually delivered.
// Delivery failures become metadata and discard, allowing sources to drain.
func (w *ClientStream) WriteDelivered(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delivered := 0
	for delivered < len(p) {
		s := w.sink
		s.mu.Lock()
		if s.finished {
			s.mu.Unlock()
			return delivered, os.ErrClosed
		}
		if s.metadata.Abandoned || w.failed {
			s.metadata.DroppedBytes += int64(len(p) - delivered)
			s.mu.Unlock()
			return delivered, nil
		}
		n, err := unix.Write(w.fd, p[delivered:])
		if n > 0 {
			delivered += n
		}
		if err != nil && err != unix.EAGAIN && err != unix.EINTR {
			w.failed = true
			reason := err.Error()
			if errors.Is(err, unix.EPIPE) {
				reason = "EPIPE"
			}
			if errors.Is(err, unix.ECONNRESET) {
				reason = "ECONNRESET"
			}
			if s.metadata.DeliveryError != "" {
				s.metadata.DeliveryError += ";"
			}
			s.metadata.DeliveryError += w.name + ":" + reason
		}
		s.mu.Unlock()
		if err == unix.EAGAIN {
			poll := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLOUT}, {Fd: int32(s.wake), Events: unix.POLLIN}}
			for {
				_, err = unix.Poll(poll, -1)
				if err != unix.EINTR {
					break
				}
			}
			if err != nil {
				s.mu.Lock()
				w.failed = true
				if s.metadata.DeliveryError != "" {
					s.metadata.DeliveryError += ";"
				}
				s.metadata.DeliveryError += w.name + ":" + err.Error()
				s.mu.Unlock()
			}
		}
	}
	return delivered, nil
}

func (s *ClientSink) Finish() TransportMetadata {
	s.finishOnce.Do(func() {
		s.streams[0].mu.Lock()
		s.streams[1].mu.Lock()
		s.mu.Lock()
		s.finished = true
		close(s.done)
		s.mu.Unlock()
		s.streams[1].mu.Unlock()
		s.streams[0].mu.Unlock()
		<-s.watched
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.metadata
}

func (s *ClientSink) Close() error {
	s.Finish()
	var result error
	s.closeOnce.Do(func() {
		for _, stream := range s.streams {
			_, err := unix.FcntlInt(uintptr(stream.fd), unix.F_SETFL, stream.flags)
			result = errors.Join(result, err, unix.Close(stream.fd))
		}
		result = errors.Join(result, unix.Close(s.wake))
		s.stopSignals()
	})
	return result
}

// Snapshot returns current metadata; Finish is required for a final audit snapshot.
func (s *ClientSink) Snapshot() TransportMetadata {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.metadata
}

// ClientOutputDestination classifies both client descriptors without changing their flags.
func ClientOutputDestination(stdout, stderr *os.File) (string, error) {
	destination := "pollable"
	for _, file := range []*os.File{stdout, stderr} {
		if file == nil {
			return "unavailable", errors.New("nil client destination")
		}
		var stat unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
			return "unavailable", err
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			destination = "file"
		case unix.S_IFIFO, unix.S_IFSOCK:
		case unix.S_IFCHR:
			if _, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS); err != nil && destination != "file" {
				destination = "other"
			}
		default:
			if destination != "file" {
				destination = "other"
			}
		}
	}
	return destination, nil
}
