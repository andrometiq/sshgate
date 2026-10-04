package gate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/redact"
)

var cleanupConfinedDescendants = confine.CleanupDescendants

// withDelivery preserves process metadata when merging the shared client's snapshot.
func withDelivery(process, delivery TransportMetadata) TransportMetadata {
	if process.DeliveryError != "" && process.DeliveryError != delivery.DeliveryError {
		delivery.DeliveryError = joinReason(delivery.DeliveryError, process.DeliveryError)
	}
	delivery.CleanupError = process.CleanupError
	delivery.SourceTruncated = process.SourceTruncated
	delivery.SourceBytesRead = process.SourceBytesRead
	delivery.WorkerStatus = process.WorkerStatus
	return delivery
}

func runConfined(ctx context.Context, command *exec.Cmd, jailed *confine.Jailed, opts ExecOpts) (res ExecResult, err error) {
	res.ExitCode = -1
	res.Transport.WorkerStatus = confine.WorkerStatus{Unavailable: "no W record"}
	started := time.Now()
	outCount := &countingWriter{dst: opts.ClientSink.Stdout(), captureLimit: opts.CaptureLimit}
	errCount := &countingWriter{dst: opts.ClientSink.Stderr(), captureLimit: opts.CaptureLimit}
	defer func() {
		res.Duration = time.Since(started)
		res.StdoutBytes, res.StderrBytes, res.Lines = outCount.bytes.Load(), errCount.bytes.Load(), outCount.lines.Load()
		res.Stdout, res.Stderr = outCount.captured(), errCount.captured()
		res.Transport.CleanupError = res.CleanupError
		res.Transport = withDelivery(res.Transport, opts.ClientSink.Snapshot())
	}()
	if err := confine.EnableSubreaper(); err != nil {
		jailed.Abort()
		return res, fmt.Errorf("exec: gate subreaper: %w", err)
	}
	command.Stdin = nil
	command.WaitDelay = 500 * time.Millisecond
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	destinations := []io.Writer{outCount, errCount}
	closers := make([]io.Closer, 2)
	if !opts.Reveal && len(opts.Rules) != 0 {
		for i := range destinations {
			writer := redact.NewWriter(destinations[i], opts.SessionSalt, opts.Rules)
			destinations[i], closers[i] = writer, writer
		}
	}
	var readers, writers []*os.File
	defer func() {
		for _, file := range readers {
			_ = file.Close()
		}
		for _, file := range writers {
			_ = file.Close()
		}
	}()
	for range 2 {
		reader, writer, pipeErr := os.Pipe()
		if pipeErr != nil {
			jailed.Abort()
			return res, fmt.Errorf("exec: output pipe: %w", pipeErr)
		}
		readers, writers = append(readers, reader), append(writers, writer)
	}
	command.Stdout, command.Stderr = writers[0], writers[1]
	if err := command.Start(); err != nil {
		jailed.Abort()
		return res, fmt.Errorf("exec: start jail: %w", err)
	}
	done := make(chan error, 2)
	var sourceBytes atomic.Int64
	var sourceClosed atomic.Bool
	var sourceEOF [2]atomic.Bool
	for i, reader := range readers {
		_ = writers[i].Close()
		go func(i int, reader *os.File) {
			defer reader.Close()
			_, copyErr := io.Copy(destinations[i], &sourceReader{reader: reader, count: &sourceBytes, eof: &sourceEOF[i]})
			if sourceClosed.Load() && errors.Is(copyErr, os.ErrClosed) {
				copyErr = nil
			}
			if closers[i] != nil {
				copyErr = errors.Join(copyErr, closers[i].Close())
			}
			done <- copyErr
		}(i, reader)
	}
	_ = jailed.Started()
	waitErr := command.Wait()
	// Freeze process outcome before cleanup or transport work.
	res.Cancelled = ctx.Err() != nil
	res.ExitCode = confinedExit(command.ProcessState, res.Cancelled, confine.WorkerStatus{})
	cleanupErr := cleanupConfinedDescendants()
	var deadline <-chan time.Time
	var timer *time.Timer
	if cleanupErr != nil {
		timer = time.NewTimer(500 * time.Millisecond)
		defer timer.Stop()
		deadline = timer.C
	}
	facts, setupErr := jailed.Status()
	res.Transport.WorkerStatus = jailed.WorkerStatus()
	if setupErr == nil {
		res.Jail = &facts
		res.ExitCode = confinedExit(command.ProcessState, res.Cancelled, res.Transport.WorkerStatus)
	}
	res.CleanupError = jailed.CleanupError
	if res.Cancelled && command.ProcessState != nil {
		if status, ok := command.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() && status.Signal() == syscall.SIGKILL {
			cleanupErr = errors.Join(cleanupErr, errors.New("shim killed during cancellation cleanup"))
		}
	}
	if res.Cancelled && res.Transport.WorkerStatus.Unavailable == "no W record" {
		cleanupErr = errors.Join(cleanupErr, errors.New("shim ended before worker status was published"))
	}
	if cleanupErr != nil {
		res.CleanupError = joinReason(res.CleanupError, cleanupErr.Error())
	}
	var copyErr error
	for remaining := 2; remaining > 0; {
		select {
		case err := <-done:
			copyErr = errors.Join(copyErr, err)
			remaining--
		case <-deadline:
			sourceClosed.Store(true)
			for i, reader := range readers {
				if !sourceEOF[i].Load() {
					_ = reader.Close()
					res.Transport.SourceTruncated = "live-writer-after-cleanup-failure"
				}
			}
			deadline = nil
		}
	}
	res.Transport.SourceBytesRead = sourceBytes.Load()
	// Diagnostics share the same cancellation and delivery policy as command output.
	if cleanupErr != nil && jailed.CleanupError == "" {
		fmt.Fprintln(errCount, "gate-jail: cleanup:", strings.Join(strings.Fields(cleanupErr.Error()), " "))
	}
	if copyErr != nil {
		res.Transport.DeliveryError = copyErr.Error()
	}
	if setupErr != nil {
		res.ExitCode = -1
		return res, fmt.Errorf("exec: %w", setupErr)
	}
	var exitErr *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exitErr) && !errors.Is(waitErr, exec.ErrWaitDelay) && !errors.Is(waitErr, context.Canceled) {
		return res, fmt.Errorf("exec: confined wait after execution: %w", waitErr)
	}
	return res, nil
}

func confinedExit(state *os.ProcessState, cancelled bool, worker confine.WorkerStatus) int {
	if worker.Known {
		if worker.Exited {
			return worker.Code
		}
		return 128 + int(worker.Signal)
	}
	if cancelled {
		return 143
	}
	if state == nil {
		return 1
	}
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return state.ExitCode()
}

func joinReason(previous, reason string) string {
	reason = strings.Join(strings.Fields(reason), " ")
	if previous != "" {
		return previous + "; " + reason
	}
	return reason
}

type sourceReader struct {
	reader io.Reader
	count  *atomic.Int64
	eof    *atomic.Bool
}

func (r *sourceReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.count.Add(int64(n))
	if err == io.EOF {
		r.eof.Store(true)
	}
	return n, err
}
