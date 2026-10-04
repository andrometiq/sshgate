//go:build linux

package gate

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestClientSinkClosedReaderDrains(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer write.Close()
	read.Close()
	stderr, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	sink, err := NewClientSink(context.Background(), write, stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if n, err := sink.Stdout().WriteDelivered([]byte("lost")); err != nil || n != 0 {
		t.Fatalf("WriteDelivered = %d, %v", n, err)
	}
	if n, err := io.Copy(sink.Stdout(), strings.NewReader("more")); err != nil || n != 4 {
		t.Fatalf("drain = %d, %v", n, err)
	}
	meta := sink.Finish()
	if meta.DeliveryError != "stdout:EPIPE" || meta.DroppedBytes != 8 || meta.Abandoned {
		t.Fatalf("metadata %+v", meta)
	}
}

func TestClientSinkFIFOAbandonmentBarrier(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	readerFD, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(readerFD)
	write, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer write.Close()
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stderrRead.Close()
	defer stderrWrite.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink, err := NewClientSink(ctx, write, stderrWrite)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	payload := bytes.Repeat([]byte("abcdef"), 1<<18)
	result := make(chan int, 1)
	go func() { n, _ := sink.Stdout().WriteDelivered(payload); result <- n }()
	// Wait until the actual FIFO has accepted bytes, proving partial delivery.
	deadline := time.Now().Add(2 * time.Second)
	for {
		count, err := unix.IoctlGetInt(readerFD, unix.TIOCINQ)
		if err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("writer never filled FIFO")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	var delivered int
	select {
	case delivered = <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not release writer")
	}
	meta := sink.Finish()
	if !meta.Abandoned || meta.OutputDestination != "pollable" || meta.DroppedBytes != int64(len(payload)-delivered) || delivered == 0 {
		t.Fatalf("delivered %d metadata %+v", delivered, meta)
	}
	// Resume after the barrier: only the previously delivered prefix can exist.
	var got []byte
	buffer := make([]byte, 32768)
	for {
		n, err := unix.Read(readerFD, buffer)
		if n > 0 {
			got = append(got, buffer[:n]...)
		}
		if err == unix.EAGAIN {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got, payload[:delivered]) {
		t.Fatalf("got %d bytes, delivered %d", len(got), delivered)
	}
	if n, err := sink.Stdout().Write([]byte("late")); err == nil || n != 0 {
		t.Fatalf("post-finish write = %d, %v", n, err)
	}
	if final := sink.Snapshot(); final != meta {
		t.Fatalf("snapshot changed: %+v -> %+v", meta, final)
	}
	if n, err := unix.Read(readerFD, buffer); n > 0 || err != unix.EAGAIN {
		t.Fatalf("late delivery: %d, %v", n, err)
	}
}

func TestClientSinkBackpressureWithoutCancellation(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	sink, err := NewClientSink(context.Background(), writer, writer)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	payload := bytes.Repeat([]byte("complete\n"), 1<<16)
	result := make(chan error, 1)
	go func() {
		n, err := sink.Stdout().WriteDelivered(payload)
		if n != len(payload) && err == nil {
			err = io.ErrShortWrite
		}
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("write ended before drain: %v", err)
	case <-time.After(600 * time.Millisecond):
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("output changed")
	}
	if meta := sink.Finish(); meta.Abandoned || meta.DroppedBytes != 0 || meta.DeliveryError != "" {
		t.Fatalf("metadata %+v", meta)
	}
}

func TestClientSinkFileDestination(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	descriptor := f.Fd()
	flags, err := unix.FcntlInt(descriptor, unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	sink, err := NewClientSink(context.Background(), f, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Stdout().Write([]byte("stdout")); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Stderr().Write([]byte("stderr")); err != nil {
		t.Fatal(err)
	}
	if meta := sink.Finish(); meta.OutputDestination != "file" || meta.DroppedBytes != 0 {
		t.Fatalf("metadata %+v", meta)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := unix.FcntlInt(descriptor, unix.F_GETFL, 0)
	if err != nil || restored != flags {
		t.Fatalf("flags %d -> %d, %v", flags, restored, err)
	}
	got, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "stdoutstderr" {
		t.Fatalf("output %q", got)
	}
}

func TestClientSinkCancellationWakesBothStreams(t *testing.T) {
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdoutRead.Close()
	defer stdoutWrite.Close()
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stderrRead.Close()
	defer stderrWrite.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink, err := NewClientSink(ctx, stdoutWrite, stderrWrite)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	payload := bytes.Repeat([]byte("x"), 1<<20)
	result := make(chan int, 2)
	for _, stream := range []*ClientStream{sink.Stdout(), sink.Stderr()} {
		go func(stream *ClientStream) { n, _ := stream.WriteDelivered(payload); result <- n }(stream)
	}
	cancel()
	delivered := 0
	for range 2 {
		select {
		case n := <-result:
			delivered += n
		case <-time.After(2 * time.Second):
			t.Fatal("stream remained blocked")
		}
	}
	meta := sink.Finish()
	if !meta.Abandoned || meta.DroppedBytes != int64(2*len(payload)-delivered) {
		t.Fatalf("metadata %+v, delivered %d", meta, delivered)
	}
}
