//go:build linux

package gate

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
)

// TestConfinedStartFailureIsCloneStage: a jail that cannot start reaches the
// caller as the "clone" setup stage, so the read router can classify it.
func TestConfinedStartFailureIsCloneStage(t *testing.T) {
	original := confinedCommand
	t.Cleanup(func() { confinedCommand = original })
	confinedCommand = func(spec *confine.Spec, ctx context.Context, command string) (*confine.Jailed, error) {
		jailed, err := spec.Command(ctx, command)
		if err == nil {
			jailed.Cmd.Path, jailed.Cmd.SysProcAttr = "/nonexistent/gate", nil
		}
		return jailed, err
	}
	res, err := ExecWithRedaction(context.Background(), ":", ExecOpts{Confine: &confine.Spec{Profile: confine.ProfileROv1}})
	var setup *confine.SetupError
	if !errors.As(err, &setup) || setup.Stage != "clone" || setup.Errno != syscall.ENOENT || res.ExitCode != -1 {
		t.Fatalf("ExecWithRedaction = %+v, %v; want clone ENOENT, exit -1", res, err)
	}
}

// TestUnconfinedRunWritesThroughClientSink: an unconfined run given the
// client sink delivers its redacted output through the sink, never directly
// to the gate's stdout, and counts what was delivered.
func TestUnconfinedRunWritesThroughClientSink(t *testing.T) {
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	gateR, gateW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = gateW
	t.Cleanup(func() { os.Stdout = original })
	collect := func(r *os.File) <-chan string {
		done := make(chan string, 1)
		go func() { b, _ := io.ReadAll(r); _ = r.Close(); done <- string(b) }()
		return done
	}
	stdout, stderr, gateOut := collect(outR), collect(errR), collect(gateR)

	sink, err := NewClientSink(context.Background(), outW, errW)
	if err != nil {
		t.Fatal(err)
	}
	var salt [32]byte
	res, err := ExecWithRedaction(context.Background(), "echo AKIA1234567890ABCDEF; echo oops >&2", ExecOpts{
		SessionSalt: salt,
		Rules:       redactrules.Combined(),
		ClientSink:  sink,
	})
	meta := sink.Finish()
	_ = sink.Close()
	os.Stdout = original
	for _, f := range []*os.File{outW, errW, gateW} {
		_ = f.Close()
	}
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("ExecWithRedaction = %+v, %v", res, err)
	}
	gotOut, gotErr, gotGate := <-stdout, <-stderr, <-gateOut
	if strings.Contains(gotOut, "AKIA1234567890ABCDEF") || !strings.Contains(gotOut, redact.MarkerPrefix) {
		t.Fatalf("client stdout not redacted: %q", gotOut)
	}
	if gotErr != "oops\n" || gotGate != "" {
		t.Fatalf("client stderr %q, gate stdout %q", gotErr, gotGate)
	}
	if res.StdoutBytes != int64(len(gotOut)) || res.StderrBytes != int64(len(gotErr)) || meta.DroppedBytes != 0 || meta.DeliveryError != "" {
		t.Fatalf("counts %d/%d for %d/%d delivered bytes; delivery %+v", res.StdoutBytes, res.StderrBytes, len(gotOut), len(gotErr), meta)
	}
}
