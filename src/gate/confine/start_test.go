//go:build linux

package confine

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestJailedStartIsCloneStage: a failed start is the "clone" stage with the
// start's errno, and releases the pipes; a context already done is a
// cancellation, not a jail failure.
func TestJailedStartIsCloneStage(t *testing.T) {
	jailed, err := Spec{Profile: ProfileROv1}.Command(context.Background(), ":")
	if err != nil {
		t.Fatal(err)
	}
	jailed.Cmd.Path, jailed.Cmd.SysProcAttr = "/nonexistent/gate", nil
	err = jailed.Start()
	var setup *SetupError
	if !errors.As(err, &setup) || setup.Stage != "clone" || setup.Errno != unix.ENOENT || setup.SawInfo {
		t.Fatalf("Start = %v, want clone ENOENT", err)
	}
	if jailed.childEnds != nil {
		t.Fatal("Start left the child pipe ends open")
	}
	if _, err := jailed.cmdW.Write([]byte(":")); err == nil {
		t.Fatal("Start left the command pipe open")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	jailed, err = Spec{Profile: ProfileROv1}.Command(ctx, ":")
	if err != nil {
		t.Fatal(err)
	}
	err = jailed.Start()
	if !errors.Is(err, context.Canceled) || errors.As(err, &setup) || jailed.childEnds != nil {
		t.Fatalf("Start with a cancelled context = %v, want context.Canceled", err)
	}
}
