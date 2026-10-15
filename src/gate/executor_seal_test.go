//go:build linux

package gate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// withShellJail replaces the jail with a plain shell that speaks the worker's
// status protocol, and hands back each Jailed it builds.
func withShellJail(t *testing.T) *[]*confine.Jailed {
	t.Helper()
	var built []*confine.Jailed
	original := confinedCommand
	confinedCommand = func(spec *confine.Spec, ctx context.Context, body string) (*confine.Jailed, error) {
		jailed, err := original(spec, ctx, body)
		if err != nil {
			return nil, err
		}
		jailed.Cmd.Path = "/bin/sh"
		jailed.Cmd.Args = []string{"sh", "-c", `cat <&3 >/dev/null; printf 'I{"profile":"ro-v1","abi":1,"net":false,"lane2":false}\nX' >&4; ` + body}
		jailed.Cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		built = append(built, jailed)
		return jailed, nil
	}
	t.Cleanup(func() { confinedCommand = original })
	return &built
}

// sealBody touches ran; the shell reaches it only after Started sends the
// command.
func sealBody(ran string) string {
	return "touch " + ran + `; printf '\nW{"exit":0}\n' >&4`
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// TestConfinedSealOrdering: Seal runs once, after the jailed child started and
// before it received its command.
func TestConfinedSealOrdering(t *testing.T) {
	built := withShellJail(t)
	ran := filepath.Join(t.TempDir(), "ran")
	calls, startedAtSeal, ranAtSeal := 0, false, false
	seal := func() error {
		calls++
		startedAtSeal = (*built)[0].Cmd.Process != nil
		time.Sleep(100 * time.Millisecond)
		ranAtSeal = exists(ran)
		return nil
	}
	res, err := ExecWithRedaction(context.Background(), sealBody(ran), ExecOpts{Confine: &confine.Spec{Profile: confine.ProfileROv1}, Seal: seal})
	if err != nil || res.ExitCode != 0 || res.Jail == nil {
		t.Fatalf("result %+v, err %v", res, err)
	}
	if calls != 1 || !startedAtSeal || ranAtSeal || !exists(ran) {
		t.Fatalf("calls %d, started at seal %v, ran at seal %v, ran %v", calls, startedAtSeal, ranAtSeal, exists(ran))
	}
}

// TestConfinedSealFailure: a Seal error kills the child before its command
// runs and reports SetupError stage "seal".
func TestConfinedSealFailure(t *testing.T) {
	built := withShellJail(t)
	ran := filepath.Join(t.TempDir(), "ran")
	res, err := ExecWithRedaction(context.Background(), sealBody(ran), ExecOpts{Confine: &confine.Spec{Profile: confine.ProfileROv1}, Seal: func() error { return syscall.EPERM }})
	var setup *confine.SetupError
	if !errors.As(err, &setup) || setup.Stage != "seal" || setup.Errno != syscall.EPERM || res.ExitCode != -1 {
		t.Fatalf("result %+v, err %v", res, err)
	}
	if state := (*built)[0].Cmd.ProcessState; state == nil || state.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("child not killed and reaped: %v", state)
	}
	time.Sleep(100 * time.Millisecond)
	if exists(ran) {
		t.Fatal("the command ran after a failed seal")
	}
}

// TestConfinedSealedGuard: a process that is no longer dumpable (sealed, or
// running a binary it cannot read) starts no jail: SetupError stage "sealed".
func TestConfinedSealedGuard(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dumpable int
		err      error
	}{
		{"sealed", 0, nil},
		{"unreadable binary", 2, nil},
		{"unknown", 0, syscall.EINVAL},
		{"dumpable", 1, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			built := withShellJail(t)
			original := dumpableFn
			dumpableFn = func() (int, error) { return tc.dumpable, tc.err }
			t.Cleanup(func() { dumpableFn = original })
			ran := filepath.Join(t.TempDir(), "ran")
			sealed := false
			res, err := ExecWithRedaction(context.Background(), sealBody(ran), ExecOpts{Confine: &confine.Spec{Profile: confine.ProfileROv1}, Seal: func() error { sealed = true; return nil }})
			if tc.dumpable == 1 && tc.err == nil {
				if err != nil || res.ExitCode != 0 || !sealed || !exists(ran) {
					t.Fatalf("result %+v, err %v, sealed %v", res, err, sealed)
				}
				return
			}
			var setup *confine.SetupError
			if !errors.As(err, &setup) || setup.Stage != "sealed" || res.ExitCode != -1 || sealed || (*built)[0].Cmd.Process != nil || exists(ran) {
				t.Fatalf("result %+v, err %v, sealed %v", res, err, sealed)
			}
		})
	}
}
