package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/redact"
)

const (
	pinDeny  = "profile=ro-v1\nnet=deny\n"
	pinAllow = "profile=ro-v1\nnet=allow\n"
)

// writePin writes the jail pin into dir with exactly mode.
func writePin(t *testing.T, dir, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, confine.PinFile)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeAttempt replaces the executor: a confined call returns the jail
// attempt's result, an unconfined one runs for real. It counts both.
type fakeAttempt struct {
	result             gate.ExecResult
	err                error
	confined, fallback int
	fallbackSink       bool
}

func withFakeAttempt(t *testing.T, result gate.ExecResult, err error) *fakeAttempt {
	t.Helper()
	fake := &fakeAttempt{result: result, err: err}
	previous := executeCommand
	executeCommand = func(ctx context.Context, cmd string, opts gate.ExecOpts) (gate.ExecResult, error) {
		if opts.Confine != nil {
			fake.confined++
			return fake.result, fake.err
		}
		fake.fallback++
		fake.fallbackSink = opts.ClientSink != nil
		return gate.ExecWithRedaction(ctx, cmd, opts)
	}
	t.Cleanup(func() { executeCommand = previous })
	return fake
}

func setupFailure(stage string, errno syscall.Errno) (gate.ExecResult, error) {
	return gate.ExecResult{ExitCode: -1}, fmt.Errorf("exec: start jail: %w", &confine.SetupError{Stage: stage, Errno: errno})
}

func seedTarget(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "target")
	if err := os.WriteFile(path, []byte("orig\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func targetIs(t *testing.T, path, want string) {
	t.Helper()
	if b, _ := os.ReadFile(path); string(b) != want {
		t.Errorf("target = %q, want %q", b, want)
	}
}

// oneDeniedRead checks the single audit record of a read the jail refused.
func oneDeniedRead(t *testing.T, dir, reason string, exit int) {
	t.Helper()
	recs := auditRecords(t, dir)
	if len(recs) != 1 || recs[0]["classification"] != "read" || recs[0]["approval_status"] != "denied" ||
		recs[0]["exit_code"] != float64(exit) || recs[0]["deny_reason"] != reason {
		t.Fatalf("audit = %v, want one denied read, exit %d, deny_reason %s", recs, exit, reason)
	}
	if _, ok := recs[0]["enforcement"]; ok {
		t.Errorf("a read that never ran has a read block: %v", recs[0])
	}
}

func TestReadJailPin(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, dir string)
		valid   bool
		damaged string // substring; "" with !valid means absent
	}{
		{name: "absent", setup: func(*testing.T, string) {}},
		{name: "valid", setup: func(t *testing.T, dir string) { writePin(t, dir, pinAllow, 0o644) }, valid: true},
		{name: "read-only", setup: func(t *testing.T, dir string) { writePin(t, dir, pinDeny, 0o400) }, valid: true},
		{name: "symlink", setup: func(t *testing.T, dir string) {
			target := writePin(t, t.TempDir(), pinDeny, 0o644)
			if err := os.Symlink(target, filepath.Join(dir, confine.PinFile)); err != nil {
				t.Fatal(err)
			}
		}, damaged: "not a regular file"},
		{name: "fifo", setup: func(t *testing.T, dir string) {
			if err := syscall.Mkfifo(filepath.Join(dir, confine.PinFile), 0o644); err != nil {
				t.Fatal(err)
			}
		}, damaged: "not a regular file"},
		{name: "directory", setup: func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, confine.PinFile), 0o755); err != nil {
				t.Fatal(err)
			}
		}, damaged: "not a regular file"},
		{name: "other owner", setup: func(t *testing.T, dir string) {
			writePin(t, dir, pinDeny, 0o644)
			previous := pinUIDFn
			pinUIDFn = func() int { return previous() + 1 }
			t.Cleanup(func() { pinUIDFn = previous })
		}, damaged: "owned by uid"},
		{name: "group-writable", setup: func(t *testing.T, dir string) { writePin(t, dir, pinDeny, 0o664) }, damaged: "group- or world-writable"},
		{name: "world-writable", setup: func(t *testing.T, dir string) { writePin(t, dir, pinDeny, 0o646) }, damaged: "group- or world-writable"},
		{name: "hard link", setup: func(t *testing.T, dir string) {
			path := writePin(t, dir, pinDeny, 0o644)
			if err := os.Link(path, filepath.Join(dir, "other")); err != nil {
				t.Fatal(err)
			}
		}, damaged: "has 2 links"},
		{name: "4096 bytes", setup: func(t *testing.T, dir string) {
			writePin(t, dir, pinDeny+"#"+strings.Repeat("x", confine.MaxPinBytes-len(pinDeny)-2)+"\n", 0o644)
		}, valid: true},
		{name: "4097 bytes", setup: func(t *testing.T, dir string) {
			writePin(t, dir, pinDeny+"#"+strings.Repeat("x", confine.MaxPinBytes-len(pinDeny)-1)+"\n", 0o644)
		}, damaged: "larger than 4096 bytes"},
		{name: "bad content", setup: func(t *testing.T, dir string) { writePin(t, dir, "profile=ro-v1\nnet=maybe\n", 0o644) }, damaged: `bad value for "net"`},
		{name: "old floor content", setup: func(t *testing.T, dir string) { writePin(t, dir, "full\n", 0o644) }, damaged: "not key=value"},
		{name: "leftover jail-floor, no pin", setup: func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, jailFloorFile), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}, damaged: "jail-floor present"},
		{name: "leftover jail-floor symlink, no pin", setup: func(t *testing.T, dir string) {
			if err := os.Symlink("/nonexistent", filepath.Join(dir, jailFloorFile)); err != nil {
				t.Fatal(err)
			}
		}, damaged: "jail-floor present"},
		{name: "jail pin wins over jail-floor", setup: func(t *testing.T, dir string) {
			writePin(t, dir, pinDeny, 0o644)
			if err := os.WriteFile(filepath.Join(dir, jailFloorFile), []byte("full\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			tc.setup(t, dir)
			got := readJailPin()
			if got.valid != tc.valid || !strings.Contains(got.damaged, tc.damaged) || (tc.damaged == "") != (got.damaged == "") {
				t.Fatalf("readJailPin = %+v, want valid=%v damaged~%q", got, tc.valid, tc.damaged)
			}
		})
	}
	t.Run("unreadable", func(t *testing.T) {
		dir := t.TempDir()
		withGateDir(t, dir)
		writePin(t, dir, pinDeny, 0o000)
		got := readJailPin()
		if os.Getuid() == 0 {
			if !got.valid {
				t.Fatalf("root reads a mode-0000 pin: %+v", got)
			}
			return
		}
		if got.valid || !strings.Contains(got.damaged, "permission denied") {
			t.Fatalf("readJailPin = %+v, want damaged", got)
		}
	})
	t.Run("no gate dir", func(t *testing.T) {
		withGateDirErr(t, errors.New("no executable"))
		if got := readJailPin(); got.valid || !strings.Contains(got.damaged, "cannot locate the gate directory") {
			t.Fatalf("readJailPin = %+v", got)
		}
	})
	t.Run("parsed", func(t *testing.T) {
		dir := t.TempDir()
		withGateDir(t, dir)
		writePin(t, dir, pinAllow+"accept_fs=network\n", 0o644)
		want := confine.Pin{Profile: confine.ProfileROv1, Net: true, AcceptFS: []string{"network"}}
		if got := readJailPin(); !got.valid || !reflect.DeepEqual(got.pin, want) {
			t.Fatalf("readJailPin = %+v", got)
		}
	})
}

// TestPhase2Tables holds the gate's decision legs. Each checks the real
// decision against literals; a difference is reported as the protection's
// effect, which only a mutation build may show.
func TestPhase2Tables(t *testing.T) {
	pins := map[string]pinState{
		"absent":     {},
		"valid deny": {valid: true, pin: confine.Pin{Profile: confine.ProfileROv1}},
		"valid allow": {valid: true, pin: confine.Pin{Profile: confine.ProfileROv1, Net: true,
			AcceptFS: []string{"network"}}},
	}
	for _, abi := range []string{"native", "abi1"} {
		t.Run(abi, func(t *testing.T) {
			t.Run("U-ExecReadConfineRequired", func(t *testing.T) {
				p := newProof(t, "U-ExecReadConfineRequired")
				changed := false
				for name, pin := range pins {
					for _, grant := range []bool{false, true} {
						requires := requiresConfinement(pin, grant)
						if want := pin.valid && pin.pin.Net || grant; requires != want {
							t.Fatalf("%s grant=%v: requires = %v", name, grant, requires)
						}
						changed = changed || routeBeforeAttempt(requires) != !requires
						for _, class := range []confine.FailureClass{confine.Absent, confine.Failed} {
							want := class == confine.Absent && !pin.valid && !requires
							changed = changed || routeAfterSetupFailure(pin.valid, requires, class) != want
						}
					}
				}
				p.Effect("decision", changed)
				p.Control("decision", true)
				p.Finish()
			})
			t.Run("U-SpecStrictSources", func(t *testing.T) {
				p := newProof(t, "U-SpecStrictSources")
				changed := false
				for name, pin := range pins {
					for _, grant := range []bool{false, true} {
						requires := requiresConfinement(pin, grant)
						got := readSpec(pin, requires, grant)
						want := confine.Spec{Profile: confine.ProfileROv1, Strict: pin.valid || requires, Net: pin.pin.Net || grant}
						if pin.valid {
							want.AcceptFS = append([]string(nil), pin.pin.AcceptFS...)
						}
						if !reflect.DeepEqual(got.AcceptFS, want.AcceptFS) || got.Net != want.Net || got.Profile != want.Profile {
							t.Fatalf("%s grant=%v: spec = %+v, want %+v", name, grant, got, want)
						}
						changed = changed || got.Strict != want.Strict
					}
				}
				p.Effect("decision", changed)
				p.Control("decision", true)
				p.Finish()
			})
		})
	}
}

func TestRunReadDeniedDamagedPin(t *testing.T) {
	readNamedWriter(t)
	for _, tc := range []struct {
		name string
		pin  func(t *testing.T, dir string)
	}{
		{"insecure mode", func(t *testing.T, dir string) { writePin(t, dir, pinDeny, 0o666) }},
		{"bad content", func(t *testing.T, dir string) { writePin(t, dir, "profile=ro-v1\n", 0o644) }},
		{"directory", func(t *testing.T, dir string) { _ = os.Mkdir(filepath.Join(dir, confine.PinFile), 0o755) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			tc.pin(t, dir)
			fake := withFakeAttempt(t, gate.ExecResult{}, nil)
			target := seedTarget(t, dir)
			code, out, stderr := runWith(t, "stat "+target+" ran")
			if code != exitNoPermVal || out != "" || !strings.HasPrefix(stderr, "gate: read jail unavailable: the jail pin is damaged (") ||
				strings.Count(stderr, "\n") != 1 {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
			}
			targetIs(t, target, "orig\n")
			oneDeniedRead(t, dir, "pin:damaged", exitNoPermVal)
			if fake.confined+fake.fallback != 0 {
				t.Errorf("a damaged pin still attempted the read: %+v", fake)
			}
		})
	}
}

// TestRunReadLegacyFloorDenies: a leftover jail-floor with no jail pin denies
// every read before any attempt, so a host whose operator asked never to run
// reads outside the jail does not silently fall back; a valid jail pin wins.
func TestRunReadLegacyFloorDenies(t *testing.T) {
	readNamedWriter(t)
	dir := t.TempDir()
	withGateDir(t, dir)
	if err := os.WriteFile(filepath.Join(dir, jailFloorFile), []byte("full\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := withFakeAttempt(t, gate.ExecResult{}, nil)
	fake.result, fake.err = setupFailure("clone", syscall.EPERM)
	target := seedTarget(t, dir)
	code, out, stderr := runWith(t, "stat "+target+" ran")
	if code != exitNoPermVal || out != "" || stderr != "gate: read jail unavailable: a jail-floor file from an earlier release is present and there is no jail pin; reads are denied until the host is re-pinned with 'gate doctor --pin' or the jail-floor file is removed\n" {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	targetIs(t, target, "orig\n")
	oneDeniedRead(t, dir, "pin:legacy-floor", exitNoPermVal)
	if fake.confined+fake.fallback != 0 {
		t.Fatalf("a leftover floor still attempted the read: %+v", fake)
	}

	writePin(t, dir, pinDeny, 0o644)
	_ = os.Remove(filepath.Join(dir, "audit.log"))
	if code, _, _ := runWith(t, "stat "+target+" ran"); code != exitNoPermVal || fake.confined != 1 {
		t.Fatalf("under a jail pin: exit %d, executor %+v", code, fake)
	}
	oneDeniedRead(t, dir, "jail:absent:clone:EPERM", exitNoPermVal)
}

func TestRunReadFailedSetupDenies(t *testing.T) {
	readNamedWriter(t)
	for _, tc := range []struct {
		stage  string
		errno  syscall.Errno
		reason string
	}{
		{"seccomp", syscall.EIO, "jail:failed:seccomp:EIO"},
		{"nsverify", syscall.EPERM, "jail:failed:nsverify:EPERM"},
		{"clone", syscall.ENOMEM, "jail:failed:clone:ENOMEM"},
		{"covers", syscall.EPERM, "jail:failed:covers:EPERM"},
		{"selfcheck", 0, "jail:failed:selfcheck"},
	} {
		for _, pinned := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s pinned=%v", tc.reason, pinned), func(t *testing.T) {
				dir := t.TempDir()
				withGateDir(t, dir)
				if pinned {
					writePin(t, dir, pinDeny, 0o644)
				}
				fake := withFakeAttempt(t, gate.ExecResult{}, nil)
				fake.result, fake.err = setupFailure(tc.stage, tc.errno)
				target := seedTarget(t, dir)
				code, out, stderr := runWith(t, "stat "+target+" ran")
				if code != exitNoPermVal || out != "" || !strings.HasPrefix(stderr, "gate: read jail unavailable: the jail could not be set up ("+tc.stage) {
					t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
				}
				targetIs(t, target, "orig\n")
				oneDeniedRead(t, dir, tc.reason, exitNoPermVal)
				if fake.confined != 1 || fake.fallback != 0 {
					t.Errorf("executor calls: %+v, want one attempt and no fallback", fake)
				}
			})
		}
	}
}

// TestRunReadAbsentUnpinnedRunsClassifierOnly: an Absent jail on an unpinned
// host runs the read once, classifier-only, quietly, through the client sink.
func TestRunReadAbsentUnpinnedRunsClassifierOnly(t *testing.T) {
	readNamedWriter(t)
	for _, tc := range []struct {
		stage  string
		errno  syscall.Errno
		absent string
	}{
		{"landlock", syscall.ENOSYS, "landlock:ENOSYS"},
		{"clone", syscall.EPERM, "clone:EPERM"},
		{"private", syscall.EACCES, "private:EACCES"},
	} {
		t.Run(tc.absent, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			fake := withFakeAttempt(t, gate.ExecResult{}, nil)
			fake.result, fake.err = setupFailure(tc.stage, tc.errno)
			target := seedTarget(t, dir)
			code, _, stderr := runWith(t, "stat "+target+" edited")
			if code != exitOK || stderr != "" {
				t.Fatalf("exit = %d, stderr = %q", code, stderr)
			}
			targetIs(t, target, "edited\n")
			if fake.confined != 1 || fake.fallback != 1 || !fake.fallbackSink {
				t.Errorf("executor calls: %+v, want one attempt and one fallback through the sink", fake)
			}
			recs := auditRecords(t, dir)
			if len(recs) != 1 || recs[0]["approval_status"] != "unsigned" || recs[0]["enforcement"] != "classifier" ||
				recs[0]["pinned"] != false || recs[0]["net"] != true || recs[0]["jail_absent"] != tc.absent || recs[0]["requires_confinement"] != false {
				t.Fatalf("audit = %v", recs)
			}
			for _, key := range []string{"profile", "label_clause_unmet", "deny_reason"} {
				if _, ok := recs[0][key]; ok {
					t.Errorf("fallback record has %s: %v", key, recs[0])
				}
			}
		})
	}
}

// TestRunReadAbsentPinnedDenies: an Absent jail denies on a pinned host and
// for a read that requires confinement.
func TestRunReadAbsentPinnedDenies(t *testing.T) {
	readNamedWriter(t)
	for _, tc := range []struct {
		name, pin, line string
		grant           bool
	}{
		{"pinned net=deny", pinDeny, "and reads are pinned", false},
		{"pinned net=allow", pinAllow, "and reads are pinned", false},
		{"unpinned with a network grant", "", "and this read must run confined", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			if tc.pin != "" {
				writePin(t, dir, tc.pin, 0o644)
			}
			forceNetGrant = tc.grant
			t.Cleanup(func() { forceNetGrant = false })
			fake := withFakeAttempt(t, gate.ExecResult{}, nil)
			fake.result, fake.err = setupFailure("landlock", syscall.ENOSYS)
			target := seedTarget(t, dir)
			code, out, stderr := runWith(t, "stat "+target+" ran")
			if code != exitNoPermVal || out != "" || !strings.Contains(stderr, "gate: read jail unavailable: this host has no usable jail (landlock: function not implemented) "+tc.line+"; nothing ran") {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
			}
			targetIs(t, target, "orig\n")
			oneDeniedRead(t, dir, "jail:absent:landlock:ENOSYS", exitNoPermVal)
			if fake.confined != 1 || fake.fallback != 0 {
				t.Errorf("executor calls: %+v", fake)
			}
		})
	}
}

// TestFallbackRefusedAfterInfo: an Absent stage on an unpinned host still
// denies when the attempt may have reached the command — the worker reported
// I, or the attempt produced output.
func TestFallbackRefusedAfterInfo(t *testing.T) {
	readNamedWriter(t)
	for _, tc := range []struct {
		name   string
		result gate.ExecResult
		setup  confine.SetupError
	}{
		{"after an I report", gate.ExecResult{ExitCode: -1}, confine.SetupError{Stage: "setattr", Errno: syscall.ENOSYS, SawInfo: true}},
		{"with stdout", gate.ExecResult{ExitCode: -1, StdoutBytes: 3}, confine.SetupError{Stage: "setattr", Errno: syscall.ENOSYS}},
		{"with stderr", gate.ExecResult{ExitCode: -1, StderrBytes: 5}, confine.SetupError{Stage: "setattr", Errno: syscall.ENOSYS}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			setup := tc.setup
			fake := withFakeAttempt(t, tc.result, &setup)
			target := seedTarget(t, dir)
			code, _, stderr := runWith(t, "stat "+target+" ran")
			if code != exitNoPermVal || !strings.Contains(stderr, "the jail could not be set up (setattr: function not implemented)") {
				t.Fatalf("exit = %d, stderr = %q", code, stderr)
			}
			targetIs(t, target, "orig\n")
			oneDeniedRead(t, dir, "jail:failed:setattr:ENOSYS", exitNoPermVal)
			if fake.confined != 1 || fake.fallback != 0 {
				t.Errorf("executor calls: %+v", fake)
			}
		})
	}
}

// TestRunReadCancelledBeforeFallback: a session that ends before the jail
// starts, or before the fallback, is a cancellation, not a jail denial.
func TestRunReadCancelledBeforeFallback(t *testing.T) {
	readNamedWriter(t)
	for _, name := range []string{"jail start", "fallback"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			target := seedTarget(t, dir)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fake := withFakeAttempt(t, gate.ExecResult{ExitCode: -1}, fmt.Errorf("exec: start jail: %w", context.Canceled))
			if name == "fallback" {
				fake.result, fake.err = setupFailure("landlock", syscall.ENOSYS)
				inner := executeCommand
				executeCommand = func(c context.Context, cmd string, opts gate.ExecOpts) (gate.ExecResult, error) {
					cancel()
					return inner(c, cmd, opts)
				}
			}
			var code int
			stderr := captureStderr(t, func() {
				_ = captureStdout(t, func() {
					sessionContext = ctx
					defer func() {
						if sessionSink != nil {
							sessionSink.Finish()
							_ = sessionSink.Close()
						}
						sessionSink, sessionContext = nil, nil
					}()
					code = execRead(newAuditLogger(), "stat "+target+" ran", "unsigned", false)
				})
			})
			if code != exitCancelled || strings.Contains(stderr, "read jail unavailable") {
				t.Fatalf("exit = %d, stderr = %q", code, stderr)
			}
			targetIs(t, target, "orig\n")
			oneDeniedRead(t, dir, "cancelled", exitCancelled)
			if fake.fallback != 0 {
				t.Errorf("the fallback ran after cancellation: %+v", fake)
			}
		})
	}
}

// TestRunReadFallbackBackgroundChild: the classifier-only fallback runs in the
// state the attempt left (subreaper, client sink); a backgrounded child still
// ends cleanly, its output is redacted, and signed writes keep no sink.
func TestRunReadFallbackBackgroundChild(t *testing.T) {
	bin := t.TempDir()
	script := "#!/bin/sh\nprintf 'AKIA1234567890ABCDEF\\n'; sleep 1 &\n"
	if err := os.WriteFile(filepath.Join(bin, "stat"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	withEnv(t, "PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dir := t.TempDir()
	withGateDir(t, dir)
	fake := withFakeAttempt(t, gate.ExecResult{}, nil)
	fake.result, fake.err = setupFailure("clone", syscall.EPERM)
	start := time.Now()
	code, out, stderr := runWith(t, "stat x")
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the fallback hung for %v", elapsed)
	}
	if code != exitOK || stderr != "" || strings.Contains(out, "AKIA1234567890ABCDEF") || !strings.Contains(out, redact.MarkerPrefix) {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	if fake.fallback != 1 || !fake.fallbackSink {
		t.Fatalf("executor calls: %+v", fake)
	}

	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	sawSink := true
	executeCommand = func(ctx context.Context, cmd string, opts gate.ExecOpts) (gate.ExecResult, error) {
		sawSink = opts.ClientSink != nil || opts.Confine != nil
		return gate.ExecWithRedaction(ctx, cmd, opts)
	}
	if code, _, stderr := runWith(t, signedLine(t, priv, freshPayload("printf done > "+filepath.Join(dir, "written")))); code != exitOK || sawSink {
		t.Fatalf("signed write: exit %d, stderr %q, sink or jail %v", code, stderr, sawSink)
	}
}

// TestJailUnavailableNeverBlocksWritesOrAdmin: with a damaged pin and a jail
// that fails every attempt, signed writes and admin verbs still run, never
// attempt the jail and never read the pin.
func TestJailUnavailableNeverBlocksWritesOrAdmin(t *testing.T) {
	var pinReads int
	previousPin := jailPinFn
	jailPinFn = func() pinState { pinReads++; return readJailPin() }
	t.Cleanup(func() { jailPinFn = previousPin })
	fake := withFakeAttempt(t, gate.ExecResult{}, nil)
	fake.result, fake.err = setupFailure("seccomp", syscall.EIO)
	check := func(t *testing.T) {
		t.Helper()
		if pinReads != 0 || fake.confined != 0 {
			t.Errorf("pin reads %d, jail attempts %d; want none", pinReads, fake.confined)
		}
	}
	damagedGate := func(t *testing.T) (string, []byte) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		writePin(t, dir, pinDeny, 0o666)
		withGateDir(t, dir)
		pinReads, fake.confined = 0, 0
		return dir, priv
	}

	t.Run("signed write", func(t *testing.T) {
		dir, priv := damagedGate(t)
		target := filepath.Join(dir, "written")
		code, _, stderr := runWith(t, signedLine(t, priv, freshPayload("printf landed > "+target)))
		if code != exitOK {
			t.Fatalf("exit = %d, stderr = %q", code, stderr)
		}
		targetIs(t, target, "landed")
		check(t)
	})
	t.Run("signed revoke", func(t *testing.T) {
		dir, priv := damagedGate(t)
		home := t.TempDir()
		withHomeDir(t, home)
		if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		line := `command="` + filepath.Join(dir, "gate") + `",no-pty ssh-ed25519 AAAAtest sshgate@laptop` + "\n"
		if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, _ := runWith(t, signedLine(t, priv, freshPayload("SSHGATE_REVOKE")))
		if code != exitOK || !strings.Contains(out, "SSHGATE_REVOKED") {
			t.Fatalf("exit = %d, stdout = %q", code, out)
		}
		check(t)
	})
	t.Run("signed update", func(t *testing.T) {
		dir, priv := damagedGate(t)
		if err := os.WriteFile(filepath.Join(dir, "gate"), []byte("OLD-GATE-BINARY"), 0o755); err != nil {
			t.Fatal(err)
		}
		newBin := readSelfELF(t)
		sum := sha256.Sum256(newBin)
		hash := hex.EncodeToString(sum[:])
		code, out, stderr := runWithStdin(t, signedLine(t, priv, freshPayload("SSHGATE_UPDATE "+hash)), newBin)
		if code != exitOK || !strings.Contains(out, "SSHGATE_UPDATED") {
			t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
		}
		check(t)
	})
	t.Run("controls", func(t *testing.T) {
		dir, _ := damagedGate(t)
		if code, _, _ := runWith(t, "cat /etc/hostname"); code != exitNoPermVal || pinReads != 1 {
			t.Fatalf("damaged pin: exit %d, pin reads %d", code, pinReads)
		}
		if err := os.Remove(filepath.Join(dir, confine.PinFile)); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(filepath.Join(dir, "audit.log"))
		if code, _, stderr := runWith(t, "cat /etc/hostname"); code != exitNoPermVal || fake.confined != 1 || !strings.Contains(stderr, "seccomp") {
			t.Fatalf("forced jail failure: exit %d, attempts %d, stderr %q", code, fake.confined, stderr)
		}
		oneDeniedRead(t, dir, "jail:failed:seccomp:EIO", exitNoPermVal)
	})
}

func TestLane2DeniedWhenConfinementRequired(t *testing.T) {
	withLane2Bins(t)
	dir := t.TempDir()
	withGateDir(t, dir)
	writePin(t, dir, pinAllow, 0o644)
	code, out, stderr := runWith(t, "docker ps")
	if code != exitNoPermVal || out != "" || stderr != "gate: read jail unavailable: this read must run confined and docker cannot run in the jail yet; nothing ran\n" {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	oneDeniedRead(t, dir, "confine:required", exitNoPermVal)
}

func TestNeedsNetwork(t *testing.T) {
	for cmd, want := range map[string]bool{
		"curl -s http://localhost:8080/health":  true,
		"FOO=1 /usr/bin/wget -qO- x":            true,
		"timeout 5 dig example.com":             true,
		"nice -n 5 git fetch":                   true,
		"env LANG=C ssh host":                   true,
		"cat /etc/hosts | nc -z host 22":        true,
		"(cd /srv; kubectl get pods)":           true,
		"ls -l; ping6 -c1 ::1":                  true,
		"cat /etc/hosts":                        false,
		"grep curl /var/log/syslog":             false,
		"echo git":                              false,
		"timeout 5 cat file":                    false,
		"systemctl status nginx | grep running": false,
	} {
		if got := needsNetwork(cmd); got != want {
			t.Errorf("needsNetwork(%q) = %v, want %v", cmd, got, want)
		}
	}
}

// TestNetworkHintReachesClient: the network hint for a failed kernel read
// without network is written before delivery to the client ends, so it
// reaches the client, and the audit record follows.
func TestNetworkHintReachesClient(t *testing.T) {
	dir := t.TempDir()
	withGateDir(t, dir)
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	read := func(r *os.File) <-chan string {
		done := make(chan string, 1)
		go func() { b, _ := io.ReadAll(r); _ = r.Close(); done <- string(b) }()
		return done
	}
	stdout, stderr := read(outR), read(errR)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink, err := gate.NewClientSink(ctx, outW, errW)
	if err != nil {
		t.Fatal(err)
	}
	sessionContext, sessionSink = ctx, sink
	defer func() { sessionContext, sessionSink = nil, nil }()
	previous := executeCommand
	executeCommand = func(context.Context, string, gate.ExecOpts) (gate.ExecResult, error) {
		return gate.ExecResult{ExitCode: 6, Jail: &confine.Facts{Profile: confine.ProfileROv1, ABI: 6}}, nil
	}
	defer func() { executeCommand = previous }()
	plan := execPlan{confine: &confine.Spec{Profile: confine.ProfileROv1}, read: &gate.ReadAudit{Enforcement: "kernel"}}
	code, _, setupErr := execAndAudit(newAuditLogger(), "curl http://localhost:8080/", "read", "unsigned", false, plan)
	_ = sink.Close()
	_ = outW.Close()
	_ = errW.Close()
	if code != 6 || setupErr != nil {
		t.Fatalf("exit = %d, %v", code, setupErr)
	}
	if got := <-stderr; got != "gate: note: reads on this host have no network access; this command may need it (network is granted per host by the jail pin, or per read by a signed request)\n" {
		t.Fatalf("client stderr = %q", got)
	}
	<-stdout
	recs := auditRecords(t, dir)
	if len(recs) != 1 || recs[0]["exit_code"] != float64(6) || recs[0]["enforcement"] != "kernel" || recs[0]["net"] != false {
		t.Fatalf("audit = %v", recs)
	}
}
