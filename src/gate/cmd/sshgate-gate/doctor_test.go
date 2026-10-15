package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"golang.org/x/sys/unix"
)

var capableFacts = confine.HostFacts{MaxUserNS: 100, DevShmDir: true, SeccompFilter: true, LandlockABI: 6, LSMs: []string{"capability", "landlock"}}

func withHostFacts(t *testing.T, facts confine.HostFacts) {
	t.Helper()
	previous := hostFactsFn
	hostFactsFn = func() confine.HostFacts { return facts }
	t.Cleanup(func() { hostFactsFn = previous })
}

// fakeRehearser stands in for the fixtures and the rehearsal.
type fakeRehearser struct {
	result    rehearsalResult
	cands     []confine.Pin
	teardowns int
}

func (f *fakeRehearser) rehearse(_ context.Context, cand confine.Pin, _ func() error) rehearsalResult {
	f.cands = append(f.cands, cand)
	result := f.result
	result.Net = cand.Net
	return result
}

func (f *fakeRehearser) teardown() error {
	f.teardowns++
	return nil
}

// passedRehearsal is a rehearsal in which every row and check passed.
func passedRehearsal() rehearsalResult {
	r := rehearsalResult{Ran: true, Strict: true, ABI: 3}
	for _, name := range rehearsalRows {
		r.Rows = append(r.Rows, rehearsalRow{Name: name, Errno: "EPERM", Attempted: true, Pass: true})
	}
	r.finish()
	return r
}

var directRoot = confine.MountReport{Point: "/", FSType: "ext4", Source: "/dev/vda1", Class: "block", Backing: "direct", Accepted: true}

// withDoctorFakes replaces the fixtures, the rehearsal, the mount reports and
// the binary check; the executor and host facts stay the test's.
func withDoctorFakes(t *testing.T) *fakeRehearser {
	t.Helper()
	fake := &fakeRehearser{result: passedRehearsal()}
	previousFixtures, previousMountOf, previousMounts, previousBinary := fixturesFn, mountOfFn, describeMountsFn, selftestBinaryFn
	fixturesFn = func(string) (rehearser, error) { return fake, nil }
	mountOfFn = func(string, []string) (confine.MountReport, error) { return directRoot, nil }
	describeMountsFn = func([]string) ([]confine.MountReport, error) { return []confine.MountReport{directRoot}, nil }
	selftestBinaryFn = func() (string, error) { return "/gate", nil }
	t.Cleanup(func() {
		fixturesFn, mountOfFn, describeMountsFn, selftestBinaryFn = previousFixtures, previousMountOf, previousMounts, previousBinary
	})
	return fake
}

// runDoctorJSON runs `gate doctor --json <args>` in-process.
func runDoctorJSON(t *testing.T, args ...string) (int, doctorReport, string) {
	t.Helper()
	var code int
	var out string
	stderr := captureStderr(t, func() {
		out = captureStdout(t, func() { code = runLocalSubcommand(append([]string{"doctor", "--json"}, args...)) })
	})
	var d doctorReport
	if out != "" {
		if err := json.Unmarshal([]byte(out), &d); err != nil {
			t.Fatalf("doctor output %q: %v", out, err)
		}
	}
	return code, d, stderr
}

// doctorJSON is `gate doctor --json` on a host with the doctor fakes.
func doctorJSON(t *testing.T) doctorReport {
	t.Helper()
	withDoctorFakes(t)
	code, d, stderr := runDoctorJSON(t)
	if code != exitOK {
		t.Fatalf("doctor --json exit = %d, stderr %q", code, stderr)
	}
	return d
}

var roKernel = kernelRun(confine.Facts{Profile: confine.ProfileROv1, ABI: 3})

// pinHost is a gate dir with the doctor fakes, a capable kernel and an
// executor answering every attempt with a kernel run.
func pinHost(t *testing.T) (string, *fakeRehearser, *[]verbCall) {
	t.Helper()
	dir := t.TempDir()
	withGateDir(t, dir)
	withHostFacts(t, capableFacts)
	return dir, withDoctorFakes(t), recordAttempts(t, roKernel, nil)
}

func readPinFile(t *testing.T, dir string) (string, os.FileInfo) {
	t.Helper()
	path := filepath.Join(dir, confine.PinFile)
	info, err := os.Lstat(path)
	if err != nil {
		return "", nil
	}
	data, _ := os.ReadFile(path)
	return string(data), info
}

const canonicalDeny = "# written by gate doctor\nprofile=ro-v1\nnet=deny\n"

func TestDoctorGrammar(t *testing.T) {
	dir, _, calls := pinHost(t)
	for _, args := range [][]string{
		{"--bogus"}, {"--net=deny"}, {"--accept-fs=network"}, {"--pin"}, {"--pin", "--net=maybe"},
		{"--pin", "--net=deny", "--net=deny"}, {"--json"}, {"--pin", "--net=deny", "--accept-fs="},
		{"--pin", "--net=deny", "--accept-fs=fuse"}, {"--pin", "--net=deny", "--accept-fs=network,network"},
	} {
		// runDoctorJSON adds one --json, so {"--json"} repeats it.
		if code, _, _ := runDoctorJSON(t, args...); code != exitDataErr {
			t.Errorf("%v: exit %d, want %d", args, code, exitDataErr)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 || len(*calls) != 0 {
		t.Fatalf("a usage error wrote %v or attempted the jail %d times", entries, len(*calls))
	}
}

func TestDoctorReportsPinStates(t *testing.T) {
	for _, tc := range []struct {
		name, pin, reads string
		mode             os.FileMode
		want             doctorPin
		attempts         int
	}{
		{name: "absent", reads: "kernel-jailed, no network", want: doctorPin{State: "absent"}, attempts: 2},
		{name: "valid deny", pin: pinDeny + "accept_fs=autofs\n", mode: 0o644, reads: "kernel-jailed, no network", want: doctorPin{State: "valid", Mode: "0644", Net: "deny", AcceptFS: []string{"autofs"}}, attempts: 2},
		{name: "valid allow", pin: pinAllow, mode: 0o600, reads: "kernel-jailed, network open", want: doctorPin{State: "valid", Mode: "0600", Net: "allow"}, attempts: 2},
		{name: "damaged", pin: pinDeny, mode: 0o666, reads: "denied (pin:damaged)", want: doctorPin{State: "damaged", Mode: "0666", Error: "group- or world-writable"}, attempts: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _, calls := pinHost(t)
			if tc.pin != "" {
				plantPin(t, dir, tc.pin, tc.mode)
			}
			code, d, _ := runDoctorJSON(t)
			tc.want.Result = "not-requested"
			d.Pin.LabelAfter = "" // TestDoctorPinWrites covers it
			if code != exitOK || !reflect.DeepEqual(d.Pin, tc.want) || d.Reads != tc.reads || d.Features.LandlockABI != 6 || d.Features.MaxUserNS != 100 || len(*calls) != tc.attempts {
				t.Fatalf("exit %d, doctor %+v, attempts %d", code, d, len(*calls))
			}
		})
	}
}

func TestDoctorReportsAttempt(t *testing.T) {
	clamp := capableFacts
	clamp.AppArmorUsernsClamp = true
	for _, tc := range []struct {
		name, pin    string
		facts        confine.HostFacts
		stage        string
		errno        syscall.Errno
		route, reads string
		class        string
		clampAdvice  bool
	}{
		{name: "kernel", facts: capableFacts, route: "kernel", reads: "kernel-jailed, no network"},
		{name: "clamp absent", facts: clamp, stage: "clone", errno: syscall.EACCES, route: "jail:absent:clone:EACCES", reads: "classifier-only (no usable jail)", class: "absent", clampAdvice: true},
		{name: "clamp absent, pinned", pin: pinDeny, facts: clamp, stage: "clone", errno: syscall.EACCES, route: "jail:absent:clone:EACCES", reads: "denied (jail:absent:clone:EACCES)", class: "absent", clampAdvice: true},
		{name: "unexplained EACCES", facts: capableFacts, stage: "clone", errno: syscall.EACCES, route: "jail:failed:clone:EACCES", reads: "denied (jail:failed:clone:EACCES)", class: "failed"},
		{name: "failed", facts: capableFacts, stage: "seccomp", errno: syscall.EIO, route: "jail:failed:seccomp:EIO", reads: "denied (jail:failed:seccomp:EIO)", class: "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			withHostFacts(t, tc.facts)
			fake := withDoctorFakes(t)
			if tc.pin != "" {
				plantPin(t, dir, tc.pin, 0o644)
			}
			result, err := roKernel, error(nil)
			if tc.stage != "" {
				result, err = setupFailure(tc.stage, tc.errno)
			}
			recordAttempts(t, result, err)
			_, d, _ := runDoctorJSON(t)
			hasClampAdvice := false
			for _, advice := range d.Advice {
				hasClampAdvice = hasClampAdvice || strings.Contains(advice, "AppArmor userns_create denial")
			}
			now := d.Features.Now
			if now.Route != tc.route || now.Class != tc.class || d.Reads != tc.reads || hasClampAdvice != tc.clampAdvice {
				t.Fatalf("doctor %+v", d)
			}
			if rehearsed := len(fake.cands) == 1; rehearsed != (tc.stage == "") {
				t.Fatalf("rehearsed %v after a precheck %+v", rehearsed, d.Features.Precheck)
			}
			if _, err := os.Stat(filepath.Join(dir, "audit.log")); err == nil {
				t.Error("doctor wrote an audit record")
			}
		})
	}
}

func TestDoctorHumanOutput(t *testing.T) {
	dir, _, _ := pinHost(t)
	plantPin(t, dir, pinAllow+"accept_fs=network\n", 0o644)
	var code int
	out := captureStdout(t, func() { code = runLocalSubcommand([]string{"doctor"}) })
	for _, want := range []string{
		"pin:                   valid: net=allow accept_fs=network\n", "attempt:               kernel\n",
		"reads:                 kernel-jailed, network open\n", "rehearsal:             passed\n",
		"label when pinned:     " + confine.LabelNetworkOpen + "\n", "landlock_abi:          6\n",
		"lsm:                   capability,landlock\n",
	} {
		if code != exitOK || !strings.Contains(out, want) {
			t.Errorf("exit %d, output lacks %q:\n%s", code, want, out)
		}
	}
}

// TestDoctorJailFloorNote: a leftover jail-floor with no jail pin is reported
// as the router treats it, denying reads; with a valid jail pin it is ignored,
// with one note.
func TestDoctorJailFloorNote(t *testing.T) {
	dir, _, _ := pinHost(t)
	if d := doctorJSON(t); len(d.Advice) != 0 {
		t.Fatalf("advice without a floor: %v", d.Advice)
	}
	if err := os.WriteFile(filepath.Join(dir, jailFloorFile), []byte("full\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := doctorJSON(t)
	if d.Pin.State != "legacy-floor" || d.Reads != "denied (pin:legacy-floor)" || len(d.Advice) != 1 || !strings.Contains(d.Advice[0], "Pin with 'gate doctor --pin --net=deny'") {
		t.Fatalf("leftover floor, no pin: %+v", d)
	}
	plantPin(t, dir, pinDeny, 0o644)
	d = doctorJSON(t)
	if d.Pin.State != "valid" || d.Reads != "kernel-jailed, no network" || len(d.Advice) != 1 || !strings.Contains(d.Advice[0], "jail-floor is no longer used and is ignored") {
		t.Fatalf("leftover floor under a jail pin: %+v", d)
	}
}

// TestDoctorAgreesWithRouter: for every attempt outcome, what doctor says an
// unsigned read would do is what the router does with that read.
func TestDoctorAgreesWithRouter(t *testing.T) {
	readNamedWriter(t)
	clamp := capableFacts
	clamp.AppArmorUsernsClamp = true
	withHostFacts(t, clamp)
	for _, pin := range []string{"", pinDeny, pinAllow} {
		for _, failure := range []struct {
			stage string
			errno syscall.Errno
		}{{"", 0}, {"clone", syscall.EACCES}, {"landlock", syscall.ENOSYS}, {"seccomp", syscall.EIO}} {
			t.Run(fmt.Sprintf("pin=%q %s", pin, failure.stage), func(t *testing.T) {
				dir := t.TempDir()
				withGateDir(t, dir)
				if pin != "" {
					plantPin(t, dir, pin, 0o644)
				}
				fake := withFakeAttempt(t, roKernel, nil)
				if failure.stage != "" {
					fake.result, fake.err = setupFailure(failure.stage, failure.errno)
				}
				reads := doctorJSON(t).Reads
				fake.confined, fake.fallback = 0, 0
				target := seedTarget(t, dir)
				code, _, _ := runWith(t, "stat "+target+" ran")
				ran := fake.fallback == 1 || failure.stage == ""
				switch {
				case strings.HasPrefix(reads, "denied"):
					if code != exitNoPermVal || fake.fallback != 0 {
						t.Fatalf("doctor says %q, router: exit %d, fallback %d", reads, code, fake.fallback)
					}
				case reads == "classifier-only (no usable jail)":
					if code != exitOK || fake.fallback != 1 {
						t.Fatalf("doctor says %q, router: exit %d, fallback %d", reads, code, fake.fallback)
					}
				default:
					if !strings.HasPrefix(reads, "kernel-jailed") || !ran || fake.fallback != 0 {
						t.Fatalf("doctor says %q, router: exit %d, fallback %d", reads, code, fake.fallback)
					}
				}
			})
		}
	}
}

// TestDoctorReportsPinToClaimBeforePin: an unpinned capable host is
// "pin to claim" now and would be kernel-jailed once pinned net=deny.
func TestDoctorReportsPinToClaimBeforePin(t *testing.T) {
	pinHost(t)
	code, d, _ := runDoctorJSON(t)
	if code != exitOK || d.Label != confine.LabelPinToClaim || d.Enforcement != "kernel" || !d.Rehearsal.Passed ||
		d.Pin.Result != "not-requested" || d.Pin.LabelAfter != confine.LabelKernelNoLabel || d.Features.Precheck == nil || d.Features.Precheck.Route != "kernel" {
		t.Fatalf("exit %d, doctor %+v", code, d)
	}
}

// TestDoctorPinWrites: --pin after a passed rehearsal writes the rehearsed
// pin at 0600; again, it is unchanged and untouched.
func TestDoctorPinWrites(t *testing.T) {
	dir, fake, _ := pinHost(t)
	code, d, stderr := runDoctorJSON(t, "--pin", "--net=deny")
	content, info := readPinFile(t, dir)
	if code != exitOK || d.Pin.Result != "written" || !d.Pin.Requested || content != canonicalDeny || info.Mode().Perm() != 0o600 {
		t.Fatalf("exit %d, stderr %q, pin %+v, file %q %v", code, stderr, d.Pin, content, info)
	}
	if got := fake.cands; len(got) != 1 || !reflect.DeepEqual(got[0], confine.Pin{Profile: confine.ProfileROv1}) {
		t.Fatalf("rehearsed %+v", got)
	}
	if pin := readJailPin(); !pin.valid || pin.pin.Net {
		t.Fatalf("read path sees %+v", pin)
	}
	code, d, _ = runDoctorJSON(t, "--pin", "--net=deny")
	_, again := readPinFile(t, dir)
	if code != exitOK || d.Pin.Result != "unchanged" || !os.SameFile(info, again) || !again.ModTime().Equal(info.ModTime()) {
		t.Fatalf("second --pin: exit %d, pin %+v", code, d.Pin)
	}
	code, d, _ = runDoctorJSON(t, "--pin", "--net=allow", "--accept-fs=network")
	content, _ = readPinFile(t, dir)
	if code != exitOK || d.Pin.Result != "written" || content != "# written by gate doctor\nprofile=ro-v1\nnet=allow\naccept_fs=network\n" || d.Pin.LabelAfter != confine.LabelNetworkOpen {
		t.Fatalf("--net=allow: exit %d, pin %+v, file %q", code, d.Pin, content)
	}
}

// TestDoctorRepins: --pin is the repair: it rehearses and writes the
// candidate whatever the current pin's state.
func TestDoctorRepins(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setUp func(t *testing.T, dir string)
		state string
	}{
		{"damaged pin", func(t *testing.T, dir string) { plantPin(t, dir, pinDeny, 0o666) }, "damaged"},
		{"wrong-mode valid pin", func(t *testing.T, dir string) { plantPin(t, dir, pinDeny, 0o640) }, "valid"},
		{"unparsable pin", func(t *testing.T, dir string) { plantPin(t, dir, "profile=ro-v1\n", 0o600) }, "damaged"},
		{"legacy floor", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, jailFloorFile), []byte("full\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "legacy-floor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, fake, _ := pinHost(t)
			tc.setUp(t, dir)
			code, d, _ := runDoctorJSON(t, "--pin", "--net=deny")
			content, info := readPinFile(t, dir)
			if code != exitOK || d.Pin.State != tc.state || d.Pin.Result != "written" || content != canonicalDeny || info.Mode().Perm() != 0o600 || len(fake.cands) != 1 {
				t.Fatalf("exit %d, pin %+v, file %q", code, d.Pin, content)
			}
			if pin := readJailPin(); !pin.valid {
				t.Fatalf("after the repair the read path sees %+v", pin)
			}
		})
	}
	t.Run("legacy floor stays in place", func(t *testing.T) {
		dir, _, _ := pinHost(t)
		floor := filepath.Join(dir, jailFloorFile)
		if err := os.WriteFile(floor, []byte("full\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := runDoctorJSON(t, "--pin", "--net=deny"); code != exitOK {
			t.Fatalf("exit %d", code)
		}
		if _, err := os.Stat(floor); err != nil {
			t.Fatal("the jail-floor file was removed")
		}
	})
	t.Run("accept_fs is rehearsed and written", func(t *testing.T) {
		dir, fake, _ := pinHost(t)
		var accepts [][]string
		mountOfFn = func(_ string, accept []string) (confine.MountReport, error) {
			accepts = append(accepts, accept)
			return directRoot, nil
		}
		code, _, _ := runDoctorJSON(t, "--pin", "--net=deny", "--accept-fs=network")
		content, _ := readPinFile(t, dir)
		want := []string{"network"}
		if code != exitOK || len(fake.cands) != 1 || !reflect.DeepEqual(fake.cands[0].AcceptFS, want) || !reflect.DeepEqual(accepts, [][]string{want}) || !strings.Contains(content, "accept_fs=network\n") {
			t.Fatalf("exit %d, rehearsed %+v, mount accept %v, file %q", code, fake.cands, accepts, content)
		}
	})
	t.Run("docker_socket carries over", func(t *testing.T) {
		dir, fake, _ := pinHost(t)
		plantPin(t, dir, pinDeny+"docker_socket=/run/docker.sock\n", 0o600)
		if code, _, _ := runDoctorJSON(t, "--pin", "--net=allow"); code != exitOK || len(fake.cands) != 1 || fake.cands[0].DockerSocket != "/run/docker.sock" {
			t.Fatalf("exit %d, rehearsed %+v", code, fake.cands)
		}
		if content, _ := readPinFile(t, dir); !strings.Contains(content, "docker_socket=/run/docker.sock\n") {
			t.Fatalf("pin %q", content)
		}
	})
}

// TestDoctorPinWriteSafety covers the pin write path's preconditions and its
// handling of what it finds at the pin's name.
func TestDoctorPinWriteSafety(t *testing.T) {
	t.Run("symlink pin is replaced, not followed", func(t *testing.T) {
		dir, _, _ := pinHost(t)
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("victim\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, filepath.Join(dir, confine.PinFile)); err != nil {
			t.Fatal(err)
		}
		code, d, _ := runDoctorJSON(t, "--pin", "--net=deny")
		content, info := readPinFile(t, dir)
		victimData, _ := os.ReadFile(victim)
		if code != exitOK || d.Pin.Result != "written" || info == nil || !info.Mode().IsRegular() || content != canonicalDeny || string(victimData) != "victim\n" {
			t.Fatalf("exit %d, pin %+v, victim %q", code, d.Pin, victimData)
		}
	})
	t.Run("a directory at the pin's name", func(t *testing.T) {
		dir, _, _ := pinHost(t)
		if err := os.Mkdir(filepath.Join(dir, confine.PinFile), 0o700); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := runDoctorJSON(t, "--pin", "--net=deny"); code != exitSoftware {
			t.Fatalf("exit %d, want %d", code, exitSoftware)
		}
		if stale := staleTempPins(dir); len(stale) != 0 {
			t.Fatalf("temporary pins left: %v", stale)
		}
	})
	t.Run("group-writable gate dir", func(t *testing.T) {
		dir, fake, _ := pinHost(t)
		if err := os.Chmod(dir, 0o770); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := runDoctorJSON(t, "--pin", "--net=deny"); code != exitNoPermVal || len(fake.cands) != 0 {
			t.Fatalf("exit %d, rehearsals %d", code, len(fake.cands))
		}
		if content, _ := readPinFile(t, dir); content != "" {
			t.Fatal("a pin was written")
		}
	})
	t.Run("wrong uid", func(t *testing.T) {
		dir, _, _ := pinHost(t)
		previous := pinUIDFn
		pinUIDFn = func() int { return os.Getuid() + 1 }
		t.Cleanup(func() { pinUIDFn = previous })
		if code, _, _ := runDoctorJSON(t, "--pin", "--net=deny"); code != exitNoPermVal {
			t.Fatalf("exit %d", code)
		}
		if content, _ := readPinFile(t, dir); content != "" {
			t.Fatal("a pin was written")
		}
	})
	t.Run("umask 0", func(t *testing.T) {
		dir, _, _ := pinHost(t)
		previous := syscall.Umask(0)
		defer syscall.Umask(previous)
		if code, _, _ := runDoctorJSON(t, "--pin", "--net=deny"); code != exitOK {
			t.Fatalf("exit %d", code)
		}
		if _, info := readPinFile(t, dir); info == nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", info)
		}
	})
	t.Run("locked gate dir", func(t *testing.T) {
		dir, _, _ := pinHost(t)
		holder, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Close()
		if err := unix.Flock(int(holder.Fd()), unix.LOCK_EX); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := runDoctorJSON(t, "--pin", "--net=deny"); code != exitTempFail {
			t.Fatalf("locked: exit %d, want %d", code, exitTempFail)
		}
		_ = unix.Flock(int(holder.Fd()), unix.LOCK_UN)
		if code, _, _ := runDoctorJSON(t, "--pin", "--net=deny"); code != exitOK {
			t.Fatalf("released: exit %d", code)
		}
	})
	t.Run("stale temporary pin is reported, never read", func(t *testing.T) {
		dir, _, _ := pinHost(t)
		stale := filepath.Join(dir, pinTempPrefix+"0123456789abcdef")
		if err := os.WriteFile(stale, []byte(pinAllow), 0o600); err != nil {
			t.Fatal(err)
		}
		_, d, _ := runDoctorJSON(t)
		if d.Pin.State != "absent" || len(d.Advice) != 1 || !strings.Contains(d.Advice[0], "stale temporary pin") {
			t.Fatalf("doctor %+v", d)
		}
	})
}

// pinRefusals are hosts on which --pin must refuse: the rehearsal did not run
// or did not pass. Each sets the host up and returns the expected exit code.
func pinRefusals() map[string]func(t *testing.T, fake *fakeRehearser) int {
	failedRow := func(change func(r *rehearsalResult)) func(t *testing.T, fake *fakeRehearser) int {
		return func(t *testing.T, fake *fakeRehearser) int {
			r := passedRehearsal()
			change(&r)
			r.finish()
			fake.result = r
			return exitNoPermVal
		}
	}
	clamp := capableFacts
	clamp.AppArmorUsernsClamp = true
	return map[string]func(t *testing.T, fake *fakeRehearser) int{
		"precheck absent": func(t *testing.T, _ *fakeRehearser) int {
			withHostFacts(t, clamp)
			result, err := setupFailure("clone", syscall.EACCES)
			recordAttempts(t, result, err)
			return exitNoPermVal
		},
		"precheck failed": func(t *testing.T, _ *fakeRehearser) int {
			result, err := setupFailure("covers", syscall.EIO)
			recordAttempts(t, result, err)
			return exitNoPermVal
		},
		"gate dir not shown": func(t *testing.T, _ *fakeRehearser) int {
			mountOfFn = func(string, []string) (confine.MountReport, error) {
				return confine.MountReport{Point: "/home", FSType: "nfs4", Class: "network"}, nil
			}
			return exitNoPermVal
		},
		"gate binary replaced": func(t *testing.T, _ *fakeRehearser) int {
			selftestBinaryFn = func() (string, error) { return "", errors.New("replaced") }
			return exitSoftware
		},
		"fixtures not built": func(t *testing.T, _ *fakeRehearser) int {
			fixturesFn = func(string) (rehearser, error) { return nil, errors.New("subreaper") }
			return exitNoPermVal
		},
		"could not run": func(t *testing.T, fake *fakeRehearser) int {
			fake.result = rehearsalResult{Skipped: "could not run: child not alive"}
			return exitNoPermVal
		},
		"a row failed":       failedRow(func(r *rehearsalResult) { r.Rows[0].Pass = false }),
		"a row not reported": failedRow(func(r *rehearsalResult) { r.Rows[5].Attempted = false }),
		"a row missing":      failedRow(func(r *rehearsalResult) { r.Rows = r.Rows[1:] }),
		"no rows":            failedRow(func(r *rehearsalResult) { r.Rows = nil }),
		"rows out of order":  failedRow(func(r *rehearsalResult) { r.Rows[0], r.Rows[1] = r.Rows[1], r.Rows[0] }),
		"an outside check":   failedRow(func(r *rehearsalResult) { r.fail("the canary or its directory changed") }),
		"network mismatch":   failedRow(func(r *rehearsalResult) { r.fail("jail facts: net true") }),
		"not run":            failedRow(func(r *rehearsalResult) { r.Ran = false }),
	}
}

// unitPinRequiresRehearsal: --pin writes nothing unless the rehearsal passed;
// writePin has one call site, guarded by pinAllowed.
func unitPinRequiresRehearsal(t *testing.T) {
	p := newProof(t, "U-PinRequiresRehearsal")
	written := false
	for name, setUp := range pinRefusals() {
		t.Run(name, func(t *testing.T) {
			dir, fake, _ := pinHost(t)
			want := setUp(t, fake)
			code, d, stderr := runDoctorJSON(t, "--pin", "--net=deny")
			if content, _ := readPinFile(t, dir); content != "" {
				written = true
				t.Logf("%s: pin written", name)
				return
			}
			if code != want || want == exitNoPermVal && (d.Pin.Result != "refused" || d.Pin.Refusal == "") {
				t.Errorf("%s: exit %d (want %d), pin %+v, stderr %q", name, code, want, d.Pin, stderr)
			}
		})
	}
	dir, _, _ := pinHost(t)
	code, _, _ := runDoctorJSON(t, "--pin", "--net=deny")
	content, _ := readPinFile(t, dir)
	if err := writePinCallSites(); err != nil {
		t.Fatal(err)
	}
	p.Effect("decision", written)
	p.Control("decision", code == exitOK && content == canonicalDeny)
	p.Finish()
}

// writePinCallSites requires exactly one call of writePin in the gate's code,
// in the body of `if pinAllowed(report)`.
func writePinCallSites() error {
	files, _ := filepath.Glob("*.go")
	total, guarded := 0, 0
	isCall := func(node ast.Node, name string) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return false
		}
		ident, ok := call.Fun.(*ast.Ident)
		return ok && ident.Name == name
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if isCall(node, "writePin") {
				total++
			}
			if stmt, ok := node.(*ast.IfStmt); ok && isCall(stmt.Cond, "pinAllowed") {
				ast.Inspect(stmt.Body, func(inner ast.Node) bool {
					if isCall(inner, "writePin") {
						guarded++
					}
					return true
				})
			}
			return true
		})
	}
	if total != 1 || guarded != 1 {
		return fmt.Errorf("writePin: %d call sites, %d inside if pinAllowed(...)", total, guarded)
	}
	return nil
}
