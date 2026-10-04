//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The USER operations below are only reachable in a child with a newly-created,
// dedicated uid. Namespace isolation alone is not a USER-operation boundary.
type disposableIdentity struct {
	UID    uint32
	Parent int
}

func legUserScheduler(t *testing.T, abi int) {
	if phase := os.Getenv("SSHGATE_TEST_USER_RETUNE_PHASE"); phase != "" {
		uid, err := strconv.ParseUint(os.Getenv("SSHGATE_TEST_USER_RETUNE_UID"), 10, 32)
		mutationSetup(t, err)
		if uid == 0 || uint32(os.Getuid()) != uint32(uid) {
			t.Fatal("SETUP: dedicated uid not active")
		}
		executable, err := os.Executable()
		mutationSetup(t, err)
		identityPath := filepath.Join(filepath.Dir(executable), "identity")
		identityFile, err := os.Open(identityPath)
		mutationSetup(t, err)
		defer identityFile.Close()
		info, err := identityFile.Stat()
		mutationSetup(t, err)
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&022 != 0 || !info.Mode().IsRegular() {
			t.Fatal("SETUP: fixture identity is not root-owned")
		}
		var identity disposableIdentity
		mutationSetup(t, json.NewDecoder(identityFile).Decode(&identity))
		if identity.UID != uint32(uid) || identity.Parent != os.Getppid() {
			t.Fatal("SETUP: fixture identity does not name this child")
		}
		probe := os.Getenv("SSHGATE_TEST_USER_RETUNE_PROBE")
		victim := startSleeper(t)
		before := readScheduler(t, victim.Process.Pid)
		command := fmt.Sprintf("%s prio-user unused; %s ioprio-user unused; renice -n 19 -u %d; ionice -c3 -u %d", probe, probe, uid, uid)
		if phase == "control" {
			output, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
			mutationSetup(t, err)
			after := readScheduler(t, victim.Process.Pid)
			if before.nice == after.nice || before.io == after.io {
				t.Fatalf("SETUP: USER control did not retune victim: %s", output)
			}
			return
		}
		changed := false
		for _, spec := range hostPIDSpecs(abi) {
			output := requireProbeOutput(t, runP12(t, spec, command, nil))
			after := readScheduler(t, victim.Process.Pid)
			changed = changed || before.nice != after.nice || before.io != after.io
			// USER calls can retune the victim and still fail on the same-uid shim.
			if !strings.Contains(output, "prio-user=1\n") || !strings.Contains(output, "ioprio-user=1\n") {
				t.Errorf("USER retune expected EPERM: %s", output)
			}
		}
		mutationEffect(t, "L-SCHED-USER", "retuned", changed)
		return
	}
	if os.Geteuid() != 0 || os.Getenv("SSHGATE_JAIL_CI") != "1" {
		t.Fatal("SETUP: USER controls require root disposable CI")
	}
	name := fmt.Sprintf("sgjail%x", time.Now().UnixNano())
	output, err := exec.Command("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name).CombinedOutput()
	if err != nil {
		t.Fatalf("SETUP: create disposable uid: %v: %s", err, output)
	}
	defer func() {
		output, err := exec.Command("userdel", name).CombinedOutput()
		if err != nil {
			t.Errorf("SETUP: remove disposable uid: %v: %s", err, output)
		}
	}()
	identity := func(flag string) uint32 {
		output, err := exec.Command("id", flag, name).Output()
		mutationSetup(t, err)
		n, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 32)
		mutationSetup(t, err)
		if n == 0 {
			t.Fatal("SETUP: disposable identity is root")
		}
		return uint32(n)
	}
	uid, gid := identity("-u"), identity("-g")
	directory, err := os.MkdirTemp("/tmp", "sshgate-user-retune-")
	mutationSetup(t, err)
	defer os.RemoveAll(directory)
	mutationSetup(t, os.Chmod(directory, 0755))
	executable, err := os.Executable()
	mutationSetup(t, err)
	copyBinary := func(source, name string) string {
		data, err := os.ReadFile(source)
		mutationSetup(t, err)
		path := filepath.Join(directory, name)
		mutationSetup(t, os.WriteFile(path, data, 0755))
		return path
	}
	runner := copyBinary(executable, "test")
	probe := copyBinary(buildProbe(t), "probe")
	identityJSON, err := json.Marshal(disposableIdentity{UID: uid, Parent: os.Getpid()})
	mutationSetup(t, err)
	mutationSetup(t, os.WriteFile(filepath.Join(directory, "identity"), identityJSON, 0444))
	for _, phase := range []string{"control", "jailed"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		command := exec.CommandContext(ctx, runner, "-test.v", "-test.run=^"+strings.ReplaceAll(t.Name(), "/", "$/^")+"$")
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
		command.Env = append(os.Environ(), "SSHGATE_TEST_USER_RETUNE_PHASE="+phase, "SSHGATE_TEST_USER_RETUNE_UID="+strconv.Itoa(int(uid)), "SSHGATE_TEST_USER_RETUNE_PROBE="+probe)
		output, err := command.CombinedOutput()
		cancel()
		if phase == "control" {
			if err != nil {
				t.Fatalf("SETUP: disposable USER control: %v: %s", err, output)
			}
			continue
		}
		convert := exec.Command("go", "tool", "test2json", "-p", "fixture")
		convert.Stdin = bytes.NewReader(output)
		stream, convertErr := convert.Output()
		mutationSetup(t, convertErr)
		leg := harness.Leg{Name: "L-SCHED-USER", Names: map[string]string{"native": t.Name(), "abi1": t.Name()}}
		for _, marker := range []string{"errno", "retuned"} {
			if bytes.Contains(output, []byte("MUTATION-EFFECT L-SCHED-USER "+marker)) {
				leg.Markers = append(leg.Markers, "MUTATION-EFFECT "+marker)
			}
		}
		if err := harness.Judge(bytes.NewReader(stream), "", exitCodeOf(err), []harness.Leg{leg}, "native"); err != nil {
			t.Fatalf("SETUP: disposable USER fixture: %v: %s", err, output)
		}
		for _, marker := range leg.Markers {
			mutationEffect(t, "L-SCHED-USER", strings.TrimPrefix(marker, "MUTATION-EFFECT "), true)
		}
	}
}
