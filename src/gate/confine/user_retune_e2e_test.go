//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
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
	runDisposableIdentity(t, "L-SCHED-USER", []string{"retuned"}, func(phase, probe string, uid uint32) {
		victim := startSleeper(t)
		before := readScheduler(t, victim.Process.Pid)
		commands := []string{probe + " prio-user unused", probe + " ioprio-user unused"}
		callers := []string{fmt.Sprintf("renice -n 19 -u %d", uid), fmt.Sprintf("ionice -c3 -u %d", uid)}
		if phase == "control" {
			for _, command := range append(commands, callers...) {
				output, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
				if err != nil {
					t.Fatalf("SETUP: USER control %q: %v: %s", command, err, output)
				}
			}
			after := readScheduler(t, victim.Process.Pid)
			if before.nice == after.nice || before.io == after.io {
				t.Fatal("SETUP: USER control did not retune victim")
			}
			return
		}
		changed := false
		for _, spec := range hostPIDSpecs(abi) {
			for i, command := range commands {
				field := []string{"prio-user", "ioprio-user"}[i]
				output := requireProbeOutput(t, runP12(t, spec, command, nil), field)
				if output != field+"=1\n" {
					t.Fatalf("SETUP: USER retune expected EPERM: %s", output)
				}
			}
			for _, command := range callers {
				result := runP12(t, spec, command, nil)
				if result.setupErr != nil || result.exit != 1 || !strings.Contains(strings.ToLower(result.stderr), "operation not permitted") {
					t.Fatalf("SETUP: USER caller expected EPERM: %+v", result)
				}
			}
			after := readScheduler(t, victim.Process.Pid)
			changed = changed || before.nice != after.nice || before.io != after.io
		}

		mutationEffect(t, "L-SCHED-USER", "retuned", changed)
	})
}

func runDisposableIdentity(t *testing.T, legName string, markerCandidates []string, child func(phase, probe string, uid uint32)) {
	t.Helper()
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

		child(phase, probe, uint32(uid))
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
		command.Dir = directory
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
		leg := harness.Leg{Name: legName, Names: map[string]string{"native": t.Name(), "abi1": t.Name()}}
		for _, marker := range markerCandidates {
			if bytes.Contains(output, []byte("MUTATION-EFFECT "+legName+" "+marker)) {
				leg.Markers = append(leg.Markers, "MUTATION-EFFECT "+marker)
			}
		}
		if legName == "L-RL-NPROC" {
			leg.Markers = nil
			if jailmut.On("P-RL-NPROC") {
				leg.Markers = []string{"MUTATION-EFFECT limit"}
			}
		}
		abi := "native"
		if strings.Contains(t.Name(), "/abi1/") {
			abi = "abi1"
		}
		if err := harness.Judge(bytes.NewReader(stream), "", exitCodeOf(err), []harness.Leg{leg}, abi); err != nil {
			t.Fatalf("SETUP: disposable USER fixture: %v: %s", err, output)
		}
		if legName == "L-RL-NPROC" {
			// The child owns the complete proof under the disposable identity. The
			// parent's own PASS remains conditional on fixture teardown succeeding.
			for _, line := range strings.Split(string(output), "\n") {
				if index := strings.Index(line, "PROOF-COMPLETE "+legName+" "); index >= 0 {
					t.Log(line[index:])
				}
			}
			continue
		}
		for _, marker := range leg.Markers {
			mutationEffect(t, legName, strings.TrimPrefix(marker, "MUTATION-EFFECT "), true)
		}
	}
}
