//go:build linux && jail_e2e

package confine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

func legCoverCwd(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	fixture := startCoverFuse(t, filepath.Join(t.TempDir(), "fuse"))
	fixture.control(t)
	previous, err := os.Getwd()
	mutationSetup(t, err)
	mutationSetup(t, os.Chdir(fixture.point))
	defer os.Chdir(previous)
	spec.Cwd = fixture.point
	mark := fixture.mark(t)
	command := coverSetter("./f") + "; " + coverSetter("/proc/self/cwd/f") + "; " + coverCommand("read", "./f") + "; " + coverQuote(coverProbe()) + " jail-proc shim cwd/f; " + coverQuote(coverProbe()) + " jail-proc gate cwd/f; " + coverCommand("mntid", ".") + "; cat /proc/self/mountinfo"
	result, facts := coverResult(t, spec, command, nil)
	if coverAbort(t, "L-COVER-CWD", result) {
		spec.Strict = false
		nonStrict, info := coverResult(t, spec, "echo COMMAND_RAN", nil)
		coverRan(t, nonStrict)
		if !strings.Contains(strings.Join(info.Unmet, " "), "fs-view:cwd@") {
			t.Errorf("non-strict cwd omitted unmet: %+v", info)
		}
		return
	}
	log := fixture.since(t, mark)
	landed := strings.Contains(log, "IOCTL")
	mutationEffect(t, "L-COVER-CWD", "fuse-ioctl", landed)
	if !landed {
		var id int
		var rows []string
		for _, line := range strings.Split(result.stdout, "\n") {
			if strings.HasPrefix(line, "mntid=") {
				fmt.Sscanf(line, "mntid=%d", &id)
			}
			if strings.Contains(line, " - ") {
				rows = append(rows, line)
			}
		}
		entries, err := parseMountInfo(strings.NewReader(strings.Join(rows, "\n")))
		mutationSetup(t, err)
		matched := false
		for _, entry := range entries {
			if entry.id == id && entry.point == fixture.point && entry.fstype == "tmpfs" {
				matched = true
			}
		}
		if !matched {
			t.Errorf("cwd mount %d is not the cover", id)
		}
		if strings.Count(result.stdout, "open=2\n") != 3 || strings.Count(result.stdout, "open=13\n") != 2 || facts.CwdReset || log != "" {
			t.Errorf("cwd cover/proc state: %+v facts=%+v log=%s", result, facts, log)
		}
	}
	if jailmut.On("P-CWD") {
		return
	}
	spec.Cwd = fixture.point + "/nested"
	result, facts = coverResult(t, spec, "pwd", nil)
	coverRan(t, result)
	if result.stdout != "/\n" || !facts.CwdReset {
		t.Errorf("covered descendant cwd not reset: %+v %+v", result, facts)
	}
}
func legShimProc(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	// The unjailed shell and its readlink child have the same uid and capability set.
	output, err := exec.Command("/bin/sh", "-c", "readlink /proc/$$/exe && readlink /proc/$$/cwd").CombinedOutput()
	if err != nil || len(strings.Split(strings.TrimSpace(string(output)), "\n")) != 2 {
		t.Fatalf("SETUP: dumpable parent control: %v %s", err, output)
	}
	if jailmut.On("P-LL-REQUIRED") {
		spec.ForceABI = ForceNoLandlock
	}
	var results strings.Builder
	for _, link := range []string{"exe", "cwd", "root", "maps"} {
		command := coverQuote(coverProbe()) + " jail-proc shim " + link
		if jailmut.On("SHIM-NOCAPS") {
			command += " wait-nocaps"
		}
		result, _ := coverResult(t, spec, command, nil)
		if !jailmut.On("P-LL-REQUIRED") {
			coverRan(t, result)
		} else {
			// The intentional no-Landlock mutation makes the parent reject ABI 0 facts.
			result.setupErr = nil
		}
		expected := []string{"target", "readlink"}
		if link == "maps" {
			expected = []string{"target", "open", "open>read", "read>bytes"}
		}
		results.WriteString(requireProbeOutputMode(t, result, probeExitAnyFailure, expected...))
	}
	lines := strings.Split(results.String(), "\n")
	denied, readable := 0, 0
	for _, line := range lines {
		if line == "readlink=13" || line == "open=13" {
			denied++
		}
		if line == "readlink=ok" || line == "read=ok" {
			readable++
		}
	}
	if denied+readable != 4 {
		t.Fatalf("SETUP: proc target/errno failure: %s", results.String())
	}
	mutationEffect(t, "L-SHIM-PROC", "shim-proc", readable == 4)
	if readable != 0 && readable != 4 {
		t.Errorf("inconsistent shim exposure: %s", results.String())
	}
}
func legCoverWalkDenied(t *testing.T, spec Spec) {
	if !coverNamespace(t, true) {
		return
	}
	for _, relative := range []bool{false, true} {
		base := t.TempDir()
		closed := base + "/closed"
		point := closed + "/movable/fuse"
		fixture := startCoverFuse(t, point)
		fixture.control(t)
		mutationSetup(t, os.Chmod(closed, 0))
		defer os.Chmod(closed, 0755)
		spec.Cwd = base
		path := point + "/f"
		if relative {
			path = "/proc/self/cwd/closed/movable/fuse/f"
		}
		mark := fixture.mark(t)
		result, facts := coverResult(t, spec, "echo POST_X; read release; "+coverSetter(path), func() { mutationSetup(t, os.Chmod(closed, 0755)) })
		if result.setupErr != nil {
			if coverAbort(t, "L-COVER-WALKDENIED", result) {
				return
			}
		}
		log := fixture.since(t, mark)
		landed := strings.Contains(log, "IOCTL")
		marker := "fuse-ioctl-absolute"
		if relative {
			marker = "fuse-ioctl-cwd"
		}
		mutationEffect(t, "L-COVER-WALKDENIED", marker, landed)
		if !landed && (log != "" || !strings.Contains(result.stdout, "open=2\n") || len(facts.CoverAtAncestor) == 0) {
			t.Errorf("ancestor cover: %+v facts=%+v log=%s", result, facts, log)
		}
		// A real unconfined post-exec chmod control: the shell waits before opening.
		mutationSetup(t, os.Chmod(closed, 0))
		output := coverControlAfterX(t, coverSetter(point+"/f"), func() { mutationSetup(t, os.Chmod(closed, 0755)) })
		if !strings.Contains(output, "ioctl=ok") {
			t.Fatalf("SETUP: chmod control: %s", output)
		}
	}
	if jailmut.On("P-COVERS") || jailmut.On("P-SELFCHECK-MOUNTS") {
		return
	}
	// Outside-owner rename is a documented exposure, not a protection assertion.
	owners := []bool{false}
	if os.Getenv("SSHGATE_COVER_ROOT_RUN") == "1" {
		owners = append(owners, true)
	} else {
		t.Log("NOT-APPLICABLE: different-UID rename requires root runner")
	}
	for _, differentUID := range owners {
		base := t.TempDir()
		closed := base + "/closed"
		fixture := startCoverFuse(t, closed+"/movable/fuse")
		fixture.control(t)
		if differentUID {
			mutationSetup(t, os.Chown(closed, 0, 0))
		}
		mutationSetup(t, os.Chmod(closed, 0))
		defer os.Chmod(closed, 0755)
		spec.Cwd = base
		mark := fixture.mark(t)
		result, facts := coverResult(t, spec, "echo POST_X; read release; "+coverSetter(base+"/exposed/fuse/f"), func() {
			if differentUID {
				actor := exec.Command("/bin/sh", "-c", "chmod 755 "+coverQuote(closed)+"; mv "+coverQuote(closed+"/movable")+" "+coverQuote(base+"/exposed"))
				actor.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}}
				output, err := actor.CombinedOutput()
				if err != nil {
					t.Fatalf("SETUP: outside different-UID owner: %v %s", err, output)
				}
			} else {
				mutationSetup(t, os.Chmod(closed, 0755))
				mutationSetup(t, os.Rename(closed+"/movable", base+"/exposed"))
			}
			t.Cleanup(func() {
				if err := unix.Unmount(base+"/exposed/fuse", unix.MNT_DETACH); err != nil {
					t.Errorf("renamed fixture unmount: %v", err)
				}
			})
		})
		coverRan(t, result)
		if len(facts.CoverAtAncestor) == 0 || !strings.Contains(result.stdout, "ioctl=ok") || !strings.Contains(fixture.since(t, mark), "IOCTL") {
			t.Errorf("R16 rename exposure (differentUID=%v): %+v facts=%+v log=%s", differentUID, result, facts, fixture.since(t, mark))
		}
	}
}
func legPrivatePropagation(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	base := filepath.Join(t.TempDir(), "shared")
	mutationSetup(t, os.Mkdir(base, 0755))
	mutationSetup(t, unix.Mount("tmpfs", base, "tmpfs", 0, "mode=0755"))
	t.Cleanup(func() { unix.Unmount(base, unix.MNT_DETACH) })
	mutationSetup(t, unix.Mount("", base, "", unix.MS_SHARED, ""))
	for _, name := range []string{"late", "latefuse"} {
		mutationSetup(t, os.Mkdir(base+"/"+name, 0755))
	}
	controlFinish := coverPropagationControl(t, "cat /proc/self/mountinfo; echo control > "+coverQuote(base+"/late/control")+"; "+coverSetter(base+"/latefuse/f"))
	var fixture *fuseFixture
	var mark int64
	command := "echo POST_X; read release; cat /proc/self/mountinfo; echo changed > " + coverQuote(base+"/late/f") + "; " + coverSetter(base+"/latefuse/f")
	result, _ := coverResult(t, spec, command, func() {
		mutationSetup(t, unix.Mount("tmpfs", base+"/late", "tmpfs", 0, "mode=0777"))
		fixture = startCoverFuse(t, base+"/latefuse")
		fixture.control(t)
		mark = fixture.mark(t)
	})
	if coverAbort(t, "L-PRIVATE-PROPAGATION", result) {
		return
	}
	log := fixture.since(t, mark)
	mutationEffect(t, "L-PRIVATE-PROPAGATION", "fuse-ioctl", strings.Contains(log, "IOCTL"))
	data, err := os.ReadFile(base + "/late/f")
	wrote := err == nil && string(data) == "changed\n"
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("SETUP: outside write observation: %v", err)
	}
	mutationEffect(t, "L-PRIVATE-PROPAGATION", "write", wrote)
	if !jailmut.On("P-PRIVATE") && strings.Contains(result.stdout, " "+base+"/late ") {
		t.Error("host late mount appeared in private jail")
	}
	controlMark := fixture.mark(t)
	control := controlFinish()
	controlData, err := os.ReadFile(base + "/late/control")
	mutationSetup(t, err)
	if string(controlData) != "control\n" || !strings.Contains(control, " "+base+"/late ") || !strings.Contains(fixture.since(t, controlMark), "IOCTL") {
		t.Fatalf("SETUP: unchanged-propagation control: %s log=%s", control, fixture.since(t, controlMark))
	}
}
