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
	p := newProof(t, "L-COVER-CWD")
	var results []JailedResult
	fixture := startCoverFuse(t, filepath.Join(t.TempDir(), "fuse"))
	p.ObserveWith("fuse", fixture)
	p.Control("facility", fixture.control(t))
	previous, err := os.Getwd()
	mutationSetup(t, err)
	mutationSetup(t, os.Chdir(fixture.point))
	defer os.Chdir(previous)
	spec.Cwd = fixture.point
	mark := fixture.mark(t)
	command := coverSetter("./f") + "; " + coverSetter("/proc/self/cwd/f") + "; " + coverCommand("read", "./f") + "; " + coverProbeCommand("jail-proc", "shim", "cwd/f") + "; " + coverProbeCommand("jail-proc", "gate", "cwd/f") + "; " + coverCommand("mntid", ".") + "; cat /proc/self/mountinfo"
	result, facts := coverProofRun(t, p, spec, command, nil)
	results = append(results, result)
	fixture.seal(t)
	if coverAbort(t, "L-COVER-CWD", result.jailResult) {
		spec.Strict = false
		nonStrict, info := coverProofRun(t, p, spec, "echo COMMAND_RAN", nil)
		results = append(results, nonStrict)
		coverRan(t, nonStrict.jailResult)
		if !strings.Contains(strings.Join(info.Unmet, " "), "fs-view:cwd@") {
			unexpected(t, "non-strict cwd omitted unmet: %+v", info)
		}
		p.Jailed("probe", results...)
		fixture.seal(t)
		p.Observed("effects", Observation{Conclusive: true, Sealed: true, Valid: fixture.since(t, mark) == "", Detail: "aborted CWD window untouched"})
		p.Finish()
		return
	}
	log := fixture.since(t, mark)
	landed := coverHasRecord(log, "IOCTL 42")
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
			unexpected(t, "cwd mount %d is not the cover", id)
		}
		if strings.Count(result.stdout, "open=2\n") != 3 || strings.Count(result.stdout, "open=13\n") != 2 || facts.CwdReset || log != "" {
			unexpected(t, "cwd cover/proc state: %+v facts=%+v log=%s", result, facts, log)
		}
	}
	p.Observed("effects", Observation{Conclusive: true, Sealed: true, Valid: landed || log == "", Detail: "CWD ioctl window sealed"})
	if jailmut.On("P-CWD") {
		p.Jailed("probe", results...)
		p.Finish()
		return
	}
	spec.Cwd = fixture.point + "/nested"
	result, facts = coverProofRun(t, p, spec, "pwd", nil)
	results = append(results, result)
	coverRan(t, result.jailResult)
	if result.stdout != "/\n" || !facts.CwdReset {
		unexpected(t, "covered descendant cwd not reset: %+v %+v", result, facts)
	}
	p.Jailed("probe", results...)
	p.Finish()
}
func legShimProc(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	p := newProof(t, "L-SHIM-PROC")
	var runs []JailedResult
	// The unjailed shell and its readlink child have the same uid and capability set.
	output, err := exec.Command("/bin/sh", "-c", "readlink /proc/$$/exe && readlink /proc/$$/cwd").CombinedOutput()
	if err != nil || len(strings.Split(strings.TrimSpace(string(output)), "\n")) != 2 {
		t.Fatalf("SETUP: dumpable parent control: %v %s", err, output)
	}
	p.Control("facility", ControlResult{Valid: err == nil && len(strings.Split(strings.TrimSpace(string(output)), "\n")) == 2, Detail: "dumpable parent links"})
	if jailmut.On("P-LL-REQUIRED") {
		spec.ForceABI = ForceNoLandlock
	}
	var results strings.Builder
	for _, link := range []string{"exe", "cwd", "root", "maps"} {
		command := coverQuote(coverProbe()) + " jail-proc shim " + link
		if jailmut.On("SHIM-NOCAPS") {
			command += " wait-nocaps"
		}
		expected := []string{"target", "readlink"}
		if link == "maps" {
			expected = []string{"target", "open", "open>read", "read>bytes"}
		}
		result := runJailed(t, p, spec, RunPlan{Mode: Execute, AcceptFactsABI0: jailmut.On("P-LL-REQUIRED"), Ops: []ProofOp{{Name: link, Command: command, Validate: func(stdout, stderr string, exit int) error {
			return validateProbeOutput(jailResult{stdout: stdout, stderr: stderr, exit: exit}, expected, probeExitAnyFailure)
		}}}})
		runs = append(runs, result)
		results.WriteString(result.stdout)
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
		unexpected(t, "inconsistent shim exposure: %s", results.String())
	}
	p.Jailed("probe", runs...)
	p.Observed("effects", Observation{Conclusive: true, Sealed: true, Valid: denied == 4 || readable == 4, Detail: "all four proc link reports complete"})
	p.Finish()
}
func legCoverWalkDenied(t *testing.T, spec Spec) {
	for _, relative := range []bool{false, true} {
		name := "absolute"
		if relative {
			name = "cwd"
		}
		t.Run(name, func(t *testing.T) {
			if !coverNamespace(t, true) {
				return
			}
			leg := "L-COVER-WALKDENIED/" + name
			p := newProof(t, leg)
			base := t.TempDir()
			closed := base + "/closed"
			point := closed + "/movable/fuse"
			fixture := startCoverFuse(t, point)
			p.ObserveWith("fuse", fixture)
			fixture.control(t)
			mutationSetup(t, os.Chmod(closed, 0))
			defer os.Chmod(closed, 0755)
			spec.Cwd = base
			path := point + "/f"
			if relative {
				path = "/proc/self/cwd/closed/movable/fuse/f"
			}
			mark := fixture.mark(t)
			result, facts := coverProofRun(t, p, spec, "echo POST_X; read release; "+coverSetter(path), func() { mutationSetup(t, os.Chmod(closed, 0755)) })
			p.Jailed("probe", result)
			fixture.seal(t)
			log := fixture.since(t, mark)
			landed := coverHasRecord(log, "IOCTL 42")
			marker := "fuse-ioctl-absolute"
			if relative {
				marker = "fuse-ioctl-cwd"
			}
			mutationEffect(t, leg, marker, landed)
			if !landed && (log != "" || !strings.Contains(result.stdout, "open=2\n") || len(facts.CoverAtAncestor) == 0) {
				unexpected(t, "ancestor cover: %+v facts=%+v log=%s", result, facts, log)
			}
			p.Observed("effects", Observation{Conclusive: true, Sealed: true, Valid: landed || (log == "" && strings.Contains(result.stdout, "open=2\n") && len(facts.CoverAtAncestor) > 0), Detail: "denied ancestor ioctl window"})
			// A real unconfined post-exec chmod control: the shell waits before opening.
			mutationSetup(t, os.Chmod(closed, 0))
			output := coverControlAfterX(t, coverSetter(point+"/f"), func() { mutationSetup(t, os.Chmod(closed, 0755)) })
			if !strings.Contains(output, "ioctl=ok") {
				t.Fatalf("SETUP: chmod control: %s", output)
			}
			p.Control("facility", ControlResult{Valid: strings.Contains(output, "ioctl=ok"), Detail: "post-exec chmod control"})
			fixture.seal(t)
			p.Finish()
		})
	}
	if jailmut.On("P-COVERS") || jailmut.On("P-SELFCHECK-MOUNTS") {
		return
	}
	// Outside-owner rename is a documented exposure, not a protection assertion.
	for _, differentUID := range []bool{false, true} {
		name := "rename-same-uid"
		if differentUID {
			name = "rename-other-uid"
		}
		t.Run(name, func(t *testing.T) {
			if !coverNamespace(t, true) {
				return
			}
			p := newProof(t, "L-COVER-WALKDENIED/"+name)
			if differentUID && os.Getenv("SSHGATE_COVER_ROOT_RUN") != "1" {
				p.Omit("root-only")
				return
			}
			base := t.TempDir()
			closed := base + "/closed"
			fixture := startCoverFuse(t, closed+"/movable/fuse")
			p.ObserveWith("fuse", fixture)
			p.Control("facility", fixture.control(t))
			if differentUID {
				mutationSetup(t, os.Chown(closed, 0, 0))
			}
			mutationSetup(t, os.Chmod(closed, 0))
			defer os.Chmod(closed, 0755)
			spec.Cwd = base
			mark := fixture.mark(t)
			result, facts := coverProofRun(t, p, spec, "echo POST_X; read release; "+coverSetter(base+"/exposed/fuse/f"), func() {
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
			})
			p.Jailed("probe", result)
			fixture.seal(t)
			coverRan(t, result.jailResult)
			if len(facts.CoverAtAncestor) == 0 || !strings.Contains(result.stdout, "ioctl=ok") || !coverHasRecord(fixture.since(t, mark), "IOCTL 42") {
				unexpected(t, "R16 rename exposure (differentUID=%v): %+v facts=%+v log=%s", differentUID, result, facts, fixture.since(t, mark))
			}
			p.Observed("effects", Observation{Conclusive: true, Sealed: true, Valid: len(facts.CoverAtAncestor) > 0 && strings.Contains(result.stdout, "ioctl=ok") && coverHasRecord(fixture.since(t, mark), "IOCTL 42"), Detail: "R16 outside-owner rename exposure"})
			p.Finish()
		})
	}
}
func legPrivatePropagation(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	p := newProof(t, "L-PRIVATE-PROPAGATION")
	base := filepath.Join(t.TempDir(), "shared")
	mutationSetup(t, os.Mkdir(base, 0755))
	mutationSetup(t, unix.Mount("tmpfs", base, "tmpfs", 0, "mode=0755"))
	t.Cleanup(func() { unix.Unmount(base, unix.MNT_DETACH) })
	mutationSetup(t, unix.Mount("", base, "", unix.MS_SHARED, ""))
	for _, name := range []string{"late", "latefuse"} {
		mutationSetup(t, os.Mkdir(base+"/"+name, 0755))
	}
	controlFinish := coverPropagationControl(t, coverExecCommand("cat /proc/self/mountinfo")+"; echo control > "+coverQuote(base+"/late/control")+"; "+coverSetter(base+"/latefuse/f"))
	var fixture *fuseFixture
	var mark int64
	command := "echo POST_X; read release; " + coverExecCommand("cat /proc/self/mountinfo") + "; " + coverCommand("cover-write", base+"/late/f") + "; " + coverSetter(base+"/latefuse/f")
	result, _ := coverProofRun(t, p, spec, command, func() {
		mutationSetup(t, unix.Mount("tmpfs", base+"/late", "tmpfs", 0, "mode=0777"))
		fixture = startCoverFuse(t, base+"/latefuse")
		p.ObserveWith("fuse", fixture)
		fixture.control(t)
		mark = fixture.mark(t)
	})
	p.Jailed("probe", result)
	fixture.seal(t)
	log := fixture.since(t, mark)
	mutationEffect(t, "L-PRIVATE-PROPAGATION", "fuse-ioctl", coverHasRecord(log, "IOCTL 42"))
	data, err := os.ReadFile(base + "/late/f")
	wrote := err == nil && string(data) == "changed\n"
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("SETUP: outside write observation: %v", err)
	}
	mutationEffect(t, "L-PRIVATE-PROPAGATION", "write", wrote)
	if !jailmut.On("P-PRIVATE") && strings.Contains(result.stdout, " "+base+"/late ") {
		unexpected(t, "host late mount appeared in private jail")
	}
	p.Observed("effects", Observation{Conclusive: true, Sealed: true, Valid: err == nil || os.IsNotExist(err), Detail: "late mounts observed after worker and record barrier"})
	controlMark := fixture.mark(t)
	control := controlFinish()
	fixture.seal(t)
	controlData, err := os.ReadFile(base + "/late/control")
	mutationSetup(t, err)
	if string(controlData) != "control\n" || !strings.Contains(control, " "+base+"/late ") || !coverHasRecord(fixture.since(t, controlMark), "IOCTL 42") {
		t.Fatalf("SETUP: unchanged-propagation control: %s log=%s", control, fixture.since(t, controlMark))
	}
	fixture.seal(t)
	p.Control("facility", ControlResult{Valid: string(controlData) == "control\n" && strings.Contains(control, " "+base+"/late ") && coverHasRecord(fixture.since(t, controlMark), "IOCTL 42"), Detail: "shared mount propagation control"})
	p.Finish()
}
