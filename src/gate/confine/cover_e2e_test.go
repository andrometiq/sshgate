//go:build linux && jail_e2e

package confine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

func TestJailMatrixCovers(t *testing.T) {
	for _, cfg := range []struct {
		name string
		abi  int
	}{{"native", 0}, {"abi1", 1}} {
		t.Run(cfg.name, func(t *testing.T) {
			spec := Spec{Profile: ProfileROv1, Net: true, Strict: true, ForceABI: cfg.abi}
			t.Run("L-FUSE-IOCTL", func(t *testing.T) { legFuseIoctl(t, spec) })
			t.Run("L-COVER-NESTED", func(t *testing.T) { legCoverNested(t, spec) })
			t.Run("L-COVER-WALKDENIED", func(t *testing.T) { legCoverWalkDenied(t, spec) })
			t.Run("L-COVER-UNKNOWN", func(t *testing.T) { legCoverUnknown(t, spec) })
			t.Run("L-COVER-CWD", func(t *testing.T) { legCoverCwd(t, spec) })
			t.Run("L-COVER-STACKED", func(t *testing.T) { legCoverStacked(t, spec) })
			if os.Geteuid() == 0 {
				t.Run("L-COVER-OVERLAY", func(t *testing.T) { legCoverOverlay(t, spec) })
				t.Run("L-SC-SYNC", func(t *testing.T) { legCoverSync(t, spec) })
			} else {
				t.Log("MUTATE-OMITTED(root-only): L-COVER-OVERLAY L-SC-SYNC")
			}
			t.Run("L-SHIM-PROC", func(t *testing.T) { legShimProc(t, spec) })
			t.Run("L-SELFCHECK-DENIED-SAFE", func(t *testing.T) { legSelfcheckDeniedSafe(t, spec) })
			t.Run("L-SELFCHECK-MOUNTS", func(t *testing.T) { legSelfcheckMounts(t, spec) })
			t.Run("L-PRIVATE-PROPAGATION", func(t *testing.T) { legPrivatePropagation(t, spec) })
			if os.Geteuid() == 0 && os.Getenv("SSHGATE_JAIL_CI") == "1" {
				t.Run("L-TRACEFS", func(t *testing.T) { legTracefs(t, spec) })
				t.Run("L-COVER-LOOP", func(t *testing.T) { legCoverLoop(t, spec) })
				t.Run("L-AUTOFS", func(t *testing.T) { legAutofs(t, spec) })
				t.Run("L-BINFMT-FIXED-CHAR", func(t *testing.T) { legBinfmtFixed(t, spec) })
			} else {
				t.Log("MUTATE-OMITTED(root/ci-only): L-COVER-LOOP L-AUTOFS L-BINFMT-FIXED-CHAR")
			}
		})
	}
}
func legFuseIoctl(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	changed := false
	for _, flags := range [][]string{nil, {"--subtype"}} {
		fixture := startCoverFuse(t, filepath.Join(t.TempDir(), "fuse"), flags...)
		fixture.control(t)
		mark := fixture.mark(t)
		result, _ := coverResult(t, spec, coverSetter(fixture.point+"/f"), nil)
		if coverAbort(t, "L-FUSE-IOCTL", result) {
			return
		}
		log := fixture.since(t, mark)
		landed := strings.Contains(log, "IOCTL")
		changed = changed || landed
		if !landed && (log != "" || !strings.Contains(result.stdout, "open=2\n")) {
			unexpected(t, "cover touched FUSE or wrong errno: %+v log=%s", result, log)
		}
	}
	mutationEffect(t, "L-FUSE-IOCTL", "fuse-ioctl", changed)
}
func legCoverNested(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	fixture := startCoverFuse(t, filepath.Join(t.TempDir(), "fuse"), "--nested")
	fixture.control(t)
	controlMark := fixture.mark(t)
	out, err := exec.Command(coverProbe(), "fuse-ioctl", fixture.point+"/nested/f", "0x40085301", "42").CombinedOutput()
	if err != nil {
		t.Fatalf("SETUP: nested control: %v %s", err, out)
	}
	fixture.waitRelease(t, controlMark)
	mark := fixture.mark(t)
	result, _ := coverResult(t, spec, coverSetter(fixture.point+"/f")+"; "+coverSetter(fixture.point+"/nested/f"), nil)
	coverRan(t, result)
	log := fixture.since(t, mark)
	if log != "" || strings.Count(result.stdout, "open=2\n") != 2 {
		unexpected(t, "nested mounts not covered: %+v log=%s", result, log)
	}
}
func legCoverUnknown(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	point := filepath.Join(t.TempDir(), "ramfs")
	mutationSetup(t, os.Mkdir(point, 0755))
	mutationSetup(t, unix.Mount("ramfs", point, "ramfs", 0, ""))
	t.Cleanup(func() { unix.Unmount(point, unix.MNT_DETACH) })
	mutationSetup(t, os.WriteFile(point+"/f", []byte("canary"), 0644))
	result, _ := coverResult(t, spec, coverCommand("read", point+"/f"), nil)
	coverRan(t, result)
	if jailmut.On("SAFE-DROP=ramfs") {
		if !strings.Contains(result.stdout, "open=2\n") {
			unexpected(t, "unknown filesystem remained visible: %+v", result)
		}
		mutationEffect(t, "L-COVER-UNKNOWN", "covered", strings.Contains(result.stdout, "open=2\n"))
	} else if !strings.Contains(result.stdout, "read=ok\n") {
		t.Fatalf("SETUP: read-safe ramfs control: %+v", result)
	}
}
func legCoverSync(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	expiry, err := os.ReadFile("/proc/sys/vm/dirty_expire_centisecs")
	mutationSetup(t, err)
	centiseconds, err := strconv.ParseInt(strings.TrimSpace(string(expiry)), 10, 64)
	mutationSetup(t, err)
	if centiseconds < 1000 {
		if os.Getenv("SSHGATE_JAIL_CI") == "1" {
			t.Fatalf("SETUP: dirty_expire_centisecs=%d is below 1000", centiseconds)
		}
		t.Logf("NOT-APPLICABLE: dirty_expire_centisecs=%d is below 1000", centiseconds)
		return
	}
	fixture := startCoverFuse(t, filepath.Join(t.TempDir(), "fuse"), "--writeback")
	writer, err := os.OpenFile(fixture.point+"/f", os.O_WRONLY, 0)
	mutationSetup(t, err)
	defer writer.Close() // Closing flushes writeback; keep it open through all observations.
	if os.Geteuid() == 0 {
		var stat unix.Stat_t
		mutationSetup(t, unix.Fstat(int(writer.Fd()), &stat))
		ratioPath := fmt.Sprintf("/sys/class/bdi/%d:%d/min_ratio", unix.Major(stat.Dev), unix.Minor(stat.Dev))
		previous, err := os.ReadFile(ratioPath)
		if err != nil {
			t.Fatalf("SETUP: FUSE min_ratio unavailable: %v", err)
		} else {
			ratio, err := strconv.Atoi(strings.TrimSpace(string(previous)))
			mutationSetup(t, err)
			if ratio < 1 {
				if err := os.WriteFile(ratioPath, []byte("1\n"), 0); err != nil {
					t.Fatalf("SETUP: FUSE min_ratio unchanged: %v", err)
				} else {
					defer func() {
						if err := os.WriteFile(ratioPath, previous, 0); err != nil {
							unexpected(t, "restore FUSE min_ratio: %v", err)
						}
					}()
				}
			}
		}
	}
	// Seed the strict-limit BDI's completion history before observing writes.
	for attempt := 0; attempt < 3; attempt++ {
		_, err := writer.WriteAt([]byte("warm"), 0)
		mutationSetup(t, err)
		mutationSetup(t, writer.Sync())
	}
	var mark int64
	var started time.Time
	dirty := func() {
		for attempt := 0; attempt < 5; attempt++ {
			mark = fixture.mark(t)
			started = time.Now()
			_, err := writer.WriteAt([]byte("dirty"), 0)
			mutationSetup(t, err)
			time.Sleep(50 * time.Millisecond)
			log := fixture.since(t, mark)
			if !strings.Contains(log, "WRITE\n") {
				return
			}
			if attempt == 4 {
				t.Fatalf("SETUP: WRITE before sync after five attempts; writeback cache is not active or data flushed early: log=%s", log)
			}
			mutationSetup(t, writer.Sync())
			time.Sleep(50 * time.Millisecond)
		}
	}
	checkWindow := func() {
		if time.Since(started) >= 5*time.Second {
			t.Fatal("SETUP: sync observation exceeded five-second writeback window")
		}
	}
	dirty()
	out, err := exec.Command(coverProbe(), "sync", "unused").CombinedOutput()
	checkWindow()
	if err != nil || string(out) != "sync=ok\n" || !strings.Contains(fixture.since(t, mark), "WRITE\n") {
		t.Fatalf("SETUP: sync control did not write back FUSE: %v %s log=%s", err, out, fixture.since(t, mark))
	}
	// Dirty only after X so jail setup cannot consume the observation window.
	result, facts := coverResult(t, spec, "echo POST_X; read release; "+coverCommand("sync", "unused")+"; "+coverCommand("read", fixture.point+"/f"), dirty)
	coverRan(t, result)
	checkWindow()
	if len(facts.Unmet) != 0 || !strings.Contains(result.stdout, "open=2\n") {
		unexpected(t, "covered mount was not hidden in strict run: %+v %+v", result, facts)
		t.FailNow()
	}
	mutationEffect(t, "L-SC-SYNC", "sync-writeback", strings.Contains(fixture.since(t, mark), "WRITE\n"))
	want := "sync=1\n"
	if jailmut.On("P-SC-SYNC") {
		want = "sync=ok\n"
	}
	if !strings.Contains(result.stdout, want) {
		unexpected(t, "sync errno: %+v", result)
	}
}
func legSelfcheckMounts(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	base := filepath.Join(t.TempDir(), "shared")
	mutationSetup(t, os.Mkdir(base, 0755))
	mutationSetup(t, unix.Mount("tmpfs", base, "tmpfs", 0, "mode=0755"))
	t.Cleanup(func() { unix.Unmount(base, unix.MNT_DETACH) })
	mutationSetup(t, unix.Mount("", base, "", unix.MS_SHARED, ""))
	fixture := startCoverFuse(t, base+"/fuse")
	fixture.control(t)
	mark := fixture.mark(t)
	result, _ := coverResult(t, spec, "echo COMMAND_RAN", nil)
	if coverAbort(t, "L-SELFCHECK-MOUNTS", result) {
		if strings.Contains(fixture.since(t, mark), "IOCTL") {
			unexpected(t, "aborted run touched ioctl")
		}
		if jailmut.On("P-COVERS") {
			spec.Strict = false
			nonStrict, facts := coverResult(t, spec, "echo COMMAND_RAN", nil)
			coverRan(t, nonStrict)
			if nonStrict.stdout != "COMMAND_RAN\n" || !strings.Contains(strings.Join(facts.Unmet, " "), "fs-view:fuse@") {
				unexpected(t, "non-strict missing filesystem unmet: %+v %+v", nonStrict, facts)
			}
		}
		return
	}
	coverRan(t, result)
	if result.stdout != "COMMAND_RAN\n" {
		t.Fatalf("SETUP: intact selfcheck %+v", result)
	}
}
func legCoverOverlay(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	directory := t.TempDir()
	point := directory + "/fuse"
	merged := directory + "/merged"
	fixture := startCoverFuse(t, point, "--overlay", merged)
	mark := fixture.mark(t)
	out, err := exec.Command(coverProbe(), "read", merged+"/f").CombinedOutput()
	if err != nil || !strings.Contains(fixture.since(t, mark), "READ") {
		t.Fatalf("SETUP: delegated read control: %v %s", err, out)
	}
	fixture.waitRelease(t, mark)
	mark = fixture.mark(t)
	result, _ := coverResult(t, spec, coverCommand("read", merged+"/f"), nil)
	coverRan(t, result)
	log := fixture.since(t, mark)
	landed := strings.Contains(log, "OPEN") && strings.Contains(log, "READ")
	if !landed && (!strings.Contains(result.stdout, "open=2\n") || log != "") {
		unexpected(t, "overlay not empty/quiet: %+v log=%s", result, log)
	}
	mutationEffect(t, "L-COVER-OVERLAY", "delegated-read", landed)
}
func legCoverStacked(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	changed, aborted := false, false
	for _, flag := range []string{"--stack-over", "--stack-under", "--stack3"} {
		point := filepath.Join(t.TempDir(), "stack")
		fixture := startCoverFuse(t, point, flag, point)
		if flag != "--stack-under" {
			fixture.control(t)
		}
		if flag == "--stack-over" {
			mutationSetup(t, unix.Mount("tmpfs", point+"/nested", "tmpfs", 0, "mode=0755"))
		}
		mark := fixture.mark(t)
		result, _ := coverResult(t, spec, coverCommand("mntid", point)+"; cat /proc/self/mountinfo; "+coverSetter(point+"/f")+"; "+coverCommand("read", point+"/f"), nil)
		if result.setupErr != nil {
			if !aborted {
				aborted = coverAbort(t, "L-COVER-STACKED", result)
			}
			if strings.Contains(fixture.since(t, mark), "LOOKUP") {
				unexpected(t, "cross-check looked inside unconfirmed FUSE")
			}
			continue
		}
		log := fixture.since(t, mark)
		landed := strings.Contains(log, "IOCTL")
		changed = changed || landed
		if !landed && log != "" {
			unexpected(t, "stack touched hidden FUSE: %s", log)
		}
		var id uint64
		for _, line := range strings.Split(result.stdout, "\n") {
			if strings.HasPrefix(line, "mntid=") {
				fmt.Sscanf(line, "mntid=%d", &id)
			}
		}
		if id == 0 {
			t.Fatalf("SETUP: missing mount ID: %+v", result)
		}
		var mountRows []string
		for _, line := range strings.Split(result.stdout, "\n") {
			if strings.Contains(line, " - ") {
				mountRows = append(mountRows, line)
			}
		}
		entries, err := parseMountInfo(strings.NewReader(strings.Join(mountRows, "\n")))
		mutationSetup(t, err)
		found := false
		for _, entry := range entries {
			if uint64(entry.id) == id {
				found = true
				if entry.point != point || (!landed && entry.fstype != "tmpfs") || (!landed && flag != "--stack-under" && !slices.Contains(entry.opts, "noexec")) {
					unexpected(t, "wrong visible mount ID %d: %+v", id, entry)
				}
			}
		}
		if !found {
			unexpected(t, "statx ID %d absent from command mountinfo", id)
		}
		if flag == "--stack-under" && !strings.Contains(result.stdout, "read=ok\n") {
			unexpected(t, "safe stack top disappeared: %+v", result)
		}
		if flag == "--stack-under" && landed {
			unexpected(t, "safe stack top exposed FUSE below")
		}
	}
	mutationEffect(t, "L-COVER-STACKED", "fuse-ioctl", changed)
	// Same-name directory in a safe stack top must not resolve to the hidden child mount.
	point := filepath.Join(t.TempDir(), "shadow")
	mutationSetup(t, os.Mkdir(point, 0755))
	mutationSetup(t, unix.Mount("tmpfs", point, "tmpfs", 0, ""))
	t.Cleanup(func() {
		if err := unix.Unmount(point, unix.MNT_DETACH); err != nil {
			unexpected(t, "shadow base cleanup: %v", err)
		}
	})
	mutationSetup(t, os.Mkdir(point+"/sub", 0755))
	mutationSetup(t, unix.Mount("tmpfs", point+"/sub", "tmpfs", 0, ""))
	t.Cleanup(func() {
		if err := unix.Unmount(point+"/sub", unix.MNT_DETACH); err != nil {
			unexpected(t, "shadow child cleanup: %v", err)
		}
	})
	mutationSetup(t, unix.Mount("tmpfs", point, "tmpfs", 0, ""))
	t.Cleanup(func() {
		if err := unix.Unmount(point, unix.MNT_DETACH); err != nil {
			unexpected(t, "shadow top cleanup: %v", err)
		}
	})
	mutationSetup(t, os.Mkdir(point+"/sub", 0755))
	result, _ := coverResult(t, spec, coverCommand("mntid", point)+"; "+coverCommand("mntid", point+"/sub"), nil)
	if !aborted {
		coverRan(t, result)
		var ids []string
		for _, line := range strings.Split(result.stdout, "\n") {
			if strings.HasPrefix(line, "mntid=") {
				ids = append(ids, line)
			}
		}
		if len(ids) != 2 || ids[0] != ids[1] {
			unexpected(t, "shadowed-name lookup: %+v", result)
		}
	}
}

func legSelfcheckDeniedSafe(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	spec.Strict = true
	for _, kind := range []string{"tmpfs", "fuse"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			closed := base + "/closed"
			point := closed + "/mount"
			mutationSetup(t, os.MkdirAll(point, 0755))
			var fixture *fuseFixture
			var mark int64
			if kind == "tmpfs" {
				mutationSetup(t, unix.Mount("tmpfs", point, "tmpfs", 0, "mode=0755"))
				t.Cleanup(func() { mutationSetup(t, unix.Unmount(point, unix.MNT_DETACH)) })
			} else {
				fixture = startCoverFuse(t, point)
				fixture.control(t)
				mark = fixture.mark(t)
			}
			mutationSetup(t, os.Chmod(closed, 0))
			defer func() { mutationSetup(t, os.Chmod(closed, 0755)) }()
			spec.Cwd = base
			command := "echo COMMAND_RAN"
			if fixture != nil {
				command += "; " + coverSetter(point+"/f")
			}
			result, facts := coverResult(t, spec, command, nil)
			coverRan(t, result)
			if !strings.Contains(result.stdout, "COMMAND_RAN\n") || len(facts.Unmet) != 0 {
				unexpected(t, "strict denied subtree: %+v facts=%+v", result, facts)
				t.FailNow()
			}
			if fixture == nil {
				if slices.Contains(facts.CoverAtAncestor, "cover_at_ancestor@"+closed) {
					unexpected(t, "safe subtree covered at ancestor: %+v", facts)
				}
				return
			}
			if log := fixture.since(t, mark); log != "" {
				unexpected(t, "covered subtree touched FUSE: %s", log)
			}
			if !strings.Contains(result.stdout, "open=2\n") {
				unexpected(t, "unsafe mount not hidden: %+v", result)
			}
			if os.Getuid() != 0 && !slices.Contains(facts.CoverAtAncestor, "cover_at_ancestor@"+closed) {
				unexpected(t, "missing denied ancestor cover: %+v", facts)
			}
		})
	}
}
