//go:build linux

package confine

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// tmpfsSizeBytes bounds each writable tmpfs so a jailed `cat /dev/zero > /tmp/x`
// cannot OOM the host; RLIMIT_FSIZE bounds a single file on top of this.
const tmpfsSizeBytes = 64 << 20 // 64 MiB per mount

// setupMounts builds the rung-1 filesystem view in the worker's mount namespace:
// a recursively read-only /, small writable tmpfs for the scratch dirs, a fresh
// read-only pid-namespace-local /proc, and a minimal /dev. Must run on the
// locked thread while the mount-phase caps are still held.
//
// A read-only mount does NOT stop writes to special files: opening a device,
// FIFO or socket for write skips the mount's ro check. So the host /dev is
// replaced by a minimal one (otherwise every device the SSH user can open by DAC
// — its own ttys, /dev/fuse, group-owned devices — stays writable), and FIFOs
// elsewhere on the ro bind require Landlock, which handles WRITE_FILE.
func setupMounts() error {
	// 1. Make the whole tree private so nothing we do propagates to the host.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make-private /: %w", err)
	}
	// 2. Recursive read-only bind of /.
	if err := remountRootReadOnly(); err != nil {
		return err
	}
	// 3. Writable tmpfs over the scratch dirs (added AFTER the ro pass, so rw).
	for _, d := range []string{"/tmp", "/var/tmp"} {
		if err := mountTmpfs(d); err != nil {
			return err
		}
	}
	// 4. Fresh /proc for the new pid namespace (hides host pids, incl. the gate),
	// mounted read-only: the kernel control files (/proc/sys, /proc/sysrq-trigger
	// and the rest) are guarded by DAC alone, so a root SSH user on a host without
	// Landlock could otherwise write them. Reads (ps, top, free, /proc/meminfo)
	// need no write, and /proc/self/fd/N magic links reopen the target's own mount.
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}
	// 5. Minimal /dev (needs the fresh /proc for its fd symlinks and binds).
	return setupDev()
}

// devNodes are the host device nodes bound into the minimal /dev. A node the
// host lacks is skipped.
var devNodes = []string{"null", "zero", "full", "random", "urandom", "tty"}

// devLinks are the /dev symlinks into /proc/self/fd.
var devLinks = [][2]string{
	{"fd", "/proc/self/fd"},
	{"stdin", "/proc/self/fd/0"},
	{"stdout", "/proc/self/fd/1"},
	{"stderr", "/proc/self/fd/2"},
}

// setupDev replaces /dev with a small tmpfs holding only devNodes (bound from the
// host, since a userns cannot mknod), the fd symlinks and a bounded /dev/shm,
// then seals that tmpfs read-only. No NODEV anywhere over the bound nodes: it
// would make open("/dev/null") fail and the jailed shell could not start.
func setupDev() error {
	// Hold the host nodes open (O_PATH) before the tmpfs hides them; each is
	// bound back in through its /proc/self/fd magic link.
	fds := map[string]int{}
	defer func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}()
	for _, n := range devNodes {
		fd, err := unix.Open("/dev/"+n, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err == unix.ENOENT {
			continue
		}
		if err != nil {
			return fmt.Errorf("open /dev/%s: %w", n, err)
		}
		fds[n] = fd
	}
	if err := unix.Mount("tmpfs", "/dev", "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC, "mode=0755,size=65536"); err != nil {
		return fmt.Errorf("mount tmpfs /dev: %w", err)
	}
	for _, n := range devNodes {
		fd, ok := fds[n]
		if !ok {
			continue
		}
		target := "/dev/" + n
		tfd, err := unix.Open(target, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC, 0o644)
		if err != nil {
			return fmt.Errorf("create %s: %w", target, err)
		}
		_ = unix.Close(tfd)
		if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", fd), target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind %s: %w", target, err)
		}
	}
	for _, l := range devLinks {
		if err := unix.Symlink(l[1], "/dev/"+l[0]); err != nil {
			return fmt.Errorf("symlink /dev/%s: %w", l[0], err)
		}
	}
	if err := unix.Mkdir("/dev/shm", 0o755); err != nil {
		return fmt.Errorf("mkdir /dev/shm: %w", err)
	}
	if err := mountTmpfs("/dev/shm"); err != nil {
		return err
	}
	// Seal the /dev tmpfs itself (the bound nodes and /dev/shm are separate mounts).
	if err := unix.Mount("", "/dev", "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("seal /dev: %w", err)
	}
	return nil
}

// remountRootReadOnly marks every mount reachable from / read-only. It prefers
// rbind + mount_setattr(AT_RECURSIVE) (kernel ≥5.12) and otherwise remounts
// each mount from mountinfo. Only RDONLY is set — never NODEV, which would reach
// /dev and break /dev/null.
func remountRootReadOnly() error {
	if !mountSetattrSupported() {
		return remountRootReadOnlyFallback()
	}
	if err := unix.Mount("/", "/", "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("rbind /: %w", err)
	}
	attr := &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}
	if err := unix.MountSetattr(unix.AT_FDCWD, "/", unix.AT_RECURSIVE, attr); err != nil {
		return fmt.Errorf("mount_setattr ro /: %w", err)
	}
	return nil
}

// mountSetattrSupported reports whether mount_setattr exists, via an all-zero
// attr the kernel treats as a no-op. Any answer but ENOSYS means "supported";
// a real failure then surfaces from the actual call.
func mountSetattrSupported() bool {
	return unix.MountSetattr(unix.AT_FDCWD, "/", 0, &unix.MountAttr{}) != unix.ENOSYS
}

// remountRootReadOnlyFallback is the pre-5.12 path: remount every mount point
// read-only, keeping each mount's own flags. In a user namespace the nosuid,
// nodev, noexec and atime flags of mounts inherited from the host are LOCKED, so
// a remount that drops one fails EPERM. Any failure is fatal: a mount left
// writable would be a hole, so the worker aborts instead (fail closed — this
// includes a mount point the worker cannot reach).
func remountRootReadOnlyFallback() error {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return fmt.Errorf("read mountinfo: %w", err)
	}
	entries, err := parseMountInfo(f)
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("parse mountinfo: %w", err)
	}
	for _, e := range remountPlan(entries) {
		if err := unix.Mount("", e.point, "", remountFlags(e.opts), ""); err != nil {
			return fmt.Errorf("remount ro %q: %w", e.point, err)
		}
	}
	return nil
}

// mountEntry is one /proc/self/mountinfo line.
type mountEntry struct {
	id    int
	point string   // unescaped mount point (field 5)
	opts  []string // per-mount options (field 6)
}

// parseMountInfo parses proc(5) mountinfo. The kernel octal-escapes space, tab,
// newline and backslash in the mount point (\040 \011 \012 \134); those are
// decoded. A malformed line is an error, never skipped.
func parseMountInfo(r io.Reader) ([]mountEntry, error) {
	var out []mountEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			return nil, fmt.Errorf("malformed mountinfo line %q", sc.Text())
		}
		id, err := strconv.Atoi(f[0])
		if err != nil {
			return nil, fmt.Errorf("mountinfo id %q: %w", f[0], err)
		}
		point, err := unescapeMountField(f[4])
		if err != nil {
			return nil, err
		}
		out = append(out, mountEntry{id: id, point: point, opts: strings.Split(f[5], ",")})
	}
	return out, sc.Err()
}

// unescapeMountField decodes the kernel's \ooo octal escapes.
func unescapeMountField(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+4 > len(s) {
			return "", fmt.Errorf("truncated escape in mount point %q", s)
		}
		v, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", fmt.Errorf("bad escape in mount point %q: %w", s, err)
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String(), nil
}

// remountPlan returns one entry per mount point — the LAST one listed, the top
// of a stack of mounts on that path and so the one a path lookup reaches —
// ordered leaf-first.
func remountPlan(entries []mountEntry) []mountEntry {
	last := map[string]mountEntry{}
	for _, e := range entries {
		last[e.point] = e
	}
	plan := make([]mountEntry, 0, len(last))
	for _, e := range last {
		plan = append(plan, e)
	}
	sort.Slice(plan, func(i, j int) bool {
		if len(plan[i].point) != len(plan[j].point) {
			return len(plan[i].point) > len(plan[j].point)
		}
		return plan[i].point < plan[j].point
	})
	return plan
}

// remountFlags is the read-only bind-remount flag set for a mount with the
// given per-mount options: its nosuid/nodev/noexec/nosymfollow and exact atime
// mode are carried over, so a locked flag is never dropped.
func remountFlags(opts []string) uintptr {
	fl := uintptr(unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY)
	atime := false
	for _, o := range opts {
		switch o {
		case "nosuid":
			fl |= unix.MS_NOSUID
		case "nodev":
			fl |= unix.MS_NODEV
		case "noexec":
			fl |= unix.MS_NOEXEC
		case "nosymfollow":
			fl |= unix.MS_NOSYMFOLLOW
		case "nodiratime":
			fl |= unix.MS_NODIRATIME
		case "noatime":
			fl |= unix.MS_NOATIME
			atime = true
		case "relatime":
			fl |= unix.MS_RELATIME
			atime = true
		}
	}
	if !atime {
		fl |= unix.MS_STRICTATIME // neither noatime nor relatime shown
	}
	return fl
}

// mountTmpfs mounts a bounded, noexec/nosuid/nodev tmpfs at dir. A missing
// mountpoint is skipped (the ro root bind still covers that path read-only).
func mountTmpfs(dir string) error {
	opts := fmt.Sprintf("mode=1777,size=%d", tmpfsSizeBytes)
	err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, opts)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return fmt.Errorf("mount tmpfs %s: %w", dir, err)
	}
	return nil
}
