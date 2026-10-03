//go:build linux

package confine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const mountinfoFixture = `22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
23 22 0:5 / /dev rw,nosuid master:2 - devtmpfs devtmpfs rw
24 22 0:21 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw
25 22 0:30 / /mnt/with\040space\011tab rw,noexec,noatime,nodiratime - tmpfs tmpfs rw
26 22 0:31 / /mnt/back\134slash\012nl ro,nosymfollow - tmpfs tmpfs rw
27 24 0:32 / /tmp rw,noexec,relatime - tmpfs tmpfs rw
`

func TestParseMountInfo(t *testing.T) {
	got, err := parseMountInfo(strings.NewReader(mountinfoFixture))
	if err != nil {
		t.Fatal(err)
	}
	want := []mountEntry{
		{22, "/", []string{"rw", "relatime"}},
		{23, "/dev", []string{"rw", "nosuid"}},
		{24, "/tmp", []string{"rw", "nosuid", "nodev"}},
		{25, "/mnt/with space\ttab", []string{"rw", "noexec", "noatime", "nodiratime"}},
		{26, "/mnt/back\\slash\nnl", []string{"ro", "nosymfollow"}},
		{27, "/tmp", []string{"rw", "noexec", "relatime"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseMountInfo:\n got %#v\nwant %#v", got, want)
	}
}

func TestParseMountInfoRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"22 1 8:2 / /\n",                       // too few fields
		"x 1 8:2 / / rw - ext4 /dev/sda2 rw\n", // non-numeric id
		"22 1 8:2 / /a\\04 rw - ext4 x rw\n",   // truncated escape
		"22 1 8:2 / /a\\09x rw - ext4 x rw\n",  // non-octal escape
		"22 1 8:2 / /a\\777 rw - ext4 x rw\n",  // escape overflows a byte
	} {
		if _, err := parseMountInfo(strings.NewReader(bad)); err == nil {
			t.Errorf("parseMountInfo(%q) accepted a malformed line", bad)
		}
	}
}

func TestRemountPlanTopOfStackLeafFirst(t *testing.T) {
	entries, err := parseMountInfo(strings.NewReader(mountinfoFixture))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range remountPlan(entries) {
		got = append(got, fmt.Sprintf("%d:%s", e.id, e.point))
	}
	want := []string{"25:/mnt/with space\ttab", "26:/mnt/back\\slash\nnl", "23:/dev", "27:/tmp", "22:/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remountPlan = %q, want %q", got, want)
	}
}

// TestRemountFlagsPreserve: every per-mount flag the kernel may have locked is
// carried into the read-only remount, with the exact atime mode.
func TestRemountFlagsPreserve(t *testing.T) {
	base := uintptr(unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY)
	cases := []struct {
		opts string
		want uintptr
	}{
		{"rw,relatime", base | unix.MS_RELATIME},
		{"rw,nosuid,nodev", base | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_STRICTATIME},
		{"rw,nosuid,nodev,noexec,relatime", base | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RELATIME},
		{"rw,noexec,noatime,nodiratime", base | unix.MS_NOEXEC | unix.MS_NOATIME | unix.MS_NODIRATIME},
		{"rw,nodiratime", base | unix.MS_NODIRATIME | unix.MS_STRICTATIME},
		{"ro,nosymfollow,relatime", base | unix.MS_NOSYMFOLLOW | unix.MS_RELATIME},
	}
	for _, c := range cases {
		if got := remountFlags(strings.Split(c.opts, ",")); got != c.want {
			t.Errorf("remountFlags(%s) = %#x, want %#x", c.opts, got, c.want)
		}
	}
}

// preservedOpts is the per-mount flag set the fallback must keep unchanged.
func preservedOpts(opts []string) string {
	keep := map[string]bool{"nosuid": true, "nodev": true, "noexec": true, "noatime": true,
		"relatime": true, "nodiratime": true, "nosymfollow": true}
	var out []string
	for _, o := range opts {
		if keep[o] {
			out = append(out, o)
		}
	}
	return strings.Join(out, ",")
}

func readMountInfo() ([]mountEntry, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseMountInfo(f)
}

// roFallbackChild is the __jailtest_rofallback re-exec (see jail_e2e_test.go).
// It runs inside a rung-1 clone, builds a root of its own holding binds of HOST
// mounts — whose nosuid/nodev/noexec/atime flags are kernel-locked in this user
// namespace — plus a mount whose path needs mountinfo escaping, then runs the
// pre-5.12 fallback and checks every mount went read-only with its flags intact
// and that writes fail with EROFS. args: <scratch dir under $HOME> <host-/tmp
// marker name>.
func roFallbackChild(args []string) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(os.Stderr, "rofallback: "+format+"\n", a...)
		return 1
	}
	if len(args) != 2 {
		return fail("usage: <dir> <marker>")
	}
	root, marker := args[0], args[1]
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fail("make-private: %v", err)
	}
	if err := unix.Mount("tmpfs", root, "tmpfs", 0, "mode=0755"); err != nil {
		return fail("tmpfs root: %v", err)
	}
	binds := map[string]string{"hosttmp": "/tmp", "pts": "/dev/pts", "sec": "/sys/kernel/security"}
	for _, d := range []string{"oldroot", "proc", "hosttmp", "pts", "sec", "with space"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			return fail("mkdir %s: %v", d, err)
		}
	}
	for dst, src := range binds {
		if err := unix.Mount(src, filepath.Join(root, dst), "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fail("bind %s: %v", src, err)
		}
	}
	if err := unix.Mount("tmpfs", filepath.Join(root, "with space"), "tmpfs", unix.MS_NOEXEC|unix.MS_NOATIME, ""); err != nil {
		return fail("tmpfs with space: %v", err)
	}
	if err := unix.PivotRoot(root, filepath.Join(root, "oldroot")); err != nil {
		return fail("pivot_root: %v", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fail("chdir: %v", err)
	}
	// Both the fallback and this check read /proc/self/mountinfo. proc must be
	// mounted while /oldroot (and its full proc) is still visible: after the
	// detach the kernel refuses a new proc mount (EPERM, mount_too_revealing).
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fail("mount proc: %v", err)
	}
	if err := unix.Unmount("/oldroot", unix.MNT_DETACH); err != nil {
		return fail("detach oldroot: %v", err)
	}

	// The test only means something if the host flags really are locked: a bare
	// ro remount that drops nosuid/nodev must be refused.
	if err := unix.Mount("", "/hosttmp", "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, ""); !errors.Is(err, unix.EPERM) {
		return fail("remount dropping locked flags: got %v, want EPERM (flags not locked?)", err)
	}

	before, err := readMountInfo()
	if err != nil {
		return fail("mountinfo: %v", err)
	}
	if err := remountRootReadOnlyFallback(); err != nil {
		return fail("fallback: %v", err)
	}
	after, err := readMountInfo()
	if err != nil {
		return fail("mountinfo: %v", err)
	}
	byID := map[int]mountEntry{}
	for _, e := range after {
		byID[e.id] = e
	}
	bad := 0
	sawSpace := false
	for _, b := range remountPlan(before) {
		a, ok := byID[b.id]
		if !ok {
			bad += fail("mount %d %q vanished", b.id, b.point)
			continue
		}
		sawSpace = sawSpace || b.point == "/with space"
		if a.opts[0] != "ro" {
			bad += fail("%q still %s after the fallback", a.point, a.opts[0])
		}
		if preservedOpts(a.opts) != preservedOpts(b.opts) {
			bad += fail("%q flags changed: %q -> %q", a.point, preservedOpts(b.opts), preservedOpts(a.opts))
		}
	}
	if !sawSpace {
		bad += fail("escaped mount point not in the plan")
	}
	for _, p := range []string{"/hosttmp/" + marker, "/with space/x", "/x"} {
		err := os.WriteFile(p, []byte("w"), 0o644)
		if !errors.Is(err, unix.EROFS) {
			bad += fail("write %s: got %v, want EROFS", p, err)
		}
	}
	if bad > 0 {
		return 1
	}
	return 0
}
