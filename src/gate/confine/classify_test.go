//go:build linux

package confine

import (
	"os"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// capableHost is a host where no fact explains a failure; a row that needs a
// fact sets it.
var capableHost = HostFacts{MaxUserNS: 100, DevShmDir: true, SeccompFilter: true, LandlockABI: 6}

// permissiveHost sets every fact that can explain a failure.
var permissiveHost = HostFacts{MaxUserNS: 0, AppArmorUsernsClamp: true, LandlockABI: -1}

// knownStages is every stage a setup failure can carry: the worker's and
// shim's, Status's, the gate's start ("clone"), client sink ("sink"), seal
// ("seal") and its guard against starting in a sealed process ("sealed").
var knownStages = []string{
	"clone", "spec", "cmdread", "nsverify", "mounts", "private", "setattr", "devnodes", "covers",
	"scratch", "fds", "cwd", "nnp", "caps", "rlimits", "landlock", "seccomp", "tsync", "session",
	"selfcheck", "exec", "report", "unknown", "shim", "sink", "seal", "sealed",
}

func TestClassifySetupFailure(t *testing.T) {
	with := func(change func(*HostFacts)) HostFacts {
		facts := capableHost
		change(&facts)
		return facts
	}
	cases := []struct {
		name  string
		stage string
		errno syscall.Errno
		facts HostFacts
		want  FailureClass
	}{
		// Rows 1-5: the clone.
		{"clone EPERM: userns disabled", "clone", unix.EPERM, capableHost, Absent},
		{"clone EINVAL: no userns support", "clone", unix.EINVAL, capableHost, Absent},
		{"clone ENOSPC with a zero limit", "clone", unix.ENOSPC, with(func(f *HostFacts) { f.MaxUserNS = 0 }), Absent},
		{"clone ENOSPC: count used up", "clone", unix.ENOSPC, capableHost, Failed},
		{"clone ENOSPC: limit unreadable", "clone", unix.ENOSPC, with(func(f *HostFacts) { f.MaxUserNS = -1 }), Failed},
		// clamp-real-failure is what the clamp produced on stock Ubuntu 24.04
		// (kernel 6.8, apparmor_restrict_unprivileged_userns=1): Cmd.Start of
		// the jail failed with "fork/exec /proc/self/exe: permission denied".
		{"clamp-real-failure", "clone", unix.EACCES, with(func(f *HostFacts) { f.AppArmorUsernsClamp = true }), Absent},
		{"clone EACCES with no clamp to explain it", "clone", unix.EACCES, capableHost, Failed},
		{"clone ENOMEM: transient", "clone", unix.ENOMEM, permissiveHost, Failed},
		{"clone EAGAIN: transient", "clone", unix.EAGAIN, permissiveHost, Failed},
		{"clone ENOENT", "clone", unix.ENOENT, permissiveHost, Failed},
		// Row 6: mounts refused by an LSM.
		{"private EPERM", "private", unix.EPERM, capableHost, Absent},
		{"private EACCES", "private", unix.EACCES, capableHost, Absent},
		{"setattr EPERM", "setattr", unix.EPERM, capableHost, Absent},
		{"setattr EACCES", "setattr", unix.EACCES, capableHost, Absent},
		{"devnodes EPERM", "devnodes", unix.EPERM, capableHost, Absent},
		{"devnodes EACCES", "devnodes", unix.EACCES, capableHost, Absent},
		{"scratch EPERM", "scratch", unix.EPERM, capableHost, Absent},
		{"scratch EACCES", "scratch", unix.EACCES, capableHost, Absent},
		{"private EINVAL", "private", unix.EINVAL, permissiveHost, Failed},
		{"devnodes ENOSYS", "devnodes", unix.ENOSYS, permissiveHost, Failed},
		// Row 7: no mount_setattr.
		{"setattr ENOSYS", "setattr", unix.ENOSYS, capableHost, Absent},
		{"setattr EINVAL", "setattr", unix.EINVAL, permissiveHost, Failed},
		// Row 8: no /dev/shm.
		{"scratch ENOENT without /dev/shm", "scratch", unix.ENOENT, with(func(f *HostFacts) { f.DevShmDir = false }), Absent},
		{"scratch ENOENT with /dev/shm", "scratch", unix.ENOENT, capableHost, Failed},
		{"scratch ENOMEM", "scratch", unix.ENOMEM, permissiveHost, Failed},
		// Row 9: Landlock.
		{"landlock ENOSYS", "landlock", unix.ENOSYS, capableHost, Absent},
		{"landlock EOPNOTSUPP", "landlock", unix.EOPNOTSUPP, capableHost, Absent},
		{"landlock EPERM", "landlock", unix.EPERM, permissiveHost, Failed},
		{"landlock EINVAL", "landlock", unix.EINVAL, permissiveHost, Failed},
		// Rows 10-11: seccomp.
		{"seccomp ENOSYS", "seccomp", unix.ENOSYS, capableHost, Absent},
		{"seccomp EINVAL without filter support", "seccomp", unix.EINVAL, with(func(f *HostFacts) { f.SeccompFilter = false }), Absent},
		{"seccomp EINVAL with filter support", "seccomp", unix.EINVAL, capableHost, Failed},
		{"seccomp EACCES", "seccomp", unix.EACCES, permissiveHost, Failed},
		{"tsync ENOSYS", "tsync", unix.ENOSYS, permissiveHost, Failed},
		// Row 12: covers.
		{"covers EPERM", "covers", unix.EPERM, permissiveHost, Failed},
		{"covers EACCES", "covers", unix.EACCES, permissiveHost, Failed},
		// Row 13: the listed Failed stages.
		{"nsverify EPERM", "nsverify", unix.EPERM, permissiveHost, Failed},
		{"selfcheck, no errno", "selfcheck", 0, permissiveHost, Failed},
		{"report", "report", 0, permissiveHost, Failed},
		{"exec ENOENT", "exec", unix.ENOENT, permissiveHost, Failed},
		{"spec EINVAL", "spec", unix.EINVAL, permissiveHost, Failed},
		{"cwd EACCES", "cwd", unix.EACCES, permissiveHost, Failed},
		// Row 14: anything else.
		{"mounts EPERM", "mounts", unix.EPERM, permissiveHost, Failed},
		{"shim EPERM", "shim", unix.EPERM, permissiveHost, Failed},
		{"unknown", "unknown", 0, permissiveHost, Failed},
		{"sink EPIPE", "sink", unix.EPIPE, permissiveHost, Failed},
		{"seal EPERM", "seal", unix.EPERM, permissiveHost, Failed},
		{"sealed", "sealed", 0, permissiveHost, Failed},
		{"unlisted stage", "elsewhere", unix.EPERM, permissiveHost, Failed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifySetupFailure(c.stage, c.errno, c.facts); got != c.want {
				t.Fatalf("ClassifySetupFailure(%s, %v) = %v, want %v", c.stage, c.errno, got, c.want)
			}
		})
	}
}

// TestClassifyAbsentRows pins the whole Absent set: on a host where every fact
// explains a failure, exactly these (stage, errno) pairs are Absent, and
// AbsentCandidate agrees with the classifier on every pair.
func TestClassifyAbsentRows(t *testing.T) {
	type pair struct {
		stage string
		errno syscall.Errno
	}
	want := map[pair]bool{
		{"clone", unix.EPERM}: true, {"clone", unix.EINVAL}: true, {"clone", unix.ENOSPC}: true, {"clone", unix.EACCES}: true,
		{"private", unix.EPERM}: true, {"private", unix.EACCES}: true,
		{"setattr", unix.EPERM}: true, {"setattr", unix.EACCES}: true, {"setattr", unix.ENOSYS}: true,
		{"devnodes", unix.EPERM}: true, {"devnodes", unix.EACCES}: true,
		{"scratch", unix.EPERM}: true, {"scratch", unix.EACCES}: true, {"scratch", unix.ENOENT}: true,
		{"landlock", unix.ENOSYS}: true, {"landlock", unix.EOPNOTSUPP}: true,
		{"seccomp", unix.ENOSYS}: true, {"seccomp", unix.EINVAL}: true,
	}
	got := map[pair]bool{}
	for _, stage := range knownStages {
		for errno := syscall.Errno(0); errno < 4096; errno++ {
			absent := ClassifySetupFailure(stage, errno, permissiveHost) == Absent
			if absent {
				got[pair{stage, errno}] = true
			}
			if AbsentCandidate(stage, errno) != absent {
				t.Errorf("AbsentCandidate(%s, %d) = %v, classifier says Absent=%v", stage, errno, !absent, absent)
			}
			if ClassifySetupFailure(stage, errno, capableHost) == Absent && !absent {
				t.Errorf("(%s, %d) is Absent on a capable host but not on a permissive one", stage, errno)
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Absent set changed:\n got %v\nwant %v", got, want)
	}
}

// TestClassifyNeverAbsentStages: no Absent row, fact-dependent or not, names a
// stage the plan calls Failed, a stage at or after X, or a stage that is not a
// host capability. On a clamp host with a gate AppArmor profile the jail works
// and the clamp sysctl still reads 1, so a clamp row on any of these stages
// would let a real wall failure fall back silently.
func TestClassifyNeverAbsentStages(t *testing.T) {
	for _, stage := range []string{"nsverify", "selfcheck", "covers", "report", "exec", "spec", "cwd", "shim", "unknown", "sink", "mounts", "tsync", "seal", "sealed"} {
		for errno := syscall.Errno(0); errno < 4096; errno++ {
			if AbsentCandidate(stage, errno) || ClassifySetupFailure(stage, errno, permissiveHost) != Failed {
				t.Errorf("(%s, %d) can be Absent", stage, errno)
			}
		}
	}
	for _, stage := range knownStages {
		if ClassifySetupFailure(stage, 0, permissiveHost) != Failed {
			t.Errorf("(%s, no errno) is Absent", stage)
		}
	}
}

func TestFailureClassZeroIsFailed(t *testing.T) {
	var class FailureClass
	if class != Failed || Failed.String() != "failed" || Absent.String() != "absent" {
		t.Fatalf("zero FailureClass = %v; Failed=%v Absent=%v", class, Failed, Absent)
	}
}

func TestDenyReasonFormat(t *testing.T) {
	cases := []struct {
		class FailureClass
		stage string
		errno syscall.Errno
		want  string
	}{
		{Absent, "setattr", unix.ENOSYS, "jail:absent:setattr:ENOSYS"},
		{Absent, "clone", unix.EACCES, "jail:absent:clone:EACCES"},
		{Absent, "landlock", unix.EOPNOTSUPP, "jail:absent:landlock:ENOTSUP"}, // the same errno on linux
		{Failed, "selfcheck", 0, "jail:failed:selfcheck"},
		{Failed, "exec", unix.ENOENT, "jail:failed:exec:ENOENT"},
		{Failed, "seccomp", 4095, "jail:failed:seccomp:4095"},
	}
	for _, c := range cases {
		if got := DenyReason(c.class, c.stage, c.errno); got != c.want {
			t.Errorf("DenyReason(%v, %s, %d) = %q, want %q", c.class, c.stage, c.errno, got, c.want)
		}
	}
}

func TestReadHostFactsThisHost(t *testing.T) {
	facts := ReadHostFacts()
	t.Logf("host facts: %+v", facts)
	abi, errno := probeLandlockABI()
	if facts.LandlockABI != abi || facts.LandlockErrno != errno {
		t.Errorf("landlock = %d/%v, probe says %d/%v", facts.LandlockABI, facts.LandlockErrno, abi, errno)
	}
	if facts.MaxUserNS < -1 || facts.MaxUserNS != readMaxUserns() {
		t.Errorf("max_user_namespaces = %d", facts.MaxUserNS)
	}
	if facts.AppArmorUsernsClamp != readAppArmorUsernsClamp() {
		t.Errorf("clamp = %v", facts.AppArmorUsernsClamp)
	}
	shm, err := os.Stat("/dev/shm")
	if facts.DevShmDir != (err == nil && shm.IsDir()) {
		t.Errorf("/dev/shm dir = %v, stat says %v, %v", facts.DevShmDir, shm, err)
	}
	if _, err := os.Stat("/proc/sys/kernel/seccomp/actions_avail"); facts.SeccompFilter != (err == nil) {
		t.Errorf("seccomp filter = %v, actions_avail: %v", facts.SeccompFilter, err)
	}
}
