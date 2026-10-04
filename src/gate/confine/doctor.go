//go:build linux

package confine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// SentinelProbe is the argv marker for the throwaway userns-availability probe
// (see RunProbe). Like the other sentinels it is only ever an internal re-exec.
const SentinelProbe = "__jailprobe"

// Probe child exit codes.
const (
	probeExitOK          = 0
	probeExitNotInClone  = 2 // not in the requested fresh namespaces: refused, nothing done
	probeExitMountDenied = 3 // the jail's first mount step was refused (EPERM/EACCES)
	probeExitMountError  = 4 // any other mount failure
)

// RunProbe is the __jailprobe entrypoint, run inside the rung-1 clone. It makes
// / private — the jail's first mount step — so the probe proves the mount phase
// works, not just that the namespaces can be created (Ubuntu's AppArmor userns
// clamp lets the clone succeed but denies the mount). It refuses to mount unless
// its namespaces match the parent-provided namespace contract.
func RunProbe(args []string) int {
	var parent NSIDs
	if len(args) != 1 || json.Unmarshal([]byte(args[0]), &parent) != nil || verifyNamespaces(parent) != nil {
		return probeExitNotInClone
	}
	err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "")
	switch {
	case err == nil:
		return probeExitOK
	case err == unix.EPERM || err == unix.EACCES:
		return probeExitMountDenied
	default:
		return probeExitMountError
	}
}

// probeFacts are the raw host observations the rung decision is made from, kept
// apart from detect so decide can be tested with injected results.
type probeFacts struct {
	landlockABI int
	landlockErr unix.Errno
	seccomp     bool
	lsms        []string
	maxUserns   int  // /proc/sys/user/max_user_namespaces; -1 when unreadable
	clamp       bool // apparmor_restrict_unprivileged_userns == 1
	// The userns clone probe, skipped when maxUserns == 0.
	cloneErr  error // the clone itself failed
	probeExit int   // probe child exit code; -1 if it did not exit normally
}

// detect probes the host read-only and resolves the strongest usable rung.
func detect() Report {
	abi, errno := probeLandlockABI()
	fx := probeFacts{
		landlockABI: abi,
		landlockErr: errno,
		seccomp:     unix.Prctl(unix.PR_GET_SECCOMP, 0, 0, 0, 0) == nil,
		lsms:        readLSMs(),
		maxUserns:   readMaxUserns(),
		clamp:       readAppArmorUsernsClamp(),
	}
	if fx.maxUserns != 0 {
		fx.cloneErr, fx.probeExit = runUsernsProbe()
	}
	return decide(fx)
}

// decide turns probe facts into a Report. Rung 1 needs a probe that created the
// namespaces AND mounted inside them. Definitive absence (userns disabled or
// limited to zero, or the AppArmor clamp refusing the mount) moves on to the
// next rung; anything unexplained sets ProbeErr so the caller denies rather than
// silently downgrading.
func decide(fx probeFacts) Report {
	rep := Report{
		LandlockABI:         fx.landlockABI,
		Seccomp:             fx.seccomp,
		LSMs:                fx.lsms,
		AppArmorUsernsClamp: fx.clamp,
	}
	if fx.clamp {
		rep.Notes = append(rep.Notes,
			"apparmor_restrict_unprivileged_userns=1: rung 1 needs an AppArmor userns profile for the gate path")
	}
	switch {
	case fx.maxUserns == 0:
		rep.Notes = append(rep.Notes, "user.max_user_namespaces=0: user namespaces disabled")
	case fx.cloneErr != nil && isDefinitiveAbsence(fx.cloneErr):
		rep.Notes = append(rep.Notes, fmt.Sprintf("userns clone refused: %v", fx.cloneErr))
	case fx.cloneErr != nil:
		rep.ProbeErr = fmt.Errorf("userns probe: %w", fx.cloneErr)
	case fx.probeExit == probeExitOK:
		rep.Userns = true
	case fx.probeExit == probeExitMountDenied && fx.clamp:
		rep.Notes = append(rep.Notes, "userns created but the AppArmor clamp denies its mounts")
	default:
		rep.ProbeErr = fmt.Errorf("userns probe child exited %d", fx.probeExit)
	}

	if fx.landlockErr != 0 && fx.landlockErr != unix.ENOSYS && fx.landlockErr != unix.EOPNOTSUPP {
		rep.ProbeErr = errors.Join(rep.ProbeErr, fmt.Errorf("landlock probe: %w", fx.landlockErr))
	}
	switch {
	case rep.Userns && rep.LandlockABI >= 1:
		rep.Rung = Rung1Full
	default:
		rep.Rung = Rung3Unconfined
	}
	return rep
}

// runUsernsProbe re-execs the probe with the real rung-1 clone policy.
func runUsernsProbe() (cloneErr error, exit int) {
	parent, err := namespaceIDs()
	if err != nil {
		return err, -1
	}
	raw, err := json.Marshal(parent)
	if err != nil {
		return err, -1
	}
	c := exec.Command("/proc/self/exe", SentinelProbe, string(raw))
	c.SysProcAttr = cloneSysProcAttr()
	if err := c.Start(); err != nil {
		return err, -1
	}
	err = c.Wait()
	if err == nil {
		return nil, probeExitOK
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.Exited() {
		return nil, ee.ExitCode()
	}
	return nil, -1
}

// isDefinitiveAbsence reports whether a clone failure means unprivileged user
// namespaces are unavailable: disabled (EPERM) or unsupported (EINVAL), as
// opposed to a transient/unexpected error. ENOSPC is NOT absence: a zero limit
// is caught by maxUserns before any clone, so ENOSPC here means the per-user
// namespace count is used up right now — a passing condition that must deny,
// never downgrade the jail.
func isDefinitiveAbsence(err error) bool {
	e := errnoOf(err)
	return e == unix.EPERM || e == unix.EINVAL
}

func readMaxUserns() int {
	b, err := os.ReadFile("/proc/sys/user/max_user_namespaces")
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return -1
	}
	return n
}

func readLSMs() []string {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), ",")
}

// readAppArmorUsernsClamp reports whether Ubuntu's AppArmor unprivileged-userns
// restriction is on (sysctl absent means no clamp).
func readAppArmorUsernsClamp() bool {
	b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}
