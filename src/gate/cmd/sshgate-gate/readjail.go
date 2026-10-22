package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// Test-only seams, the same class as executeCommand and gateDirFn: package
// variables, never the environment.
var (
	// readSpecHook adjusts the read Spec (ForceABI, InjectFailAt).
	readSpecHook func(*confine.Spec)
	hostFactsFn  = confine.ReadHostFacts
	pinUIDFn     = os.Getuid
	jailPinFn    = readJailPin
	// sealFn makes the gate non-dumpable. The in-process test binary records
	// the call instead: sealed, it would refuse its own next jail attempt.
	sealFn = confine.SealProcess
)

// sealRead is the Seal of every jailed read. While the read runs, the gate's
// client pipes, environment and redaction key are then out of reach of
// same-uid processes outside the jail that lack CAP_SYS_PTRACE.
func sealRead() error {
	if jailmut.On("P-G-SEAL") {
		return nil
	}
	return sealFn()
}

// jailFloorFile is the pin of earlier releases. A host that has one and no
// jail pin asked never to run reads outside the jail, which the jail pin can
// no longer promise without being re-pinned, so its reads are denied.
const jailFloorFile = "jail-floor"

// pinState is the jail pin as the read path sees it: absent, valid, or
// damaged (a non-empty reason). legacyFloor marks a damaged state that is a
// leftover jail-floor with no jail pin.
type pinState struct {
	valid       bool
	damaged     string
	legacyFloor bool
	pin         confine.Pin
}

// denial is the deny_reason and deny line of a damaged pin.
func (p pinState) denial() (reason, line string) {
	if p.legacyFloor {
		return "pin:legacy-floor", "a jail-floor file from an earlier release is present and there is no jail pin; reads are denied until the host is re-pinned with 'gate doctor --pin' or the jail-floor file is removed"
	}
	return "pin:damaged", "the jail pin is damaged (" + p.damaged + "); reads are denied until it is fixed"
}

// readJailPin reads the jail pin from the gate directory. A pin that is not
// a regular file owned by the gate's uid, is group- or world-writable, has
// another link, is larger than confine.MaxPinBytes, or does not parse is
// damaged. With no jail pin, a leftover jail-floor (any content) also denies.
// Only the read path and doctor call it.
func readJailPin() pinState {
	damaged := func(format string, args ...any) pinState {
		return pinState{damaged: fmt.Sprintf(format, args...)}
	}
	gateDir, _, err := gateDirFn()
	if err != nil {
		return damaged("cannot locate the gate directory: %v", err)
	}
	pinPath := filepath.Join(gateDir, confine.PinFile)
	before, err := os.Lstat(pinPath)
	if errors.Is(err, os.ErrNotExist) {
		if _, err := os.Lstat(filepath.Join(gateDir, jailFloorFile)); !errors.Is(err, os.ErrNotExist) {
			return pinState{damaged: "jail-floor present", legacyFloor: true}
		}
		return pinState{}
	}
	if err != nil {
		return damaged("%v", err)
	}
	if !before.Mode().IsRegular() {
		return damaged("not a regular file")
	}
	file, err := os.OpenFile(pinPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return damaged("%v", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return damaged("%v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	lstat, lok := before.Sys().(*syscall.Stat_t)
	switch {
	case !ok || !lok || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Dev != lstat.Dev || stat.Ino != lstat.Ino:
		return damaged("changed while reading")
	case stat.Uid != uint32(pinUIDFn()):
		return damaged("owned by uid %d, want %d", stat.Uid, pinUIDFn())
	case stat.Mode&0o022 != 0:
		return damaged("group- or world-writable")
	case stat.Nlink != 1:
		return damaged("has %d links", stat.Nlink)
	}
	data, err := io.ReadAll(io.LimitReader(file, confine.MaxPinBytes+1))
	if err != nil {
		return damaged("%v", err)
	}
	pin, err := confine.ParsePin(data)
	if err != nil {
		return damaged("%v", err)
	}
	return pinState{valid: true, pin: pin}
}

// requiresConfinement is computed once per read: a valid pin with net=allow,
// or a network grant. Such a read never runs outside the jail.
func requiresConfinement(pin pinState, grant bool) bool {
	return pin.valid && pin.pin.Net || grant
}

// routeAfterSetupFailure reports whether a jail that never reached the command
// may fall back to a classifier-only run: only an Absent jail on an unpinned
// host, for a read that does not require confinement.
func routeAfterSetupFailure(pinned, requires bool, class confine.FailureClass) bool {
	if class != confine.Absent || pinned {
		return false
	}
	return !requires || jailmut.On("P-G-CONFINE-REQUIRED")
}

// lane2Spec is a daemon read's jail: the read jail the pin gives (strict, the
// accepted filesystems), never network, from /, running the admitted client.
func lane2Spec(pin pinState, requires bool, plan *lane2Execution) confine.Spec {
	spec := readSpec(pin, requires, false)
	if !jailmut.On("P-L2-NET-OFF") {
		spec.Net = false
	}
	spec.Cwd, spec.Lane2 = "/", plan.jailLane2()
	return spec
}

// readSpec builds the jail for a read: readSpecBase, then the test-only
// readSpecHook.
func readSpec(pin pinState, requires, grant bool) confine.Spec {
	spec := readSpecBase(pin, requires, grant)
	if readSpecHook != nil {
		readSpecHook(&spec)
	}
	return spec
}

// readSpecBase is the read jail before any test hook. Strict comes from a
// valid pin or from requiring confinement; AcceptFS and Net come only from the
// pin (Net also from a grant).
func readSpecBase(pin pinState, requires, grant bool) confine.Spec {
	spec := confine.Spec{Profile: confine.ProfileROv1}
	if pin.valid && !jailmut.On("P-G-STRICT") {
		spec.Strict = true
	}
	if requires && !jailmut.On("P-G-NET-STRICT") {
		spec.Strict = true
	}
	if pin.valid {
		spec.Net = pin.pin.Net
		spec.AcceptFS = append([]string(nil), pin.pin.AcceptFS...)
	}
	if grant {
		spec.Net = true
	}
	return spec
}

type readFlags struct {
	netGrant, envelope, expectNet bool
}

var readAdmittedHook func(pinState)

// execRead runs a command the classifier called a read, on the Tier-1 and
// signed read paths alike. Signed writes and admin verbs never reach it.
//
// A damaged pin denies, and so does a daemon read whose admission fails.
// Every other read attempts the jail; the attempt is the probe. A daemon read
// runs its admitted client in its own narrower jail. A setup failure that
// never reached the command is classified, and only an Absent jail on an
// unpinned host, for a read that does not require confinement, falls back to
// an unconfined run: classifier-only, or the shell-free client for a daemon
// read. Nothing that may have reached the command is ever run again.
func execRead(audit *gate.AuditLogger, cmd, approval string, reveal bool, flags readFlags) int {
	if _, matched := lane2Parse(cmd); matched && (flags.netGrant || flags.expectNet) && !jailmut.On("P-G-NET-DAEMON-READ") {
		logf("%s", sigwire.GateDenyNetDaemonRead)
		auditReadDenied(audit, cmd, "net:daemon-read", exitNoPermVal, flags)
		return exitNoPermVal
	}
	pin := jailPinFn()
	if readAdmittedHook != nil {
		readAdmittedHook(pin)
	}
	if pin.damaged != "" {
		reason, line := pin.denial()
		logf("read jail unavailable: %s", line)
		auditReadDenied(audit, cmd, reason, exitNoPermVal, flags)
		return exitNoPermVal
	}
	if flags.expectNet && !(pin.valid && pin.pin.Net) && !jailmut.On("P-G-ENVELOPE-EXPECT-NET") {
		logf("%s", sigwire.GateDenyNetNotPermitted)
		auditReadDenied(audit, cmd, "net:not-permitted", exitNoPermVal, flags)
		return exitNoPermVal
	}
	grant := flags.netGrant
	requires := requiresConfinement(pin, grant || flags.envelope)
	plan, matched, refusal := lane2Plan(cmd, pin)
	defer plan.Close()
	if !matched {
		spec := readSpec(pin, requires, grant)
		read := &gate.ReadAudit{Enforcement: "kernel", Profile: spec.Profile, Pinned: pin.valid, AcceptFS: spec.AcceptFS, RequiresConfinement: requires}
		return routeRead(audit, cmd, approval, reveal, pin, requires, execPlan{netGrant: flags.netGrant, envelope: flags.envelope, confine: &spec, read: read},
			execPlan{netGrant: flags.netGrant, envelope: flags.envelope, read: &gate.ReadAudit{Enforcement: "classifier", Net: true}})
	}
	if refusal != "" {
		logf("daemon read refused: %s; nothing ran", refusal)
		auditReadDenied(audit, cmd, "lane2:admit:"+refusal, exitNoPermVal, flags)
		return exitNoPermVal
	}
	if lane2AfterAdmitHook != nil {
		lane2AfterAdmitHook(&plan)
	}
	spec := lane2Spec(pin, requires, &plan)
	read := &gate.ReadAudit{Enforcement: "daemon-read", Profile: spec.Profile, Pinned: pin.valid, AcceptFS: spec.AcceptFS, RequiresConfinement: requires}
	return routeRead(audit, cmd, approval, reveal, pin, requires, execPlan{netGrant: flags.netGrant, envelope: flags.envelope, confine: &spec, lane2: plan.argv, execPath: plan.binary.path, read: read},
		execPlan{netGrant: flags.netGrant, envelope: flags.envelope, argv: plan.argv, execPath: plan.binary.path, read: &gate.ReadAudit{Enforcement: "daemon-read", Net: true}})
}

// lane2AfterAdmitHook runs, in tests only, between a daemon read's admission
// and its jail, to replace an admitted object at a fixed point. Production
// leaves it nil; TestLane2TrustDefaults guards that.
var lane2AfterAdmitHook func(*lane2Execution)

// routeRead attempts the jail with jailed and applies the outcome table: the
// read ran there, the session ended, it is denied, or it falls back once to
// the unconfined fallback plan, which never reached the command before.
func routeRead(audit *gate.AuditLogger, cmd, approval string, reveal bool, pin pinState, requires bool, jailed, fallback execPlan) int {
	flags := readFlags{netGrant: jailed.netGrant, envelope: jailed.envelope}
	rc, res, setupErr := execAndAudit(audit, cmd, "read", approval, reveal, jailed)
	route := routeAttempt(pin.valid, requires, res, setupErr)
	switch {
	case route.kernel:
		return rc
	case route.cancelled:
		auditReadDenied(audit, cmd, route.reason, exitCancelled, flags, res.Transport)
		return exitCancelled
	case !route.fallback:
		logf("read jail unavailable: %s", route.line)
		auditReadDenied(audit, cmd, route.reason, exitNoPermVal, flags, res.Transport)
		return exitNoPermVal
	}
	if sessionContext != nil && sessionContext.Err() != nil {
		auditReadDenied(audit, cmd, "cancelled", exitCancelled, flags, res.Transport)
		return exitCancelled
	}
	// The command never started, so running it once, unconfined, is its
	// first run. Nothing removes network here.
	fallback.read.JailAbsent = route.jailAbsent
	rc, _, _ = execAndAudit(audit, cmd, "read", approval, reveal, fallback)
	return rc
}

// attemptRoute is what the read router does after a jail attempt: the read
// reached the command in the jail, the session ended before the jail
// started, a classifier-only fallback, or a deny with its reason and line.
type attemptRoute struct {
	kernel, cancelled, fallback bool
	reason, line, jailAbsent    string
}

// routeAttempt applies the outcome table to a jail attempt. setupErr is
// execChild's: nil when the jail reached the command.
func routeAttempt(pinned, requires bool, res gate.ExecResult, setupErr error) attemptRoute {
	if setupErr == nil {
		return attemptRoute{kernel: true}
	}
	var setup *confine.SetupError
	if !errors.As(setupErr, &setup) {
		return attemptRoute{cancelled: true, reason: "cancelled"}
	}
	class := attemptClass(setup, res)
	if routeAfterSetupFailure(pinned, requires, class) {
		absent := strings.TrimPrefix(confine.DenyReason(confine.Absent, setup.Stage, setup.Errno), "jail:absent:")
		return attemptRoute{fallback: true, reason: confine.DenyReason(class, setup.Stage, setup.Errno), jailAbsent: absent}
	}
	reason, line := confine.DenyReason(class, setup.Stage, setup.Errno), unavailableReason(class, setup, pinned)+"; nothing ran"
	// After an I report the command may have started, unless the worker
	// reported its execve failing (XFexec:<errno>).
	if setup.SawInfo && !(setup.Stage == "exec" && setup.Errno != 0) {
		reason += ":after-start"
		line = "the jail failed after the read may have started (" + setupDetail(setup) + "); its result is not trusted"
	}
	return attemptRoute{reason: reason, line: line}
}

// attemptClass classifies a failed jail attempt. An Absent stage never
// reports I and writes nothing, so an attempt that did either is Failed. The
// bytes are also counted before redaction and delivery, so a lost client
// cannot hide them. Only an I report means the command may have started: a
// pre-X failure's bytes are the worker's own diagnostic.
func attemptClass(setup *confine.SetupError, res gate.ExecResult) confine.FailureClass {
	class := confine.ClassifySetupFailure(setup.Stage, setup.Errno, hostFactsFn())
	wrote := res.StdoutBytes != 0 || res.StderrBytes != 0 || res.Transport.SourceBytesRead != 0
	if class == confine.Absent && (setup.SawInfo || wrote) {
		return confine.Failed
	}
	return class
}

func setupDetail(setup *confine.SetupError) string {
	if setup.Errno != 0 {
		return setup.Stage + ": " + setup.Errno.Error()
	}
	return setup.Stage
}

// unavailableReason is the human half of a read-jail deny line.
func unavailableReason(class confine.FailureClass, setup *confine.SetupError, pinned bool) string {
	detail := setupDetail(setup)
	switch {
	case class != confine.Absent:
		return "the jail could not be set up (" + detail + ")"
	case pinned:
		return "this host has no usable jail (" + detail + ") and reads are pinned"
	default:
		return "this host has no usable jail (" + detail + ") and this read must run confined"
	}
}

// setupErrorOf turns an executor error from a confined run that never reached
// the command into the error the read router classifies: the jail's
// SetupError, a context error when the session ended before the jail started,
// or an "unknown" SetupError.
func setupErrorOf(err error) error {
	var setup *confine.SetupError
	switch {
	case errors.As(err, &setup):
		return setup
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	}
	var errno syscall.Errno
	errors.As(err, &errno)
	return &confine.SetupError{Stage: "unknown", Errno: errno}
}

// networkTools are command names that usually need the network.
var networkTools = map[string]bool{
	"curl": true, "wget": true, "dig": true, "nslookup": true, "host": true, "ping": true,
	"ping6": true, "traceroute": true, "tracepath": true, "ssh": true, "scp": true, "sftp": true,
	"rsync": true, "git": true, "nc": true, "ncat": true, "netcat": true, "telnet": true,
	"openssl": true, "kubectl": true,
}

var commandWrappers = map[string]bool{"env": true, "timeout": true, "nice": true, "nohup": true, "stdbuf": true}

// needsNetwork reports whether any command word of cmd is a network tool. It
// only picks a hint; it never decides anything.
func needsNetwork(cmd string) bool {
	segments := strings.FieldsFunc(cmd, func(r rune) bool { return strings.ContainsRune("|;&()\n", r) })
	for _, segment := range segments {
		wrapped := false
		for _, word := range strings.Fields(segment) {
			switch {
			case strings.Contains(word, "=") && !strings.HasPrefix(word, "-"):
				continue
			case commandWrappers[word]:
				wrapped = true
				continue
			case wrapped && (strings.HasPrefix(word, "-") || word[0] >= '0' && word[0] <= '9'):
				continue
			}
			if networkTools[path.Base(word)] {
				return true
			}
			break
		}
	}
	return false
}

// networkHintLine states the network default for unsigned reads.
const networkHintLine = "note: reads on this host have no network; this command may need it (allow network per host by pinning it net=allow)"

// networkHint prints one advisory line when a kernel read without network
// failed and its command looks like it needs the network. It must run before
// the client sink is finished.
func networkHint(cmd string, rc int, facts *confine.Facts) {
	if facts == nil || facts.Net || rc == 0 || !needsNetwork(cmd) {
		return
	}
	logf("%s", networkHintLine)
}
