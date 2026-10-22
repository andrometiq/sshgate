package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

// jailProbeCommand is the only command a capability probe runs: a shell
// builtin, inside the jail.
const jailProbeCommand = ":"

// netGrantsSupported reports whether this gate accepts signed per-read
// network grants.
const netGrantsSupported = true

// maxCorePattern caps the core_pattern the verb reports.
const maxCorePattern = 128

// resetVerbEnv clears the environment before the verb's jail attempt: the
// jail forwards the gate's environment to the probe's shell, and none of it
// is the operator's. The in-process test binary records the call instead.
var resetVerbEnv = func() {
	os.Clearenv()
	_ = os.Setenv("PATH", "/usr/bin:/bin")
}

// capability is what an unsigned read gets on this host right now: the pin,
// the read Spec, one jail attempt of the probe command, and how the read
// router routes that attempt. A damaged pin makes no attempt.
type capability struct {
	pin      pinState
	spec     confine.Spec
	res      gate.ExecResult
	setupErr error
	route    attemptRoute
}

// hostCapability makes the probe's one jail attempt under the read Spec (with
// cwd "/") and routes it like a read. sink and seal are passed to the
// executor; nil means none.
func hostCapability(ctx context.Context, pin pinState, command string, sink *gate.ClientSink, seal func() error) capability {
	c := capability{pin: pin}
	if pin.damaged != "" {
		c.route.reason, _ = pin.denial()
		return c
	}
	requires := requiresConfinement(pin, false)
	c.spec = readSpec(pin, requires, false)
	c.spec.Cwd = "/"
	res, err := executeCommand(ctx, command, gate.ExecOpts{Confine: &c.spec, Seal: seal, ClientSink: sink})
	if res.ExitCode < 0 {
		c.setupErr = setupErrorOf(err)
	}
	c.res = res
	c.route = routeAttempt(pin.valid, requires, res, c.setupErr)
	return c
}

// attemptFacts are a jail attempt's stage, errno and class, for doctor.
type attemptFacts struct {
	Attempted bool   `json:"attempted"`
	Route     string `json:"route"` // kernel, or the router's reason
	Stage     string `json:"stage,omitempty"`
	Errno     string `json:"errno,omitempty"`
	Class     string `json:"class,omitempty"`
}

func newAttemptFacts(attempted bool, route attemptRoute, res gate.ExecResult, setupErr error) attemptFacts {
	facts := attemptFacts{Attempted: attempted, Route: route.reason}
	if route.kernel {
		facts.Route = "kernel"
	}
	var setup *confine.SetupError
	if errors.As(setupErr, &setup) {
		facts.Stage, facts.Class = setup.Stage, attemptClass(setup, res).String()
		if setup.Errno != 0 {
			facts.Errno = unix.ErrnoName(setup.Errno)
		}
	}
	return facts
}

func (c capability) attemptFacts() attemptFacts {
	return newAttemptFacts(c.pin.damaged == "", c.route, c.res, c.setupErr)
}

// jailNet reports whether the jail gave the probe network.
func (c capability) jailNet() bool {
	return c.route.kernel && c.res.Jail != nil && c.res.Jail.Net
}

// enforcement is how an unsigned read runs: in the kernel jail, classifier-only
// after an Absent jail, or not at all.
func (c capability) enforcement() string {
	switch {
	case c.route.kernel:
		return "kernel"
	case c.route.fallback:
		return "classifier"
	}
	return "unavailable"
}

// label is the read label of this capability.
func (c capability) label() string {
	state := confine.LabelState{Pinned: c.pin.valid, Damaged: c.pin.damaged != "", Strict: c.spec.Strict}
	switch {
	case c.route.kernel:
		state.Outcome = confine.RunKernel
		if facts := c.res.Jail; facts != nil {
			state.Profile, state.ABI, state.Unmet = facts.Profile, facts.ABI, facts.Unmet
		}
	case c.route.fallback || strings.HasPrefix(c.route.reason, "jail:absent:"):
		state.Outcome = confine.RunAbsent
	default:
		state.Outcome = confine.RunFailed
	}
	return confine.Label(state, c.jailNet() || c.spec.Net, confine.KernelLabelEnabled)
}

// jailVerbReport is the SSHGATE_JAIL line. Its fields are fixed and always
// present.
//
// Wire meaning: net describes the read, while pinned and accept_fs describe
// the pin. Key on enforcement first: the kernel network test is
// enforcement=="kernel" && pinned && net. A gate older than this verb answers
// it with exit 77 and no JSON.
type jailVerbReport struct {
	V           int      `json:"v"`
	Profile     string   `json:"profile"`
	Enforcement string   `json:"enforcement"`
	Pinned      bool     `json:"pinned"`
	Net         bool     `json:"net"`
	LandlockABI int      `json:"landlock_abi"`
	Label       string   `json:"label"`
	NetGrants   bool     `json:"net_grants"`
	Reason      string   `json:"reason"`
	Unmet       []string `json:"unmet"`
	AcceptFS    []string `json:"accept_fs"`
	CorePattern string   `json:"core_pattern"`
}

func (c capability) verbReport() jailVerbReport {
	r := jailVerbReport{
		V: 1, Profile: confine.ProfileROv1, Enforcement: c.enforcement(), Pinned: c.pin.valid,
		LandlockABI: max(hostFactsFn().LandlockABI, 0), Label: c.label(), NetGrants: netGrantsSupported,
		Reason: c.route.reason, Unmet: []string{}, AcceptFS: append([]string{}, c.spec.AcceptFS...),
		CorePattern: readCorePattern(),
	}
	switch {
	case c.route.kernel:
		r.Net, r.Reason = c.jailNet(), ""
		if facts := c.res.Jail; facts != nil {
			r.LandlockABI, r.Unmet = facts.ABI, append(r.Unmet, facts.Unmet...)
		}
	case c.route.fallback:
		r.Net = true
	}
	return r
}

// readCorePattern is the host's kernel.core_pattern, trimmed and capped.
func readCorePattern() string {
	data, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	if err != nil {
		return ""
	}
	pattern := strings.TrimSpace(string(data))
	if len(pattern) > maxCorePattern {
		pattern = pattern[:maxCorePattern]
	}
	return pattern
}

// jailVerbProbe recognises the SSHGATE_JAIL verb: exactly those bytes, which
// run the constant probe command. Anything else is not the verb.
func jailVerbProbe(raw string) (string, bool) {
	if raw == "SSHGATE_JAIL" {
		return jailProbeCommand, true
	}
	if rest, ok := strings.CutPrefix(raw, "SSHGATE_JAIL "); ok && jailmut.On("P-G-JAILVERB-NOEXEC") {
		return rest, true
	}
	return "", false
}

// runJailVerb answers SSHGATE_JAIL: one sealed jail attempt of command with
// the environment reset, then one JSON line on the client's stdout. It writes
// no audit record and nothing else on stdout; a session cancelled before the
// jail started prints nothing (143).
func runJailVerb(command string) int {
	resetVerbEnv()
	if err := ensureClientSink(); err != nil {
		return exitSoftware
	}
	c := hostCapability(sessionContext, jailPinFn(), command, sessionSink, sealRead)
	if c.route.cancelled {
		return exitCancelled
	}
	line, err := json.Marshal(c.verbReport())
	if err != nil {
		return exitSoftware
	}
	if _, err := sessionSink.Stdout().Write(append(line, '\n')); err != nil {
		return exitSoftware
	}
	return exitOK
}
