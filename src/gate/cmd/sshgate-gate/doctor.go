package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
)

// `gate doctor [--json] [--pin --net=allow|deny [--accept-fs=network[,autofs]]]`
// is the operator's view of the read jail, and the only way to pin a host
// short of a signed write. It reports what an unsigned read gets now (the
// capability SSHGATE_JAIL reports), the host's features, the mounts, and a
// rehearsal: the jailed selftest, run in the read jail of the candidate pin
// against fixtures doctor built, with every effect checked from outside.
// --pin writes the candidate only after a passing rehearsal. The candidate
// decides everything: a damaged or outdated current pin is reported and
// replaced, never consulted.

// Test-only seams (package variables, never the environment).
var (
	// fixturesFn builds the rehearsal's fixtures.
	fixturesFn = func(gateDir string) (rehearser, error) {
		fx, err := buildFixtures(gateDir)
		if err != nil {
			return nil, err
		}
		return fx, nil
	}
	mountOfFn        = confine.MountOf
	describeMountsFn = confine.DescribeMounts
)

// rehearser is the rehearsal on fixtures already built.
type rehearser interface {
	rehearse(ctx context.Context, cand confine.Pin, seal func() error) rehearsalResult
	teardown() error
}

type doctorOptions struct {
	json, pin     bool
	net, acceptFS string
}

// parseDoctorArgs is the closed grammar: each flag at most once; --net and
// --accept-fs only with --pin, which needs --net.
func parseDoctorArgs(args []string) (doctorOptions, bool) {
	var opts doctorOptions
	seen := map[string]bool{}
	for _, arg := range args {
		name, value, hasValue := strings.Cut(arg, "=")
		if seen[name] {
			return opts, false
		}
		seen[name] = true
		switch {
		case arg == "--json":
			opts.json = true
		case arg == "--pin":
			opts.pin = true
		case name == "--net" && (value == "allow" || value == "deny"):
			opts.net = value
		case name == "--accept-fs" && hasValue && acceptFSValue(value):
			opts.acceptFS = value
		default:
			return opts, false
		}
	}
	if opts.pin != (opts.net != "") || opts.acceptFS != "" && !opts.pin {
		return opts, false
	}
	return opts, true
}

// acceptFSValue is a comma-separated list of lowercase words: the pin's
// grammar then decides which words it takes. Nothing else, a newline least
// of all, reaches the candidate's text.
func acceptFSValue(value string) bool {
	for _, word := range strings.Split(value, ",") {
		if word == "" || strings.Trim(word, "abcdefghijklmnopqrstuvwxyz") != "" {
			return false
		}
	}
	return true
}

// doctorCandidate is the pin doctor rehearses: from the flags with --pin
// (keeping a valid current pin's docker_socket), else the valid current pin,
// else profile=ro-v1 net=deny. Its canonical bytes must parse back to it.
func doctorCandidate(opts doctorOptions, current pinState) (confine.Pin, []byte, error) {
	cand := confine.Pin{Profile: confine.ProfileROv1}
	switch {
	case opts.pin:
		text := "profile=" + confine.ProfileROv1 + "\nnet=" + opts.net + "\n"
		if opts.acceptFS != "" {
			text += "accept_fs=" + opts.acceptFS + "\n"
		}
		if current.valid && current.pin.DockerSocket != "" {
			text += "docker_socket=" + current.pin.DockerSocket + "\n"
		}
		var err error
		if cand, err = confine.ParsePin([]byte(text)); err != nil {
			return cand, nil, err
		}
	case current.valid:
		cand = current.pin
	}
	candBytes := cand.Canonical()
	parsed, err := confine.ParsePin(candBytes)
	if err != nil || !reflect.DeepEqual(parsed, cand) {
		return cand, nil, errors.Join(errors.New("the candidate pin does not round-trip"), err)
	}
	return parsed, candBytes, nil
}

// doctorReport is doctor's output. The embedded fields are the capability an
// unsigned read gets now, exactly as SSHGATE_JAIL reports it.
type doctorReport struct {
	jailVerbReport
	Reads        string                `json:"reads"`
	Features     doctorFeatures        `json:"features"`
	Rehearsal    rehearsalResult       `json:"rehearsal"`
	Pin          doctorPin             `json:"pin"`
	Mounts       []confine.MountReport `json:"mounts"`
	GateDirMount *confine.MountReport  `json:"gate_dir_mount"`
	Modules      doctorModules         `json:"modules"`
	MountView    string                `json:"mount_view"`
	Advice       []string              `json:"advice"`
}

type doctorFeatures struct {
	LandlockABI         int           `json:"landlock_abi"`
	LandlockErrno       string        `json:"landlock_errno,omitempty"`
	MaxUserNS           int           `json:"max_user_namespaces"`
	AppArmorUsernsClamp bool          `json:"apparmor_userns_clamp"`
	SeccompFilter       bool          `json:"seccomp_filter"`
	DevShm              bool          `json:"dev_shm"`
	LSM                 []string      `json:"lsm"`
	Now                 attemptFacts  `json:"now"`
	Precheck            *attemptFacts `json:"precheck"`
}

type doctorPin struct {
	State        string   `json:"state"` // absent, valid, damaged, legacy-floor
	Error        string   `json:"error,omitempty"`
	Mode         string   `json:"mode,omitempty"`
	Net          string   `json:"net,omitempty"`
	AcceptFS     []string `json:"accept_fs,omitempty"`
	DockerSocket string   `json:"docker_socket,omitempty"`
	Requested    bool     `json:"requested"`
	Result       string   `json:"result"` // written, unchanged, refused, not-requested
	Refusal      string   `json:"refusal,omitempty"`
	LabelAfter   string   `json:"label_after,omitempty"`
}

// doctorModules is information only.
type doctorModules struct {
	ModulesDisabled string `json:"modules_disabled"`
}

// pinAllowed is the only gate on writing the pin: a passed rehearsal.
func pinAllowed(report doctorReport) bool {
	return report.Rehearsal.Passed || jailmut.On("P-G-PIN-REHEARSAL")
}

// runDoctor is the `gate doctor` ARGV subcommand, an operator tool reached
// only from a plain shell (see runLocalSubcommand). Exit: 0 report (with
// --pin: written or unchanged), 65 usage, 70 internal error or a gate binary
// that is not the running one, 75 another --pin holds the lock, 77 --pin
// refused.
func runDoctor(args []string) int {
	opts, ok := parseDoctorArgs(args)
	if !ok {
		logf("doctor: usage: gate doctor [--json] [--pin --net=allow|deny [--accept-fs=network[,autofs]]]")
		return exitDataErr
	}
	gateDir, _, err := gateDirFn()
	if err != nil {
		logf("doctor: locate gate dir: %v", err)
		return exitSoftware
	}
	current := jailPinFn()
	cand, candBytes, err := doctorCandidate(opts, current)
	if err != nil {
		logf("doctor: %v", err)
		return exitDataErr
	}
	var dir *os.File
	if opts.pin {
		var refusal *pinPrecondition
		if dir, refusal = lockGateDir(gateDir); refusal != nil {
			logf("doctor: --pin refused: %s; nothing was written", refusal.reason)
			return refusal.code
		}
		defer dir.Close()
	}
	report, err := doctor(context.Background(), gateDir, current, cand)
	if err != nil {
		logf("doctor: %v", err)
		return exitSoftware
	}
	code := exitOK
	if opts.pin {
		report.Pin.Requested = true
		if pinAllowed(report) {
			result, err := writePin(dir, candBytes, cand)
			if err != nil {
				logf("doctor: --pin: %v", err)
				return exitSoftware
			}
			report.Pin.Result = result
		} else {
			report.Pin.Result, report.Pin.Refusal = "refused", rehearsalRefusal(report.Rehearsal)
			code = exitNoPermVal
		}
	}
	if err := printReport(report, opts.json); err != nil {
		logf("doctor: %v", err)
		return exitSoftware
	}
	return code
}

func rehearsalRefusal(r rehearsalResult) string {
	switch {
	case r.Skipped != "":
		return "the rehearsal did not run: " + r.Skipped
	case len(r.Failures) > 0:
		return "the rehearsal failed: " + strings.Join(r.Failures, "; ")
	}
	return "the rehearsal failed a row"
}

// doctor builds the report. Its jail attempts, in order: the unsealed "now"
// probe (none for a damaged pin), the unsealed candidate precheck, then the
// sealed rehearsal, the last attempt of the process. The fixtures are built
// before all of them.
func doctor(ctx context.Context, gateDir string, current pinState, cand confine.Pin) (d doctorReport, err error) {
	// Leftovers of an interrupted doctor, before this run makes its own.
	stale := staleDoctorFiles(gateDir)
	d.Pin = currentPinReport(gateDir, current)
	d.Pin.Result = "not-requested"
	d.MountView = mountView()
	d.Modules.ModulesDisabled = readSysctl("/proc/sys/kernel/modules_disabled")
	if d.Mounts, err = describeMountsFn(cand.AcceptFS); err != nil {
		return d, fmt.Errorf("mounts: %w", err)
	}
	advise := func(format string, args ...any) { d.Advice = append(d.Advice, fmt.Sprintf(format, args...)) }

	skipped := ""
	if mount, err := mountOfFn(gateDir, cand.AcceptFS); err != nil {
		skipped = "the gate directory's mount is unknown: " + err.Error()
	} else {
		d.GateDirMount = &mount
		if !mount.Accepted {
			skipped = "the read jail does not show the gate directory"
			if mount.Class == "network" || mount.Backing == "network" {
				advise("the gate directory is on %s (backing %s), a network file system: add --accept-fs=network", mount.FSType, orNone(mount.Backing))
			} else {
				advise("the gate directory is on %s (backing %s, device %s, slaves %v), which the read jail does not show; this host cannot be pinned in this build and runs reads classifier-only",
					mount.FSType, orNone(mount.Backing), orNone(mount.DevicePath), mount.Slaves)
			}
		}
	}
	if exe, err := os.Executable(); err == nil {
		if info, err := os.Stat(exe); err == nil && info.Mode().Perm()&0o400 == 0 {
			advise("the gate binary is not readable by its owner: such a process is not dumpable, so every jailed read is refused; chmod u+r it")
		}
	}
	if _, err := selftestBinaryFn(); err != nil {
		return d, fmt.Errorf("gate binary: %w", err)
	}

	var fixtures rehearser
	if skipped == "" {
		if fixtures, err = fixturesFn(gateDir); err != nil {
			skipped = "could not build the fixtures: " + err.Error()
		} else {
			defer func() {
				if err := fixtures.teardown(); err != nil {
					d.Advice = append(d.Advice, "fixture teardown: "+err.Error())
				}
			}()
		}
	}

	sink, closeSink, err := devNullSink(ctx)
	if err != nil {
		return d, err
	}
	now := hostCapability(ctx, current, jailProbeCommand, sink, nil)
	d.jailVerbReport, d.Reads, d.Features = now.verbReport(), nowReads(now), hostFeatures(now)
	if skipped == "" {
		precheck := candidatePrecheck(ctx, cand, sink)
		d.Features.Precheck = &precheck
		switch {
		case precheck.Route == "kernel":
		case strings.HasPrefix(precheck.Route, "jail:absent:"):
			skipped = "no usable jail: " + precheck.Route
		default:
			skipped = "the candidate's jail fails: " + precheck.Route
			d.Advice = append(d.Advice, unshownNetworkMounts(d.Mounts)...)
		}
	}
	closeSink()

	if skipped == "" {
		d.Rehearsal = fixtures.rehearse(ctx, cand, sealRead)
		if d.Rehearsal.Passed {
			state := confine.LabelState{Pinned: true, Strict: true, Outcome: confine.RunKernel, Profile: confine.ProfileROv1, ABI: d.Rehearsal.ABI}
			d.Pin.LabelAfter = confine.Label(state, d.Rehearsal.Net || cand.Net, confine.KernelLabelEnabled)
		}
	} else {
		d.Rehearsal.Skipped = skipped
	}
	d.Advice = append(d.Advice, nowAdvice(gateDir, current, now, d.Features)...)
	for _, path := range stale {
		advise("%s was left by an interrupted doctor or pin write; it is never read and can be removed", path)
	}
	if d.MountView == "container" {
		advise("this gate runs in a container or toolbox: sshd may run the gate in another mount namespace, where the mounts differ")
	}
	return d, nil
}

// candidatePrecheck is one unsealed `:` in the candidate's jail.
func candidatePrecheck(ctx context.Context, cand confine.Pin, sink *gate.ClientSink) attemptFacts {
	spec := readSpecBase(pinState{valid: true, pin: cand}, cand.Net, false)
	if rehearsalSpecHook != nil {
		rehearsalSpecHook(&spec)
	}
	spec.Cwd = "/"
	res, err := executeCommand(ctx, jailProbeCommand, gate.ExecOpts{Confine: &spec, ClientSink: sink})
	var setupErr error
	if res.ExitCode < 0 {
		setupErr = setupErrorOf(err)
	}
	return newAttemptFacts(true, routeAttempt(true, cand.Net, res, setupErr), res, setupErr)
}

// nowReads is what an unsigned read does now, in words.
func nowReads(c capability) string {
	switch {
	case c.pin.damaged != "":
		return "denied (" + c.route.reason + ")"
	case c.route.kernel && c.spec.Net:
		return "kernel-jailed, network open"
	case c.route.kernel:
		return "kernel-jailed, no network"
	case c.route.fallback:
		return "classifier-only (no usable jail)"
	}
	return "denied (" + c.route.reason + ")"
}

func hostFeatures(now capability) doctorFeatures {
	facts := hostFactsFn()
	features := doctorFeatures{LandlockABI: facts.LandlockABI, MaxUserNS: facts.MaxUserNS, AppArmorUsernsClamp: facts.AppArmorUsernsClamp,
		SeccompFilter: facts.SeccompFilter, DevShm: facts.DevShmDir, LSM: facts.LSMs, Now: now.attemptFacts()}
	if facts.LandlockErrno != 0 {
		features.LandlockErrno = facts.LandlockErrno.Error()
	}
	return features
}

// currentPinReport describes the pin in place now.
func currentPinReport(gateDir string, current pinState) doctorPin {
	p := doctorPin{State: "absent"}
	switch {
	case current.legacyFloor:
		p.State, p.Error = "legacy-floor", current.damaged
	case current.damaged != "":
		p.State, p.Error = "damaged", current.damaged
	case current.valid:
		p.State, p.Net, p.AcceptFS, p.DockerSocket = "valid", "deny", current.pin.AcceptFS, current.pin.DockerSocket
		if current.pin.Net {
			p.Net = "allow"
		}
	}
	if info, err := os.Lstat(filepath.Join(gateDir, confine.PinFile)); err == nil {
		p.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	}
	return p
}

// nowAdvice is the advice about the host as it is now.
func nowAdvice(gateDir string, current pinState, now capability, features doctorFeatures) []string {
	var advice []string
	_, floorErr := os.Lstat(filepath.Join(gateDir, jailFloorFile))
	switch {
	case current.legacyFloor:
		advice = append(advice, "a jail-floor file from an earlier release is present and there is no jail pin, so reads are denied. Pin with 'gate doctor --pin --net=deny', or remove jail-floor to run reads classifier-only where the host has no usable jail.")
	case !errors.Is(floorErr, os.ErrNotExist):
		advice = append(advice, "jail-floor is no longer used and is ignored: the jail pin decides.")
	}
	if now.route.reason == "jail:absent:clone:EACCES" && features.AppArmorUsernsClamp {
		advice = append(advice, "the AppArmor userns restriction refuses the jail: each read makes one attempt, which logs one AppArmor userns_create denial; install an AppArmor profile for the gate, or accept classifier-only reads (and the log line), or pin the host to refuse reads")
	}
	if now.route.kernel && !current.valid && now.res.Jail != nil && len(now.res.Jail.Unmet) > 0 {
		advice = append(advice, fmt.Sprintf("reads here are classifier-only: the read jail cannot show %s; --accept-fs=network shows network file systems, other types cannot be shown in this build", strings.Join(now.res.Jail.Unmet, ", ")))
	}
	return advice
}

// unshownNetworkMounts is advice for a candidate whose jail failed: each
// network mount the jail does not show, which --accept-fs=network would.
func unshownNetworkMounts(mounts []confine.MountReport) []string {
	var advice []string
	for _, mount := range mounts {
		if !mount.Accepted && (mount.Class == "network" || mount.Backing == "network") {
			advice = append(advice, fmt.Sprintf("the jail does not show %s (%s), a network file system, and a pinned read refuses an unshown mount; add --accept-fs=network to show it", mount.Point, mount.FSType))
		}
	}
	return advice
}

// staleDoctorFiles are leftovers of an interrupted doctor: temporary pins,
// fixture directories in the gate directory, and /tmp fixture files.
func staleDoctorFiles(gateDir string) []string {
	var stale []string
	for _, pattern := range []string{filepath.Join(gateDir, pinTempPrefix+"*"), filepath.Join(gateDir, ".doctor-*"), filepath.Join(fixtureTmp, "sshgate-doctor-*")} {
		matches, _ := filepath.Glob(pattern)
		stale = append(stale, matches...)
	}
	return stale
}

// mountView is "container" when a container or toolbox marker is present,
// else "unknown": doctor cannot see the namespace sshd runs the gate in.
func mountView() string {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv", "/run/.toolboxenv"} {
		if _, err := os.Lstat(marker); err == nil {
			return "container"
		}
	}
	return "unknown"
}

func readSysctl(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func printReport(d doctorReport, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(d)
	}
	yesNo := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	pin := d.Pin.State
	switch {
	case d.Pin.Error != "":
		pin += ": " + d.Pin.Error
	case d.Pin.State == "valid":
		pin += ": net=" + d.Pin.Net
		if len(d.Pin.AcceptFS) > 0 {
			pin += " accept_fs=" + strings.Join(d.Pin.AcceptFS, ",")
		}
	}
	rehearsal := "passed"
	switch {
	case d.Rehearsal.Skipped != "":
		rehearsal = "skipped: " + d.Rehearsal.Skipped
	case !d.Rehearsal.Passed:
		rehearsal = "failed: " + strings.Join(d.Rehearsal.Failures, "; ")
	}
	fmt.Printf("pin:                   %s\n", pin)
	fmt.Printf("attempt:               %s\n", d.Features.Now.Route)
	fmt.Printf("reads:                 %s\n", d.Reads)
	fmt.Printf("label:                 %s\n", d.Label)
	fmt.Printf("rehearsal:             %s\n", rehearsal)
	if d.Pin.Requested {
		fmt.Printf("pin result:            %s\n", d.Pin.Result)
		if d.Pin.Refusal != "" {
			fmt.Printf("pin refusal:           %s\n", d.Pin.Refusal)
		}
	}
	if d.Pin.LabelAfter != "" {
		fmt.Printf("label when pinned:     %s\n", d.Pin.LabelAfter)
	}
	fmt.Printf("landlock_abi:          %d\n", d.Features.LandlockABI)
	fmt.Printf("max_user_namespaces:   %d\n", d.Features.MaxUserNS)
	fmt.Printf("apparmor_userns_clamp: %s\n", yesNo(d.Features.AppArmorUsernsClamp))
	fmt.Printf("seccomp_filter:        %s\n", yesNo(d.Features.SeccompFilter))
	fmt.Printf("dev_shm:               %s\n", yesNo(d.Features.DevShm))
	fmt.Printf("lsm:                   %s\n", orNone(strings.Join(d.Features.LSM, ",")))
	fmt.Printf("core_pattern:          %s\n", d.CorePattern)
	for _, advice := range d.Advice {
		fmt.Printf("advice: %s\n", advice)
	}
	return nil
}
