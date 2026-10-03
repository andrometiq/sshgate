package confine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// Rung is the interim probe result: full confinement or classifier-only.
type Rung int

const (
	Rung3Unconfined Rung = iota // no kernel wall (labelled UNCONFINED)
	Rung1Full                   // userns+mount+pid ns, ro /, Landlock, seccomp
)

func (r Rung) String() string {
	switch r {
	case Rung1Full:
		return "full"
	case Rung3Unconfined:
		return "unconfined"
	default:
		return "invalid"
	}
}

// Sentinel argv markers for the gate's internal re-exec. The gate's main
// dispatches these BEFORE any SSH_ORIGINAL_COMMAND handling; they only ever add
// restrictions, and the forced command passes no argv, so the agent can never
// reach them.
const (
	SentinelShim   = "__jail"     // RunShim: pid-1 reaper of the new pid namespace (rung 1)
	SentinelWorker = "__jailexec" // RunWorker: applies restrictions, then execs /bin/sh
)

// ExitSetupFailed is the worker's exit code when it aborts during jail setup,
// before execve. It is distinct from any /bin/sh exit so the parent can tell a
// setup failure (nothing ran) from a real command exit code; the authoritative
// signal is still the fd-4 status report (see Jailed.Status).
const ExitSetupFailed = 70

// NSIDs identifies the namespaces inherited from the parent gate.
type NSIDs struct{ User, Mnt, Pid, IPC uint64 }

const ProfileROv1 = "ro-v1"

// Spec is the fully-resolved confinement policy for ONE command. Built by the
// gate from Detect (production) or by a test directly. It is the
// ONLY thing that selects behaviour — there is no env var or argv an agent can
// set to change it: the worker reads the Spec from the sentinel argv the parent
// gate wrote, a path the agent never reaches (the forced command passes no argv;
// the agent-controlled command travels on fd 3).
type Spec struct {
	Profile  string
	Net      bool
	Strict   bool
	AcceptFS []string
	Cwd      string
	ParentNS NSIDs
	// ForceABI caps the real ABI in tests; -1 forces a landlock-stage abort.
	ForceABI int
	// InjectFailAt forces a setup error in tests.
	InjectFailAt string
}

const ForceNoLandlock = -1

// Report is the host-probe result for `gate doctor` and the audit line.
type Report struct {
	Rung                Rung
	LandlockABI         int
	Userns              bool
	Seccomp             bool
	LSMs                []string
	AppArmorUsernsClamp bool
	// ProbeErr is set when a probe failed for a reason OTHER than definitive
	// feature absence (e.g. a transient resource error). A non-nil ProbeErr
	// means the caller must DENY, never silently downgrade to a weaker rung.
	ProbeErr error
	Notes    []string
}

// SetupError means NOTHING was executed: the worker aborted before execve
// (or died before reporting). Stage names the setup step; Errno is the raw
// errno the worker reported, 0 when unknown.
type SetupError struct {
	Stage string
	Errno syscall.Errno
}

func (e *SetupError) Error() string {
	if e.Errno != 0 {
		return fmt.Sprintf("jail setup failed at stage %q: %v", e.Stage, e.Errno)
	}
	return fmt.Sprintf("jail setup failed at stage %q", e.Stage)
}

// Facts records mount-recipe observations; full profile reporting lands with S2.
type Facts struct {
	Unmet           []string `json:"unmet,omitempty"`
	CoverAtAncestor []string `json:"cover_at_ancestor,omitempty"`
	CwdReset        bool     `json:"cwd_reset,omitempty"`
}

// Jailed wraps the command and its private setup-report pipes.
type Jailed struct {
	Facts  Facts
	strict bool
	Cmd    *exec.Cmd

	// cmd is the command string the parent streams to the worker on fd 3.
	cmd string
	// cmdW is the parent's write end of the fd-3 (command) pipe.
	// statusR is the parent's read end of the fd-4 (status) pipe.
	cmdW    *os.File
	statusR *os.File
	// childEnds are the pipe ends handed to the child via ExtraFiles; the
	// parent closes its copies in Started (after a successful Start) or Abort
	// (after a failed Start).
	childEnds []*os.File
}

// Started must be called once, right after Cmd.Start succeeds. It closes the
// parent's copies of the child-side pipe ends and streams the command to the
// fd-3 pipe from a goroutine, then closes it (so a command larger than the pipe
// buffer cannot deadlock).
func (j *Jailed) Started() error {
	for _, f := range j.childEnds {
		_ = f.Close()
	}
	j.childEnds = nil
	go func() {
		_, _ = io.WriteString(j.cmdW, j.cmd)
		_ = j.cmdW.Close()
	}()
	return nil
}

// Abort releases every pipe end when Cmd.Start fails.
func (j *Jailed) Abort() {
	for _, f := range j.childEnds {
		_ = f.Close()
	}
	j.childEnds = nil
	if j.cmdW != nil {
		_ = j.cmdW.Close()
	}
	if j.statusR != nil {
		_ = j.statusR.Close()
	}
}

// Status must be called after Cmd.Wait. It returns nil ONLY if the worker
// reported (on the fd-4 status pipe) that it completed every setup stage and
// reached execve — a single 'X' byte. Anything else — an explicit
// "F<stage>:<errno>" report, or EOF with no report (the worker died before
// reporting) — is a *SetupError, meaning nothing ran.
func (j *Jailed) Status() error {
	defer func() {
		if j.statusR != nil {
			_ = j.statusR.Close()
		}
	}()
	if j.statusR == nil {
		return &SetupError{Stage: "unknown"}
	}
	buf, _ := io.ReadAll(j.statusR)
	var facts Facts
	if len(buf) > 0 && buf[0] == 'I' {
		line, tail, ok := strings.Cut(string(buf), "\n")
		if !ok {
			return &SetupError{Stage: "report"}
		}
		decoder := json.NewDecoder(strings.NewReader(line[1:]))
		decoder.DisallowUnknownFields()
		var extra any
		if decoder.Decode(&facts) != nil || decoder.Decode(&extra) != io.EOF || (j.strict && len(facts.Unmet) > 0) {
			return &SetupError{Stage: "report"}
		}
		buf = []byte(tail)
	}
	if err := statusFromReport(buf); err != nil {
		return err
	}
	j.Facts = facts
	return nil
}

// statusFromReport maps the raw fd-4 bytes to Status's result: nil only for
// exactly "X"; a parsed *SetupError for "F<stage>:<errno>"; and an "unknown"
// *SetupError for EOF-without-report or anything else.
func statusFromReport(buf []byte) error {
	s := strings.TrimRight(string(buf), "\n")
	switch {
	case s == statusReachedExec:
		return nil
	case s == "":
		// EOF with no report: the worker (or shim) died before writing.
		return &SetupError{Stage: "unknown"}
	case strings.HasPrefix(s, "XFexec:"):
		stage, errno := parseFailReport(s[1:])
		return &SetupError{Stage: stage, Errno: errno}
	case strings.HasPrefix(s, statusFailPrefix):
		stage, errno := parseFailReport(s)
		return &SetupError{Stage: stage, Errno: errno}
	default:
		return &SetupError{Stage: "unknown"}
	}
}

// Wire tokens for the fd-4 status pipe.
const (
	statusReachedExec = "X" // written immediately before execve
	statusFailPrefix  = "F" // "F<stage>:<errno>"
)

// formatFailReport renders a worker abort for fd 4: "F<stage>:<errno>\n".
func formatFailReport(stage string, errno syscall.Errno) string {
	return fmt.Sprintf("%s%s:%d\n", statusFailPrefix, stage, int(errno))
}

// parseFailReport parses "F<stage>:<errno>" back into its parts.
func parseFailReport(s string) (stage string, errno syscall.Errno) {
	body := strings.TrimPrefix(s, statusFailPrefix)
	i := strings.LastIndexByte(body, ':')
	if i < 0 {
		return body, 0
	}
	stage = body[:i]
	if n, err := strconv.Atoi(body[i+1:]); err == nil {
		errno = syscall.Errno(n)
	}
	return stage, errno
}

// Command returns a Jailed whose Cmd runs `sh -c cmd` INSIDE the jail the Spec
// describes. It is implemented per platform; on non-linux it returns an error.
// It is never called for Rung3Unconfined (the gate passes a nil *Spec instead).
func (s Spec) Command(ctx context.Context, cmd string) (*Jailed, error) {
	return s.command(ctx, cmd)
}

// Detect probes the host and returns the Report (Rung + real ABI). Pure
// read-only probing; it never mutates the host.
func Detect() Report { return detect() }
