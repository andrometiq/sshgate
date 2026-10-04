package confine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
)

// Rung is the interim probe result: full confinement or classifier-only.
type Rung int

const (
	Rung3Unconfined Rung = iota // no kernel wall (labelled UNCONFINED)
	Rung1Full                   // user/mount/IPC namespaces, host PID, ro /, Landlock, seccomp
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
	SentinelShim   = "__jail"     // RunShim: confined command subreaper
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

// Status is collected after the five-second descendant cleanup has ended.
const statusWait = 500 * time.Millisecond

const maxStatusBytes = 1 << 20

// Leave room for the shim's bounded cleanup diagnostic after I/X.
const maxInfoBytes = maxStatusBytes - 4096

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

// Facts is the worker report after all self-checks pass.
type Facts struct {
	coverIDs        map[int]bool
	Profile         string   `json:"profile"`
	ABI             int      `json:"abi"`
	Net             bool     `json:"net"`
	Lane2           bool     `json:"lane2"`
	Unmet           []string `json:"unmet,omitempty"`
	CoverAtAncestor []string `json:"cover_at_ancestor,omitempty"`
	CwdReset        bool     `json:"cwd_reset,omitempty"`
}

// Jailed wraps the command and its private setup-report pipes.
type Jailed struct {
	// CleanupError reports post-execution cleanup failure without changing status.
	CleanupError string
	Facts        Facts
	spec         Spec
	strict       bool
	Cmd          *exec.Cmd

	// cmd is the command string the parent streams to the worker on fd 3.
	cmd string
	// cmdW is the parent's write end of the fd-3 (command) pipe.
	// statusR is the parent's read end of the fd-4 (status) pipe.
	cmdW         *os.File
	statusR      *os.File
	statusDone   chan struct{}
	statusReport workerReport
	workerStatus WorkerStatus
	// childEnds are the pipe ends handed to the child via ExtraFiles; the
	// parent closes its copies in Started (after a successful Start) or Abort
	// (after a failed Start).
	childEnds []*os.File
}

type workerReport struct {
	data []byte
	err  error
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
	// Drain before releasing the worker: Facts may exceed the pipe capacity.
	j.startStatusReader()
	go func() {
		_, _ = io.WriteString(j.cmdW, j.cmd)
		_ = j.cmdW.Close()
	}()
	return nil
}

func (j *Jailed) startStatusReader() {
	reader := j.statusR
	j.statusDone = make(chan struct{})
	go func() {
		defer close(j.statusDone)
		defer reader.Close()
		j.statusReport.data, j.statusReport.err = io.ReadAll(io.LimitReader(reader, maxStatusBytes))
	}()
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
	if j.statusDone != nil {
		<-j.statusDone
	}
}

// Status validates the worker's I/X report after Cmd.Wait and descendant cleanup. Facts are published
// only on success; the shim appends worker status and an optional cleanup diagnostic.
func (j *Jailed) Status() (Facts, error) {
	defer func() {
		if j.statusR != nil {
			_ = j.statusR.Close()
		}
	}()
	failure := func(stage string) (Facts, error) { return Facts{}, &SetupError{Stage: stage} }
	if j.statusR == nil {
		return failure("unknown")
	}
	if j.statusDone == nil {
		j.startStatusReader()
	}
	timer := time.NewTimer(statusWait)
	defer timer.Stop()
	timedOut := false
	select {
	case <-j.statusDone:
	case <-timer.C:
		timedOut = true
		_ = j.statusR.Close()
		<-j.statusDone
	}
	buf, err := j.statusReport.data, j.statusReport.err
	if jailmut.On("P-STATUS") {
		return Facts{Profile: j.spec.Profile, ABI: 1, Net: j.spec.Net}, nil
	}
	if err != nil && !(timedOut && errors.Is(err, os.ErrClosed)) || len(buf) == maxStatusBytes {
		return failure("report")
	}
	if len(buf) == 0 {
		return failure("unknown")
	}
	if buf[0] == 'F' {
		head, worker, cleanup, err := splitStatusRecords(string(buf))
		if err != nil {
			return failure("report")
		}
		j.workerStatus, j.CleanupError = worker, cleanup
		return Facts{}, statusFromReport([]byte(head))
	}
	line, tail, ok := strings.Cut(string(buf), "\n")
	if !ok || len(line) < 2 || line[0] != 'I' {
		return failure("report")
	}
	var facts Facts
	decoder := json.NewDecoder(strings.NewReader(line[1:]))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&facts) != nil || decoder.Decode(&extra) != io.EOF {
		return failure("report")
	}
	// Require the four mandatory fields even where false is the expected value.
	fields := map[string]json.RawMessage{}
	keys := json.NewDecoder(strings.NewReader(line[1:]))
	if token, err := keys.Token(); err != nil || token != json.Delim('{') {
		return failure("report")
	}
	for keys.More() {
		token, err := keys.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return failure("report")
		}
		switch key {
		case "profile", "abi", "net", "lane2", "unmet", "cover_at_ancestor", "cwd_reset":
		default:
			return failure("report")
		}
		if _, duplicate := fields[key]; duplicate {
			return failure("report")
		}
		var value json.RawMessage
		if keys.Decode(&value) != nil {
			return failure("report")
		}
		fields[key] = value
	}
	for _, key := range []string{"profile", "abi", "net", "lane2"} {
		if value, ok := fields[key]; !ok || string(value) == "null" {
			return failure("report")
		}
	}
	if facts.Profile != j.spec.Profile || facts.Net != j.spec.Net || facts.Lane2 || facts.ABI < 1 || j.spec.ForceABI > 0 && facts.ABI > j.spec.ForceABI || j.strict && len(facts.Unmet) > 0 {
		return failure("report")
	}
	tail, worker, cleanup, recordErr := splitStatusRecords(tail)
	if recordErr != nil {
		return failure("report")
	}
	if tail != "X" {
		if strings.HasPrefix(tail, "XFexec:") {
			j.workerStatus, j.CleanupError = worker, cleanup
			return Facts{}, statusFromReport([]byte(tail))
		}
		if strings.HasPrefix(tail, "X") {
			return failure("exec")
		}
		return failure("report")
	}
	if timedOut {
		if cleanup != "" {
			cleanup += "; "
		}
		cleanup += "status pipe remained open after cleanup"
	}
	j.Facts, j.CleanupError, j.workerStatus = facts, cleanup, worker
	return facts, nil
}

func writeExecReport(writer io.Writer, facts Facts) error {
	raw, err := json.Marshal(facts)
	if err != nil {
		return err
	}
	if len(raw) > maxInfoBytes {
		return syscall.E2BIG
	}
	_, err = fmt.Fprintf(writer, "I%s\nX", raw)
	return err
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
