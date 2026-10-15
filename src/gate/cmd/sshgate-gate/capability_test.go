package main

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/classify"
	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// verbCall is one executor call the verb made.
type verbCall struct {
	cmd          string
	spec         confine.Spec
	sealed, sink bool
	resetsAtCall int32
}

// recordAttempts replaces the executor: every confined call is recorded and
// answered with result and err; an unconfined call runs for real.
func recordAttempts(t *testing.T, result gate.ExecResult, err error) *[]verbCall {
	t.Helper()
	var calls []verbCall
	previous := executeCommand
	executeCommand = func(ctx context.Context, cmd string, opts gate.ExecOpts) (gate.ExecResult, error) {
		if opts.Confine == nil {
			return gate.ExecWithRedaction(ctx, cmd, opts)
		}
		calls = append(calls, verbCall{cmd: cmd, spec: *opts.Confine, sealed: opts.Seal != nil, sink: opts.ClientSink != nil, resetsAtCall: verbEnvResets.Load()})
		return result, err
	}
	t.Cleanup(func() { executeCommand = previous })
	return &calls
}

func kernelRun(facts confine.Facts) gate.ExecResult {
	return gate.ExecResult{ExitCode: 0, Jail: &facts}
}

// decodeVerbLine requires exactly one line holding exactly the verb's twelve
// keys, in order, with no null list, and decodes it.
func decodeVerbLine(t *testing.T, out string) jailVerbReport {
	t.Helper()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("verb stdout is not one line: %q", out)
	}
	decoder := json.NewDecoder(strings.NewReader(out))
	decoder.DisallowUnknownFields()
	var report jailVerbReport
	if err := decoder.Decode(&report); err != nil {
		t.Fatalf("verb line %q: %v", out, err)
	}
	// Re-encoding gives back the line only if every key is present, in order.
	again, err := json.Marshal(report)
	if err != nil || string(again)+"\n" != out || report.Unmet == nil || report.AcceptFS == nil {
		t.Fatalf("verb line %q is not the fixed twelve-key form", out)
	}
	return report
}

// verbState is one host state the verb reports.
type verbState struct {
	name        string
	pin         string
	pinMode     os.FileMode
	floor       bool
	facts       confine.HostFacts
	result      gate.ExecResult
	err         error
	attempts    int
	enforcement string
	pinned, net bool
	abi         int
	label       string
	reason      string
	unmet       []string
	acceptFS    []string
}

var unmetFuse = []string{"fs-view:fuse@/x"}

func verbStates() []verbState {
	clamp := capableFacts
	clamp.AppArmorUsernsClamp = true
	roFacts := func(net bool, unmet []string) confine.Facts {
		return confine.Facts{Profile: confine.ProfileROv1, ABI: 3, Net: net, Unmet: unmet}
	}
	absent, absentErr := setupFailure("clone", syscall.EACCES)
	failed, failedErr := setupFailure("seccomp", syscall.EIO)
	return []verbState{
		{name: "unpinned kernel", facts: capableFacts, result: kernelRun(roFacts(false, nil)), attempts: 1, enforcement: "kernel", abi: 3, label: confine.LabelPinToClaim},
		{name: "unpinned kernel with unmet", facts: capableFacts, result: kernelRun(roFacts(false, unmetFuse)), attempts: 1, enforcement: "kernel", abi: 3, label: confine.LabelClassifierOnly, unmet: unmetFuse},
		{name: "pinned deny", pin: pinDeny + "accept_fs=network\n", pinMode: 0o600, facts: capableFacts, result: kernelRun(roFacts(false, nil)), attempts: 1, enforcement: "kernel", pinned: true, abi: 3, label: confine.LabelKernelNoLabel, acceptFS: []string{"network"}},
		{name: "pinned allow", pin: pinAllow, pinMode: 0o600, facts: capableFacts, result: kernelRun(roFacts(true, nil)), attempts: 1, enforcement: "kernel", pinned: true, net: true, abi: 3, label: confine.LabelNetworkOpen},
		{name: "unpinned absent", facts: clamp, result: absent, err: absentErr, attempts: 1, enforcement: "classifier", net: true, abi: 6, label: confine.LabelClassifierOnly, reason: "jail:absent:clone:EACCES"},
		{name: "pinned absent", pin: pinDeny, pinMode: 0o600, facts: clamp, result: absent, err: absentErr, attempts: 1, enforcement: "unavailable", pinned: true, abi: 6, label: confine.LabelDenied, reason: "jail:absent:clone:EACCES"},
		{name: "failed", facts: capableFacts, result: failed, err: failedErr, attempts: 1, enforcement: "unavailable", abi: 6, label: confine.LabelDenied, reason: "jail:failed:seccomp:EIO"},
		{name: "damaged pin", pin: pinDeny, pinMode: 0o666, facts: capableFacts, enforcement: "unavailable", abi: 6, label: confine.LabelDenied, reason: "pin:damaged"},
		{name: "legacy floor", floor: true, facts: capableFacts, enforcement: "unavailable", abi: 6, label: confine.LabelDenied, reason: "pin:legacy-floor"},
	}
}

// setUpVerbState puts the gate dir, pin, host facts and executor in state s.
func setUpVerbState(t *testing.T, s verbState) (string, *[]verbCall) {
	t.Helper()
	dir := t.TempDir()
	withGateDir(t, dir)
	withHostFacts(t, s.facts)
	if s.pin != "" {
		writePin(t, dir, s.pin, s.pinMode)
	}
	if s.floor {
		if err := os.WriteFile(filepath.Join(dir, jailFloorFile), []byte("full\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, recordAttempts(t, s.result, s.err)
}

// TestJailVerbOneJSONLine: in every host state the verb prints exactly one
// line with the twelve keys, adds nothing to stderr (a failed jail's worker
// line comes from the worker), and writes no audit record.
func TestJailVerbOneJSONLine(t *testing.T) {
	for _, s := range verbStates() {
		t.Run(s.name, func(t *testing.T) {
			dir, calls := setUpVerbState(t, s)
			code, out, stderr := runWith(t, "SSHGATE_JAIL")
			if code != exitOK || stderr != "" || len(*calls) != s.attempts {
				t.Fatalf("exit %d, stderr %q, attempts %d", code, stderr, len(*calls))
			}
			got := decodeVerbLine(t, out)
			want := jailVerbReport{V: 1, Profile: confine.ProfileROv1, Enforcement: s.enforcement, Pinned: s.pinned, Net: s.net,
				LandlockABI: s.abi, Label: s.label, Reason: s.reason, Unmet: append([]string{}, s.unmet...),
				AcceptFS: append([]string{}, s.acceptFS...), CorePattern: readCorePattern()}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("verb\n got %+v\nwant %+v", got, want)
			}
			if _, err := os.Stat(filepath.Join(dir, "audit.log")); err == nil {
				t.Fatal("the verb wrote an audit record")
			}
		})
	}
}

// TestJailVerbBeforePubkey: the verb answers on a host whose gate.pub would
// fail every other command.
func TestJailVerbBeforePubkey(t *testing.T) {
	dir := t.TempDir()
	withGateDir(t, dir)
	withHostFacts(t, capableFacts)
	recordAttempts(t, kernelRun(confine.Facts{Profile: confine.ProfileROv1, ABI: 3}), nil)
	if err := os.WriteFile(filepath.Join(dir, "gate.pub"), []byte("corrupt"), 0o666); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runWith(t, "true"); code != exitSoftware {
		t.Fatalf("a read with a corrupt gate.pub exited %d, want %d", code, exitSoftware)
	}
	code, out, _ := runWith(t, "SSHGATE_JAIL")
	if report := decodeVerbLine(t, out); code != exitOK || report.Enforcement != "kernel" {
		t.Fatalf("exit %d, report %+v", code, report)
	}
}

// TestJailVerbSinkFailure: with no usable client output the verb attempts
// nothing and exits 70 with no output.
func TestJailVerbSinkFailure(t *testing.T) {
	dir := t.TempDir()
	withGateDir(t, dir)
	calls := recordAttempts(t, kernelRun(confine.Facts{Profile: confine.ProfileROv1, ABI: 3}), nil)
	withHostFPs(t, testGateHostFP)
	withEnv(t, "SSH_ORIGINAL_COMMAND", "SSHGATE_JAIL")
	closed, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	original := os.Stdout
	os.Stdout = closed
	code := run()
	os.Stdout = original
	if code != exitSoftware || len(*calls) != 0 {
		t.Fatalf("exit %d, attempts %d", code, len(*calls))
	}
	if data, _ := os.ReadFile(closed.Name()); len(data) != 0 {
		t.Fatalf("output %q", data)
	}
}

// TestDoctorAgreesWithJailVerb: doctor reports the verb's label, and what it
// says reads do matches the verb's enforcement.
func TestDoctorAgreesWithJailVerb(t *testing.T) {
	for _, s := range verbStates() {
		t.Run(s.name, func(t *testing.T) {
			setUpVerbState(t, s)
			_, out, _ := runWith(t, "SSHGATE_JAIL")
			verb := decodeVerbLine(t, out)
			d := doctorJSON(t)
			prefix := map[string]string{"kernel": "kernel-jailed", "classifier": "classifier-only", "unavailable": "denied"}[verb.Enforcement]
			if d.Label != verb.Label || !strings.HasPrefix(d.Reads, prefix) {
				t.Fatalf("doctor label %q reads %q; verb %+v", d.Label, d.Reads, verb)
			}
		})
	}
}

// unitJailVerbNoExec: the exact verb makes one sealed attempt of ":" under the
// read Spec with cwd "/", after resetting the environment, and prints one
// line with no audit; no other byte string is handled as the verb.
func unitJailVerbNoExec(t *testing.T) {
	p := newProof(t, "U-JailVerbNoExec")
	dir := t.TempDir()
	withGateDir(t, dir)
	withHostFacts(t, capableFacts)
	calls := recordAttempts(t, kernelRun(confine.Facts{Profile: confine.ProfileROv1, ABI: 3}), nil)
	before := verbEnvResets.Load()
	code, out, _ := runWith(t, "SSHGATE_JAIL")
	want := readSpec(pinState{}, false, false)
	want.Cwd = "/"
	_, auditErr := os.Stat(filepath.Join(dir, "audit.log"))
	exact := code == exitOK && strings.Count(out, "\n") == 1 && strings.HasPrefix(out, `{"v":1,`) && auditErr != nil && len(*calls) == 1
	if exact {
		call := (*calls)[0]
		exact = call.cmd == jailProbeCommand && call.sealed && call.sink && reflect.DeepEqual(call.spec, want) && call.resetsAtCall == before+1
	}
	if !exact {
		t.Fatalf("exact verb: exit %d, stdout %q, calls %+v", code, out, *calls)
	}
	executed := false
	for _, variant := range []string{"SSHGATE_JAIL printf x", "SSHGATE_JAIL ", " SSHGATE_JAIL", "SSHGATE_JAIL;id", "SSHGATE_JAIL\n", "SSHGATE_JAIL\tprintf x", "sshgate_jail", "SSHGATE_JAILX", "SSHGATE_VERSION SSHGATE_JAIL"} {
		*calls = nil
		code, out, _ := runWith(t, variant)
		verb := strings.Contains(out, `{"v":1,`)
		executed = executed || verb
		if !verb && classify.Classify(variant) == classify.KindWrite && code != exitNoPermVal {
			t.Errorf("%q: exit %d, want %d", variant, code, exitNoPermVal)
		}
		if !verb && len(*calls) != 0 && classify.Classify(variant) != classify.KindRead {
			t.Errorf("%q attempted the jail", variant)
		}
	}
	if err := jailVerbLiteralsOnlyInProbe(); err != "" {
		t.Fatal(err)
	}
	p.Effect("exec", executed)
	p.Control("decision", exact)
	p.Finish()
}

// jailVerbLiteralsOnlyInProbe is the constant guard: the probe command is the
// constant ":", and every string literal naming the verb in the gate's
// non-test code is in jailVerbProbe.
func jailVerbLiteralsOnlyInProbe() string {
	files, _ := filepath.Glob("*.go")
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err.Error()
		}
		for _, decl := range file.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok && gen.Tok == token.CONST {
				for _, spec := range gen.Specs {
					value := spec.(*ast.ValueSpec)
					if value.Names[0].Name == "jailProbeCommand" && (len(value.Values) != 1 || !isStringLiteral(value.Values[0], ":")) {
						return "jailProbeCommand is not the constant \":\""
					}
				}
			}
			function, isFunc := decl.(*ast.FuncDecl)
			found := ""
			ast.Inspect(decl, func(node ast.Node) bool {
				if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
					if value, _ := strconv.Unquote(literal.Value); strings.Contains(value, "SSHGATE_JAIL") {
						found = value
					}
				}
				return true
			})
			if found != "" && (!isFunc || function.Name.Name != "jailVerbProbe") {
				return path + ": the verb literal " + strconv.Quote(found) + " is outside jailVerbProbe"
			}
		}
	}
	return ""
}

func isStringLiteral(expr ast.Expr, want string) bool {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	value, err := strconv.Unquote(literal.Value)
	return err == nil && value == want
}

// unitLabelContract: over every label state, the read-only label needs the
// switch, a pinned strict kernel run with the ro-v1 profile and a Landlock ABI,
// no network and no unmet clause; the BUILD-PLAN rows hold at both switch
// values; and the capability's label of a run with no jail facts is never a
// kernel claim.
func unitLabelContract(t *testing.T) {
	p := newProof(t, "U-LabelContract")
	pinned := confine.LabelState{Pinned: true, Strict: true, Outcome: confine.RunKernel, Profile: confine.ProfileROv1, ABI: 3}
	p.Control("decision", confine.Label(pinned, false, true) == confine.LabelReadOnlyKernel)
	p.Unit("switch", !confine.KernelLabelEnabled)
	claimedOff := false
	bools := []bool{false, true}
	for _, pin := range bools {
		for _, damaged := range bools {
			for _, strict := range bools {
				for _, outcome := range []confine.RunOutcome{0, confine.RunKernel, confine.RunAbsent, confine.RunFailed, confine.RunDaemonRead} {
					for _, profile := range []string{confine.ProfileROv1, ""} {
						for _, abi := range []int{0, 3} {
							for _, unmet := range [][]string{nil, unmetFuse} {
								for _, binary := range []string{"", "systemctl"} {
									for _, net := range bools {
										for _, enabled := range bools {
											s := confine.LabelState{Pinned: pin, Damaged: damaged, Strict: strict, Outcome: outcome, Profile: profile, ABI: abi, Unmet: unmet, Binary: binary}
											if confine.Label(s, net, enabled) != confine.LabelReadOnlyKernel {
												continue
											}
											claimedOff = claimedOff || !enabled
											if len(unmet) > 0 || net || damaged || !pin || !strict || outcome != confine.RunKernel || profile != confine.ProfileROv1 || abi < 1 {
												t.Errorf("%+v net=%v enabled=%v: claimed read-only", s, net, enabled)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	kernel := func(s confine.LabelState) confine.LabelState {
		s.Outcome, s.Profile, s.ABI = confine.RunKernel, confine.ProfileROv1, 3
		return s
	}
	for _, row := range []struct {
		state   confine.LabelState
		net     bool
		off, on string
	}{
		{kernel(confine.LabelState{Pinned: true, Strict: true}), true, confine.LabelNetworkOpen, confine.LabelNetworkOpen},
		{kernel(confine.LabelState{}), false, confine.LabelPinToClaim, confine.LabelPinToClaim},
		{kernel(confine.LabelState{Unmet: unmetFuse}), false, confine.LabelClassifierOnly, confine.LabelClassifierOnly},
		{confine.LabelState{Outcome: confine.RunAbsent}, true, confine.LabelClassifierOnly, confine.LabelClassifierOnly},
		{confine.LabelState{Pinned: true, Strict: true, Outcome: confine.RunAbsent}, false, confine.LabelDenied, confine.LabelDenied},
		{confine.LabelState{Outcome: confine.RunFailed}, false, confine.LabelDenied, confine.LabelDenied},
		{kernel(confine.LabelState{Damaged: true}), false, confine.LabelDenied, confine.LabelDenied},
		{confine.LabelState{Outcome: confine.RunDaemonRead, Binary: "systemctl"}, true, "daemon read, limited verbs: systemctl (not kernel read-only)", "daemon read, limited verbs: systemctl (not kernel read-only)"},
	} {
		if off, on := confine.Label(row.state, row.net, false), confine.Label(row.state, row.net, true); off != row.off || on != row.on {
			t.Errorf("%+v net=%v: labels %q / %q, want %q / %q", row.state, row.net, off, on, row.off, row.on)
		}
	}
	if off := confine.Label(pinned, false, false); off != confine.LabelKernelNoLabel && off != confine.LabelReadOnlyKernel {
		t.Errorf("pinned row, switch off: %q", off)
	}
	for _, c := range []capability{
		{route: attemptRoute{fallback: true, reason: "jail:absent:clone:EACCES"}},
		{pin: pinState{valid: true}, spec: confine.Spec{Strict: true}, route: attemptRoute{reason: "jail:failed:seccomp:EIO"}},
		{pin: pinState{valid: true}, spec: confine.Spec{Strict: true}, route: attemptRoute{kernel: true}},
	} {
		if label := c.label(); label != confine.LabelClassifierOnly && label != confine.LabelDenied {
			t.Errorf("%+v with no jail facts: label %q", c.route, label)
		}
	}
	p.Effect("label", claimedOff)
	p.Finish()
}
