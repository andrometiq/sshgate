package jobplan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	gatessh "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

type phasedFunc func(context.Context, string, string, int, string, io.Reader, func() error, io.Writer, io.Writer) (int, error)

func (f phasedFunc) RunPhasedTo(c context.Context, h, u string, p int, w string, in io.Reader, g func() error, out, err io.Writer) (int, error) {
	return f(c, h, u, p, w, in, g, out, err)
}

type registryFunc func(string) (approvalplan.RouteSnapshot, string, error)

func (f registryFunc) ReadCurrent(a string) (approvalplan.RouteSnapshot, string, error) { return f(a) }

type journal struct {
	before, after []int
	beforeHook    func(int) error
	afterHook     func(int, approvalplan.StepResult) error
}

func (j *journal) BeforeStep(k int) error {
	j.before = append(j.before, k)
	if j.beforeHook != nil {
		return j.beforeHook(k)
	}
	return nil
}
func (j *journal) AfterStep(k int, r approvalplan.StepResult) error {
	j.after = append(j.after, k)
	if j.afterHook != nil {
		return j.afterHook(k, r)
	}
	return nil
}

func runnerFixture(t *testing.T, commands []string, policy approvalplan.StopPolicy, transport PhasedRunner) (*Runner, *elapsedtest.Fake, []Dispatch) {
	t.Helper()
	options, target := draftFixture()
	d, err := BuildBatch(options, target, commands, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.CommandJob.StopPolicy = policy
	clock := elapsedtest.NewFake(target.AddedAt)
	r, err := NewRunner(d, transport, registryFunc(func(string) (approvalplan.RouteSnapshot, string, error) { return target, target.Digest(), nil }), clock, 0)
	if err != nil {
		t.Fatal(err)
	}
	windows := make([]time.Time, len(commands))
	dispatch := make([]Dispatch, len(commands))
	for i, s := range d.CommandJob.Steps {
		if s.Route.Signed() {
			windows[i] = clock.Wall().Add(time.Duration(s.SignatureTTLSeconds) * time.Second)
			dispatch[i].WireCommand = "SSHGATE_SIG:c2ln:cGF5bG9hZA " + s.ExactCommand
		}
	}
	if err = r.HoldWindows(approvalplan.Now{Wall: clock.Wall(), Elapsed: clock.Elapsed()}, windows); err != nil {
		t.Fatal(err)
	}
	return r, clock, dispatch
}
func guardTransport(fn func(io.Writer, io.Writer) (int, error)) PhasedRunner {
	return phasedFunc(func(_ context.Context, _, _ string, _ int, _ string, _ io.Reader, g func() error, out, err io.Writer) (int, error) {
		if g != nil && g() != nil {
			return 0, &gatessh.PhasedError{Class: "guard_refused"}
		}
		return fn(out, err)
	})
}
func assertRun(t *testing.T, got RunResult, want []approvalplan.StepStatus) {
	t.Helper()
	if !reflect.DeepEqual(got.Summary.Steps, want) || got.Summary.State != approvalplan.JobFinal {
		t.Fatalf("summary %+v; want %v", got.Summary, want)
	}
	if got.Summary.Class != approvalplan.AggregateJobClass(want) || !reflect.DeepEqual(got.Summary.ExecutedOrdinals, approvalplan.ExecutedOrdinals(want)) || got.Summary.Partial != approvalplan.Partial(want) {
		t.Fatalf("aggregation %+v", got.Summary)
	}
}

func TestRunnerStopPolicyAndAggregation(t *testing.T) {
	for _, policy := range []approvalplan.StopPolicy{approvalplan.StopClassDefaultWritesOnly, approvalplan.StopAnyNonzero, approvalplan.StopNever} {
		for _, first := range []string{"cat /x", "touch /x"} {
			t.Run(string(policy)+first, func(t *testing.T) {
				calls := 0
				transport := guardTransport(func(io.Writer, io.Writer) (int, error) {
					calls++
					if calls == 1 {
						return 3, nil
					}
					return 0, nil
				})
				r, _, dispatch := runnerFixture(t, []string{first, "touch /y"}, policy, transport)
				j := &journal{}
				got, err := r.Run(context.Background(), dispatch, j)
				if err != nil {
					t.Fatal(err)
				}
				want := []approvalplan.StepStatus{approvalplan.StepFailed, approvalplan.StepSucceeded}
				if policy == approvalplan.StopAnyNonzero || policy == approvalplan.StopClassDefaultWritesOnly && first == "touch /x" {
					want[1] = approvalplan.StepSkipped
					if len(j.before) != 1 {
						t.Fatal("marked skipped step")
					}
				}
				assertRun(t, got, want)
			})
		}
	}
	for _, size := range []int{2, 3} {
		calls := 0
		transport := guardTransport(func(io.Writer, io.Writer) (int, error) {
			calls++
			if calls == 1 {
				return 3, nil
			}
			return -1, &gatessh.PhasedError{Class: "indeterminate"}
		})
		commands := []string{"cat /x", "touch /y", "touch /z"}[:size]
		r, _, dispatch := runnerFixture(t, commands, approvalplan.StopClassDefaultWritesOnly, transport)
		got, err := r.Run(context.Background(), dispatch, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := []approvalplan.StepStatus{approvalplan.StepFailed, approvalplan.StepIndeterminate, approvalplan.StepNotRun}[:size]
		assertRun(t, got, want)
	}
}

func TestRunnerHeldClocksAndUnsignedTail(t *testing.T) {
	for _, change := range []string{"back", "forward", "suspend"} {
		t.Run(change, func(t *testing.T) {
			var clock *elapsedtest.Fake
			calls := 0
			transport := guardTransport(func(io.Writer, io.Writer) (int, error) {
				calls++
				if calls == 1 {
					switch change {
					case "back":
						clock.Advance(61 * time.Second)
						clock.StepWall(-7 * time.Minute)
					case "forward":
						clock.StepWall(61 * time.Second)
					case "suspend":
						clock.Suspend(8 * time.Hour)
						clock.StepWall(-8 * time.Hour)
					}
				}
				return 0, nil
			})
			r, c, dispatch := runnerFixture(t, []string{"touch /x", "cat /x", "touch /y", "cat /y"}, approvalplan.StopNever, transport)
			clock = c
			original := r.held[3]
			j := &journal{afterHook: func(k int, _ approvalplan.StepResult) error {
				if k == 1 {
					windows := []time.Time{original.WallEnd, {}, original.WallEnd, {}}
					if err := r.HoldWindows(approvalplan.Now{Wall: clock.Wall(), Elapsed: clock.Elapsed()}, windows); err != nil {
						t.Fatal(err)
					}
					if r.held[3] != original {
						t.Fatal("repeat Claim renewed window")
					}
				}
				return nil
			}}
			got, err := r.Run(context.Background(), dispatch, j)
			if err != nil {
				t.Fatal(err)
			}
			assertRun(t, got, []approvalplan.StepStatus{approvalplan.StepSucceeded, approvalplan.StepSucceeded, approvalplan.StepExpiredUnexecuted, approvalplan.StepNotRun})
			if calls != 2 || !reflect.DeepEqual(j.before, []int{1, 2}) || !reflect.DeepEqual(j.after, []int{1, 2, 3}) {
				t.Fatalf("calls %d journal %+v", calls, j)
			}
			clock.StepWall(-24 * time.Hour)
			if r.HoldWindows(approvalplan.Now{Wall: clock.Wall()}, []time.Time{original.WallEnd, {}, original.WallEnd, {}}) == nil {
				t.Fatal("expired set reacquired")
			}
		})
	}
	var clock *elapsedtest.Fake
	calls := 0
	r, c, dispatch := runnerFixture(t, []string{"touch /x", "cat /x"}, approvalplan.StopNever, guardTransport(func(io.Writer, io.Writer) (int, error) { calls++; clock.Advance(time.Hour); return 0, nil }))
	clock = c
	got, err := r.Run(context.Background(), dispatch, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertRun(t, got, []approvalplan.StepStatus{approvalplan.StepSucceeded, approvalplan.StepSucceeded})
	if calls != 2 {
		t.Fatal("unsigned tail refused")
	}
}

func TestRunnerAbortMatrix(t *testing.T) {
	for _, policy := range []approvalplan.StopPolicy{approvalplan.StopClassDefaultWritesOnly, approvalplan.StopAnyNonzero, approvalplan.StopNever} {
		for _, status := range []approvalplan.StepStatus{approvalplan.StepFailedNotStarted, approvalplan.StepExpiredUnexecuted, approvalplan.StepStaleTarget, approvalplan.StepIndeterminate} {
			for _, last := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%t", policy, status, last), func(t *testing.T) {
					calls := 0
					r, clock, dispatch := runnerFixture(t, []string{"touch /x", "touch /y"}, policy, guardTransport(func(io.Writer, io.Writer) (int, error) {
						calls++
						class := string(status)
						return -1, &gatessh.PhasedError{Class: class}
					}))
					if last {
						r, clock, dispatch = runnerFixture(t, []string{"touch /x"}, policy, r.ssh)
					}
					if status == approvalplan.StepExpiredUnexecuted {
						clock.Advance(time.Minute)
					}
					if status == approvalplan.StepStaleTarget {
						r.registry = registryFunc(func(string) (approvalplan.RouteSnapshot, string, error) {
							return approvalplan.RouteSnapshot{}, "", errors.New("unreadable secret")
						})
					}
					j := &journal{}
					got, err := r.Run(context.Background(), dispatch, j)
					if err != nil {
						t.Fatal(err)
					}
					want := []approvalplan.StepStatus{status}
					if !last {
						want = append(want, approvalplan.StepNotRun)
					}
					assertRun(t, got, want)
					if len(j.before) > 1 || len(j.after) != 1 || calls > 1 {
						t.Fatalf("dispatch after abort %+v", j)
					}
				})
			}
		}
	}
}

func TestRunnerJournalFailures(t *testing.T) {
	for _, stage := range []string{"before", "after"} {
		t.Run(stage, func(t *testing.T) {
			calls := 0
			r, _, dispatch := runnerFixture(t, []string{"touch /x", "touch /y"}, approvalplan.StopNever, guardTransport(func(io.Writer, io.Writer) (int, error) { calls++; return 0, nil }))
			j := &journal{}
			if stage == "before" {
				j.beforeHook = func(int) error { return errors.New("private storage error") }
			} else {
				j.afterHook = func(int, approvalplan.StepResult) error { return errors.New("private storage error") }
			}
			_, err := r.Run(context.Background(), dispatch, j)
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatalf("error %v", err)
			}
			if stage == "before" && (calls != 0 || len(j.after) != 0) || stage == "after" && calls != 1 {
				t.Fatal("dispatch crossed failed journal")
			}
		})
	}
}

func TestRunnerRegistryFailsClosed(t *testing.T) {
	for _, mode := range []string{"malformed", "unreadable", "insecure", "absent", "changed", "empty fingerprint"} {
		t.Run(mode, func(t *testing.T) {
			r, _, dispatch := runnerFixture(t, []string{"touch /x"}, approvalplan.StopNever, guardTransport(func(io.Writer, io.Writer) (int, error) { t.Fatal("stale target dispatched"); return 0, nil }))
			target := r.draft.CommandJob.Steps[0].Target
			path := filepath.Join(t.TempDir(), "servers.json")
			reg, err := registry.New(path)
			if err != nil {
				t.Fatal(err)
			}
			entry := registry.Entry{Host: target.ResolvedHost, Port: target.ResolvedPort, User: target.ResolvedUser, Fingerprint: target.TrustedHostFingerprint, AddedAt: target.AddedAt}
			if err = reg.Add(target.ServerAlias, entry); err != nil {
				t.Fatal(err)
			}
			r.registry = reg
			switch mode {
			case "malformed":
				err = os.WriteFile(path, []byte("{"), 0600)
			case "unreadable":
				if os.Geteuid() == 0 {
					t.Skip("mode 0000 requires unprivileged user")
				}
				err = os.Chmod(path, 0)
			case "insecure":
				err = os.Chmod(path, 0666)
			case "absent":
				err = os.Remove(path)
			case "changed":
				entry.Host = "changed.test"
				err = reg.Add(target.ServerAlias, entry)
			case "empty fingerprint":
				entry.Fingerprint = ""
				err = reg.Add(target.ServerAlias, entry)
			}
			if err != nil {
				t.Fatal(err)
			}
			j := &journal{}
			got, err := r.Run(context.Background(), dispatch, j)
			if err != nil {
				t.Fatal(err)
			}
			assertRun(t, got, []approvalplan.StepStatus{approvalplan.StepStaleTarget})
			if len(j.before) != 0 || len(j.after) != 1 {
				t.Fatal("stale check journal order")
			}
			if mode == "unreadable" && got.Steps[0].Result.Annotation != "registry unreadable" {
				t.Fatal("lost unreadable detail")
			}
		})
	}
}

func TestRunnerCapture(t *testing.T) {
	for _, async := range []bool{false, true} {
		t.Run(fmt.Sprint(async), func(t *testing.T) {
			r, _, dispatch := runnerFixture(t, []string{"touch /x"}, approvalplan.StopNever, guardTransport(func(out, err io.Writer) (int, error) {
				_, _ = io.WriteString(out, strings.Repeat("a", 200))
				_, _ = err.Write([]byte{0xff, 0xfe})
				return 0, nil
			}))
			if async {
				r.budget = &captureBudget{remaining: 100}
				r.draft.CommandJob.MaxOutputBytes = 64
			}
			got, err := r.Run(context.Background(), dispatch, nil)
			if err != nil {
				t.Fatal(err)
			}
			s := got.Steps[0].Result
			want := 200
			if async {
				want = 64
			}
			if len(s.Stdout) != want || s.StdoutBytes != 200 || s.Truncated != async || s.StdoutSHA256 != outputDigest(s.Stdout) || !reflect.DeepEqual(s.Stderr, []byte{0xff, 0xfe}) {
				t.Fatalf("capture %+v", s)
			}
		})
	}
	b := &captureBudget{remaining: approvalplan.MaxJobOutputBytes}
	for i := 0; i < 10; i++ {
		c := newCapture(approvalplan.MaxStreamOutputBytes, b)
		for j := 0; j < 2; j++ {
			_, _ = c.Write(make([]byte, approvalplan.MaxStreamOutputBytes))
		}
		body, truncated := c.finish()
		if !truncated || len(body) > approvalplan.MaxStreamOutputBytes {
			t.Fatal("stream overflow")
		}
	}
	if b.remaining != 0 {
		t.Fatal("job budget not enforced")
	}
}

func TestRunnerCappedJailEvidence(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			r, _, dispatch := runnerFixture(t, []string{"cat /x", "touch /y"}, approvalplan.StopNever, guardTransport(func(_, stderr io.Writer) (int, error) {
				_, _ = io.WriteString(stderr, strings.Repeat("x", 100))
				_, _ = io.WriteString(stderr, "gate: read jail unav")
				_, _ = io.WriteString(stderr, "ailable: ")
				if after {
					_, _ = io.WriteString(stderr, "the jail failed after the read may have started")
				}
				return 77, nil
			}))
			r.budget = &captureBudget{remaining: 8}
			r.draft.CommandJob.MaxOutputBytes = 4
			got, err := r.Run(context.Background(), dispatch, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !after {
				assertRun(t, got, []approvalplan.StepStatus{approvalplan.StepFailedNotStarted, approvalplan.StepNotRun})
			} else if got.Steps[0].Result.Status != approvalplan.StepFailed {
				t.Fatal("lost after-start evidence")
			}
		})
	}
}

func TestRunnerMissingWindowAndGuardAfterJournal(t *testing.T) {
	for _, mode := range []string{"missing", "journal delay", "missing wire"} {
		t.Run(mode, func(t *testing.T) {
			execs := 0
			r, clock, dispatch := runnerFixture(t, []string{"touch /x"}, approvalplan.StopNever, guardTransport(func(io.Writer, io.Writer) (int, error) { execs++; return 0, nil }))
			j := &journal{}
			switch mode {
			case "missing":
				clear(r.held)
			case "journal delay":
				j.beforeHook = func(int) error { clock.Advance(59 * time.Second); return nil }
			case "missing wire":
				dispatch[0].WireCommand = "touch /x"
			}
			got, err := r.Run(context.Background(), dispatch, j)
			if err != nil {
				t.Fatal(err)
			}
			want := approvalplan.StepExpiredUnexecuted
			if mode == "missing wire" {
				want = approvalplan.StepFailedNotStarted
			}
			assertRun(t, got, []approvalplan.StepStatus{want})
			if execs != 0 {
				t.Fatal("dispatch without live authority")
			}
		})
	}
}

func TestRunnerConstructionAndAuthorityLifetime(t *testing.T) {
	options, target := draftFixture()
	options.Coordinator = approvalplan.CoordinatorExecutor
	draft, err := BuildRun(options, target, "touch /x", false)
	if err != nil {
		t.Fatal(err)
	}
	clock := elapsedtest.NewFake(target.AddedAt)
	transport := guardTransport(func(io.Writer, io.Writer) (int, error) { return 0, nil })
	registry := registryFunc(func(string) (approvalplan.RouteSnapshot, string, error) { return target, target.Digest(), nil })
	r, err := NewRunner(draft, transport, registry, clock, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.budget == nil || r.budget.remaining != approvalplan.MaxJobOutputBytes {
		t.Fatal("async capture unbounded")
	}
	draft.CommandJob.Steps[0].ExactCommand = "changed"
	if r.draft.CommandJob.Steps[0].ExactCommand != "touch /x" {
		t.Fatal("caller mutated frozen job")
	}
	if r.HoldWindows(approvalplan.Now{Wall: clock.Wall()}, nil) == nil || r.HoldWindows(approvalplan.Now{Wall: clock.Wall()}, []time.Time{{}}) == nil {
		t.Fatal("invalid windows accepted")
	}
	window := clock.Wall().Add(time.Minute)
	if err = r.HoldWindows(approvalplan.Now{Wall: clock.Wall()}, []time.Time{window}); err != nil {
		t.Fatal(err)
	}
	r.ssh = guardTransport(func(io.Writer, io.Writer) (int, error) {
		if len(r.held) != 0 || !r.released {
			t.Fatal("held set survived last Start")
		}
		return 0, nil
	})
	_, err = r.Run(context.Background(), []Dispatch{{WireCommand: "SSHGATE_SIG:test:test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.RunStep(context.Background(), 1, Dispatch{}, false, nil); err == nil {
		t.Fatal("step redispatched")
	}
	if _, err = NewRunner(approvalplan.ApprovalDraft{}, transport, registry, clock, 0); err == nil {
		t.Fatal("invalid draft accepted")
	}
}

func TestRunnerRecoveredBudgetAndAbortLatch(t *testing.T) {
	options, target := draftFixture()
	options.Coordinator = approvalplan.CoordinatorExecutor
	draft, err := BuildBatch(options, target, []string{"touch /x", "cat /x"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	clock := elapsedtest.NewFake(target.AddedAt)
	registry := registryFunc(func(string) (approvalplan.RouteSnapshot, string, error) { return target, target.Digest(), nil })
	transport := guardTransport(func(stdout, stderr io.Writer) (int, error) {
		_, _ = io.WriteString(stdout, "some output")
		_, _ = io.WriteString(stderr, "more output")
		return 0, nil
	})
	for _, retained := range []int64{approvalplan.MaxJobOutputBytes - 3, approvalplan.MaxJobOutputBytes} {
		r, err := NewRunner(draft, transport, registry, clock, retained)
		if err != nil {
			t.Fatal(err)
		}
		result, err := r.RunStep(context.Background(), 2, Dispatch{}, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(result.Result.Stdout)+len(result.Result.Stderr)) != approvalplan.MaxJobOutputBytes-retained {
			t.Fatal("recovery reset capture budget")
		}
	}
	r, err := NewRunner(draft, transport, registry, clock, 0)
	if err != nil {
		t.Fatal(err)
	}
	// No held signature: expiry must also prevent a caller from dispatching a later read.
	result, err := r.RunStep(context.Background(), 1, Dispatch{}, false, nil)
	if err != nil || result.Result.Status != approvalplan.StepExpiredUnexecuted {
		t.Fatalf("missing window: %+v %v", result, err)
	}
	if _, err = r.RunStep(context.Background(), 2, Dispatch{}, false, nil); err == nil {
		t.Fatal("unsigned dispatch after abort")
	}
}
