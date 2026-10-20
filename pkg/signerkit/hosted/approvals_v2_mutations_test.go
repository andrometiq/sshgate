package hosted

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/gate"
)

type approvalMintFunc func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error)

func (f approvalMintFunc) Mint(c context.Context, p ap.ApprovalPlanV1, at time.Time) ([]string, error) {
	return f(c, p, at)
}

func approvalVote(t *testing.T, e *ApprovalV2Engine, db *sqlitestore.DB, operator, decision string, flags ap.VoteFlags) ap.Answer {
	t.Helper()
	r := readApproval(t, db, 1).Record
	digest := ""
	revision := 0
	if r.Header.Assist != nil {
		digest = r.Header.Assist.Digest
		revision = 1
	}
	a, err := e.Vote(context.Background(), approvalKey(1), ap.CastVote{Operator: operator, Decision: decision, Authn: "webauthn", Flags: flags, Hosted: &ap.HostedTap{PlanHash: r.Header.PlanHash, Revision: revision, Digest: digest, Actions: ap.ActionsAt(revision)}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func approvalReady(t *testing.T, e *ApprovalV2Engine, db *sqlitestore.DB) ap.Claim {
	t.Helper()
	submitApproval(t, e, 1)
	if _, _, err := e.mutate(context.Background(), approvalKey(1), ap.AssistDone{Unavailable: "test unavailable"}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	approvalVote(t, e, db, "operator", ap.VoteApprove, ap.VoteFlags{})
	r := readApproval(t, db, 1).Record
	if r.Header.Decision == nil {
		t.Fatal("not approved")
	}
	if _, _, err := e.mutate(context.Background(), approvalKey(1), ap.Flush{Through: r.Header.OutboxSeq}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
		return []string{"signature"}, nil
	})
	return ap.Claim{Token: statetest.Token(statetest.ID(1)), PlanHash: r.Header.PlanHash}
}

func TestApprovalV2EffectiveVotePolicy(t *testing.T) {
	for _, sub := range []string{"", "local-uid:1000"} {
		for _, self := range []bool{false, true} {
			t.Run(fmt.Sprint(sub, self), func(t *testing.T) {
				e, db, _ := approvalEngineFixture(t, false)
				e.config.RequiredApprovals = 2
				key := approvalKey(1)
				key.SubPrincipal = sub
				if _, err := e.Submit(context.Background(), key.ClientID, sub, approvalDraft(1)); err != nil {
					t.Fatal(err)
				}
				if _, _, err := e.mutate(context.Background(), key, ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
					t.Fatal(err)
				}
				cfg := e.config
				cfg.RequiredApprovals = 1
				e, err := NewApprovalV2Engine(cfg)
				if err != nil {
					t.Fatal(err)
				}
				vote := func(op, decision string) {
					r, err := db.ReadV2(context.Background(), key)
					if err != nil {
						t.Fatal(err)
					}
					_, err = e.Vote(context.Background(), key, ap.CastVote{Operator: op, Decision: decision, Authn: "webauthn", Flags: ap.VoteFlags{AllowSelfApprove: self, DenyVeto: true}, Hosted: &ap.HostedTap{PlanHash: r.Record.Header.PlanHash, Revision: 1, Digest: r.Record.Header.Assist.Digest, Actions: ap.ActionsAt(1)}})
					if err != nil {
						t.Fatal(err)
					}
				}
				vote("client", ap.VoteApprove)
				vote("other", ap.VoteApprove)
				r, err := db.ReadV2(context.Background(), key)
				if err != nil {
					t.Fatal(err)
				}
				if (r.Record.Header.Decision != nil) != self {
					t.Fatal("self policy or frozen quorum ignored")
				}
				if !self {
					vote("third", ap.VoteApprove)
				}
				r, err = db.ReadV2(context.Background(), key)
				if err != nil || r.Record.Header.Decision == nil || r.Record.Header.Decision.Status != ap.ApprovalApproved {
					t.Fatalf("quorum: %v %v", r, err)
				}
			})
		}
	}
	e, db, clock := approvalEngineFixture(t, false)
	submitApproval(t, e, 1)
	approvalVote(t, e, db, "client", ap.VoteDeny, ap.VoteFlags{DenyVeto: true})
	if readApproval(t, db, 1).Record.Header.Decision != nil {
		t.Fatal("self deny vetoed")
	}
	clock.Advance(ap.ValidityMin + time.Second)
	a := approvalVote(t, e, db, "other", ap.VoteDeny, ap.VoteFlags{DenyVeto: true})
	if a.Reason != "expired" || readApproval(t, db, 1).Record.Header.Decision.Status != ap.ApprovalExpired {
		t.Fatal("vote skipped Clock")
	}
}

func TestApprovalV2ConcurrentClaimMintsWithoutWriterLock(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, true)
	cl := approvalReady(t, e, db)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var calls atomic.Int32
	e.config.Minter = approvalMintFunc(func(_ context.Context, p ap.ApprovalPlanV1, at time.Time) ([]string, error) {
		n := calls.Add(1)
		entered <- struct{}{}
		<-release
		return []string{fmt.Sprint("signature-", n)}, nil
	})
	type result struct {
		a   ap.Answer
		err error
	}
	done := make(chan result, 2)
	for range 2 {
		go func() { a, err := e.Claim(context.Background(), approvalKey(1), cl); done <- result{a, err} }()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("mint blocked")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := e.Submit(ctx, "client", "", approvalDraft(2))
	close(release)
	if err != nil {
		t.Fatalf("mint held writer lock: %v", err)
	}
	a, b := <-done, <-done
	if a.err != nil || b.err != nil || a.a.Claim != ap.ClaimSignatures || !reflect.DeepEqual(a.a.Signatures, b.a.Signatures) {
		t.Fatalf("claims: %+v %+v", a, b)
	}
	if readApproval(t, db, 1).Record.Header.ClaimCount != 2 {
		t.Fatal("claim count")
	}
}

func TestApprovalV2ClaimRechecksClockAfterMint(t *testing.T) {
	for _, back := range []bool{false, true} {
		t.Run(fmt.Sprint(back), func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			cl := approvalReady(t, e, db)
			e.config.Minter = approvalMintFunc(func(_ context.Context, _ ap.ApprovalPlanV1, at time.Time) ([]string, error) {
				if !at.Equal(readApproval(t, db, 1).Record.Header.Decision.DecidedAt) {
					t.Fatal("mint timestamp")
				}
				if back {
					clock.StepWall(-time.Hour)
				} else {
					clock.Advance(time.Hour)
				}
				return []string{"discard"}, nil
			})
			a, err := e.Claim(context.Background(), approvalKey(1), cl)
			if err != nil || len(a.Signatures) != 0 {
				t.Fatalf("claim: %+v %v", a, err)
			}
			want := ap.ClaimExpired
			if back {
				want = ap.ClaimMaterializationError
			}
			if a.Claim != want {
				t.Fatalf("claim=%+v", a)
			}
			if readApproval(t, db, 1).Record.Header.ClaimCount != 0 {
				t.Fatal("discarded mint counted")
			}
		})
	}
}

func approvalReport(cl ap.Claim) ap.Report {
	states := []ap.StepStatus{ap.StepSucceeded}
	return ap.Report{Token: cl.Token, PlanHash: cl.PlanHash, Body: ap.FinalReport{Class: ap.AggregateJobClass(states), ExecutedOrdinals: ap.ExecutedOrdinals(states), Partial: ap.Partial(states), Steps: []ap.StepReport{{Ordinal: 1, Status: ap.StepSucceeded}}, ResultDigest: strings.Repeat("a", 64)}}
}
func TestApprovalV2ReportAndClaimGuards(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	cl := approvalReady(t, e, db)
	ctx := context.Background()
	r := approvalReport(cl)
	_, err := e.Report(ctx, approvalKey(1), r)
	requireApprovalCode(t, err, ap.CodeInvalidReport)
	bad := cl
	bad.Token = [32]byte{}
	_, err = e.Claim(ctx, approvalKey(1), bad)
	requireApprovalCode(t, err, ap.CodeInvalidClaim)
	a, err := e.Claim(ctx, approvalKey(1), cl)
	if err != nil || a.Claim != ap.ClaimSignatures {
		t.Fatalf("claim: %+v %v", a, err)
	}
	clock.Advance(48 * time.Hour)
	if _, err = e.Report(ctx, approvalKey(1), r); err != nil {
		t.Fatal(err)
	}
	before := readApproval(t, db, 1).RecordJSON
	if _, err = e.Report(ctx, approvalKey(1), r); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, readApproval(t, db, 1).RecordJSON) {
		t.Fatal("duplicate report wrote")
	}
	a, err = e.Claim(ctx, approvalKey(1), cl)
	if err != nil || a.Claim != ap.ClaimExecutionReported || len(a.Signatures) != 0 {
		t.Fatalf("reported claim: %+v %v", a, err)
	}
	for _, key := range []sqlitestore.V2Key{{ClientID: "other", RequestID: statetest.ID(1)}, {ClientID: "client", SubPrincipal: "other", RequestID: statetest.ID(1)}} {
		_, err = e.Claim(ctx, key, cl)
		requireApprovalCode(t, err, ap.CodeNotFound)
		_, err = e.Report(ctx, key, r)
		requireApprovalCode(t, err, ap.CodeNotFound)
	}
}

func TestApprovalV2MutationCommitUncertainty(t *testing.T) {
	for _, op := range []string{"vote", "claim", "report"} {
		for _, lands := range []bool{false, true} {
			t.Run(fmt.Sprint(op, lands), func(t *testing.T) {
				e, db, clock := approvalEngineFixture(t, false)
				ctx := context.Background()
				var cl ap.Claim
				if op == "vote" {
					e.config.RequiredApprovals = 2
					submitApproval(t, e, 1)
					if _, _, err := e.mutate(ctx, approvalKey(1), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
						t.Fatal(err)
					}
					approvalVote(t, e, db, "first", ap.VoteApprove, ap.VoteFlags{})
					cl.PlanHash = readApproval(t, db, 1).Record.Header.PlanHash
				} else {
					cl = approvalReady(t, e, db)
				}
				if op == "report" {
					if _, err := e.Claim(ctx, approvalKey(1), cl); err != nil {
						t.Fatal(err)
					}
				}
				row := readApproval(t, db, 1).Record
				run := func() (ap.Answer, error) {
					switch op {
					case "vote":
						return e.Vote(ctx, approvalKey(1), ap.CastVote{Operator: "operator", Decision: ap.VoteApprove, Authn: "webauthn", Hosted: &ap.HostedTap{PlanHash: cl.PlanHash, Revision: 1, Digest: row.Header.Assist.Digest, Actions: ap.ActionsAt(1)}})
					case "report":
						return e.Report(ctx, approvalKey(1), approvalReport(cl))
					default:
						return e.Claim(ctx, approvalKey(1), cl)
					}
				}
				checkVote := func(decided bool, at time.Time) {
					t.Helper()
					h := readApproval(t, db, 1).Record.Header
					if !decided {
						if h.Decision != nil || !reflect.DeepEqual(h.Votes, row.Header.Votes) {
							t.Fatalf("rolled-back deciding vote persisted: %+v", h)
						}
						return
					}
					wantVotes := append(append([]ap.Vote{}, row.Header.Votes...), ap.Vote{Operator: "operator", Decision: ap.VoteApprove, Authn: "webauthn", TS: at})
					if !reflect.DeepEqual(h.Votes, wantVotes) || h.Decision == nil || h.Decision.Status != ap.ApprovalApproved || !h.Decision.DecidedAt.Equal(at) || h.Decision.DecidedBy != "first,operator" {
						t.Fatalf("deciding vote facts: votes=%+v decision=%+v, want timestamp %s", h.Votes, h.Decision, at)
					}
				}
				if op == "vote" {
					checkVote(false, time.Time{})
				}
				clock.Advance(time.Second)
				voteAt := clock.Wall()
				ready := make(chan struct{}, 1)
				e.waiters[approvalKey(1)] = map[chan struct{}]struct{}{ready: {}}
				for len(e.flushNudge) > 0 {
					<-e.flushNudge
				}
				commit := e.commit
				e.commit = func(tx *sql.Tx) error {
					if lands {
						if err := tx.Commit(); err != nil {
							return err
						}
					}
					return errors.New("uncertain")
				}
				a, err := run()
				requireApprovalCode(t, err, ap.CodeStorageUncertain)
				if !reflect.DeepEqual(a, ap.Answer{}) || len(ready) != 0 || len(e.flushNudge) != 0 {
					t.Fatal("uncertain effects")
				}
				if op == "vote" {
					checkVote(lands, voteAt)
				}
				e.commit = commit
				clock.Advance(time.Second)
				if _, err = run(); err != nil {
					t.Fatal(err)
				}
				if op == "vote" {
					if !lands {
						voteAt = clock.Wall()
					}
					checkVote(true, voteAt)
				}
			})
		}
	}
}

type approvalMintCore struct {
	calls    int
	commands []signerkit.HostedSignCommand
	at       time.Time
}

func (c *approvalMintCore) Verdict(context.Context, signerkit.AuditVerdict) error { return nil }
func (c *approvalMintCore) SignApproved(cmds []signerkit.HostedSignCommand, at time.Time) ([]signerkit.HostedSignResult, error) {
	c.calls++
	c.commands = cmds
	c.at = at
	out := make([]signerkit.HostedSignResult, len(cmds))
	for i, cmd := range cmds {
		out[i] = signerkit.HostedSignResult{Cmd: cmd.Cmd, Sig: fmt.Sprint("sig", i)}
	}
	return out, nil
}
func TestApprovalV2MinterReservedVerbRecheck(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	approvalReady(t, e, db)
	plan := readApproval(t, db, 1).Record.Payload.Plan
	core := &approvalMintCore{}
	m := ApprovalV2Minter{Core: core}
	sigs, err := m.Mint(context.Background(), plan, statetest.T0)
	if err != nil || len(sigs) != 1 || core.calls != 1 || !core.at.Equal(statetest.T0) || core.commands[0].HostKeyFP != plan.CommandJob.Steps[0].Target.TrustedHostFingerprint {
		t.Fatalf("mint: %v %v", sigs, err)
	}
	plan.CommandJob.Steps[0].ExactCommand = "SSHGATE_XFER_SEND forged"
	_, err = m.Mint(context.Background(), plan, statetest.T0)
	requireApprovalCode(t, err, ap.CodeRecordCorrupt)
	if core.calls != 1 {
		t.Fatal("corrupt plan reached custody")
	}
}

func TestApprovalV2ClaimAndReportBusy(t *testing.T) {
	for _, op := range []string{"claim", "report", "vote"} {
		t.Run(op, func(t *testing.T) {
			e, db, _ := approvalEngineFixture(t, false)
			cl := approvalReady(t, e, db)
			ctx := context.Background()
			if op == "report" {
				if _, err := e.Claim(ctx, approvalKey(1), cl); err != nil {
					t.Fatal(err)
				}
			}
			before := readApproval(t, db, 1).RecordJSON
			e.config.Store = approvalFaultStore{ApprovalV2Store: db, beginErr: approvalBusy(5)}
			run := func() (ap.Answer, error) {
				switch op {
				case "report":
					return e.Report(ctx, approvalKey(1), approvalReport(cl))
				case "vote":
					return e.Vote(ctx, approvalKey(1), ap.CastVote{Operator: "other", Decision: ap.VoteDeny, Authn: "webauthn", Hosted: &ap.HostedTap{PlanHash: cl.PlanHash}})
				default:
					return e.Claim(ctx, approvalKey(1), cl)
				}
			}
			a, err := run()
			requireApprovalCode(t, err, ap.CodeBusy)
			if len(a.Signatures) != 0 || !bytes.Equal(before, readApproval(t, db, 1).RecordJSON) {
				t.Fatal("busy mutation escaped")
			}
			e.config.Store = db
			if _, err = run(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestApprovalV2ClaimDoesNotMintBeforeAuditOrOnFailure(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	cl := approvalReady(t, e, db)
	ctx := context.Background()
	calls := 0
	e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
		calls++
		return nil, errors.New("custody offline")
	})
	a, err := e.Claim(ctx, approvalKey(1), cl)
	if err != nil || a.Claim != ap.ClaimMaterializationError || a.Reason != ap.MintReasonSigningFailed {
		t.Fatalf("failed mint: %+v %v", a, err)
	}
	if _, err = e.Claim(ctx, approvalKey(1), cl); err != nil || calls != 1 {
		t.Fatal("retried failed mint")
	}
	e, db, _ = approvalEngineFixture(t, false)
	submitApproval(t, e, 1)
	if _, _, err = e.mutate(ctx, approvalKey(1), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	approvalVote(t, e, db, "operator", ap.VoteApprove, ap.VoteFlags{})
	r := readApproval(t, db, 1).Record
	e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
		t.Error("unaudited mint")
		return nil, nil
	})
	a, err = e.Claim(ctx, approvalKey(1), ap.Claim{Token: cl.Token, PlanHash: r.Header.PlanHash})
	if err != nil || a.Claim != ap.ClaimNotReady {
		t.Fatalf("unaudited: %+v %v", a, err)
	}
}

func TestApprovalV2ClaimGateRoundTrip(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	cl := approvalReady(t, e, db)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	core, err := signerkit.New(signerkit.Config{Signer: priv, Audit: signerkit.NewAppendOnlySink(io.Discard)})
	if err != nil {
		t.Fatal(err)
	}
	e.config.Minter = ApprovalV2Minter{Core: core}
	a, err := e.Claim(context.Background(), approvalKey(1), cl)
	if err != nil || a.Claim != ap.ClaimSignatures {
		t.Fatalf("claim: %+v %v", a, err)
	}
	r := readApproval(t, db, 1).Record
	step := r.Payload.Plan.CommandJob.Steps[0]
	command, _, err := gate.VerifySigned(a.Signatures[0], pub, r.Header.Decision.DecidedAt.Add(time.Second), []string{step.Target.TrustedHostFingerprint})
	if err != nil || command != step.ExactCommand {
		t.Fatalf("gate: %q %v", command, err)
	}
}

type approvalCorruptRead struct{ ApprovalV2Store }

func (s approvalCorruptRead) ReadV2(ctx context.Context, key sqlitestore.V2Key) (*sqlitestore.V2Row, error) {
	row, err := s.ApprovalV2Store.ReadV2(ctx, key)
	if err == nil {
		row.Record.Payload.Plan.CommandJob.Steps[0].ExactCommand = "SSHGATE_XFER_SEND forged"
	}
	return row, err
}
func TestApprovalV2CorruptClaimCommitsNothing(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	cl := approvalReady(t, e, db)
	before := readApproval(t, db, 1).RecordJSON
	e.config.Store = approvalCorruptRead{db}
	e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
		t.Error("corrupt mint")
		return nil, nil
	})
	a, err := e.Claim(context.Background(), approvalKey(1), cl)
	requireApprovalCode(t, err, ap.CodeRecordCorrupt)
	if len(a.Signatures) != 0 || !bytes.Equal(before, readApproval(t, db, 1).RecordJSON) {
		t.Fatal("corrupt claim changed row")
	}
}

// The second plain read is the waiter's recheck, after the first Claim transaction.
type approvalWaitRead struct {
	ApprovalV2Store
	afterRead func()
	reads     int
}

func (s *approvalWaitRead) ReadV2(ctx context.Context, key sqlitestore.V2Key) (*sqlitestore.V2Row, error) {
	row, err := s.ApprovalV2Store.ReadV2(ctx, key)
	s.reads++
	if s.reads == 2 {
		s.afterRead()
	}
	return row, err
}

func TestApprovalV2ClaimFlushWait(t *testing.T) {
	for _, mode := range []string{"flush", "timeout", "cancel", "writer", "registration"} {
		t.Run(mode, func(t *testing.T) {
			e, db, _ := approvalEngineFixture(t, true)
			submitApproval(t, e, 1)
			if _, _, err := e.mutate(context.Background(), approvalKey(1), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
				t.Fatal(err)
			}
			approvalVote(t, e, db, "operator", ap.VoteApprove, ap.VoteFlags{})
			r := readApproval(t, db, 1).Record
			cl := ap.Claim{Token: statetest.Token(statetest.ID(1)), PlanHash: r.Header.PlanHash}
			var mints atomic.Int32
			e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
				mints.Add(1)
				return []string{"signature"}, nil
			})
			flush := func() error {
				_, _, err := e.mutate(context.Background(), approvalKey(1), ap.Flush{Through: r.Header.OutboxSeq}, ap.Inputs{})
				return err
			}
			rechecked := make(chan struct{})
			resume := make(chan struct{})
			e.config.Store = &approvalWaitRead{ApprovalV2Store: db, afterRead: func() {
				if mode == "registration" {
					e.mu.Lock()
					registered := len(e.waiters[approvalKey(1)]) > 0
					e.mu.Unlock()
					if !registered {
						t.Error("rechecked before registering")
					}
					if err := flush(); err != nil {
						t.Error(err)
					}
				}
				close(rechecked)
				<-resume
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type result struct {
				answer ap.Answer
				err    error
			}
			done := make(chan result, 1)
			start := time.Now()
			go func() { a, err := e.Claim(ctx, approvalKey(1), cl); done <- result{a, err} }()
			select {
			case <-rechecked:
				close(resume)
			case got := <-done:
				t.Fatalf("Claim returned without waiting: %+v", got)
			case <-time.After(5 * time.Second):
				t.Fatal("Claim did not reach flush recheck")
			}
			switch mode {
			case "cancel":
				cancel()
			case "writer":
				writerCtx, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if _, err := e.Submit(writerCtx, "client", "", approvalDraft(2)); err != nil {
					t.Fatalf("flush wait blocked writer: %v", err)
				}
				fallthrough
			case "flush":
				select {
				case got := <-done:
					t.Fatalf("Claim returned before flush: %+v", got)
				default:
				}
				if err := flush(); err != nil {
					t.Fatal(err)
				}
			}
			var got result
			select {
			case got = <-done:
			case <-time.After(4 * time.Second):
				t.Fatal("Claim did not finish")
			}
			duration := time.Since(start)
			switch mode {
			case "cancel":
				if !errors.Is(got.err, context.Canceled) || mints.Load() != 0 || duration >= time.Second {
					t.Fatalf("cancellation: %+v, mints=%d, duration=%s", got, mints.Load(), duration)
				}
			case "timeout":
				if got.err != nil || got.answer.Claim != ap.ClaimNotReady || mints.Load() != 0 || duration < 1800*time.Millisecond || duration > 4*time.Second || e.config.Store.(*approvalWaitRead).reads != 3 {
					t.Fatalf("timeout: %+v, mints=%d, duration=%s", got, mints.Load(), duration)
				}
			default:
				if got.err != nil || got.answer.Claim != ap.ClaimSignatures || !reflect.DeepEqual(got.answer.Signatures, []string{"signature"}) || mints.Load() != 1 || duration >= 1800*time.Millisecond {
					t.Fatalf("flush completion: %+v, mints=%d, duration=%s", got, mints.Load(), duration)
				}
			}
			e.mu.Lock()
			remaining := len(e.waiters)
			e.mu.Unlock()
			if remaining != 0 {
				t.Fatal("Claim leaked a waiter")
			}
		})
	}
}

func TestApprovalV2ClaimTerminalFlushWait(t *testing.T) {
	for _, status := range []ap.ApprovalStatus{ap.ApprovalDenied, ap.ApprovalCanceled, ap.ApprovalExpired, ap.ApprovalError} {
		t.Run(string(status), func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			submitApproval(t, e, 1)
			apply := func(command ap.Command) {
				t.Helper()
				if _, _, err := e.mutate(context.Background(), approvalKey(1), command, ap.Inputs{}); err != nil {
					t.Fatal(err)
				}
			}
			switch status {
			case ap.ApprovalDenied:
				approvalVote(t, e, db, "operator", ap.VoteDeny, ap.VoteFlags{DenyVeto: true})
			case ap.ApprovalCanceled:
				apply(ap.AdminCancel{PlanHash: readApproval(t, db, 1).Record.Header.PlanHash, Admin: "operator"})
			case ap.ApprovalExpired:
				clock.Advance(ap.ValidityMin + time.Second)
				apply(ap.Tick{})
			case ap.ApprovalError:
				// Persist a notification failure as a local notifier would before migration.
				e.config.Settings.Hosted = false
				apply(ap.BurstStart{})
				apply(ap.BurstDone{Failed: true})
				e.config.Settings.Hosted = true
			}
			r := readApproval(t, db, 1).Record
			if r.Header.Decision == nil || r.Header.Decision.Status != status {
				t.Fatalf("decision: %+v", r.Header.Decision)
			}
			e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
				t.Error("terminal decision minted")
				return nil, nil
			})
			e.config.Store = &approvalWaitRead{ApprovalV2Store: db, afterRead: func() {
				// The recheck holds an unflushed snapshot; the notification must cause a retry.
				apply(ap.Flush{Through: r.Header.OutboxSeq})
			}}
			start := time.Now()
			answer, err := e.Claim(context.Background(), approvalKey(1), ap.Claim{Token: statetest.Token(statetest.ID(1)), PlanHash: r.Header.PlanHash})
			if err != nil || answer.Claim != ap.ClaimStatus(status) || time.Since(start) >= time.Second {
				t.Fatalf("terminal flush: %+v, %v, elapsed %s", answer, err, time.Since(start))
			}
		})
	}
}

type approvalDeadlineRead struct {
	ApprovalV2Store
	engine       *ApprovalV2Engine
	mode         string
	reads        int
	deadline     time.Time
	finalReads   int
	expiredReads int
}

func (s *approvalDeadlineRead) ReadV2(ctx context.Context, key sqlitestore.V2Key) (*sqlitestore.V2Row, error) {
	s.reads++
	if s.reads > 1 {
		deadline, bounded := ctx.Deadline()
		if bounded {
			if ctx.Err() != nil {
				s.expiredReads++
				return nil, ctx.Err()
			}
			if s.deadline.IsZero() {
				s.deadline = deadline
			} else if !deadline.Equal(s.deadline) {
				return nil, errors.New("recheck deadline moved")
			}
			if s.mode == "blocked" {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			// Emulate reads that finish after expiry and a stream of unrelated wakes.
			time.Sleep(150 * time.Millisecond)
			s.engine.mu.Lock()
			for waiter := range s.engine.waiters[key] {
				select {
				case waiter <- struct{}{}:
				default:
				}
			}
			s.engine.mu.Unlock()
		} else {
			s.finalReads++
			if s.reads == 2 {
				return nil, errors.New("recheck has no deadline")
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
	}
	if s.mode == "notifications" {
		return s.ApprovalV2Store.ReadV2(context.Background(), key)
	}
	return s.ApprovalV2Store.ReadV2(ctx, key)
}

func TestApprovalV2ClaimFlushDeadline(t *testing.T) {
	for _, mode := range []string{"blocked", "notifications"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, db, _ := approvalEngineFixture(t, false)
				submitApproval(t, e, 1)
				approvalVote(t, e, db, "operator", ap.VoteDeny, ap.VoteFlags{DenyVeto: true})
				r := readApproval(t, db, 1).Record
				store := &approvalDeadlineRead{ApprovalV2Store: db, engine: e, mode: mode}
				e.config.Store = store
				start := time.Now()
				answer, err := e.Claim(context.Background(), approvalKey(1), ap.Claim{Token: statetest.Token(statetest.ID(1)), PlanHash: r.Header.PlanHash})
				elapsed := time.Since(start)
				if err != nil || answer.Claim != ap.ClaimNotReady || elapsed < 1800*time.Millisecond || elapsed > 2600*time.Millisecond || store.finalReads != 1 || store.expiredReads != 0 {
					t.Fatalf("deadline: %+v, %v, elapsed %s, final retries %d", answer, err, elapsed, store.finalReads)
				}
			})
		})
	}
}
