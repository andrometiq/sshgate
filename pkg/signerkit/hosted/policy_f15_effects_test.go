package hosted

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/src/policyreview"
	"github.com/karthikeyan5/sshgate/src/policywire"
	"github.com/karthikeyan5/sshgate/src/redact"
)

type policyFetchSpy struct {
	policystore.Store
	result      policystore.FetchResult
	fetchCalls  int
	lookupCalls int
}

type rosterCadenceClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *rosterCadenceClock) set(now time.Time) {
	clock.mu.Lock()
	clock.now = now
	clock.mu.Unlock()
}

func (clock *rosterCadenceClock) advance(duration time.Duration) time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
	return clock.now
}

func (clock *rosterCadenceClock) read() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

type rosterCadenceStore struct {
	policystore.Store
	clock       *rosterCadenceClock
	duration    time.Duration
	completions chan time.Time
}

func (store *rosterCadenceStore) ReconcilePendingAttainability(context.Context, string, time.Time) (policystore.AttainabilityResult, error) {
	store.completions <- store.clock.advance(store.duration)
	return policystore.AttainabilityResult{}, nil
}

func TestRosterWorkerCompletionCadenceUsesFakeClock(t *testing.T) {
	base := time.Unix(30_000, 0).UTC()
	clock := &rosterCadenceClock{now: base}
	const sweepDuration = 7 * time.Second
	store := &rosterCadenceStore{clock: clock, duration: sweepDuration, completions: make(chan time.Time, 2)}
	engine := newTestEngine(t, store, newTestPolicyCore(t), &testPolicyAudit{}, base, nil)
	engine.now = clock.read
	ticks := make(chan time.Time, 2)
	server := NewServer("secret", nil, nil)
	server.policyRosterTick = ticks
	ctx, cancel := context.WithCancel(context.Background())
	server.policyWorkers.Add(1)
	go server.runRosterWorker(ctx, engine)
	t.Cleanup(func() {
		cancel()
		server.policyWorkers.Wait()
	})

	completions := make([]time.Time, 0, 2)
	for sweep := 1; sweep <= 2; sweep++ {
		started := base.Add(time.Duration(sweep) * policyRosterSweepInterval)
		clock.set(started)
		ticks <- started
		select {
		case completed := <-store.completions:
			completions = append(completions, completed)
		case <-time.After(time.Second):
			t.Fatalf("fake-clock roster sweep %d did not complete", sweep)
		}
	}
	gap := completions[1].Sub(completions[0])
	if maximum := 30*time.Second + sweepDuration; gap > maximum {
		t.Fatalf("completion-to-completion cadence = %s; exceeds %s", gap, maximum)
	}
}

func (store *policyFetchSpy) Fetch(context.Context, policystore.Key) (policystore.FetchResult, error) {
	store.fetchCalls++
	return store.result, nil
}

func (store *policyFetchSpy) Lookup(context.Context, policystore.Key, policystore.RequestTuple) (policystore.LookupResult, error) {
	store.lookupCalls++
	return policystore.LookupResult{}, policystore.ErrCorrupt
}

func TestPolicyGETUsesExactlyOneFetchAndNoLookup(t *testing.T) {
	requestID := "pm_11111111111111111111111111111111"
	core := newTestPolicyCore(t)
	body, err := policywire.MarshalResponse(policywire.Response{
		RequestID: requestID, AuthorityID: testPolicyAuthority, Purpose: policywire.Purpose,
		Status: policywire.StatusPending, PayloadSHA256: strings.Repeat("1", 64),
		BaseDigest: strings.Repeat("2", 64), SignerKeyID: core.keyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &policyFetchSpy{result: policystore.FetchResult{
		Class: policystore.RowLive, Visibility: policystore.VisibilityPending, PendingResponse: body,
	}}
	audit := &testPolicyAudit{}
	engine := newTestEngine(t, store, core, audit, time.Now().UTC(), nil)
	lease, archive := testPolicyArchive(t)
	defer lease.Close()
	handler, err := NewPolicyMachineHandler(engine, archive)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer("secret", nil, nil)
	server.MachineClientID = "machine"
	server.Human = &HumanAPI{}
	if err := server.AttachPolicy(&PolicyAPIConfig{Engine: engine, Handler: handler, Archive: archive, Lease: lease, DurableAudit: audit}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Readiness().SetReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v2/policy/base-manifests/"+requestID, nil)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !bytes.Equal(response.Body.Bytes(), body) {
		t.Fatalf("GET response = %d %q; want %q", response.Code, response.Body.Bytes(), body)
	}
	if store.fetchCalls != 1 || store.lookupCalls != 0 {
		t.Fatalf("GET store calls: Fetch=%d Lookup=%d; want 1/0", store.fetchCalls, store.lookupCalls)
	}
}

func TestPolicyReviewSaltIsIndependentAcrossEngineInstancesAndNotPersisted(t *testing.T) {
	core := newTestPolicyCore(t)
	rule := redact.CompileRule("review-test", "review test", `(<review>)`, []string{"<review>"}, 1, 1, 32)
	salts := [][32]byte{{1}, {2}}
	stores := []*admissionCaptureStore{{headErr: policystore.ErrNotFound}, {headErr: policystore.ErrNotFound}}
	for index := range stores {
		random := append(bytes.Repeat([]byte{byte(0xa0 + index)}, 16), bytes.Repeat([]byte{byte(index + 1)}, 32)...)
		for saltIndex := 1; saltIndex < len(salts[index]); saltIndex++ {
			salts[index][saltIndex] = byte(index + 1)
		}
		engine, err := NewPolicyEngine(PolicyEngineConfig{
			AuthorityID: testPolicyAuthority, WorkerID: "worker", Store: stores[index], Core: core,
			Audit: &testPolicyAudit{}, Random: bytes.NewReader(random), ReviewRules: []redact.Rule{rule},
			RedactString: redact.RedactString,
		})
		if err != nil {
			t.Fatal(err)
		}
		admission := testPolicyAdmission(t, core.keyID, "pm_11111111111111111111111111111111", "", true, 1)
		if _, err := engine.Admit(context.Background(), admission); err != nil {
			t.Fatal(err)
		}
	}
	markers := []string{
		redact.FormatMarker(salts[0], []byte("<review>")),
		redact.FormatMarker(salts[1], []byte("<review>")),
	}
	if markers[0] == markers[1] {
		t.Fatal("independent engine salts produced the same deterministic marker")
	}
	for index, store := range stores {
		if len(store.inputs) != 1 || !bytes.Contains(store.inputs[0].ReviewJSON, []byte(markers[index])) {
			t.Fatalf("engine %d persisted review without its independent marker: %+v", index, store.inputs)
		}
		for _, encoding := range []string{hex.EncodeToString(salts[index][:]), base64.StdEncoding.EncodeToString(salts[index][:])} {
			if bytes.Contains(store.inputs[0].ReviewJSON, []byte(encoding)) {
				t.Fatalf("engine %d persisted raw review salt encoding %q", index, encoding)
			}
		}
		if store.inputs[0].ReviewRendererVersion != policyreview.RendererVersion || store.inputs[0].ReviewRulesDigest != policyreview.RulesDigest() {
			t.Fatalf("engine %d persisted incomplete review binding", index)
		}
	}
}

func TestPolicyPendingAndVoteRecoveryReuseOneLeaseForEightAttempts(t *testing.T) {
	for _, crashPoint := range []PolicyFaultPoint{PolicyFaultAfterVoteAcknowledged, PolicyFaultAfterVoteAudit} {
		t.Run(string(crashPoint), func(t *testing.T) {
			database, store, core, audit, input := newHostedPolicyHarness(t, 1)
			defer database.Close()
			crash := errors.New("crash before synchronous claim")
			engine := newTestEngine(t, store, core, audit, input.Now, func(point PolicyFaultPoint) error {
				if point == crashPoint {
					return crash
				}
				return nil
			})
			if _, err := engine.Submit(context.Background(), input); err != nil {
				t.Fatal(err)
			}
			_, err := engine.Vote(context.Background(), policystore.VoteInput{
				ReviewID: input.ReviewID, Operator: "voter", Decision: policystore.DecisionApprove,
				AuthnMethod: policystore.AuthnSession, Now: input.Now,
			})
			if !errors.Is(err, crash) {
				t.Fatalf("vote crash = %v", err)
			}
			before, err := store.GetByReviewID(context.Background(), input.ReviewID)
			if err != nil || before.State != policystore.StatePending || before.RecoveryLeaseGeneration != 0 {
				t.Fatalf("pre-recovery row = %+v, %v", before, err)
			}

			core.failMint = true
			core.mintCalls.Store(0)
			var delays []time.Duration
			recovery, err := NewPolicyEngine(PolicyEngineConfig{
				AuthorityID: testPolicyAuthority, WorkerID: "recovery-worker", Store: store, Core: core, Audit: audit,
				Now:    func() time.Time { return input.Now.Add(time.Second) },
				Sleep:  func(_ context.Context, delay time.Duration) error { delays = append(delays, delay); return nil },
				Jitter: func(delay time.Duration) time.Duration { return delay },
			})
			if err != nil {
				t.Fatal(err)
			}
			if crashPoint == PolicyFaultAfterVoteAudit {
				page, err := store.ListUnauditedVotes(context.Background(), testPolicyAuthority, nil, policyRecoveryPageSize)
				if err != nil || len(page.Votes) != 1 {
					t.Fatalf("unaudited vote page = %+v, %v", page, err)
				}
				if err := recovery.recoverVoteGroup(context.Background(), input.Key, page.Votes); err != nil {
					t.Fatal(err)
				}
			} else if err := recovery.RecoverOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			after, err := store.GetByReviewID(context.Background(), input.ReviewID)
			if err != nil {
				t.Fatal(err)
			}
			if after.State != policystore.StateErrorReceived || after.RecoveryLeaseGeneration != 1 ||
				after.RecoveryLeaseOwner != "" || after.RecoveryLeaseUntil != 0 {
				t.Fatalf("post-recovery row = %+v", after)
			}
			if core.mintCalls.Load() != policyRecoveryMaxAttempts || len(delays) != policyRecoveryMaxAttempts-1 {
				t.Fatalf("recovery attempts=%d backoffs=%d; want %d/%d", core.mintCalls.Load(), len(delays), policyRecoveryMaxAttempts, policyRecoveryMaxAttempts-1)
			}
		})
	}
}
