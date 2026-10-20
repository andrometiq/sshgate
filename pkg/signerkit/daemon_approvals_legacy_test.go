package signerkit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/approvalreview"
	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

type legacyTestAssessor struct {
	inputs  []assist.Input
	release chan struct{}
}

func (a *legacyTestAssessor) Assess(ctx context.Context, input assist.Input) (ap.AssistResult, error) {
	a.inputs = append(a.inputs, input)
	if a.release != nil {
		select {
		case <-a.release:
		case <-ctx.Done():
			return ap.AssistResult{}, ctx.Err()
		}
	}
	effects := make([]string, len(input.Commands))
	for i := range effects {
		effects[i] = "Effect"
	}
	return ap.AssistResult{Alignment: ap.AlignmentAligned, Summary: "Summary", Effects: effects, Model: "test", PromptVersion: assist.PromptVersion, GeneratedAt: time.Now().UTC()}, nil
}

type legacyTestNotifier struct {
	mu        sync.Mutex
	artifacts map[string]*lc.PreparedLegacyApproval
	delivered []*lc.PreparedLegacyApproval
	mutate    func(*lc.LegacyPreparedData)
	fail      bool
}

func (*legacyTestNotifier) Destination() lc.LegacyDestination {
	return lc.LegacyDestination{ChatID: 1, TopicID: 2}
}
func (n *legacyTestNotifier) prepare(p *lc.PreparedLegacyApproval) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.artifacts[p.Data().Instance] = p
	return nil
}
func (n *legacyTestNotifier) Prepared(id string) (*lc.PreparedLegacyApproval, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	p := n.artifacts[id]
	if n.mutate == nil {
		return p, nil
	}
	data := p.Data()
	n.mutate(&data)
	return lc.NewPreparedLegacyApproval(data)
}
func (n *legacyTestNotifier) Deliver(_ context.Context, p *lc.PreparedLegacyApproval) (lc.LegacyDelivery, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.delivered = append(n.delivered, p)
	if n.fail {
		return lc.LegacyDelivery{}, errors.New("failed")
	}
	return lc.LegacyDelivery{AllDelivered: true}, nil
}
func (*legacyTestNotifier) EditStatus(context.Context, *lc.PreparedLegacyApproval, string) error {
	return nil
}

type legacyTestMinter struct{ calls int }

func (m *legacyTestMinter) Mint(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
	m.calls++
	return nil, errors.New("must not mint")
}

type legacyTestFreezer struct{ calls int }

func (f *legacyTestFreezer) Freeze(context.Context, ap.ApprovalDraft, string, string, time.Time) (ap.ApprovalPlanV1, error) {
	f.calls++
	return ap.ApprovalPlanV1{}, errors.New("must not authorize")
}

type legacyHarness struct {
	service   *Service
	runtime   *ApprovalRuntime
	notifier  *legacyTestNotifier
	assessor  *legacyTestAssessor
	store     *runtimeStore
	minter    *legacyTestMinter
	freezer   *legacyTestFreezer
	auditPath string
}

func newLegacyHarness(t *testing.T) *legacyHarness {
	t.Helper()
	service, _ := adapterTransfer(t, time.Now())
	for _, alias := range []string{"web-1", "db-1"} {
		entry, err := service.daemon.XferRegistry.Snapshot(st.Fingerprint(alias))
		if err != nil {
			t.Fatal(err)
		}
		if err := service.daemon.XferRegistry.Register(legacyFingerprint(alias), entry.Label, entry.BoxPub, entry.IDPub); err != nil {
			t.Fatal(err)
		}
	}
	h := &legacyHarness{service: service, store: &runtimeStore{}, notifier: &legacyTestNotifier{artifacts: map[string]*lc.PreparedLegacyApproval{}}, assessor: &legacyTestAssessor{}, minter: &legacyTestMinter{}, freezer: &legacyTestFreezer{}}
	h.auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	audit, auditErr := OpenAuditLog(h.auditPath)
	if auditErr != nil {
		t.Fatal(auditErr)
	}
	t.Cleanup(func() { audit.Close() })
	service.daemon.Audit = audit
	service.audit = audit
	service.daemon.lifecycleSink = audit
	service.daemon.Backend = &StubBackend{}
	service.daemon.RedactRules = []redact.Rule{redact.CompileRule("secret", "secret", `secret-value`, nil, 0, 0, 0)}
	legacy, err := lc.NewLegacyService(lc.LegacyConfig{Clock: elapsed.Real(), LegacyNotifier: h.notifier, Assessor: h.assessor, AuditWriter: service.ApprovalAuditWriter()})
	if err != nil {
		t.Fatal(err)
	}
	c := ApprovalRuntimeConfig{Store: h.store, Legacy: legacy, PrepareLegacy: h.notifier.prepare}
	c.NewEngine = func(s lc.Store) (*lc.Engine, error) {
		return lc.New(lc.Config{Store: s, Clock: elapsed.Real(), Freezer: h.freezer, SnapshotBuilder: runtimeSnapshot{}, Minter: h.minter, LegacyService: legacy})
	}
	h.runtime, err = NewApprovalRuntime(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.AttachApprovals(h.runtime); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { service.Close() })
	return h
}
func (h *legacyHarness) begin(t *testing.T, request any) (*bytes.Buffer, <-chan error) {
	return h.beginContext(t, context.Background(), request)
}

func (h *legacyHarness) beginContext(t *testing.T, ctx context.Context, request any) (*bytes.Buffer, <-chan error) {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	conn := &dispatchConn{Reader: bytes.NewReader(append(raw, '\n'))}
	done := make(chan error, 1)
	go func() {
		done <- h.service.HandleSignRequestWithPeer(ctx, conn, &PeerCredentials{UID: 7})
	}()
	return &conn.Buffer, done
}

type dispatchConn struct {
	*bytes.Reader
	bytes.Buffer
}

func (c *dispatchConn) Read(b []byte) (int, error)  { return c.Reader.Read(b) }
func (c *dispatchConn) Write(b []byte) (int, error) { return c.Buffer.Write(b) }
func legacySignFrame(net bool) signRequest {
	return signRequest{Kind: "sign", RequestID: "legacy", Commands: []signRequestCmd{{Server: "web-1", Host: legacyFingerprint("web-1"), Cmd: "cat /etc/hosts", TTLSec: 37, Net: net, Reason: "check network"}}}
}
func (h *legacyHarness) vote(t *testing.T, decision string) {
	t.Helper()
	if len(h.notifier.delivered) != 1 {
		t.Fatalf("deliveries=%d", len(h.notifier.delivered))
	}
	d := h.notifier.delivered[0].Data()
	r, e := h.runtime.Legacy().VoteLegacy(ap.CastVote{Operator: st.Operator, Decision: decision, Card: &ap.CardTap{Handle: d.Context.Handle, Challenge: d.Context.Challenge}}, func(lc.LegacyTapResult) {})
	if e != nil || !r.Resolved {
		t.Fatalf("vote=%+v %v", r, e)
	}
}
func (h *legacyHarness) isolated(t *testing.T, signatures int) {
	t.Helper()
	records, err := h.store.List()
	if err != nil || len(records) != 0 || h.minter.calls != 0 || h.freezer.calls != 0 {
		t.Fatalf("advisory escaped: records=%v mint=%d freeze=%d err=%v", records, h.minter.calls, h.freezer.calls, err)
	}
	if got := h.service.daemon.Signer.(*countingApprovalSigner).calls; got != signatures {
		t.Fatalf("custody calls=%d want %d", got, signatures)
	}
}

func (h *legacyHarness) frame(t *testing.T, kind string) any {
	t.Helper()
	var request any = legacySignFrame(false)
	switch kind {
	case "request_grant":
		request = grantRequest{Kind: kind, RequestID: "legacy", Alias: "web-1", Scope: "all", DurationSec: 60}
	case "transfer":
		request = transferRequest{Kind: kind, RequestID: "legacy", SrcFP: legacyFingerprint("web-1"), DestFP: legacyFingerprint("db-1"), SrcPath: "/etc/secret", DestPath: "/srv/secret", Mode: "0600", TTLSec: 37}
	case "register_xfer_key":
		entry, err := h.service.daemon.XferRegistry.Snapshot(legacyFingerprint("web-1"))
		if err != nil {
			t.Fatal(err)
		}
		request = registerXferKeyRequest{Kind: kind, RequestID: "legacy", HostFP: legacyFingerprint("new-host"), Label: "new-registration", BoxPub: entry.BoxPub, IDPub: entry.IDPub}
	}
	return request
}

func TestLegacyApproveFourCallSites(t *testing.T) {
	for _, kind := range []string{"sign", "request_grant", "transfer", "register_xfer_key"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newLegacyHarness(t)
				request := h.frame(t, kind)
				response, done := h.begin(t, request)
				synctest.Wait()
				if len(h.assessor.inputs) != 1 || len(h.notifier.delivered) != 1 {
					t.Fatalf("did not route through legacy approval: %s", response.String())
				}
				h.isolated(t, 0)
				data := h.notifier.delivered[0].Data()
				if data.Context.Assist.Result == nil || data.Context.Assist.Result.Alignment != ap.AlignmentNotAssessed {
					t.Fatal("legacy alignment assessed")
				}
				h.vote(t, ap.VoteDeny)
				synctest.Wait()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(response.String(), `"status":"denied"`) {
					t.Fatal(response.String())
				}
				h.isolated(t, 0)
			})
		})
	}
}

func TestLegacyNetRefusalsBeforePreparation(t *testing.T) {
	for _, name := range []string{"batch", "reason", "admin", "write"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newLegacyHarness(t)
				r := legacySignFrame(true)
				switch name {
				case "batch":
					r.Commands = append(r.Commands, r.Commands[0])
				case "reason":
					r.Commands[0].Reason = " "
				case "admin":
					r.Commands[0].Cmd = "SSHGATE_REVOKE"
				case "write":
					r.Commands[0].Cmd = "touch /tmp/no"
				}
				response, done := h.begin(t, r)
				synctest.Wait()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				wantError := map[string]string{
					"batch":  "network requires a single-command request",
					"reason": "network requires a non-empty reason",
					"admin":  "network is not available for admin verbs",
					"write":  "network grants cover reads only",
				}[name]
				want := `{"request_id":"legacy","status":"error","error":"` + wantError + `","proto_version":` + fmt.Sprint(sigwire.ProtoVersion) + "}\n"
				if response.String() != want {
					t.Fatalf("Net refusal changed: got %s want %s", response, want)
				}
				if len(h.assessor.inputs) != 0 || len(h.notifier.artifacts) != 0 {
					t.Fatal("Net refusal reached preparation")
				}
				h.isolated(t, 0)
			})
		})
	}
}

func TestPreparedLegacySendsArtifact(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newLegacyHarness(t)
		request := legacySignFrame(true)
		request.Commands[0].Reveal = true
		response, done := h.begin(t, request)
		synctest.Wait()
		h.isolated(t, 0)
		input := h.assessor.inputs[0]
		raw, _ := json.Marshal(input)
		if strings.Contains(string(raw), `"net"`) || !reflect.DeepEqual(input.Commands, []string{request.Commands[0].Cmd}) {
			t.Fatal("provider input mismatch")
		}
		h.vote(t, ap.VoteApprove)
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		var result signResponse
		if err := json.Unmarshal(response.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Signatures) != 1 {
			t.Fatal(response.String())
		}
		_, payload, err := sigwire.DecodeSigned(result.Signatures[0].Sig)
		if err != nil {
			t.Fatal(err)
		}
		data := h.notifier.delivered[0].Data()
		in := data.Inputs[0]
		if payload.Cmd != in.Command || payload.Host != in.HostFingerprint || payload.Exp-payload.TS != in.TTLSeconds || payload.Reveal != in.Reveal || payload.Net != in.Net {
			t.Fatalf("wrong signature: %+v", payload)
		}
		h.isolated(t, 1)
	})
}

func TestPreparedLegacyAuthoritative(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newLegacyHarness(t)
		_, done := h.begin(t, legacySignFrame(true))
		synctest.Wait()
		data := h.notifier.delivered[0].Data()
		var snapshot approvalreview.ReviewSnapshot
		if err := json.Unmarshal(data.Snapshot, &snapshot); err != nil {
			t.Fatal(err)
		}
		var salt [32]byte
		expected, err := approvalreview.BuildPreparedSignSnapshot(data.Instance, data.Inputs, approvalreview.LegacyMeta{RequestID: "legacy", Requester: "local-uid:7", SubmittedAt: snapshot.SubmittedAt, ExpiresAt: snapshot.ExpiresAt}, &salt, h.service.daemon.RedactRules)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := expected.Encode()
		if !bytes.Equal(encoded, data.Snapshot) {
			t.Fatal("snapshot not authoritative")
		}
		view, err := approvalreview.BuildView(expected, approvalreview.Assist{State: data.Context.Assist.State, Result: data.Context.Assist.Result, Reason: data.Context.Assist.Reason})
		if err != nil {
			t.Fatal(err)
		}
		parts, _ := approvalreview.PackParts(view, data.Context.Handle)
		card, _ := approvalreview.DecisionCard(view, data.Context.Handle, len(parts))
		if len(data.Payload) != len(parts)+1 {
			t.Fatal("wrong payload count")
		}
		for i, part := range append(parts, card) {
			if string(data.Payload[i].Bytes) != part {
				t.Fatal("render differs")
			}
		}
		last := data.Payload[len(parts)]
		if last.ApproveLabel != view.ApproveLabel || last.DenyLabel != view.DenyLabel {
			t.Fatal("labels differ")
		}
		h.vote(t, ap.VoteDeny)
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestPreparedLegacySequence(t *testing.T) {
	for _, ready := range []bool{true, false} {
		t.Run(map[bool]string{true: "ready", false: "unavailable"}[ready], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newLegacyHarness(t)
				h.assessor.release = make(chan struct{})
				_, done := h.begin(t, legacySignFrame(true))
				synctest.Wait()
				h.notifier.mu.Lock()
				rendered := len(h.notifier.artifacts) != 0 || len(h.notifier.delivered) != 0
				h.notifier.mu.Unlock()
				if len(h.assessor.inputs) != 1 || rendered {
					t.Fatal("render or delivery before terminal assist")
				}
				if ready {
					close(h.assessor.release)
				} else {
					time.Sleep(6 * time.Second)
				}
				synctest.Wait()
				if len(h.notifier.delivered) != 1 {
					t.Fatal("no delivery after assist")
				}
				data := h.notifier.delivered[0].Data()
				if !ap.ValidCardHandle(data.Context.Handle) || !ap.ValidChallenge(data.Context.Challenge) || data.Context.Destination != h.notifier.Destination() {
					t.Fatal("context not frozen")
				}
				want := ap.AssistUnavailable
				if ready {
					want = ap.AssistReady
				}
				if data.Context.Assist.State != want {
					t.Fatal("wrong assist state")
				}
				h.vote(t, ap.VoteDeny)
				synctest.Wait()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestPreparedLegacyRefusesMismatch(t *testing.T) {
	t.Run("swapped-snapshots", testPreparedLegacySwappedSnapshots)
	snapshotChange := func(f func(*approvalreview.ReviewSnapshot)) func(*lc.LegacyPreparedData) {
		return func(d *lc.LegacyPreparedData) {
			var s approvalreview.ReviewSnapshot
			json.Unmarshal(d.Snapshot, &s)
			f(&s)
			d.Snapshot, _ = json.Marshal(s)
		}
	}
	cases := map[string]func(*lc.LegacyPreparedData){
		"command-bytes": func(d *lc.LegacyPreparedData) {
			d.Inputs[0].Command = "cat /wrong"
			hash := sha256.Sum256([]byte(d.Inputs[0].Command))
			d.Inputs[0].CommandSHA256 = hex.EncodeToString(hash[:])
			d.SignDigest, _ = ap.LegacySignDigest(d.Instance, d.Inputs)
		},
		"command-hash":     snapshotChange(func(s *approvalreview.ReviewSnapshot) { s.Steps[0].Command.SHA256 = strings.Repeat("a", 64) }),
		"host-fingerprint": snapshotChange(func(s *approvalreview.ReviewSnapshot) { s.Steps[0].Target.Fingerprint = legacyFingerprint("db-1") }),
		"ttl":              snapshotChange(func(s *approvalreview.ReviewSnapshot) { s.Steps[0].TTLSeconds++ }),
		"reveal":           snapshotChange(func(s *approvalreview.ReviewSnapshot) { s.Steps[0].Reveal = true }),
		"net":              snapshotChange(func(s *approvalreview.ReviewSnapshot) { s.Steps[0].Net = false }),
		"step-count":       snapshotChange(func(s *approvalreview.ReviewSnapshot) { s.Steps = append(s.Steps, s.Steps[0]) }),
		"step-order":       snapshotChange(func(s *approvalreview.ReviewSnapshot) { s.Steps[0].Ordinal = 2 }),
		"reason-display": snapshotChange(func(s *approvalreview.ReviewSnapshot) {
			s.Steps[0].LegacyReason.Segments = []approvalreview.Segment{{Text: "wrong reason"}}
		}),
		"headline":      func(d *lc.LegacyPreparedData) { d.Payload[len(d.Payload)-1].Bytes = []byte("wrong headline") },
		"approve-label": func(d *lc.LegacyPreparedData) { d.Payload[len(d.Payload)-1].ApproveLabel = "Approve something else" },
		"assist":        func(d *lc.LegacyPreparedData) { d.Context.Assist.Result.Summary = "Different summary" },
		"handle":        func(d *lc.LegacyPreparedData) { d.Context.Handle = "abcdefghijkl" },
		"challenge":     func(d *lc.LegacyPreparedData) { d.Context.Challenge = "0123456789abcdef" },
		"destination":   func(d *lc.LegacyPreparedData) { d.Context.Destination.ChatID++ },
		"part-bytes":    func(d *lc.LegacyPreparedData) { d.Payload[0].Bytes = append(d.Payload[0].Bytes, '!') },
		"visible-segments-only": snapshotChange(func(s *approvalreview.ReviewSnapshot) {
			s.Steps[0].Command.Segments = []approvalreview.Segment{{Text: "cat /wrong"}}
		}),
		"missing-banner": func(d *lc.LegacyPreparedData) {
			for i := range d.Payload {
				d.Payload[i].Bytes = bytes.ReplaceAll(d.Payload[i].Bytes, []byte(ap.NetworkBanner("web-1")), nil)
			}
		},
		"missing-network-label": func(d *lc.LegacyPreparedData) {
			for i := range d.Payload {
				d.Payload[i].Bytes = bytes.ReplaceAll(d.Payload[i].Bytes, []byte(ap.LabelNetworkJustification), nil)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newLegacyHarness(t)
				h.notifier.mutate = mutate
				response, done := h.begin(t, legacySignFrame(true))
				synctest.Wait()
				if len(h.notifier.delivered) > 0 {
					h.vote(t, ap.VoteApprove)
					synctest.Wait()
					<-done
					t.Logf("render-mismatch-signed: %s", response)
					t.Fatal("MUTATION-EFFECT legacy-prepared-skip-check")
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(response.String(), "net_unsupported:") {
					t.Fatal(response.String())
				}
				h.isolated(t, 0)
				audit, err := os.ReadFile(h.auditPath)
				if err != nil {
					t.Fatal(err)
				}
				lines := bytes.Split(bytes.TrimSpace(audit), []byte("\n"))
				if len(lines) != 1 || !bytes.Contains(lines[0], []byte(`"status":"error"`)) {
					t.Fatalf("wrong refusal audit: %s", audit)
				}
			})
		})
	}
}

func TestPreparedLegacyImmutable(t *testing.T) {
	t.Run("getter-payload", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newLegacyHarness(t)
			_, done := h.begin(t, legacySignFrame(true))
			synctest.Wait()
			artifact := h.notifier.delivered[0]
			before := artifact.Data()
			frozen, err := json.Marshal(before)
			if err != nil {
				t.Fatal(err)
			}
			got := artifact.Data()
			got.Payload[0].Bytes[0] = '!'
			after, err := json.Marshal(artifact.Data())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(frozen, after) {
				t.Fatal("MUTATION-EFFECT legacy-prepared-shallow-copy")
			}
			got = artifact.Data()
			got.Inputs[0].Command = "wrong"
			got.Snapshot[0] = '!'
			got.Context.Metadata[0] = '!'
			got.Context.Assist.Result.Effects[0] = "wrong"
			got.Payload[0].ApproveLabel = "wrong"
			if !reflect.DeepEqual(before, artifact.Data()) {
				t.Fatal("MUTATION-EFFECT legacy-prepared-shallow-copy")
			}
			copy, err := lc.NewPreparedLegacyApproval(before)
			if err != nil {
				t.Fatal(err)
			}
			before.Payload[0].Bytes[0] = '!'
			before.Context.Assist.Result.Summary = "wrong"
			if !reflect.DeepEqual(copy.Data(), artifact.Data()) {
				t.Fatal("constructor aliases input")
			}
			h.vote(t, ap.VoteDeny)
			synctest.Wait()
			<-done
		})
	})
}

func TestLegacyWireBytesUnchanged(t *testing.T) {
	for _, kind := range []string{"sign", "request_grant", "transfer", "register_xfer_key"} {
		for _, decision := range []string{ap.VoteApprove, ap.VoteDeny} {
			t.Run(kind+"/"+decision, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					h, direct := newLegacyHarness(t), newLegacyHarness(t)
					request := h.frame(t, kind)
					if kind == "sign" {
						request = legacySignFrame(true)
					}
					at := time.Now()
					h.service.daemon.NowFunc = func() time.Time { return at }
					direct.service.daemon.NowFunc = func() time.Time { return at }
					original := randRead
					defer func() { randRead = original }()
					randRead = fixedEntropy()
					response, done := h.begin(t, request)
					synctest.Wait()
					h.vote(t, decision)
					synctest.Wait()
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					mock := NewMockBackend()
					if decision == ap.VoteApprove {
						mock.Approve("legacy", st.Operator)
					} else {
						mock.Deny("legacy")
					}
					direct.service.daemon.Backend = mock
					raw, _ := json.Marshal(request)
					conn := &dispatchConn{Reader: bytes.NewReader(append(raw, '\n'))}
					randRead = fixedEntropy()
					if err := direct.service.daemon.HandleSignRequest(context.Background(), conn); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(response.Bytes(), conn.Buffer.Bytes()) {
						t.Fatalf("v1 wire drift:\n%s\n%s", response, conn.Buffer.String())
					}
					approved := decision == ap.VoteApprove
					status := "denied"
					if approved {
						status = "approved"
					}
					if !strings.Contains(response.String(), `"status":"`+status+`"`) {
						t.Fatal(response.String())
					}
					signatures := 0
					switch kind {
					case "sign":
						if approved {
							signatures = 1
						}
					case "request_grant":
						got, exists := h.service.daemon.grants["web-1"]
						if exists != approved || !reflect.DeepEqual(h.service.daemon.grants, direct.service.daemon.grants) {
							t.Fatal("grant effects differ")
						}
						if approved {
							var result grantResponse
							if err := json.Unmarshal(response.Bytes(), &result); err != nil {
								t.Fatal(err)
							}
							if got.id != result.GrantID || got.alias != "web-1" || got.scope != "all" || !got.expiry.Equal(at.Add(time.Minute)) {
								t.Fatalf("wrong grant: %+v", got)
							}
						}
					case "transfer":
						if approved {
							signatures = 2
							var result transferResponse
							if err := json.Unmarshal(response.Bytes(), &result); err != nil {
								t.Fatal(err)
							}
							if result.Send == nil || result.Recv == nil || result.XferID == "" {
								t.Fatal("missing transfer legs")
							}
							for i, leg := range []*transferLeg{result.Send, result.Recv} {
								_, payload, err := sigwire.DecodeSigned(leg.Sig)
								if err != nil {
									t.Fatal(err)
								}
								host := []string{legacyFingerprint("web-1"), legacyFingerprint("db-1")}[i]
								if payload.Cmd != leg.Cmd || payload.Host != host || payload.TS != at.Unix() || payload.Exp != at.Unix()+37 || payload.Net || payload.Reveal {
									t.Fatalf("wrong transfer payload: %+v", payload)
								}
							}
						}
					case "register_xfer_key":
						for _, fixture := range []*legacyHarness{h, direct} {
							registry, err := LoadXferRegistry(fixture.service.daemon.XferRegistry.path)
							if err != nil {
								t.Fatal(err)
							}
							r := request.(registerXferKeyRequest)
							entry, err := registry.Snapshot(r.HostFP)
							if approved {
								if err != nil || entry.Label != r.Label || entry.BoxPub != r.BoxPub || entry.IDPub != r.IDPub {
									t.Fatalf("registration not persisted: %+v %v", entry, err)
								}
							} else if err == nil {
								t.Fatal("denied registration persisted")
							}
						}
					}
					h.isolated(t, signatures)
					direct.isolated(t, signatures)
				})
			})
		}
	}
}

func TestPreparedLegacyDeliveryFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newLegacyHarness(t)
		h.notifier.fail = true
		response, done := h.begin(t, legacySignFrame(true))
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(response.String(), `"error":"backend: legacy card delivery failed"`) {
			t.Fatal(response.String())
		}
		data := h.notifier.delivered[0].Data()
		result, err := h.runtime.Legacy().VoteLegacy(ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Card: &ap.CardTap{Handle: data.Context.Handle, Challenge: data.Context.Challenge}}, func(lc.LegacyTapResult) {})
		if err != nil || result.Resolved {
			t.Fatal("failed delivery activated approval")
		}
		h.isolated(t, 0)
	})
}

func TestPreparedLegacySnapshotChecks(t *testing.T) {
	request := legacySignFrame(false)
	request.Commands = append(request.Commands, signRequestCmd{Server: "web-1", Host: legacyFingerprint("web-1"), Cmd: "cat /etc/resolv.conf", TTLSec: 60})
	commands := []CommandReq{}
	for _, c := range request.Commands {
		commands = append(commands, CommandReq{Server: c.Server, HostKeyFP: c.Host, Cmd: c.Cmd, TTLSec: c.TTLSec, Reveal: c.Reveal, Net: c.Net, Reason: c.Reason})
	}
	inputs := legacySignInputs(commands)
	instance := st.Epoch(1)
	var salt [32]byte
	snapshot, err := approvalreview.BuildPreparedSignSnapshot(instance, inputs, approvalreview.LegacyMeta{RequestID: "legacy", Requester: "local-uid:7", SubmittedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, &salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !legacySnapshotMatches(instance, inputs, snapshot) {
		t.Fatal("valid snapshot refused")
	}
	for _, name := range []string{"hash", "count", "order", "alias", "host", "ttl", "reveal", "net", "digest"} {
		t.Run(name, func(t *testing.T) {
			altered := snapshot
			altered.Steps = append([]approvalreview.Step(nil), snapshot.Steps...)
			switch name {
			case "hash":
				altered.Steps[0].Command.SHA256 = "wrong"
			case "count":
				altered.Steps = altered.Steps[:1]
			case "order":
				altered.Steps[0], altered.Steps[1] = altered.Steps[1], altered.Steps[0]
			case "alias":
				altered.Steps[0].Target.Alias = "wrong"
			case "host":
				altered.Steps[0].Target.Fingerprint = "wrong"
			case "ttl":
				altered.Steps[0].TTLSeconds++
			case "reveal":
				altered.Steps[0].Reveal = true
			case "net":
				altered.Steps[0].Net = true
			case "digest":
				altered.SignDigest = "wrong"
			}
			if legacySnapshotMatches(instance, inputs, altered) {
				t.Fatal("snapshot mismatch accepted")
			}
		})
	}
}

func testPreparedLegacySwappedSnapshots(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newLegacyHarness(t)
		// Prepare both instances before either comparison/delivery, then swap echoes.
		caller := approvalCaller{runtime: h.runtime, uid: 7, hasPeer: true, principal: "local-uid:7"}
		a := ApprovalRequest{RequestID: "one", Submitted: time.Now(), Commands: []CommandReq{{Server: "web-1", Cmd: "cat /etc/hosts", TTLSec: 60, Net: true, Reason: "check"}}}
		b := a
		b.RequestID = "two"
		b.Commands = append([]CommandReq(nil), a.Commands...)
		b.Commands[0].Cmd = "cat /etc/resolv.conf"
		p1, r1, err := h.service.daemon.prepareLegacy(context.Background(), caller, a, nil)
		if err != nil {
			t.Fatal(err)
		}
		p2, r2, err := h.service.daemon.prepareLegacy(context.Background(), caller, b, nil)
		if err != nil {
			t.Fatal(err)
		}
		h.notifier.artifacts[p1.Data().Instance] = p2
		h.notifier.artifacts[p2.Data().Instance] = p1
		for i, r := range []*lc.LegacyReservation{r1, r2} {
			p := []*lc.PreparedLegacyApproval{p1, p2}[i]
			if err := h.runtime.Legacy().DeliverLegacy(r, p); err == nil {
				t.Fatal("render-mismatch-signed")
			}
		}
		if len(h.notifier.delivered) != 0 {
			t.Fatal("swapped artifacts delivered")
		}
		h.isolated(t, 0)
	})
}

func TestLegacyTimeoutAndDisconnect(t *testing.T) {
	for _, mode := range []string{"deadline", "disconnect", "preparing-disconnect"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newLegacyHarness(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if mode == "preparing-disconnect" {
					h.assessor.release = make(chan struct{})
				}
				response, done := h.beginContext(t, ctx, legacySignFrame(true))
				synctest.Wait()
				if mode == "deadline" {
					time.Sleep(sigwire.ApprovalWindow)
				} else {
					cancel()
				}
				synctest.Wait()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(response.String(), `"status":"timeout"`) {
					t.Fatal(response.String())
				}
				h.isolated(t, 0)
				if mode != "preparing-disconnect" {
					original := bytes.Clone(response.Bytes())
					data := h.notifier.delivered[0].Data()
					result, err := h.runtime.Legacy().VoteLegacy(ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Card: &ap.CardTap{Handle: data.Context.Handle, Challenge: data.Context.Challenge}}, func(lc.LegacyTapResult) {})
					if err != nil || result.Resolved || result.Answer != lc.LegacyTapRefused {
						t.Fatal("late tap accepted")
					}
					if !bytes.Equal(original, response.Bytes()) {
						t.Fatal("late tap changed response bytes")
					}
					h.isolated(t, 0)
					rows := approvalAuditRows(t, h.service, h.auditPath)
					count := 0
					for _, row := range rows {
						if row.Approval != nil && row.Approval.Transition == "legacy_vote_refused{expired}" {
							count++
						}
					}
					if count != 1 {
						t.Fatalf("late tap audit rows: %+v", rows)
					}
				}
			})
		})
	}
}

func TestLegacyAssistInputIsAdvisory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newLegacyHarness(t)
		request := legacySignFrame(false)
		request.Commands[0].Cmd = "printf secret-value"
		request.Commands = append(request.Commands, signRequestCmd{Server: "web-1", Cmd: "cat /etc/hosts", TTLSec: 60})
		_, done := h.begin(t, request)
		synctest.Wait()
		input := h.assessor.inputs[0]
		if input.Kind != ap.KindCommandJob || input.Reason != ap.LegacyRationaleText || len(input.Commands) != 2 || strings.Contains(input.Commands[0], "secret-value") || !strings.HasPrefix(input.Commands[0], "printf ") || input.Commands[1] != "cat /etc/hosts" {
			t.Fatalf("unsafe or reordered assist input: %+v", input)
		}
		h.isolated(t, 0)
		h.vote(t, ap.VoteDeny)
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		h.isolated(t, 0)
	})
}

func TestPreparedLegacySigningInputMismatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newLegacyHarness(t)
		request := legacySignFrame(true)
		_, done := h.begin(t, request)
		synctest.Wait()
		artifact := h.notifier.delivered[0]
		request.Commands[0].Cmd = "cat /other"
		var response bytes.Buffer
		if err := h.service.daemon.respondLegacy(&response, request, Result{Status: StatusApproved, ApprovedBy: st.Operator}, artifact); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(response.String(), "net_unsupported:") {
			t.Fatal("mismatched socket input signed")
		}
		h.isolated(t, 0)
		h.vote(t, ap.VoteDeny)
		synctest.Wait()
		<-done
	})
}

func TestLegacyRedactionFailureNeverCallsProvider(t *testing.T) {
	for _, kind := range []string{"sign", "request_grant", "transfer", "register_xfer_key"} {
		for _, decision := range []string{ap.VoteApprove, ap.VoteDeny} {
			t.Run(kind+"/"+decision, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					h := newLegacyHarness(t)
					h.service.daemon.RedactRules = nil
					response, done := h.begin(t, h.frame(t, kind))
					synctest.Wait()
					if len(h.assessor.inputs) != 0 || len(h.notifier.delivered) != 1 {
						t.Fatal("redaction failure called provider or prevented delivery")
					}
					data := h.notifier.delivered[0].Data()
					if data.Context.Assist.State != ap.AssistUnavailable || data.Context.Assist.Reason != assist.ReasonRedaction || data.Context.Assist.Result != nil {
						t.Fatal("wrong frozen assist")
					}
					card := string(data.Payload[len(data.Payload)-1].Bytes)
					if !strings.Contains(card, "AI advisory: unavailable") || !strings.Contains(card, assist.ReasonRedaction) {
						t.Fatalf("missing unavailable advisory: %s", card)
					}
					h.isolated(t, 0)
					select {
					case <-done:
						t.Fatal("resolved before human vote")
					default:
					}
					h.vote(t, decision)
					synctest.Wait()
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					status := "denied"
					signatures := 0
					if decision == ap.VoteApprove {
						status = "approved"
						if kind == "sign" {
							signatures = 1
						}
						if kind == "transfer" {
							signatures = 2
						}
					}
					if !strings.Contains(response.String(), `"status":"`+status+`"`) {
						t.Fatal(response.String())
					}
					if len(h.assessor.inputs) != 0 {
						t.Fatal("provider called after resolution")
					}
					h.isolated(t, signatures)
				})
			})
		}
	}
}

func legacyFingerprint(alias string) string {
	sum := sha256.Sum256([]byte(alias))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func TestLegacySnapshotFailureStillRefuses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newLegacyHarness(t)
		h.service.daemon.RedactRules = nil
		request := legacySignFrame(false)
		request.Commands[0].Host = "invalid-fingerprint"
		response, done := h.begin(t, request)
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(response.String(), `"status":"error"`) || !strings.Contains(response.String(), "backend:") {
			t.Fatal(response.String())
		}
		if len(h.assessor.inputs) != 0 || len(h.notifier.delivered) != 0 {
			t.Fatal("snapshot failure reached provider or delivery")
		}
		h.isolated(t, 0)
	})
}
