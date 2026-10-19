package signerkit

import (
	"context"
	"crypto/ed25519"
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
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	lt "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle/lifecycletest"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/approvalreview"
	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/xfer"
	"github.com/karthikeyan5/sshgate/src/xferwire"
)

func adapterTransfer(t *testing.T, at time.Time) (*Service, ap.ApprovalDraft) {
	t.Helper()
	registry, err := LoadXferRegistry(filepath.Join(t.TempDir(), "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i, alias := range []string{"web-1", "db-1"} {
		var box [32]byte
		box[0] = byte(i + 1)
		identity := make(ed25519.PublicKey, 32)
		identity[0] = byte(i + 3)
		if err := registry.Register(st.Fingerprint(alias), "registered-"+alias, xfer.BoxPublicText(&box), xfer.IDPublicText(identity)); err != nil {
			t.Fatal(err)
		}
	}
	draft := st.JobDraft(st.ID(3), ap.CoordinatorExecutor, at, st.Write("touch /tmp/a", 37))
	endpoint := func(alias, path string) ap.TransferEndpoint {
		target := st.Route(alias)
		return ap.TransferEndpoint{Target: target, RegistryEntryDigest: target.Digest(), Path: path}
	}
	draft.Kind, draft.CommandJob = ap.KindTransfer, nil
	draft.Transfer = &ap.Transfer{Source: endpoint("web-1", "/etc/secret"), Destination: endpoint("db-1", "/srv/secret"), Mode: ap.TransferMode, SignatureTTLSeconds: 37}
	key, _ := goldenSignerKey()
	return &Service{daemon: &Daemon{Signer: &countingApprovalSigner{Signer: key}, XferRegistry: registry}}, draft
}

func TestApprovalAdaptersFreezeAndDigests(t *testing.T) {
	ctx := context.Background()
	service, draft := adapterTransfer(t, st.T0)
	freezer := service.ApprovalFreezer(time.Hour)
	plan, err := freezer.Freeze(ctx, draft, st.PrincipalB, "", st.T0)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RequesterPrincipal != st.PrincipalB || plan.SubmittedAt != st.T0 || plan.RequestExpiresAt != st.T0.Add(time.Hour) {
		t.Fatal("freeze lost authoritative ownership or clock")
	}
	transfer := plan.Transfer
	source, _ := service.daemon.XferRegistry.Snapshot(st.Fingerprint("web-1"))
	destination, _ := service.daemon.XferRegistry.Snapshot(st.Fingerprint("db-1"))
	if transfer.Source.PublicKey != source.IDPub || transfer.Destination.PublicKey != destination.BoxPub || transfer.Source.KeyLabel != source.Label || transfer.Destination.KeyLabel != destination.Label {
		t.Fatal("keys or labels not registry-owned")
	}
	box, _ := xfer.ParseBoxPublicText(destination.BoxPub)
	identity, _ := xfer.ParseIDPublicText(source.IDPub)
	send, _ := xferwire.EncodeSend(box, transfer.TransferID, st.Fingerprint("db-1"), draft.Transfer.Source.Path)
	recv, _ := xferwire.EncodeRecv(identity, transfer.TransferID, st.Fingerprint("web-1"), st.Fingerprint("db-1"), ap.TransferMode, draft.Transfer.Destination.Path)
	if transfer.SendCommand != send || transfer.RecvCommand != recv {
		t.Fatal("wrong exact wire legs")
	}
	digests, err := service.ApprovalXferDigests().Current(ctx, *transfer)
	if err != nil || digests.Source != transfer.Source.KeyEntryDigest || digests.Destination != transfer.Destination.KeyEntryDigest {
		t.Fatalf("digests: %+v %v", digests, err)
	}
	second, err := freezer.Freeze(ctx, draft, st.PrincipalB, "", st.T0)
	if err != nil || second.Transfer.TransferID == transfer.TransferID {
		t.Fatal("transfer id reused")
	}
	draft.Transfer.Source.Path = "/changed"
	if transfer.Source.Path != "/etc/secret" {
		t.Fatal("draft aliases frozen plan")
	}
	for _, alias := range []string{"web-1", "db-1"} {
		t.Run(alias, func(t *testing.T) {
			registry := service.daemon.XferRegistry
			registry.mu.Lock()
			saved := registry.servers[st.Fingerprint(alias)]
			delete(registry.servers, st.Fingerprint(alias))
			registry.mu.Unlock()
			defer func() { registry.mu.Lock(); registry.servers[st.Fingerprint(alias)] = saved; registry.mu.Unlock() }()
			if _, err := service.ApprovalXferDigests().Current(ctx, *transfer); err == nil {
				t.Fatal("missing enrollment accepted")
			}
			if _, err := freezer.Freeze(ctx, draft, st.PrincipalB, "", st.T0); err == nil {
				t.Fatal("missing enrollment frozen")
			}
		})
	}
}

func TestApprovalAdaptersMinterRefusals(t *testing.T) {
	for _, route := range []ap.Route{ap.RouteSignedWrite, ap.RouteSignedReveal, ap.RouteSignedAdmin, ap.RouteUnsignedRead} {
		t.Run(string(route), func(t *testing.T) {
			service, _ := adapterTransfer(t, st.T0)
			// Put the forbidden step last: no earlier valid step may reach custody.
			plan := st.Freeze(st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("touch /tmp/a", 60), st.Write("touch /tmp/b", 60)), st.PrincipalA, st.T0, time.Hour)
			step := &plan.CommandJob.Steps[1]
			step.Route, step.ExactCommand = route, "SSHGATE_XFER_SEND attacker"
			digest := sha256.Sum256([]byte(step.ExactCommand))
			step.CommandSHA256 = hex.EncodeToString(digest[:])
			if route == ap.RouteUnsignedRead {
				step.SignatureTTLSeconds = 0
			}
			signatures, err := service.ApprovalMinter().Mint(context.Background(), plan, st.T0)
			var coded *ap.CodeError
			if !errors.As(err, &coded) || coded.Code != ap.CodeRecordCorrupt || len(signatures) != 0 || service.daemon.Signer.(*countingApprovalSigner).calls != 0 {
				t.Fatalf("reserved command reached custody: %v", err)
			}
		})
	}
	for _, alias := range []string{"web-1", "db-1"} {
		t.Run("rotated-"+alias, func(t *testing.T) {
			service, draft := adapterTransfer(t, st.T0)
			plan, err := service.ApprovalFreezer(time.Hour).Freeze(context.Background(), draft, st.PrincipalA, "", st.T0)
			if err != nil {
				t.Fatal(err)
			}
			registry := service.daemon.XferRegistry
			registry.mu.Lock()
			entry := registry.servers[st.Fingerprint(alias)]
			entry.label += "-rotated"
			registry.servers[st.Fingerprint(alias)] = entry
			registry.mu.Unlock()
			signatures, err := service.ApprovalMinter().Mint(context.Background(), plan, st.T0)
			var stale *lc.StaleEnrollmentError
			if !errors.As(err, &stale) || err.Error() != ap.MintReasonStaleTransferKey || len(signatures) != 0 || service.daemon.Signer.(*countingApprovalSigner).calls != 0 {
				t.Fatalf("stale key reached custody: %v", err)
			}
		})
	}
}

func TestApprovalAdaptersSnapshotAndAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := OpenAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	service := &Service{audit: log, daemon: &Daemon{NowFunc: func() time.Time { return st.T0 }}}
	plan := adapterReviewPlan("touch /tmp/a")
	bytes, reason, err := service.ApprovalSnapshotBuilder().BuildSnapshot(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	var salt [32]byte
	want, err := approvalreview.BuildSnapshot(plan, &salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := want.Encode()
	if string(bytes) != string(encoded) || reason != plan.Rationale {
		t.Fatal("snapshot differs from shared renderer")
	}
	metadata := ap.AuditMetadata{RequestID: plan.RequestID, Transition: "vote_refused{expired}", Replay: true, Principal: st.PrincipalA, EventKey: "record:2", RationaleRedacted: reason}
	if err := service.ApprovalAuditWriter().WriteApproval(context.Background(), metadata); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var event AuditEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	if event.TS != st.T0 || event.RequestID != plan.RequestID || event.Status != "approval-"+metadata.Transition || !reflect.DeepEqual(event.Approval, &metadata) || len(event.Commands) != 0 || event.AuthMode != "" {
		t.Fatalf("wrong audit projection: %s", raw)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := service.ApprovalAuditWriter().WriteApproval(context.Background(), metadata); err == nil {
		t.Fatal("sink failure swallowed")
	}
	plan.Rationale = strings.Repeat("a", ap.MaxRationaleBytes+1)
	if _, _, err := service.ApprovalSnapshotBuilder().BuildSnapshot(context.Background(), plan); err == nil {
		t.Fatal("invalid snapshot accepted")
	}
}

func TestApprovalAdaptersCanceledAndUnavailable(t *testing.T) {
	service, draft := adapterTransfer(t, st.T0)
	plan, err := service.ApprovalFreezer(time.Hour).Freeze(context.Background(), draft, st.PrincipalA, "", st.T0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.ApprovalFreezer(time.Hour).Freeze(ctx, draft, st.PrincipalA, "", st.T0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := service.ApprovalMinter().Mint(ctx, plan, st.T0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := service.ApprovalXferDigests().Current(ctx, *plan.Transfer); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := service.ApprovalSnapshotBuilder().BuildSnapshot(ctx, plan); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := service.ApprovalAuditWriter().WriteApproval(ctx, ap.AuditMetadata{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	service.daemon.XferRegistry = nil
	if _, err := service.ApprovalFreezer(time.Hour).Freeze(context.Background(), draft, st.PrincipalA, "", st.T0); err == nil {
		t.Fatal("nil registry frozen")
	}
	if _, err := service.ApprovalXferDigests().Current(context.Background(), *plan.Transfer); err == nil {
		t.Fatal("nil registry read")
	}
	if _, err := service.ApprovalMinter().Mint(context.Background(), plan, st.T0); err == nil {
		t.Fatal("nil registry signed")
	}
	if service.daemon.Signer.(*countingApprovalSigner).calls != 0 {
		t.Fatal("refusal reached custody")
	}
}

func TestApprovalAdaptersRegistryDigestFields(t *testing.T) {
	service, _ := adapterTransfer(t, st.T0)
	registry := service.daemon.XferRegistry
	fp := st.Fingerprint("web-1")
	original, err := registry.Snapshot(fp)
	if err != nil {
		t.Fatal(err)
	}
	saved := registry.servers[fp]
	for _, field := range []string{"label", "box", "id", "added"} {
		entry := saved
		switch field {
		case "label":
			entry.label += "new"
		case "added":
			entry.addedAt = "2026-10-20T00:00:00Z"
		case "box":
			var key [32]byte
			key[0] = 99
			entry.boxPub = xfer.BoxPublicText(&key)
		case "id":
			key := make(ed25519.PublicKey, 32)
			key[0] = 99
			entry.idPub = xfer.IDPublicText(key)
		}
		registry.servers[fp] = entry
		snapshot, err := registry.Snapshot(fp)
		if err != nil || snapshot.EntryDigest == original.EntryDigest {
			t.Fatalf("digest omitted %s: %v", field, err)
		}
	}
	for _, field := range []string{"box", "id"} {
		entry := saved
		if field == "box" {
			entry.boxPub = "bad"
		} else {
			entry.idPub = "bad"
		}
		registry.servers[fp] = entry
		if _, err := registry.Snapshot(fp); err == nil {
			t.Fatal("corrupt key accepted")
		}
	}
}

func TestApprovalAdaptersFreezeCommandsAndGrants(t *testing.T) {
	service := &Service{daemon: &Daemon{}}
	for _, draft := range []ap.ApprovalDraft{
		st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("touch /tmp/a", 60)),
		st.GrantDraft(st.ID(2), "web-1", time.Hour, st.T0, "touch /tmp/a"),
	} {
		plan, err := service.ApprovalFreezer(time.Hour).Freeze(context.Background(), draft, st.PrincipalB, "", st.T0)
		if err != nil {
			t.Fatal(err)
		}
		want, err := ap.FreezeDraft(draft, ap.FreezeInputs{RequesterPrincipal: st.PrincipalB, Now: st.T0, Validity: time.Hour})
		if err != nil || !reflect.DeepEqual(plan, want) {
			t.Fatal("adapter differs from shared freeze")
		}
		if _, err := service.ApprovalFreezer(time.Second).Freeze(context.Background(), draft, st.PrincipalB, "", st.T0); err == nil {
			t.Fatal("invalid validity accepted")
		}
	}
	for _, draft := range []ap.ApprovalDraft{
		st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("SSHGATE_XFER_SEND attack", 60)),
		st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.StepSpec{Route: ap.RouteSignedAdmin, Command: "SSHGATE_REVOKE", TTL: 60, Alias: "web-1"}, st.Write("touch /tmp/a", 60)),
		st.GrantDraft(st.ID(2), "web-1", time.Hour, st.T0, "SSHGATE_REVOKE"),
	} {
		if _, err := service.ApprovalFreezer(time.Hour).Freeze(context.Background(), draft, st.PrincipalA, "", st.T0); err == nil {
			t.Fatal("reserved command or mixed admin accepted")
		}
	}
}

func TestApprovalAdaptersSnapshotRedaction(t *testing.T) {
	service := &Service{daemon: &Daemon{RedactRules: []redact.Rule{redact.CompileRule("fixture", "fixture secret", `secret-value`, nil, 0, 0, 0)}}}
	plan := adapterReviewPlan("echo secret-value > /tmp/a")
	plan.Rationale = "Replace secret-value"
	raw, reason, err := service.ApprovalSnapshotBuilder().BuildSnapshot(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-value") || strings.Contains(reason, "secret-value") || !strings.Contains(reason, ap.HiddenMarker(len("secret-value"), []string{"fixture"})) {
		t.Fatal("snapshot or audit reason leaks secret")
	}
	var salt [32]byte
	expected, err := approvalreview.BuildSnapshot(plan, &salt, service.daemon.RedactRules)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := expected.Encode()
	if string(raw) != string(encoded) {
		t.Fatal("redacted snapshot differs from shared renderer")
	}
	plan.RequesterPrincipal = "local-uid:1000"
	service.daemon.RedactRules = []redact.Rule{redact.CompileRule("identity", "identity", `local-uid:1000`, nil, 0, 0, 0)}
	_, _, err = service.ApprovalSnapshotBuilder().BuildSnapshot(context.Background(), plan)
	if !approvalreview.IsUnrenderable(err) {
		t.Fatalf("secret identity did not fail closed: %v", err)
	}
}

func TestApprovalAdaptersMinterCorruptTransfer(t *testing.T) {
	for _, leg := range []string{"send", "receive", "recipient-key", "sender-key", "send-id", "recv-id", "send-dest", "recv-src", "recv-dest", "send-path", "recv-path", "mode", "frozen-source-key", "frozen-dest-key"} {
		t.Run(leg, func(t *testing.T) {
			service, draft := adapterTransfer(t, st.T0)
			plan, err := service.ApprovalFreezer(time.Hour).Freeze(context.Background(), draft, st.PrincipalA, "", st.T0)
			if err != nil {
				t.Fatal(err)
			}
			if leg == "send" {
				plan.Transfer.SendCommand += " changed"
			} else if leg == "recipient-key" {
				var key [32]byte
				key[0] = 99
				tr := plan.Transfer
				tr.SendCommand, err = xferwire.EncodeSend(&key, tr.TransferID, tr.Destination.Target.TrustedHostFingerprint, tr.Source.Path)
				if err != nil {
					t.Fatal(err)
				}
			} else if leg == "receive" {
				plan.Transfer.RecvCommand += " changed"
			} else if strings.HasPrefix(leg, "frozen-") {
				endpoint := &plan.Transfer.Source
				key := make(ed25519.PublicKey, 32)
				key[0] = 99
				text := xfer.IDPublicText(key)
				if leg == "frozen-dest-key" {
					endpoint = &plan.Transfer.Destination
					text = xfer.BoxPublicText((*[32]byte)(key))
				}
				endpoint.PublicKey = text
				endpoint.PublicKeySHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(text)))
			} else {
				command := &plan.Transfer.RecvCommand
				if strings.HasPrefix(leg, "send-") {
					command = &plan.Transfer.SendCommand
				}
				index, value := 0, ""
				switch leg {
				case "sender-key":
					key := make(ed25519.PublicKey, 32)
					key[0] = 99
					index, value = 1, xfer.IDPublicText(key)
				case "send-id", "recv-id":
					index, value = 2, "x8Kq3YVvH4f2m9WqZr0B1g"
				case "send-dest", "recv-src":
					index, value = 3, st.Fingerprint("other")
				case "recv-dest":
					index, value = 4, st.Fingerprint("other")
				case "send-path":
					index, value = 4, "/different"
				case "recv-path":
					index, value = 6, "/different"
				case "mode":
					index, value = 5, "0644"
				}
				tokens := strings.Split(*command, " ")
				tokens[index] = base64.RawURLEncoding.EncodeToString([]byte(value))
				*command = strings.Join(tokens, " ")
			}
			plan.Transfer.SendCommandSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(plan.Transfer.SendCommand)))
			plan.Transfer.RecvCommandSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(plan.Transfer.RecvCommand)))
			if err := plan.Validate(); err != nil {
				t.Fatalf("fixture must pass hash validation: %v", err)
			}
			signatures, err := service.ApprovalMinter().Mint(context.Background(), plan, st.T0)
			var coded *ap.CodeError
			if !errors.As(err, &coded) || coded.Code != ap.CodeRecordCorrupt || len(signatures) != 0 || service.daemon.Signer.(*countingApprovalSigner).calls != 0 {
				t.Fatalf("corrupt leg reached custody: %v", err)
			}
		})
	}
}

func adapterReviewPlan(command string) ap.ApprovalPlanV1 {
	draft := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write(command, 60))
	step := &draft.CommandJob.Steps[0]
	step.Target.TrustedHostFingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	step.RegistryEntryDigest = step.Target.Digest()
	return st.Freeze(draft, st.PrincipalA, st.T0, time.Hour)
}

type rotatingApprovalDigests struct {
	lc.XferDigests
	registry *XferRegistry
	alias    string
	reads    int
	readErr  error
}

func (d *rotatingApprovalDigests) Current(ctx context.Context, transfer ap.Transfer) (ap.XferDigests, error) {
	d.reads++
	if d.readErr != nil {
		return ap.XferDigests{}, d.readErr
	}
	digests, err := d.XferDigests.Current(ctx, transfer)
	if d.reads == 1 {
		d.registry.mu.Lock()
		entry := d.registry.servers[st.Fingerprint(d.alias)]
		if d.alias == "web-1" {
			key := make(ed25519.PublicKey, 32)
			key[0] = 99
			entry.idPub = xfer.IDPublicText(key)
		} else {
			var key [32]byte
			key[0] = 99
			entry.boxPub = xfer.BoxPublicText(&key)
		}
		d.registry.servers[st.Fingerprint(d.alias)] = entry
		d.registry.mu.Unlock()
	}
	return digests, err
}

type staleApprovalMinter struct {
	lc.Minter
	afterStale func(*lc.StaleEnrollmentError)
	calls      int
}

func (m *staleApprovalMinter) Mint(ctx context.Context, plan ap.ApprovalPlanV1, at time.Time) ([]string, error) {
	m.calls++
	signatures, err := m.Minter.Mint(ctx, plan, at)
	var stale *lc.StaleEnrollmentError
	if errors.As(err, &stale) {
		m.afterStale(stale)
	}
	return signatures, err
}

func TestApprovalAdaptersClaimEnrollmentRotation(t *testing.T) {
	for _, scenario := range []string{"rotated", "canceled", "read-failure", "restored"} {
		for _, alias := range []string{"web-1", "db-1"} {
			t.Run(scenario+"/"+alias, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				service, draft := adapterTransfer(t, st.T0)
				draft.RequestID = st.ID(1)
				draft.ExecutorClaimTokenHash = ap.ClaimTokenHash(st.Token(st.ID(1)))
				plan, err := service.ApprovalFreezer(time.Hour).Freeze(ctx, draft, st.PrincipalA, "", st.T0)
				if err != nil {
					t.Fatal(err)
				}
				trace := lt.RecoveryTrace(t)
				record := trace[len(trace)-1]
				record.Payload.Plan = plan
				record.Header.PlanHash, err = ap.PlanHash(plan)
				if err != nil {
					t.Fatal(err)
				}
				record.Header.Kind = ap.KindTransfer
				record.Header.StepCount = 1
				record.Header.StepTTLs = []int{plan.Transfer.SignatureTTLSeconds}
				record.Header.SubmitNotAfter = plan.SubmitNotAfter
				record.Header.RequestExpiresAt = plan.RequestExpiresAt
				record.Header.AuditedThrough = record.Header.OutboxSeq
				record.Header.Outbox = nil
				store := &lc.MemStore{}
				key := ap.RecordKey(st.PrincipalA, st.ID(1))
				if err := store.Commit(key, record); err != nil {
					t.Fatal(err)
				}
				digests := &rotatingApprovalDigests{XferDigests: service.ApprovalXferDigests(), registry: service.daemon.XferRegistry, alias: alias}
				registry := service.daemon.XferRegistry
				registry.mu.RLock()
				original := registry.servers[st.Fingerprint(alias)]
				registry.mu.RUnlock()
				minter := &staleApprovalMinter{Minter: service.ApprovalMinter(), afterStale: func(stale *lc.StaleEnrollmentError) {
					observed, err := service.ApprovalXferDigests().Current(ctx, *plan.Transfer)
					if err != nil || stale.Digests != observed {
						t.Fatalf("stale evidence: got %+v, observed %+v: %v", stale.Digests, observed, err)
					}
					switch scenario {
					case "canceled":
						cancel()
					case "read-failure":
						digests.readErr = errors.New("registry read failed after stale result")
					case "restored":
						registry.mu.Lock()
						registry.servers[st.Fingerprint(alias)] = original
						registry.mu.Unlock()
					}
				}}
				engine, err := lc.New(lc.Config{Store: store, Clock: elapsedtest.NewFake(st.T0), Freezer: service.ApprovalFreezer(time.Hour), SnapshotBuilder: runtimeSnapshot{}, Minter: minter, XferDigests: digests})
				if err != nil {
					t.Fatal(err)
				}
				defer engine.Close()
				for attempt := 0; attempt < 2; attempt++ {
					claimContext := ctx
					if attempt > 0 {
						claimContext = context.Background()
					}
					answer, err := engine.Claim(claimContext, st.PrincipalA, st.ID(1), ap.Claim{Token: st.Token(st.ID(1)), PlanHash: record.Header.PlanHash})
					if err != nil || answer.Claim != ap.ClaimMaterializationError || answer.Reason != ap.MintReasonStaleTransferKey {
						t.Fatalf("rotation outcome: %+v %v", answer, err)
					}
					persisted, err := store.Load(key)
					if err != nil || persisted.Header.Mint == nil || persisted.Header.Mint.State != ap.MintError || persisted.Header.Mint.Reason != ap.MintReasonStaleTransferKey {
						t.Fatalf("rotation not persisted: %+v %v", persisted.Header.Mint, err)
					}
					if len(persisted.Header.Outbox) != 1 || persisted.Header.Outbox[0].Kind != ap.EventMint || persisted.Header.Outbox[0].Detail != ap.MintReasonStaleTransferKey {
						t.Fatalf("wrong rotation audit event: %+v", persisted.Header.Outbox)
					}
					if digests.reads != 1 || minter.calls != 1 || service.daemon.Signer.(*countingApprovalSigner).calls != 0 {
						t.Fatalf("attempt %d: digest reads=%d, mint calls=%d, custody calls=%d", attempt, digests.reads, minter.calls, service.daemon.Signer.(*countingApprovalSigner).calls)
					}
				}
			})
		}
	}
}
