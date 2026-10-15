// Package statetest is the property and model harness of the pure state core
// (SA-11): fixture builders, a two-reading clock fake, the transition
// invariants every commit must keep, and a model of signer, executor,
// Telegram and gate fakes that drives random schedules with crash injection
// after every commit. It imports the standard library and approvalplan only,
// so every store (A6, B1, A10, C1, C2) can run the same properties.
package statetest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// T0 is the fixtures' starting wall clock.
var T0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// Principals and an operator.
const (
	PrincipalA = "local-uid:1000"
	PrincipalB = "local-uid:1001"
	Operator   = "telegram:42"
	Admin      = "telegram:42"
)

// Review is the fixtures' review snapshot.
var Review = json.RawMessage(`{"segments":[]}`)

// Fingerprint is a fixed host key fingerprint per alias.
func Fingerprint(alias string) string {
	sum := sha256.Sum256([]byte(alias))
	return "SHA256:" + hex.EncodeToString(sum[:])[:43]
}

// Route is a registry snapshot of alias.
func Route(alias string) ap.RouteSnapshot {
	return ap.RouteSnapshot{
		ServerAlias: alias, ResolvedHost: alias + ".example.net", ResolvedPort: 22, ResolvedUser: "deploy",
		TrustedHostFingerprint: Fingerprint(alias), AddedAt: time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
	}
}

// StepSpec describes one command_job step.
type StepSpec struct {
	Route   ap.Route
	Command string
	TTL     int
	Alias   string
}

// Write, Read and Reveal are one-step specs on web-1.
func Write(cmd string, ttl int) StepSpec {
	return StepSpec{Route: ap.RouteSignedWrite, Command: cmd, TTL: ttl, Alias: "web-1"}
}
func Read(cmd string) StepSpec {
	return StepSpec{Route: ap.RouteUnsignedRead, Command: cmd, Alias: "web-1"}
}
func Reveal(cmd string) StepSpec {
	return StepSpec{Route: ap.RouteSignedReveal, Command: cmd, TTL: 60, Alias: "web-1"}
}

// Token is a deterministic claim token per request ID.
func Token(id string) [32]byte { return sha256.Sum256([]byte("token:" + id)) }

// ID is the n-th fixture request ID.
func ID(n int) string { return fmt.Sprintf("a2_%022d", n) }

// JobDraft is a command_job draft submitted at now.
func JobDraft(id string, coord ap.Coordinator, now time.Time, specs ...StepSpec) ap.ApprovalDraft {
	steps := make([]ap.Step, len(specs))
	for i, s := range specs {
		target := Route(s.Alias)
		sum := sha256.Sum256([]byte(s.Command))
		steps[i] = ap.Step{
			Ordinal: i + 1, Route: s.Route, Target: target, RegistryEntryDigest: target.Digest(),
			ExactCommand: s.Command, CommandSHA256: hex.EncodeToString(sum[:]), SignatureTTLSeconds: s.TTL,
		}
	}
	maxOut := int64(1 << 20)
	if coord == ap.CoordinatorInProcessSync {
		maxOut = 0
	}
	return ap.ApprovalDraft{
		Version: ap.DraftVersion, Kind: ap.KindCommandJob, RequestID: id, Rationale: "Rotate logs on web-1",
		ExecutorClaimTokenHash: ap.ClaimTokenHash(Token(id)), SubmitNotAfter: now.Add(ap.SubmitWindowMax),
		Coordinator: coord, CommandJob: &ap.CommandJob{Steps: steps, StopPolicy: ap.StopClassDefaultWritesOnly, MaxOutputBytes: maxOut},
	}
}

// GrantDraft is a standing-grant draft for alias; no commands means scope all.
func GrantDraft(id, alias string, duration time.Duration, now time.Time, commands ...string) ap.ApprovalDraft {
	scope := ap.GrantScopeAll
	if len(commands) > 0 {
		scope = ap.GrantScopeCommands
	}
	return ap.ApprovalDraft{
		Version: ap.DraftVersion, Kind: ap.KindStandingGrant, RequestID: id, Rationale: "Maintenance window on " + alias,
		SubmitNotAfter: now.Add(ap.SubmitWindowMax),
		StandingGrant: &ap.StandingGrant{
			Alias: alias, Scope: scope, Commands: commands, DurationSeconds: int(duration / time.Second),
			TrustedHostFingerprint: Fingerprint(alias), RegistryEntryDigest: Route(alias).Digest(),
		},
	}
}

// Freeze is the plan a signer freezes from d at now, valid for validity.
func Freeze(d ap.ApprovalDraft, principal string, now time.Time, validity time.Duration) ap.ApprovalPlanV1 {
	return ap.ApprovalPlanV1{
		Version: ap.PlanVersion, Kind: d.Kind, RequestID: d.RequestID, RequesterPrincipal: principal,
		SubmittedAt: now, RequestExpiresAt: now.Add(validity), Rationale: d.Rationale, RationaleOrigin: ap.OriginAgent,
		ExecutorClaimTokenHash: d.ExecutorClaimTokenHash, SubmitNotAfter: d.SubmitNotAfter, Coordinator: d.Coordinator,
		CommandJob: d.CommandJob, StandingGrant: d.StandingGrant,
	}
}

// AssistTimeout is the fixtures' assist deadline after freeze (E68's cap).
const AssistTimeout = 5 * time.Second

// SubmitOf is the Submit command that freezes d for principal at now.
func SubmitOf(d ap.ApprovalDraft, principal string, now time.Time, validity time.Duration) ap.Submit {
	return ap.Submit{
		Draft: d, Plan: Freeze(d, principal, now, validity), ReviewSnapshot: Review, RationaleRedacted: d.Rationale,
		RequiredApprovals: 1, AssistDeadline: now.Add(AssistTimeout), Allowance: ap.LocalSkew,
	}
}

// Assist is a valid provider result generated at now.
func Assist(now time.Time) ap.AssistResult {
	sum := sha256.Sum256([]byte("input"))
	return ap.AssistResult{
		Alignment: ap.AlignmentAligned, Summary: "Rotates the logs.", Model: "model-x", PromptVersion: "assist-v1",
		InputDigest: hex.EncodeToString(sum[:]), GeneratedAt: now,
	}
}

// Epoch is the n-th fixture epoch.
func Epoch(n int) string { return fmt.Sprintf("%032x", n) }

// Sig is a fake signature envelope: distinct per (request, leg, nonce), so a
// re-mint is visibly different bytes.
func Sig(id string, leg, nonce int) string {
	return fmt.Sprintf("SSHGATE_SIG:%s.%d.%d", id[3:], leg, nonce)
}
