package approvalplan

import "time"

// FreezeInputs contains signer-owned values, never fields decoded from a request.
// The caller authenticates the principal, chooses validity, and supplies its clock.
// Submit-window admission and idempotency remain the engine's responsibility.
type FreezeInputs struct {
	RequesterPrincipal string
	RequesterSub       string
	Now                time.Time
	Validity           time.Duration
	Transfer           *TransferFreezeInputs
}

// TransferKeySnapshot is the relevant key from the signer's transfer registry:
// the source identity key or the destination box key. EntryDigest covers the
// registry entry, not just this key; the caller computes it at snapshot time.
type TransferKeySnapshot struct {
	HostFingerprint string
	Label           string
	PublicKey       string
	EntryDigest     string
}

// TransferFreezeInputs supplies signer-minted randomness and exact wire legs.
// The caller builds both legs with xferwire from these snapshots, the transfer
// ID and the draft paths/mode. FreezeDraft does not parse or construct that wire.
type TransferFreezeInputs struct {
	Source      TransferKeySnapshot
	Destination TransferKeySnapshot
	TransferID  string
	SendCommand string
	RecvCommand string
}

// FreezeDraft validates and copies a draft into an independent frozen plan.
// Registry access, randomness and transfer-wire construction belong to callers.
func FreezeDraft(d ApprovalDraft, f FreezeInputs) (ApprovalPlanV1, error) {
	if err := d.Validate(); err != nil {
		return ApprovalPlanV1{}, err
	}
	if (d.Transfer != nil) != (f.Transfer != nil) {
		return ApprovalPlanV1{}, invalid("transfer", "signer transfer inputs are required exactly for a transfer")
	}
	p := ApprovalPlanV1{
		Version: PlanVersion, Kind: d.Kind, RequestID: d.RequestID,
		RequesterPrincipal: f.RequesterPrincipal, RequesterSub: f.RequesterSub,
		SubmittedAt: f.Now, RequestExpiresAt: f.Now.Add(f.Validity),
		Rationale: d.Rationale, RationaleOrigin: OriginAgent,
		ExecutorClaimTokenHash: d.ExecutorClaimTokenHash,
		SubmitNotAfter:         d.SubmitNotAfter, Coordinator: d.Coordinator,
	}
	if d.CommandJob != nil {
		job := *d.CommandJob
		job.Steps = append([]Step(nil), job.Steps...)
		for i := range job.Steps {
			if display := job.Steps[i].TrustedDisplay; display != nil {
				copy := *display
				job.Steps[i].TrustedDisplay = &copy
			}
		}
		p.CommandJob = &job
	}
	if d.StandingGrant != nil {
		grant := *d.StandingGrant
		if grant.Commands != nil {
			grant.Commands = append([]string{}, grant.Commands...)
		}
		p.StandingGrant = &grant
	}
	if d.Transfer != nil {
		transfer := *d.Transfer
		for _, endpoint := range []struct {
			name string
			dest *TransferEndpoint
			key  TransferKeySnapshot
		}{
			{"source", &transfer.Source, f.Transfer.Source},
			{"destination", &transfer.Destination, f.Transfer.Destination},
		} {
			if endpoint.key.HostFingerprint != endpoint.dest.Target.TrustedHostFingerprint {
				return ApprovalPlanV1{}, invalid("transfer."+endpoint.name, "registry snapshot fingerprint does not match target")
			}
			endpoint.dest.KeyLabel = endpoint.key.Label
			endpoint.dest.PublicKey = endpoint.key.PublicKey
			endpoint.dest.PublicKeySHA256 = sha256Hex(endpoint.key.PublicKey)
			endpoint.dest.KeyEntryDigest = endpoint.key.EntryDigest
		}
		transfer.TransferID = f.Transfer.TransferID
		transfer.SendCommand = f.Transfer.SendCommand
		transfer.RecvCommand = f.Transfer.RecvCommand
		transfer.SendCommandSHA256 = sha256Hex(transfer.SendCommand)
		transfer.RecvCommandSHA256 = sha256Hex(transfer.RecvCommand)
		p.Transfer = &transfer
	}
	if err := p.Validate(); err != nil {
		return ApprovalPlanV1{}, err
	}
	return p, nil
}
