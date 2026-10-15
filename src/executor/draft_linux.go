//go:build linux

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/executorwire"
	"github.com/karthikeyan5/sshgate/src/gatever"
	"github.com/karthikeyan5/sshgate/src/mcp/jobplan"
)

func (s *Service) buildDraft(in executorwire.Input, tokenHash string) (ap.ApprovalDraft, error) {
	options := jobplan.DraftOptions{RequestID: in.RequestID, Reason: in.Reason,
		ClaimTokenHash: tokenHash, SubmitNotAfter: in.SubmitNotAfter,
		Coordinator: ap.CoordinatorExecutor, MaxOutputBytes: in.MaxOutputBytes}
	alias := in.Server
	if in.Transfer != nil {
		alias = in.Transfer.SourceAlias
	}
	target, _, err := s.servers.ReadCurrent(alias)
	if err != nil {
		return ap.ApprovalDraft{}, refusal("invalid_request")
	}
	switch in.Tool {
	case "run":
		return jobplan.BuildRun(options, target, in.Command, in.Reveal)
	case "run_batch":
		return jobplan.BuildBatch(options, target, in.Commands, in.StopOnError)
	case "revoke_server":
		return jobplan.BuildRevoke(options, target)
	case "update_gate":
		body, err := os.ReadFile(s.stagedGatePath)
		if err != nil || len(body) == 0 {
			return ap.ApprovalDraft{}, refusal("invalid_request")
		}
		hash := sha256.Sum256(body)
		display := ap.TrustedDisplay{StagedBasename: filepath.Base(s.stagedGatePath), StagedVersion: gatever.Scan(body), RunningVersion: gatever.Unknown, Size: int64(len(body))}
		return jobplan.BuildUpdate(options, target, hex.EncodeToString(hash[:]), display)
	case "transfer":
		transfer := in.Transfer
		destination, _, err := s.servers.ReadCurrent(transfer.DestinationAlias)
		if err != nil {
			return ap.ApprovalDraft{}, refusal("invalid_request")
		}
		return jobplan.BuildTransfer(options, target, transfer.SourcePath, destination, transfer.DestinationPath, transfer.Mode)
	}
	return ap.ApprovalDraft{}, refusal("invalid_request")
}
