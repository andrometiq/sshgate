package jobplan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/classify"
)

// DraftOptions are fixed by the caller before building or retrying a request.
// SubmitNotAfter is passed unchanged, including for executor jobs. The caller
// resolves the output cap; zero preserves synchronous unlimited capture.
type DraftOptions struct {
	RequestID      string
	Reason         string
	ClaimTokenHash string
	SubmitNotAfter time.Time
	Coordinator    approvalplan.Coordinator
	MaxOutputBytes int64
}

// BuildRun builds a single-command approval. Ordinary reads need no draft and
// are rejected by the shared validator; reveal always requires approval.
func BuildRun(options DraftOptions, target approvalplan.RouteSnapshot, command string, reveal bool) (approvalplan.ApprovalDraft, error) {
	route := approvalplan.RouteSignedReveal
	if !reveal {
		var err error
		if route, err = commandRoute(command, 0); err != nil {
			return approvalplan.ApprovalDraft{}, err
		}
	}
	return buildCommands(options, target, []string{command}, []approvalplan.Route{route}, nil, nil)
}

// BuildBatch retains every command in order, including unsigned reads. Bulk
// reveal is deliberately not an input to this API.
func BuildBatch(options DraftOptions, target approvalplan.RouteSnapshot, commands []string, stopOnError *bool) (approvalplan.ApprovalDraft, error) {
	if len(commands) > approvalplan.MaxSteps {
		return approvalplan.ApprovalDraft{}, tooManySteps()
	}
	routes := make([]approvalplan.Route, len(commands))
	for i, command := range commands {
		route, err := commandRoute(command, i)
		if err != nil {
			return approvalplan.ApprovalDraft{}, err
		}
		routes[i] = route
	}
	return buildCommands(options, target, commands, routes, stopOnError, nil)
}

// BuildRevoke builds the sole administrative step for server removal.
func BuildRevoke(options DraftOptions, target approvalplan.RouteSnapshot) (approvalplan.ApprovalDraft, error) {
	return buildCommands(options, target, []string{"SSHGATE_REVOKE"}, []approvalplan.Route{approvalplan.RouteSignedAdmin}, nil, nil)
}

// BuildUpdate takes the staged binary hash and metadata from the local adapter,
// never from tool input. The hash is bound through the exact command bytes.
func BuildUpdate(options DraftOptions, target approvalplan.RouteSnapshot, binarySHA256 string, display approvalplan.TrustedDisplay) (approvalplan.ApprovalDraft, error) {
	return buildCommands(options, target, []string{"SSHGATE_UPDATE " + binarySHA256}, []approvalplan.Route{approvalplan.RouteSignedAdmin}, nil, &display)
}

// commandRoute refuses a command the classifier cannot parse (for example a
// bare ";"), as the ordinary run tool does, instead of asking for approval.
func commandRoute(command string, index int) (approvalplan.Route, error) {
	switch classify.Classify(command) {
	case classify.KindRead:
		return approvalplan.RouteUnsignedRead, nil
	case classify.KindUnknown:
		return "", &approvalplan.CodeError{Code: approvalplan.CodeInvalidRequest, Field: fmt.Sprintf("steps[%d].exact_command", index), Msg: "is not a parseable command"}
	}
	return approvalplan.RouteSignedWrite, nil
}

func buildCommands(options DraftOptions, target approvalplan.RouteSnapshot, commands []string, routes []approvalplan.Route, stopOnError *bool, display *approvalplan.TrustedDisplay) (approvalplan.ApprovalDraft, error) {
	policy := approvalplan.StopClassDefaultWritesOnly
	if stopOnError != nil {
		policy = approvalplan.StopNever
		if *stopOnError {
			policy = approvalplan.StopAnyNonzero
		}
	}
	steps := make([]approvalplan.Step, len(commands))
	for i, command := range commands {
		if strings.TrimSpace(command) == "" {
			return approvalplan.ApprovalDraft{}, &approvalplan.CodeError{Code: approvalplan.CodeInvalidRequest, Field: "exact_command", Msg: "must not be blank"}
		}
		if err := approvalplan.ValidateStepBytes(routes[i], command); err != nil {
			return approvalplan.ApprovalDraft{}, err
		}
		if routes[i].Signed() && target.ReadOnly {
			return approvalplan.ApprovalDraft{}, readOnlyTarget()
		}
		sum := sha256.Sum256([]byte(command))
		steps[i] = approvalplan.Step{Ordinal: i + 1, Route: routes[i], Target: target,
			RegistryEntryDigest: target.Digest(), ExactCommand: command, CommandSHA256: hex.EncodeToString(sum[:]),
			SignatureTTLSeconds: approvalplan.MaxStepTTL(routes[i], command), TrustedDisplay: display}
	}
	draft := newDraft(options, approvalplan.KindCommandJob)
	draft.CommandJob = &approvalplan.CommandJob{Steps: steps, StopPolicy: policy, MaxOutputBytes: options.MaxOutputBytes}
	return validateDraft(draft)
}

// BuildGrant copies the exact allow-list; no command classification can widen it.
// Grants have no executor or claim token, so those options must be empty.
func BuildGrant(options DraftOptions, target approvalplan.RouteSnapshot, scope approvalplan.GrantScope, commands []string, durationSeconds int) (approvalplan.ApprovalDraft, error) {
	if target.ReadOnly {
		return approvalplan.ApprovalDraft{}, readOnlyTarget()
	}
	if err := approvalplan.ValidateRouteSnapshot(target); err != nil {
		return approvalplan.ApprovalDraft{}, err
	}
	if len(commands) > approvalplan.MaxSteps {
		return approvalplan.ApprovalDraft{}, tooManySteps()
	}
	draft := newDraft(options, approvalplan.KindStandingGrant)
	draft.StandingGrant = &approvalplan.StandingGrant{Alias: target.ServerAlias, Scope: scope,
		Commands: append([]string(nil), commands...), DurationSeconds: durationSeconds,
		TrustedHostFingerprint: target.TrustedHostFingerprint, RegistryEntryDigest: target.Digest()}
	return validateDraft(draft)
}

// BuildTransfer carries only requester route facts and paths. Keys, IDs and
// transfer commands are resolved by the signer when it freezes the draft.
func BuildTransfer(options DraftOptions, source approvalplan.RouteSnapshot, sourcePath string, destination approvalplan.RouteSnapshot, destinationPath, mode string) (approvalplan.ApprovalDraft, error) {
	if source.ReadOnly || destination.ReadOnly {
		return approvalplan.ApprovalDraft{}, readOnlyTarget()
	}
	if mode == "" {
		mode = approvalplan.TransferMode
	}
	draft := newDraft(options, approvalplan.KindTransfer)
	draft.Transfer = &approvalplan.Transfer{
		Source:      approvalplan.TransferEndpoint{Target: source, RegistryEntryDigest: source.Digest(), Path: sourcePath},
		Destination: approvalplan.TransferEndpoint{Target: destination, RegistryEntryDigest: destination.Digest(), Path: destinationPath},
		Mode:        mode, SignatureTTLSeconds: approvalplan.MaxTransferTTLSeconds}
	return validateDraft(draft)
}

func newDraft(options DraftOptions, kind approvalplan.Kind) approvalplan.ApprovalDraft {
	return approvalplan.ApprovalDraft{Version: approvalplan.DraftVersion, Kind: kind,
		RequestID: options.RequestID, Rationale: options.Reason, ExecutorClaimTokenHash: options.ClaimTokenHash,
		SubmitNotAfter: options.SubmitNotAfter, Coordinator: options.Coordinator}
}

func validateDraft(draft approvalplan.ApprovalDraft) (approvalplan.ApprovalDraft, error) {
	reason, err := approvalplan.ValidateRationale(draft.Rationale)
	if err != nil {
		return approvalplan.ApprovalDraft{}, err
	}
	draft.Rationale = reason
	if err := draft.Validate(); err != nil {
		return approvalplan.ApprovalDraft{}, err
	}
	return draft, nil
}

func readOnlyTarget() error {
	return &approvalplan.CodeError{Code: approvalplan.CodeInvalidRequest, Field: "target.read_only", Msg: "signed operations require a signed-write server"}
}

func tooManySteps() error {
	return &approvalplan.CodeError{Code: approvalplan.CodeRequestTooLarge, Field: "steps", Msg: "too many commands"}
}
