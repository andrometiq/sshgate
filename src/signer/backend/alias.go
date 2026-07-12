package backend

// Compatibility bridge for the signerkit extraction.
//
// The approval-channel seam (backend.go/stub.go/mock.go/hosted.go) moved
// to pkg/signerkit; the Telegram front-end (telegram.go/chatstore.go/
// explainer.go) and every external consumer still reference these symbols
// through package backend. Go has no function or const aliases, so the
// bridge is: type aliases for types, const re-declarations for consts, and
// var re-declarations for constructors. These aliases die at phase 6 when
// all imports flip to pkg/signerkit directly.

import "github.com/karthikeyan5/sshgate/pkg/signerkit"

// Approval-request payloads and the command shape.
type (
	ApprovalRequest         = signerkit.ApprovalRequest
	GrantApprovalRequest    = signerkit.GrantApprovalRequest
	TransferApprovalRequest = signerkit.TransferApprovalRequest
	RegisterApprovalRequest = signerkit.RegisterApprovalRequest
	CommandReq              = signerkit.CommandReq
)

// Result, its status enum, and the signed-command payload.
type (
	ResultStatus = signerkit.ResultStatus
	SignedCmd    = signerkit.SignedCmd
	Result       = signerkit.Result
)

// The approval-channel interface and its concrete implementations.
type (
	Backend             = signerkit.Backend
	StubBackend         = signerkit.StubBackend
	MockBackend         = signerkit.MockBackend
	HostedServerBackend = signerkit.HostedServerBackend
)

// ResultStatus values (typed consts — Go has no const aliases).
const (
	StatusApproved = signerkit.StatusApproved
	StatusDenied   = signerkit.StatusDenied
	StatusTimeout  = signerkit.StatusTimeout
)

// NewMockBackend constructs the test fixture (Go has no func aliases).
var NewMockBackend = signerkit.NewMockBackend
