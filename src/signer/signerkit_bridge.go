package signer

// Compatibility bridge for the signerkit extraction.
//
// The signing core (daemon.go/audit.go/keystore.go/xferregistry.go/
// socket.go) moved to pkg/signerkit; the local cmd/sshgate-signer-telegram
// entry point and every external test still reference these symbols through
// package signer. Go has no function or const aliases, so the bridge is:
// type aliases for types, var re-declarations for constructors/helpers, and
// a const re-declaration for MaxGrantDuration. These aliases die at phase 6
// when all imports flip to pkg/signerkit directly.

import "github.com/karthikeyan5/sshgate/pkg/signerkit"

// Core types.
type (
	Daemon         = signerkit.Daemon
	Server         = signerkit.Server
	RequestHandler = signerkit.RequestHandler
	AuditLog       = signerkit.AuditLog
	AuditEvent     = signerkit.AuditEvent
	XferRegistry   = signerkit.XferRegistry
)

// Constructors and loaders (Go has no func aliases).
var (
	LoadKey          = signerkit.LoadKey
	GenerateKeyPair  = signerkit.GenerateKeyPair
	OpenAuditLog     = signerkit.OpenAuditLog
	NewMemAuditLog   = signerkit.NewMemAuditLog
	LoadXferRegistry = signerkit.LoadXferRegistry
)

// MaxGrantDuration re-exported (Go has no const aliases).
const MaxGrantDuration = signerkit.MaxGrantDuration
