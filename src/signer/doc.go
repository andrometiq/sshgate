// Package signer is a compatibility bridge during the signerkit
// extraction. The local approval daemon that owns the master Ed25519
// signing key now lives in pkg/signerkit; this package re-exports the
// symbols the local cmd/sshgate-signer-telegram entry point and the
// external tests still reference (Daemon, Server, RequestHandler,
// AuditLog, AuditEvent, XferRegistry, LoadKey, GenerateKeyPair,
// OpenAuditLog, NewMemAuditLog, LoadXferRegistry, MaxGrantDuration) as
// type/var/const aliases — see signerkit_bridge.go.
//
// The daemon's behavior is unchanged: it runs as a dedicated OS user so
// that the agent cannot read the key or attach to the daemon's process
// memory, listens on a Unix socket, serves the one-JSON-line
// request/response protocol from the SSHGate MCP, dispatches each sign
// request to a pluggable Backend, and on Approved signs each command
// with the master key and returns the wire-format SSHGATE_SIG envelope.
//
// These aliases are removed once all consumers import pkg/signerkit
// directly (extraction phase 6).
package signer
