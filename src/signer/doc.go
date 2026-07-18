// Package signer holds the local sshgate-signer-telegram entry point
// (cmd/sshgate-signer-telegram) and its tests. The signing core that
// owns the master Ed25519 key — Daemon, the Unix-socket Server, key
// loading, the audit log, and the transfer-key registry — lives in
// pkg/signerkit; this front end wires that core to a Telegram approval
// backend (src/signer/backend) and runs it as a dedicated OS user so
// the agent can never read the key or attach to the daemon's process
// memory.
package signer
