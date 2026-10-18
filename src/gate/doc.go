// Package gate implements the remote-side gate that runs on each
// SSHGate-protected server. It is invoked by OpenSSH via
// command="~/.sshgate-gate/gate" forcing on the SSHGate dedicated key, so
// every connection using that key is funnelled through this binary.
//
// Command execution and the gate binary require Linux. Verification and audit
// types are also available to clients on other supported platforms.
//
// The package exports three pieces used by both the cmd/gate entry
// point and the integration tests:
//
//   - VerifySigned parses a SSHGATE_SIG: line, verifies its Ed25519
//     signature against the bundled gate.pub, and enforces the spec's
//     time bounds. It returns the inner cmd string for execution.
//   - ExecWithRedaction runs a shell command via /bin/sh -c, streaming
//     stdout/stderr to the caller (optionally through the secrets redactor)
//     and forwarding SIGTERM/SIGINT to the child.
//   - LoadPubKey loads the Ed25519 public key from a file, refusing to
//     read it if the mode is more permissive than 0644.
//
// All operator-side log messages are written to stderr with the
// "gate: " prefix; stdout is reserved for the executed inner
// command's stdout. Exit codes follow BSD sysexits where applicable
// (see cmd/gate/main.go).
package gate
