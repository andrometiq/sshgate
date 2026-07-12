// Package signerkit is the shared SSHGate signing core. It holds the
// approval-channel seam (the Backend interface and its concrete
// implementations) and — as the extraction proceeds — the decision
// plumbing, envelope minting, keystore, audit log, transfer registry,
// and Unix-socket transport that together own the master signing key.
//
// Both SSHGate front-ends consume this one core: the local
// sshgate-signer-telegram binary and the embeddable/hosted signer. The
// wire envelope is src/sigwire, kept byte-identical across the refactor
// so the gate verifies both front-ends' signatures with the same code.
//
// (A fuller trusted-computing-base statement leads this doc once the
// crypto.Signer seam and the New(Config) constructor land.)
package signerkit
