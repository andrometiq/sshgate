// Package hosted is the Tier-3 hosted signer: the HTTP engine that serves
// SSHGate's machine and human approval planes over one mux. SSHGate plugins on
// any number of machines POST command-signing requests to the bearer-gated
// MACHINE plane (POST /v1/sign, GET /v1/poll/{id}, GET /v1/audit, GET /healthz);
// a human approves each request on the session-gated HUMAN plane (/auth/*,
// /ui/*) via WebAuthn/TOTP; on approval the shared signerkit core mints
// gate-valid SSHGATE_SIG envelopes, verifiable by the same gate path the local
// signer uses. It is one signing core, two front-ends: the same
// signerkit.Service the local Telegram signer runs.
//
// TRUST BOUNDARY — read this first. The process that embeds this package holds
// custody of an Ed25519 signing key, and therefore joins the Trusted Computing
// Base of EVERY gate provisioned with that key's public half. A compromise of
// this process — the key, its host, or its approval logic — yields gate-valid
// signatures for as long as the key stays live: that is, until an operator
// Locks or RotateTo's the core. Deploy it accordingly:
//
//   - Terminate TLS in front of it. The bearer token and the session cookie are
//     bearer credentials and must never cross the wire in the clear.
//   - Prefer a KMS/HSM-backed crypto.Signer over an on-disk key file, so the raw
//     private key never lives in this process's address space.
//   - Anchor the AuditSink OUTSIDE this process (append-only / external store),
//     so an attacker who owns the box cannot rewrite the record of what it signed.
//
// Plane separation is structural, not advisory. The machine plane authenticates
// ONLY a Bearer token (constant-time compared, see withAuth); the human plane
// authenticates ONLY a server-side session cookie (see withSession). A wrong
// credential at the wrong plane is 401 by construction — AttachMachine and
// AttachHuman mount the two planes on the shared mux, and TestPlaneSeparation
// asserts both directions.
//
// The additive policy-authority plane is mounted only through AttachPolicy.
// Production composition uses StartPolicy to acquire and mount the policy plane
// behind false readiness, starts ordinary HTTP service, then calls
// PolicyRuntime.CompleteStartup for the one-transaction safety scan, startup
// roster sweep, and separate ROSTER and RECOVERY workers. Policy readiness is
// independent of the ordinary /v1 plane; a sticky durable-audit failure closes
// policy responses without stopping /v1.
//
// The wire the machine plane speaks is BYTE-FROZEN: the frozen
// HostedServerBackend client in pkg/signerkit is the oracle (wire_frozen_test.go),
// so /v1/sign, /v1/poll and /healthz cannot drift without failing to decode.
package hosted
