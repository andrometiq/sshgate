// Package signerkit is the shared SSHGate signing core: the master signing
// key, the approval-channel seam (the Backend interface and its concrete
// implementations), envelope minting, keystore, audit log, transfer registry,
// and the Unix-socket transport — plus the custody API (New/Config, the
// crypto.Signer seam, Lock/Unlock/RotateTo, AuditSink) that an embedding
// application uses.
//
// TCB STATEMENT (read this first). The process that embeds signerkit joins the
// trusted computing base of EVERY gate provisioned with this signer's public
// key: compromise of the host app is the ability to mint gate-valid signatures
// until Lock or RotateTo. There is no gate-side revocation of an
// already-minted signature — the only bounds are the per-signature expiry
// (<= sigwire.MaxSigValidity, 5 minutes), the gate's host binding, and the
// custody controls in this package. Deploy accordingly: put the host behind
// TLS, prefer a KMS/HSM/agent-backed crypto.Signer over an in-memory file key
// (the Signer seam means app compromise yields online misuse, not key
// exfiltration), bound the blast radius with Lock/RotateTo and short TTLs, and
// anchor the audit externally (NewAppendOnlySink over an append-only store) so
// a compromised host cannot silently erase its own trail. The residual
// online-misuse window is irreducible in an embeddable design — do not claim
// otherwise.
//
// Both SSHGate front-ends consume this one core: the local
// sshgate-signer-telegram binary and the embeddable/hosted signer. The wire
// envelope is src/sigwire, kept byte-identical across the refactor so the gate
// verifies both front-ends' signatures with the same code — the Signer seam
// pins crypto.Hash(0) (pure Ed25519) precisely so a file key routed through
// crypto.Signer stays byte-identical to the pre-seam ed25519.Sign path.
package signerkit
