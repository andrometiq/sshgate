# Security Policy

SSHGate is a security gate for AI-agent SSH access. If you have found a way to
make it run a write without a human approval — or to read what it is meant to
protect — we want to hear about it.

## Reporting a vulnerability

**Please report privately, not in a public issue.**

Use GitHub's private vulnerability reporting on this repository:

1. Go to the repository's **Security** tab → **Advisories** → **Report a
   vulnerability** (this opens a private draft advisory visible only to you and
   the maintainers).
2. Describe the issue, the affected component (gate / signer / MCP / CLI), the
   version or commit, and a reproduction if you have one.

If GitHub private reporting is unavailable to you, open a public issue that
contains **only** "requesting a security contact" — with no details — and a
maintainer will open a private channel.

Please do not disclose the details publicly until a fix is released or we have
agreed on a coordinated disclosure date.

### What to expect

This is a small open-source project, so responses are best-effort rather than
SLA-backed:

- **Acknowledgement:** we aim to reply within about 5 business days.
- **Triage:** we will tell you whether we consider it in-scope (see the boundary
  model below), and our assessment of severity.
- **Fix + disclosure:** for an in-scope issue we will work with you on a fix and
  a coordinated disclosure, and credit you in the advisory and CHANGELOG unless
  you prefer to stay anonymous.

## Supported versions

SSHGate is pre-1.0 and moves fast. Security fixes land on the default branch
(`main`) and in the next tagged release; there are no long-term maintenance
branches yet. Run a recent `main` or the latest release.

## Scope — what SSHGate actually enforces

Read [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) for the full, honest treatment.
The short version, stated factually:

- **The boundary is the Ed25519 signature checked by the on-host gate under an
  OpenSSH forced command.** A write runs on a remote only if it carries a valid
  signature the gate verifies against the signing pubkey deployed on that host,
  within a bounded validity window and bound to that host's key. OpenSSH enforces
  the forced command server-side, so SSHGate's key can only ever invoke the gate.
- **The read/write classifier only *routes*; it is not the wall.** It decides
  whether a command needs a signature. If it ever misjudges a write as a read,
  that command runs without approval. This is why the classifier is documented
  honestly rather than described as a security guarantee — a classifier bypass
  that causes a *write to run unapproved* is in scope and worth reporting.
- **Fail-closed:** a command counts as a read only when every part of it is a
  recognized read; anything unrecognized, or any write segment, routes to
  approval. Writes to a read-only (Tier-1) host have no signer pubkey to verify
  against and are refused at the gate before any approval is even consulted.
- **The signing key is isolated** under a dedicated Unix user the agent cannot
  read from. On a single machine this is a safety rail, not a hard wall: an agent
  that can escalate privileges on the host (e.g. has `sudo`) could read the key
  directly. After the hosted policy-authority and release gates close, run the
  signer on a separate machine for a guarantee that holds against a privileged
  rogue agent. See
  [`docs/approval-architecture.md`](docs/approval-architecture.md).

We make **no claim that SSHGate is "proven secure."** It is a defense-in-depth
design with one hard boundary (the signature) and several softer layers around
it; the threat model spells out exactly what each layer does and does not stop.

### Especially in scope

- A **write executing on a remote without a valid, human-approved signature**.
- A **classifier bypass** that routes a state-changing command as a read.
- Anything that lets the **agent read the signing key** or forge a signature.
- A **signature replayed** outside its validity window or against a different
  host than approved.
- Secret **plaintext leaking** to the agent or any log via the `transfer` path.

### Likely out of scope

- The classifier being conservative (routing a harmless read to approval) — that
  is fail-closed working as intended, not a vulnerability.
- Attacks that require pre-existing privileged access on the operator's laptop or
  the target host beyond what SSHGate grants (documented as a known limit in the
  threat model), though we still want to hear about anything surprising.
