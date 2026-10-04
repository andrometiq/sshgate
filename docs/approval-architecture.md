# SSHGate — approval authority and install tiers

SSHGate has three install tiers. The approval authority changes only when a
signer is present; the remote gate always remains the enforcement point.

## What enforces a write

Every writable remote pins SSHGate's dedicated SSH key to an OpenSSH forced
command. The gate accepts a write only with a fresh Ed25519 signature for that
remote. The signature is time-bounded and host-bound, so an approval cannot be
replayed indefinitely or against another server.

The read/write classifier decides whether a command is sent for signing; it is
not the security boundary. If it misclassifies a write as a read, that command
runs unsigned. On a host with the kernel read jail it then runs inside the jail,
where it cannot change host files, reach local daemons over Unix sockets or touch
other processes, though it can still use the network; on a host without the jail
it runs unconfined. The full residual-risk treatment is in
[THREAT-MODEL.md](THREAT-MODEL.md).

## Tier 1 — read-only

Tier 1 deploys the gate but does not give it a signing public key. Reads work
(inside the read jail where the host supports it); writes are refused locally
by the gate. There is no signer, master key, or approval channel.

Use Tier 1 to try SSHGate or when read-only access is the intended boundary.

## Tier 2 — local Telegram signer

Tier 2 adds `sshgate-signer-telegram` on the laptop. It runs under the
dedicated `sshgatesigner` Unix user, owns the signing key and Telegram token,
and uses its own dedicated Telegram bot and signer-owned poller. A write is
signed only after an Approve tap from the configured Telegram account; the gate
then verifies that exact signature on the remote.

This separation keeps the approval authority out of the agent process and
makes the normal write path explicit and auditable. It is still a **safety
rail, not a hard boundary**, when the agent can obtain root or the signer's
host privileges: that agent could read the local signing key and bypass the
approval flow. The dedicated user, private key/token files, and signer-owned
poller raise the bar for an unprivileged compromise; they do not change that
same-machine limit.

`/sshgate:setup` installs and configures the local signer, then stages
`gate.pub` for the human to deploy. It does not silently turn an existing
Tier 1 alias into a writable remote: those aliases remain read-only until the
human manually de-provisions and re-adds them with the staged public key.
Re-running setup is safe.

## Tier 3 — hosted signer server

The Tier 3 design runs `sshgate-signer-server` on a separate system the
laptop-side agent cannot administer. It keeps the signing key and approval
state there, serves the embedded approval UI, authenticates operators with TOTP
or WebAuthn, and applies N-of-M approval with deny-veto before signing.

Once its policy-authority and release gates close, this is the approval boundary
that continues to hold against a privileged rogue agent on the laptop: the
agent may request a signature but cannot read the key or forge the server's
human approval. The repository contains the hosted foundation, not yet a
release-ready deployment; its remaining release gates are tracked in the
[roadmap](ROADMAP.md). It is separate from the local setup menu; its
DNS, HTTPS, backups, reverse proxy, and credential-distribution requirements are
documented in
[the hosted signer guide](../src/signer-server/README.md).

The local and hosted signers use the same signer core. The hosted signer is the
approval surface for the current Tier 3 foundation; its policy-authority
corrections are release blockers, while hosted Telegram, per-client
credentials, grants, secret reveal, and transfer are intentionally deferred or
fail closed as documented in the [roadmap](ROADMAP.md) and hosted guide.

## Why the local signer owns its Telegram channel

A shared channel administered in the agent's trust domain was considered and
rejected. If a compromised on-machine agent can change the approval routing or
its allowlist, it can turn the supposed off-machine human verdict into an
agent-controlled oracle. Tier 2 therefore keeps the dedicated, signer-owned
Telegram poller as its approval authority. This does not solve the
same-machine privileged-agent limit; Tier 3 solves that by moving custody and
approval to a separate system after that deployment's release gates close.

## Common invariants

- A channel verdict never replaces the Ed25519 signature; every remote gate
  verifies the signature itself.
- Provisioning remains human-only, so an agent cannot add a new server to its
  own reach.
- Tier 2 is a single-operator phone-tap flow. Tier 3 supports its own
  authenticated multi-operator policy.
- A denial, timeout, unsupported hosted capability, or absent signing key
  fails closed.
