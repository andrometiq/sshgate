# sshgate-signer-server

The hosted SSHGate signer is the source foundation for a separate approval
boundary for laptops using the `hosted` signer backend. It queues
bearer-authenticated signing requests in SQLite, serves an embedded human
approval UI, authenticates operators with TOTP or WebAuthn, applies N-of-M and
deny-veto policy, signs only after approval, and writes an append-only audit
stream.

**Release status:** the v0.2 policy-authority and release gates are still open.
Treat this guide as engineering/deployment reference, not as a declaration that
the current branch is a release-ready hosted boundary.

The server listens on private HTTP. A reverse proxy must provide the stable public HTTPS origin used by WebAuthn and the session-CSRF boundary.

## Fresh VPS install

Prerequisites: Linux with systemd, Go, OpenSSL, a public DNS name, and an HTTPS reverse proxy configuration ready for that name.

```bash
git clone https://github.com/karthikeyan5/SSHGate.git
cd SSHGate/src/signer-server
sudo env \
  SIGNER_SERVER_RP_ID=signer.example.com \
  SIGNER_SERVER_RP_ORIGIN=https://signer.example.com \
  SIGNER_SERVER_BOOTSTRAP_OPERATORS=alice,bob \
  SIGNER_SERVER_MACHINE_CLIENT_ID=alice \
  SIGNER_SERVER_REQUIRED_APPROVALS=1 \
  ./install/deploy.sh
```

The installer creates an unprivileged service account, a private SQLite database, a 0600 bearer token, a 0600 Ed25519 signing key, the initial TOTP operators, and a hardened systemd unit with the approval UI enabled. With self-approval disabled (the default), the requester and at least one other operator are required for a one-approval policy. Each new operator's TOTP URI and secret are written once to a 0600 `bootstrap-<operator>.txt` artifact under the state directory. Read it directly into the operator's authenticator, then securely remove it; never copy it to shell history, chat, or source control.

The installer deliberately does not configure TLS. Route the exact `SIGNER_SERVER_RP_ORIGIN` to `127.0.0.1:8443`, then open that origin in a browser and sign in with the bootstrapped TOTP code.

Important generated files:

- `/etc/sshgate-signer-server/keys/api-key.txt` — copy securely to each approved laptop.
- `/etc/sshgate-signer-server/keys/signing-key.ed25519` — master private key; never copy to a laptop.
- `/etc/sshgate-signer-server/keys/signing-key.ed25519.pub` — copy to the laptop path used as SSHGate's gate signing public key before provisioning hosts.
- `/var/lib/sshgate-signer-server/state.db` — approval, operator, factor, session, and audit-index state.
- `/var/lib/sshgate-signer-server/bootstrap-<operator>.txt` — one-time 0600 TOTP enrollment artifact; remove after enrollment.

Re-running the installer preserves all keys and the database. An incomplete signing-key pair is a hard failure rather than an implicit rotation.

## Add an operator

Run the offline bootstrap command as the service account. It creates a new operator but refuses to rotate an existing operator's factor.

```bash
sudo -u sshgate-signer-server \
  /usr/local/bin/sshgate-signer-server \
  --bootstrap-operator bob \
  --bootstrap-output-file /var/lib/sshgate-signer-server/bootstrap-bob.txt \
  --db /var/lib/sshgate-signer-server/state.db \
  --rp-id signer.example.com \
  --rp-origin https://signer.example.com
```

Factor changes after bootstrap require an authenticated session plus a fresh current TOTP proof. Successful TOTP timesteps are one-use across login, factor changes, and approval step-up; after signing in, wait for the authenticator code to rotate before re-authenticating. HTTP self-bootstrap is intentionally absent.

## Offline policy maintenance

Policy terminal compaction and recovery-lease owner clearing are offline-only
operations. Stop the serving process first; the command takes the exclusive
maintenance lease before opening either resource. Both paths require absolute
paths, an existing migration-6 database with a verified authority binding, and
an existing owner-only archive whose binding matches the database. They never
create or migrate a database and never repair an archive during preflight.

```bash
sudo -u sshgate-signer-server \
  /usr/local/bin/sshgate-signer-server \
  --db /var/lib/sshgate-signer-server/state.db \
  --policy-archive-dir /var/lib/sshgate-signer-server/policy-archive \
  --compact-policy-before 2026-08-01T00:00:00Z

sudo -u sshgate-signer-server \
  /usr/local/bin/sshgate-signer-server \
  --db /var/lib/sshgate-signer-server/state.db \
  --policy-archive-dir /var/lib/sshgate-signer-server/policy-archive \
  --clear-policy-recovery-lease pr_0123456789abcdef0123456789abcdef
```

The two maintenance actions are mutually exclusive. Compaction publishes a
content-addressed full archive record before replacing the terminal database
row with its tombstone. Owner clearing increments the recovery generation, so
all outstanding workers remain fenced.

## Permanent-policy serving

The permanent-policy plane is requested when any policy flag is set. Serving
requires the complete set below plus the existing `--ui`, RP, machine
principal, quorum, database, API-key, and signing-key configuration:

```text
--policy-authority-id pauth_0123456789abcdef0123456789abcdef
--policy-archive-dir /var/lib/sshgate-signer-server/policy-archive
--policy-archive-id parch_0123456789abcdef0123456789abcdef
--policy-audit-file /var/log/sshgate-signer-server/policy-audit.jsonl
--policy-max-rejection-bytes-per-principal 8388608  # optional
```

The database, archive directory, and audit file paths must be absolute. The
optional rejection cap defaults to 8 MiB and may only be reduced to a positive
decimal value. A partial policy flag set is a startup error; leaving every
policy flag empty preserves ordinary hosted signing without mounting v2 policy
routes.

## Laptop backend

Copy the API token to a 0600 local file, then select the hosted backend in the signer configuration:

```toml
[backend]
type = "hosted"

[backend.hosted]
base_url = "https://signer.example.com"
api_key_file = "/path/to/hosted-api.key"
client_id = "alice"
policy_pubkey_file = "/path/to/hosted-policy-public-key.hex"
policy_authority_id = "pauth_0123456789abcdef0123456789abcdef"
poll_wait_sec = 30
timeout_sec = 60
```

The two policy fields are an inseparable trust anchor. The public-key file must
be owned by the signer process, must not be a symlink, must have no group/world
permission bits, and must contain exactly 64 lowercase hexadecimal characters
with at most one trailing newline. Omitting both leaves hosted policy approval
disabled while ordinary hosted command approval continues to work.

`client_id` must exactly match the server's `SIGNER_SERVER_MACHINE_CLIENT_ID`;
the bearer credential is bound to that requester identity at intake, persisted
with the request, and shown to approvers. The current foundation still has one
shared bearer token rather than a different credential per laptop, so
distribute that token only within the intended requester boundary during
approved engineering exercises. Per-client credentials remain follow-up work.

The gate on every writable server must trust the hosted signer's public key. Place the generated 32-byte public-key file at the configured local `gate.pub` path before running the human-only `sshgate add` flow.

## HTTP planes

The credentials are structurally separated:

| Plane | Routes | Authentication |
|---|---|---|
| Machine | `POST /v1/sign`, `GET /v1/poll/{id}`, `GET /v1/audit` | Bearer API key |
| Human | `/auth/*`, `/ui/*` | Opaque HttpOnly session cookie; mutations also require the exact configured Origin and JSON content type |
| Static UI | `/`, `/*.html`, `/*.js`, `/app.css` | Login page is public; data APIs remain session-gated |
| Health | `GET /healthz` | Public liveness only |

The policy human surface is five session-only JSON routes under
`/ui/policy`: the full pending queue, request detail, approve, deny, and audit.
Its dedicated reference pages render the admission-frozen
`sshgate-policy-review-v2` document, frozen signer/digest evidence, and audited
votes using text nodes only. Terminal tombstones retain their opaque review ID;
detail and audit resolve the verified content-addressed archive record instead
of consulting the current policy head. The ordinary command UI and its v1
routes remain separate and unchanged.

The embedded UI has no external assets and enforces a restrictive Content
Security Policy. The ordinary pages render the exact command, command SHA-256,
target server, host-key fingerprint, validity, tally, voters, and final audit
rows.

## Current scope and limits

- SQLite is single-node; do not run multiple server replicas against one local database file.
- TLS termination, DNS, backups, and log shipping remain operator responsibilities.
- `SIGNER_SERVER_REQUIRED_APPROVALS` sets the positive N copied into each new request. The installer rejects a fresh roster that cannot satisfy N after self-approval policy is applied. There is no operator-facing policy-management screen yet.
- The machine plane uses one shared bearer token. Per-client keys and cryptographic client-to-operator binding are follow-up work.
- Hosted standing grants, secret reveal, box-to-box transfer, and transfer-key registration fail closed; use the local Telegram signer for those features.
- WebAuthn registration is supported by the authenticated API, while the minimal reference UI focuses on login and approval. TOTP bootstrap is the complete default path.
- `/healthz` is liveness, not dependency readiness; production monitoring should also exercise an authenticated workflow.

The embeddable implementation lives under `pkg/signerkit` and `pkg/signerkit/hosted`; this binary is the reference deployment surface over the same signing core used by the local signer.
