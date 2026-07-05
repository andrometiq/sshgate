# CLAUDE.md — SSHGate

The cross-tool source of truth is `AGENTS.md`. Read it now — Codex and any other agent that supports `AGENTS.md` reads the same file, so keep tool-agnostic rules there, not here.

## SSHGate-specific notes for Claude Code

This is a Claude Code plugin. The agent (MCP) tool surface is exactly **ten
tools** — `run`, `run_batch`, `list_servers`, `status`, `revoke_server`,
`request_grant`, `revoke_grant`, `list_grants`, `update_gate`, `transfer`:

- `sshgate.run(alias, command)` — run one command on a registered server
- `sshgate.run_batch(alias, commands[])` — run several commands; writes bulk-approve in one Telegram tap
- `sshgate.list_servers()` — list registered aliases
- `sshgate.status()` — health of the signer + reachability of each server
- `sshgate.revoke_server(alias)` — uninstall gate from a server (requires Telegram approval)
- `sshgate.request_grant(alias, scope, commands?, duration_hours, reason?)` — request a standing grant so matching writes auto-sign for a window (≤ 24h); needs a distinct human Telegram approval, the agent can only request one
- `sshgate.revoke_grant(alias)` — drop a server's standing grant (de-escalation only — always safe, no approval)
- `sshgate.list_grants(alias?)` — list the signer's live standing grants (read-only, no approval); use to reconcile after a request_grant timeout
- `sshgate.update_gate(alias)` — request a signed, in-place update of the gate binary on an already-registered server; the agent supplies only the alias (never binary bytes or a hash), the MCP hashes the operator's locally-staged gate binary, and the operator must approve a distinct "GATE BINARY UPDATE" Telegram banner bound to that exact SHA-256 before it runs. Fail-closed (hash mismatch / wrong-arch binary / Tier-1 all refuse and write nothing), signed, and audited; it does not expand the agent's reach (no new server is onboarded), and a standing grant never auto-signs it
- `sshgate.transfer(src_alias, src_path, dest_alias, dest_path, mode?)` — move a secret file from one registered server to another, END-TO-END ENCRYPTED through the gate. The agent supplies only aliases + absolute paths (+ optional octal mode, default `0600`) — never keys, fingerprints, or an id. The source gate seals the value to the destination's registered box key, the MCP relays ONLY the ciphertext (SEND stdout → RECV stdin), and the destination gate decrypts and atomically writes it; the plaintext never reaches the agent or any log (you get metadata only: xfer id, byte count). One human "SECRET TRANSFER" Telegram approval covers both signed, host-bound legs; a standing grant can never auto-sign it, and read-only (Tier-1) servers are refused before any tap. Both endpoints must be registered for transfer on the signer. Transfers require the local (Tier-2) Telegram signer — the hosted (Tier-3) signer does not support them yet and fails closed

**Provisioning is NOT an agent tool.** There is deliberately no `add_server`
on the MCP surface: a new machine is onboarded by a human at a terminal with
the `sshgate` CLI (installed to `~/go/bin/sshgate` by `make install-local`),
never by the agent. Provisioning is the control plane — it defines the trust
boundary (which machines the agent can reach). Running commands is the data
plane. Keeping provisioning human-only means the agent can never expand its
own reach; it only operates within boundaries a human established. The human
flow is:

1. `sshgate pubkey` — print SSHGate's dedicated public-key line.
2. Paste that line into the target server's `~/.ssh/authorized_keys` by hand
   (out-of-band, using existing admin access to the box).
3. `sshgate add <alias> <user@host>[:port] [--read-only]` — connect with
   SSHGate's own key, install the gate, and rewrite the pasted plain line into
   the locked `command="~/.sshgate-gate/gate"` forced-command line. The alias
   lands in `~/.config/sshgate/servers.json`, the same registry the MCP reads.

If you (the agent) are asked to add a server, do NOT attempt it — tell the
user to run the `sshgate` CLI steps above; you have no tool for it.

When the user asks to debug, diagnose, or operate a remote server:
1. Start with `sshgate.list_servers` to confirm the alias is registered.
2. For diagnostics, use `sshgate.run` with read commands (df -h, top -bn1, journalctl). No approval prompt.
3. For fixes, queue writes into `sshgate.run_batch` so the user approves all in ONE Telegram tap.
4. ALWAYS show the user the list of planned writes before calling run_batch.
5. After fixes, re-run a read health check.

**Phantom-live grant after a `request_grant` error/timeout.** If `request_grant`
returns an error or times out, the grant may still have gone live (the human
approved, but the response did not get back to you). Call `sshgate.list_grants`
to check the true state before re-requesting — re-requesting would prompt the
human a second time and risk a double grant.

See `skills/debugging-remote-servers/SKILL.md` for the full skill.

## Tiers, read-only servers, and write denials

A server is provisioned either **read-only (Tier-1)** or **signed-write (Tier-2)**
(via `sshgate add` / `sshgate add --read-only`). `gate.pub` present on the
remote = signed-write; absent = read-only.
`sshgate.list_servers` does not surface the flag directly; check `sshgate.status`
and the error messages below.

- **Writes to a read-only server are refused locally, BEFORE any Telegram tap.**
  `sshgate.run`/`sshgate.run_batch` return an error like `server "<alias>" is
  registered read-only — writes are denied at the gate (no signer pubkey was
  pushed)`. Do NOT retry. To change a server's tier today: a human runs
  `/sshgate:revoke <alias>` (keeps its Telegram approval) and then re-provisions
  it with `sshgate add` at the desired tier (run `/sshgate:setup` first if no
  signer is configured yet). An in-place read-only→write flip was considered
  and rejected for security (any unsigned tier-flip path the CLI could
  exercise, the agent could emulate — read-only is read-only); re-tiering
  stays revoke + re-provision — see roadmap #17 (redefined). There is no agent
  tool for any of this.
- **Gate deny exit codes** come back annotated, not bare:
  - **exit 77** — missing signature OR the host has no signer pubkey
    (read-only / Tier-1). Check `sshgate.status`; if the signer is not
    configured, the user runs `/sshgate:setup` and re-provisions with
    `sshgate add` (no `--read-only`) — see the tier note above.
  - **exit 65** — bad/expired signature, usually clock skew or a stale
    approval. Retry once.

## When to escalate to the user

- Provisioning is the human-only `sshgate` CLI (see above), not an agent tool — if `sshgate add` fails on the user's side, ask them to check the host's `/var/log/auth.log` and that SSHGate's public-key line was pasted into the target's `~/.ssh/authorized_keys` before they ran `sshgate add`.
- If `sshgate.transfer` fails with **`src/dest server not registered for transfer`**, that endpoint has no transfer keypair registered on the signer yet. This is enrolled by a human with the `sshgate` CLI (`sshgate xfer-register <alias>`, or `sshgate xfer-rotate <alias>` to re-key an existing host) — there is **no agent tool** for it, exactly like provisioning. Do NOT try to work around it; tell the user to run that CLI step, then retry the transfer. (`sshgate xfer-status <alias>` shows a host's tier / on-host keys / fingerprint.)
- If a write fails with a **signer-permission** error (`signer socket … is present
  but not accessible (permission denied) — your shell/session is not yet in the
  sshgatesigner group`) → STOP. This is NOT a dead daemon. The user (or the agent
  that just ran `/sshgate:setup`) must **fully quit and relaunch Claude Code after
  a logout/login** so the session picks up `sshgatesigner` group membership.
  After relaunch, run `/mcp` to confirm the `sshgate` server is live, then retry.
- If `sshgate.status` shows the signer socket **UNREACHABLE** *and* `configured:true`
  (socket file present, dial failed) → STOP, suggest `systemctl status
  sshgate-signer-telegram` and `journalctl -u sshgate-signer-telegram -n 50`.
  If `status` shows `configured:false` / "not configured", that is the NORMAL
  Tier-1 read-only state — not a fault. Writes are simply unavailable until
  `/sshgate:setup` adds a signer.
- After `/sshgate:setup` (first signer install) the full sequence is mandatory:
  log out/in for the group to take effect, **restart Claude Code**, run `/mcp` to
  confirm the `sshgate` MCP server is live, then writes will work.
- If a write is denied by the user via Telegram → DO NOT re-submit. Ask why; propose alternatives.
- If a write fails with a **verdict-undelivered** error (`verdict undelivered — the
  signer decided but the response did not arrive; a human may have DENIED this`) →
  DO NOT auto-retry. A denied write must never be silently re-submitted. Check
  `sshgate.status` and the Telegram approval thread; only resubmit if you confirm
  it was NOT a denial.
