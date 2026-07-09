---
description: Run a single command on a registered server (rarely needed — Claude usually calls the tool directly)
argument-hint: <alias> <command...>
allowed-tools: mcp__sshgate__run
---

The user invoked `/sshgate:run <alias> <command...>`. This is the
explicit entry point for the `sshgate.run` MCP tool. In ordinary use,
the user types something like "run df -h on prod-db" and Claude calls
the tool directly — this slash command is the scriptable / belt-and-
suspenders form.

Parse the arguments:
- `alias` — first positional. Must match `[a-z][a-z0-9-]{0,30}`.
- `command` — everything after the alias, joined with single spaces.
  Preserve the user's quoting as-is; do not re-quote.

If either is missing or alias is malformed, print:

```
Usage: /sshgate:run <alias> <command...>
Alias must match [a-z][a-z0-9-]{0,30}.
```

…and stop. Do not prompt inline.

Call `mcp__sshgate__run` with `{ "alias": "<alias>", "command": "<command>" }`.

The tool classifies the command (the result carries a top-level `kind`
field, `"read"` or `"write"`):
- Read → executes immediately, no approval.
- Write → requests approval via the signer; the user gets a Telegram
  prompt. The classification happens before the tap, so you cannot read
  `kind` until the tool returns — if the command is plainly a write
  (e.g. an edit/install/restart), tell the user a tap is coming;
  otherwise just wait.

Surface the tool's output structure:

```
exit:   <exit_code>
stdout:
<stdout>
stderr:
<stderr>
```

Omit empty stdout/stderr sections. If `exit_code` is non-zero, lead
with that. If the tool itself errors, surface the error verbatim — do
not re-interpret it.

## Tool-level errors (write path)

Unlike `run_batch`, `sshgate.run` does NOT return a structured
`Denied` result — every non-success returns a plain tool error whose
message already carries the remediation. Surface it verbatim; the
common write-path cases are:

- **Read-only server.** A write aimed at a server registered read-only
  (Tier 1, no signer pubkey on the host) is REFUSED before any signing
  or Telegram tap — the tool returns `server "<alias>" is registered
  read-only — writes are denied at the gate …`. Do NOT retry. Provisioning
  is human-only: a person runs `/sshgate:setup` to add a signer (if none yet),
  then de-provisions the server by hand and re-adds it — on the host, swap
  SSHGate's forced `command="..."` line back to `sshgate pubkey`'s plain line,
  drop the alias from the registry (`~/.config/sshgate/servers.json`), then
  `sshgate add <alias> <user@host>` (without `--read-only`) to bring it up as
  signed-write. A Tier-1 gate has no signer pubkey, so `/sshgate:revoke` can't
  run on a read-only host. No phone tap was spent.
- **Signer not in group (permission).** `signer socket … is present but
  not accessible (permission denied) — your shell/session is not yet in
  the sshgatesigner group`. This is NOT a dead daemon. The user must log
  out and back in AND relaunch Claude Code so the `sshgatesigner` group
  is active in the session; `newgrp` in a side terminal does NOT fix the
  already-running session. After relaunch, `/mcp` to confirm `sshgate`
  is live, then retry.
- **Signer unreachable.** Two shapes, already disambiguated in the
  message: `no signer configured (Tier-1 read-only)` → a human runs
  `/sshgate:setup`, then re-tiers each read-only server by hand (strip its
  forced `command="..."` line back to `sshgate pubkey`'s plain line on the host,
  drop the alias from the registry, then `sshgate add <alias> <user@host>` — a
  Tier-1 gate has no signer pubkey, so `/sshgate:revoke` can't run on it); or `signer socket …
  is present but not accepting connections` → a real Tier-2 daemon
  problem, check `systemctl status sshgate-signer-telegram` and
  `journalctl -u sshgate-signer-telegram -n 50`.
- **Denied / timed out.** The user tapped Deny, or no tap landed in the
  approval window. Do NOT re-submit a denial; for a timeout, offer to
  re-run so a fresh prompt is sent.
- **Unknown alias.** Surface verbatim; suggest `/sshgate:status` or
  `sshgate.list_servers` to see what is registered.

## Recognizing gate exit codes

Two exit codes come from the gate itself (not the remote command) and have
specific meanings — call them out instead of treating them as a generic
command failure:

- **77 — gate denied the write.** No signer pubkey is configured on the
  remote (read-only / Tier 1), or the write arrived without a signature.
  Check `/sshgate:status`; if the signer is `not configured`, the server is
  read-only — a human runs `/sshgate:setup` to add a signer (if none yet),
  then re-tiers the server by hand — on the host, swap the forced `command="..."`
  line back to `sshgate pubkey`'s plain line, drop the alias from the registry,
  then `sshgate add <alias> <user@host>` (without `--read-only`) to push the new
  `gate.pub`. A Tier-1 gate has no signer pubkey, so `/sshgate:revoke` can't run
  on it. Re-run the command after the re-add.
- **65 — signature rejected.** The signature was present but invalid or
  expired — usually clock skew between laptop and remote, or a stale approval.
  Retry the command; if it persists, check the clocks on both ends.

Do not run a follow-up command on your own. Stop after one
invocation.
