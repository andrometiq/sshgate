---
description: Run a single command on a registered server (rarely needed — Claude usually calls the tool directly)
argument-hint: <alias> <command...>
allowed-tools: mcp__sshgate__run
---

The user invoked `/sshgate:run <alias> <command...>`. This is the
explicit entry point for the `run` MCP tool (`mcp__sshgate__run`). In
ordinary use, the user types something like "run df -h on prod-db" and
Claude calls the tool directly — this slash command is the scriptable
form.

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

The tool also accepts optional inputs this slash command does not set on
its own. Use them only when the user asks:
- `max_output_bytes` — per-call cap on each of stdout and stderr. The
  default is 262144 (256 KiB); `0` means no cap. A capped stream ends with
  `[...truncated <dropped> of <total> bytes]`.
- `reveal` + `reason` — run this one command with output redaction turned
  off, so raw secret values reach the agent. It always needs its own
  Telegram approval (even for a read) and `reason` must be non-empty; the
  approver sees it.

The tool classifies the command (the result carries a top-level `kind`
field, `"read"` or `"write"`):
- Read → executes immediately, no approval. On a host that supports it,
  the gate runs the read inside the kernel read jail.
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
with that. If the result carries a `denial` object, show its `summary`
and `how_to` steps. If the tool itself errors, surface the error
verbatim — do not re-interpret it.

## Refusals (the `denial` object)

When the command did not run and someone must act, the result carries a
`denial` object: `verdict_class` (a stable name such as
`read_only_server`, `approval_denied`, `approval_timeout`,
`signer_unreachable`, `signer_permission`, `bad_signature`,
`missing_signature`, `read_jail_unavailable`), a one-line `summary`,
`required_action`, `retryable`, and `how_to` (ordered steps). Refusals
before the command reaches the server also come back as a tool error
whose text already carries the remediation. Surface it; do not
re-interpret it. The common cases:

- **Read-only server.** A write aimed at a server registered read-only
  (Tier 1, no signer pubkey on the host) is REFUSED before any signing
  or Telegram tap — the tool returns `server "<alias>" is registered
  read-only — writes are denied at the gate …`. Do NOT retry. Changing
  a server's tier is human-only: a person runs `/sshgate:setup` to add a
  signer (if none yet), then de-provisions the server by hand and re-adds
  it without `--read-only`. `sshgate revoke <alias>` (the human CLI) prints
  the exact steps; it changes nothing itself. `/sshgate:revoke` cannot run
  on a read-only host because its gate has no signer pubkey. No phone tap
  was spent.
- **Signer not in group (permission).** `signer socket … is present but
  not accessible (permission denied) — your shell/session is not yet in
  the sshgatesigner group`. This is NOT a dead daemon. The user must log
  out and back in AND relaunch Claude Code so the `sshgatesigner` group
  is active in the session; `newgrp` in a side terminal does NOT fix the
  already-running session. After relaunch, `/mcp` to confirm `sshgate`
  is live, then retry.
- **Signer unreachable.** Two shapes, already disambiguated in the
  message: `no signer configured (Tier-1 read-only)` → a human runs
  `/sshgate:setup`, then re-tiers each read-only server by hand as above;
  or `signer socket … is present but not accepting connections` → a real
  Tier-2 daemon problem, check `systemctl status sshgate-signer-telegram`
  and `journalctl -u sshgate-signer-telegram -n 50`.
- **Denied / timed out.** The user tapped Deny, or no tap landed in the
  approval window. Do NOT re-submit a denial; for a timeout, offer to
  re-run so a fresh prompt is sent.
- **Unknown alias.** Surface verbatim; suggest `/sshgate:status` or
  the `list_servers` tool to see what is registered.

## Recognizing gate exit codes

Some exit codes come from the gate itself, not the remote command. Call
them out instead of treating them as a generic command failure:

- **77 on a read — read jail unavailable.** The gate refused to run the
  read because it could not confirm or set up the host's kernel read jail.
  The command did not run. stderr contains `gate: read jail unavailable`
  and the result's `denial.verdict_class` is `read_jail_unavailable`.
  This happens when the operator pinned a `jail-floor` and the host no
  longer supports the jail, when the `jail-floor` file is damaged, when
  the host probe fails for an unexplained reason, or when jail setup
  fails. Do NOT retry and do NOT tell the user to add a signer: reads
  are refused the same way until the host is fixed. Ask a human to
  run `~/.sshgate-gate/gate doctor` on the host (from their own shell);
  it reports the jail level and why reads are refused.
- **77 on a write — gate denied the write.** No signer pubkey is
  configured on the remote (read-only / Tier 1), or the write arrived
  without a signature. Check `/sshgate:status`: a `read_only` server or a
  signer that is `not configured` means a human must add a signer (if none
  yet) and re-tier the server by hand, as above. Re-run the command after
  the re-add.
- **65 — signature rejected.** The signature was present but invalid or
  expired — usually clock skew between laptop and remote, or a stale approval.
  Retry the command once; if it persists, check the clocks on both ends.
- **70 — gate configuration error.** The gate could not read its signer
  pubkey file, or the file has an insecure mode. A human must fix the file
  on the host.

Any other exit code is the remote command's own exit status.

Do not run a follow-up command on your own. Stop after one
invocation.
