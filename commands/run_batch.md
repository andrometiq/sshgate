---
description: Run several commands on a registered server in one shot (the mandated write path — one Telegram tap approves all writes)
argument-hint: <alias> <command> [; <command> ...]
allowed-tools: mcp__sshgate__run_batch
---

The user invoked `/sshgate:run_batch <alias> <commands...>`. This is the
explicit entry point for the `sshgate.run_batch` MCP tool. `run_batch` is the
MANDATED write path: a batch's writes are bulk-approved in ONE Telegram tap
(each command is still individually signed for audit; the "bulk" is purely the
UI). In ordinary use the user types something like "update the nginx config
and restart it" and Claude queues the writes into `run_batch` directly — this
slash command is the scriptable / belt-and-suspenders form.

Parse the arguments:
- `alias` — first positional. Must match `[a-z][a-z0-9-]{0,30}`.
- `commands` — everything after the alias. Split on `;` into the ordered list
  of commands. Preserve each command's quoting as-is; do not re-quote.

If the alias is missing or malformed, or no commands are given, print:

```
Usage: /sshgate:run_batch <alias> <command> [; <command> ...]
Alias must match [a-z][a-z0-9-]{0,30}.
```

…and stop. Do not prompt inline.

## ALWAYS show the planned writes before invoking

Before calling the tool, list the commands you are about to send — in order —
so the user sees exactly what one tap will approve. Classify each as a read or
a write if you can; reads stream back with no approval, writes go to the signer
for the single bulk approval. Do not call `run_batch` until you have surfaced
this plan.

Call `mcp__sshgate__run_batch` with
`{ "alias": "<alias>", "commands": ["<cmd1>", "<cmd2>", ...] }`.

`stop_on_error` defaults to true — the sequence aborts at the first non-zero
exit and the remaining commands are marked skipped. Pass `stop_on_error=false`
only if the user explicitly wants every command to run regardless of prior
exits.

The tool classifies each command:
- Read → executes immediately, no approval.
- Write → all writes in the batch go to the signer as ONE approval request;
  the user gets ONE Telegram prompt listing every queued write. Tell the user
  the tap is coming if any command in the plan is a write.

## Handling a denied batch

When approval does not go through, the tool returns `out.Denied == true`, an
empty `results`, and `out.Reason`. `Reason` is a SHORT machine-readable token
(`denied` / `timeout`) for the simple cases, but for the two actionable cases
(permission, signer-unreachable) it carries the FULL remediation sentence
verbatim instead of a bare token — so match on a substring or just surface it,
do NOT test `Reason == "permission"`. Surface the reason with its human
meaning; do not re-interpret it as a command failure:

- **`denied`** (exact token) — the user tapped **Deny** on Telegram. Do NOT
  re-submit; ask why and propose alternatives.
- **`timeout`** (exact token) — no tap landed inside the approval window. The
  request expired; offer to re-run so a fresh prompt is sent.
- **signer unreachable** (full sentence) — `Reason` is one of two shapes,
  already disambiguated in the text: `no signer configured (Tier-1
  read-only). …` → there is no signer at all; a human runs `/sshgate:setup`,
  then re-tiers each read-only server by hand (strip its forced `command="..."`
  line back to `sshgate pubkey`'s plain line on the host, drop the alias from
  the registry, then `sshgate add <alias> <user@host>` — a Tier-1 gate has no
  signer pubkey, so `/sshgate:revoke` can't run on it). Or `signer socket … is present but not
  accepting connections — check systemctl status …` → a real Tier-2 daemon
  problem; check `/sshgate:status`,
  `systemctl status sshgate-signer-telegram`, and the journal. After fixing,
  re-run.
- **signer permission** (full sentence) — `Reason` reads `signer socket … is
  present but not accessible (permission denied) — your shell/session is not
  yet in the sshgatesigner group. …`. The socket is `0660 sshgatesigner`; the
  user must log out and back in AND relaunch Claude Code so the group is
  active. `newgrp` in a side terminal does NOT fix the already-running
  session. Re-run after relaunch.

## Rendering per-command results

When the batch runs, `out.results` holds one entry per command. Render them in
order:

```
[<n>] <command>   (<kind>)
exit:   <exit_code>
stdout:
<stdout>
stderr:
<stderr>
```

Omit empty stdout/stderr sections. Mark skipped commands explicitly — when
`stop_on_error` is true and a command exits non-zero, every later command has
`skipped: true` and never ran:

```
[<n>] <command>   (skipped — earlier command failed)
```

If `out.approved` is true, note that the writes ran after the Telegram tap. If
the tool itself errors (unknown alias, SSH transport failure), surface the
error verbatim — do not re-interpret it.

## Recognizing gate exit codes

Two exit codes come from the gate itself (not the remote command) and have
specific meanings — call them out per command instead of treating them as a
generic command failure:

- **77 — gate denied the write.** No signer pubkey is configured on the
  remote (read-only / Tier 1), or the write arrived without a signature.
  Check `/sshgate:status`; if the signer is `not configured`, the server is
  read-only — a human runs `/sshgate:setup` to add a signer (if none yet),
  then re-tiers the server by hand — on the host, swap the forced `command="..."`
  line back to `sshgate pubkey`'s plain line, drop the alias from the registry,
  then `sshgate add <alias> <user@host>` (without `--read-only`) to push the new
  `gate.pub`. A Tier-1 gate has no signer pubkey, so `/sshgate:revoke` can't run
  on it. Re-run the batch after the re-add.
- **65 — signature rejected.** The signature was present but invalid or
  expired — usually clock skew between laptop and remote, or a stale approval.
  Retry; if it persists, check the clocks on both ends.

Do not run a follow-up batch on your own. Stop after one invocation.
