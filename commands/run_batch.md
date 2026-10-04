---
description: Run several commands on a registered server in one shot (one Telegram tap approves all the writes)
argument-hint: <alias> <command> [; <command> ...]
allowed-tools: mcp__sshgate__run_batch
---

The user invoked `/sshgate:run_batch <alias> <commands...>`. This is the
explicit entry point for the `run_batch` MCP tool
(`mcp__sshgate__run_batch`). Use `run_batch` whenever a task needs more
than one write: all of a batch's writes go to the signer as ONE approval
request, so the user taps once instead of once per command. In ordinary
use the user types something like "update the nginx config and restart
it" and Claude queues the writes into `run_batch` directly — this slash
command is the scriptable form.

Parse the arguments:
- `alias` — first positional. Must match `[a-z][a-z0-9-]{0,30}`.
- `commands` — everything after the alias. Split it into the ordered list
  of commands on `;` characters that are **outside quotes** (a `;` inside
  `'...'` or `"..."`, as in `sed 's/a/b;/'`, belongs to that command).
  Preserve each command's quoting as-is; do not re-quote. If the split is
  ambiguous, show the user the list you derived and ask before calling.

If the alias is missing or malformed, or no commands are given, print:

```
Usage: /sshgate:run_batch <alias> <command> [; <command> ...]
Alias must match [a-z][a-z0-9-]{0,30}.
```

…and stop. Do not prompt inline.

## ALWAYS show the planned writes before invoking

Before calling the tool, list the commands you are about to send — in order —
so the user sees exactly what one tap will approve. Classify each as a read or
a write if you can; reads run with no approval, writes go to the signer
for the single approval. Do not call `run_batch` until you have surfaced
this plan.

Call `mcp__sshgate__run_batch` with
`{ "alias": "<alias>", "commands": ["<cmd1>", "<cmd2>", ...] }`.

`stop_on_error`, when you leave it out, depends on what the batch holds:
- **A batch with at least one write** stops on error, but only a WRITE's
  non-zero exit stops it. A read that exits non-zero (an absent file, an
  empty `grep`) does not skip the remaining writes.
- **An all-read batch** continues on error: every read runs.

Pass `stop_on_error=true` to stop at ANY command's non-zero exit, or
`stop_on_error=false` to run every command regardless; do either only if
the user asks. Commands after the stop are marked `skipped: true`.

The tool also accepts `max_output_bytes`: a cap applied to each command's
stdout and stderr separately (default 262144; `0` = no cap). A capped
stream ends with `[...truncated <dropped> of <total> bytes]`. `run_batch`
never reveals secrets; a reveal is single-command only (see
`/sshgate:run`).

The tool classifies each command:
- Read → executes immediately, no approval (inside the kernel read jail on
  a host that supports it).
- Write → all writes in the batch go to the signer as ONE approval request;
  the user gets ONE Telegram prompt listing every queued write. Tell the user
  the tap is coming if any command in the plan is a write.

## Handling a refused batch

If a write is aimed at a read-only (Tier 1) server, or no SSH key exists
yet, the tool errors before any tap and the result carries a `denial`
object (see below). Surface the error text verbatim.

When approval does not go through, the tool returns `denied: true`, an
empty `results`, a `reason`, and a `denial` object. `reason` is a SHORT
machine-readable token (`denied`, `timeout`, `error`) for the simple cases,
but for the actionable cases (permission, signer-unreachable, verdict
unknown) it carries the FULL remediation sentence instead of a bare token —
so match on a substring or just surface it, do NOT test
`reason == "permission"`. Surface the reason with its human meaning; do not
re-interpret it as a command failure:

- **`denied`** (exact token) — the user tapped **Deny** on Telegram. Do NOT
  re-submit; ask why and propose alternatives.
- **`timeout`** (exact token) — no tap landed inside the approval window. The
  request expired; offer to re-run so a fresh prompt is sent.
- **verdict unknown** (starts with `verdict_unknown:`) — the signer decided
  but the answer was lost; a human may have denied it. Do NOT auto-retry;
  check `/sshgate:status` and the Telegram thread first.
- **signer unreachable** (full sentence) — one of two shapes, already
  disambiguated in the text: `no signer configured (Tier-1 read-only). …` →
  there is no signer at all; a human runs `/sshgate:setup`, then re-tiers each
  read-only server by hand (`sshgate revoke <alias>` prints the exact steps;
  `/sshgate:revoke` cannot run on a read-only host because its gate has no
  signer pubkey). Or `signer socket … is present but not accepting
  connections — check systemctl status …` → a real Tier-2 daemon problem;
  check `/sshgate:status`, `systemctl status sshgate-signer-telegram`, and the
  journal. After fixing, re-run.
- **signer permission** (full sentence) — `reason` reads `signer socket … is
  present but not accessible (permission denied) — your shell/session is not
  yet in the sshgatesigner group. …`. The socket is `0660 sshgatesigner`; the
  user must log out and back in AND relaunch Claude Code so the group is
  active. `newgrp` in a side terminal does NOT fix the already-running
  session. Re-run after relaunch.

The `denial` object has a stable `verdict_class`, a one-line `summary`,
`required_action`, `retryable`, and ordered `how_to` steps. Show its
`summary` and `how_to`. A `denial` can also be present while `denied` is
false: that means the batch ran but the gate refused one of its writes
(exit 77 or 65, see below).

## Rendering per-command results

When the batch runs, `results` holds one entry per command. Render them in
order:

```
[<n>] <command>   (<kind>)
exit:   <exit_code>
stdout:
<stdout>
stderr:
<stderr>
```

Omit empty stdout/stderr sections. Mark skipped commands explicitly — they
never ran:

```
[<n>] <command>   (skipped — an earlier command failed)
```

A write result can carry `reason`, naming why the command counted as a
write. If a command you meant as a read shows up as a write, that is the
hint for how to rephrase it.

If `approved` is true, note that the writes ran after the Telegram tap
(`auth_mode` says whether a human tapped or a standing grant signed). If
the tool itself errors (unknown alias, SSH transport failure), surface the
error verbatim — do not re-interpret it.

## Recognizing gate exit codes

Some exit codes come from the gate itself (not the remote command). Call
them out per command instead of treating them as a generic command failure:

- **77 on a read — read jail unavailable.** The gate refused to run the
  read because it could not confirm or set up the host's kernel read jail;
  the command did not run. The result's stderr contains
  `gate: read jail unavailable`. (Inside a batch there is no per-command
  `denial` object for this; the stderr line is the signal.) Do NOT retry and
  do NOT tell the user to add a signer: reads on that host are refused the
  same way until the host is fixed. Ask a human to run
  `~/.sshgate-gate/gate doctor` on the host from their own shell; it
  reports the jail level and why reads are refused.
- **77 on a write — gate denied the write.** No signer pubkey is configured
  on the remote (read-only / Tier 1), or the write arrived without a
  signature. The result's stderr carries a remediation note. Check
  `/sshgate:status`; a read-only server needs a human to add a signer (if
  none yet) and re-tier it by hand. Re-run the batch after the re-add.
- **65 — signature rejected.** The signature was present but invalid or
  expired — usually clock skew between laptop and remote, or a stale approval.
  Retry once; if it persists, check the clocks on both ends.
- **70 — gate configuration error.** The gate could not read its signer
  pubkey file, or the file has an insecure mode. A human must fix it on the
  host.

Any other exit code is the remote command's own exit status.

Do not run a follow-up batch on your own. Stop after one invocation.
