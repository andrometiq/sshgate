# AGENTS.md — SSHGate

Tool-agnostic playbook for this Claude Code plugin / MCP server.

## What this is

SSHGate is a Claude Code plugin that lets an agent SSH into Linux servers. Reads run freely. Writes need one Telegram-button approval from the operator.

## Architecture (one-liner)

A small Go binary (`gate`) sits between OpenSSH and shell exec on each remote server. A local daemon (`signer-telegram`, running as a separate Unix user) holds the master Ed25519 signing key and asks the operator to approve writes via Telegram. The MCP server (`sshgate-mcp`) exposes ten tools to Claude (`run`, `run_batch`, `list_servers`, `status`, `revoke_server`, `request_grant`, `revoke_grant`, `list_grants`, `update_gate`, `transfer` — `update_gate` requesting a signed, human-approved, hash-bound in-place update of the gate binary on an already-registered server, and `transfer` moving a secret file between two registered servers end-to-end encrypted through the gate under one human approval, the MCP relaying only ciphertext so the plaintext never reaches the agent). Provisioning a server is a human-only `sshgate` CLI — deliberately off the agent surface so the agent can't expand its own reach.

## How to use this project as an agent

The setup walkthrough is in `commands/setup.md`. The main entry points:
- `/sshgate:setup` — install (one-time)
- `/sshgate:status` — check health
- `/sshgate:revoke <alias>` — clean removal

**Provisioning is a human-only CLI, not a slash command and not an agent tool.**
A human registers a server with the `sshgate` binary (installed to
`~/go/bin/sshgate` by `make install-local`):
- `sshgate pubkey` — print SSHGate's dedicated public-key line.
- The human pastes that line into the target's `~/.ssh/authorized_keys`.
- `sshgate add <alias> <user@host>[:port] [--read-only]` — install the gate and
  lock that key down to the forced command. `--read-only` registers Tier-1.

The agent has no way to add a server. If asked, point the user at these CLI steps.

For debugging workflows, the active skill is `skills/debugging-remote-servers/SKILL.md`. Read it before responding to "debug X on server Y" requests.

## Tiers (read-only vs signed-write)

A server is provisioned either **read-only (Tier-1)** — gate deployed, no signer
pubkey, every write denied locally at the gate — or **signed-write (Tier-2)** —
a Telegram signer approves writes. `sshgate add … --read-only` registers Tier-1;
`sshgate add` (no flag) registers Tier-2 (`gate.pub` present = signed-write,
absent = read-only). To change a server's tier today, a human runs
`/sshgate:revoke <alias>` (its Telegram approval is kept) and re-provisions with
`sshgate add` at the desired tier (`/sshgate:setup` first if no signer exists).
An in-place tier flip was considered and rejected for security (any unsigned
upgrade path the CLI could exercise, the agent could emulate); re-tiering stays
revoke + re-provision — see roadmap #17 (redefined).

- A write aimed at a read-only server is **refused before any Telegram tap**.
  Don't retry; surface the re-provision path above (the agent can't do it).
- Gate denials surface as annotated errors: **exit 77** = missing signature /
  read-only host; **exit 65** = bad/expired signature (clock skew, stale approval).

## Operating model (multi-agent work in this repo)

How development work on SSHGate itself is run (dispatching subagents/workflows
for design, implementation, or review):

- **The main (orchestrator) session runs the most capable model available.**
  It does the planning, dispatching, and verification, holds the executive
  view, and is accountable for the end result. SSHGate work is judgment-heavy
  (a security backbone with real trust boundaries), so the orchestrator seat
  is not the place to economize.
- **Subagents run the right-sized model per task** — the least powerful model
  that does the job *well*, not the top tier by default:
  - purely mechanical steps (scaffolding, fixture generation, rote edits to a
    precise spec) → a fast/cheap model;
  - integration and general implementation → a standard model;
  - design, adversarial critique, security analysis, and code review → the
    strongest tier available to subagents (never below it — these are
    judgment/recall tasks where a weaker model's mistakes are expensive).
- **The orchestrator verifies, never rubber-stamps.** Read the diffs, run the
  build/vet/tests yourself, and confirm green before calling a unit done.
  Catching subagent mistakes is the orchestrator's job.
- The bar is "the change actually works end-to-end", not "tasks were
  dispatched".

## Operator constraints

- Treat Telegram-denial as final; do NOT loop on denials.
- Show the user the planned writes BEFORE soliciting bulk approval.
- Never log MCP tool args containing user-supplied secrets to stdout.
- After the FIRST `/sshgate:setup` (signer install): the operator must log out/in
  for `sshgatesigner` group membership, then **restart Claude Code** and run `/mcp`
  to confirm the `sshgate` server is live before writes work. A "signer socket
  permission denied" error means this step was skipped — it is NOT a dead daemon.
