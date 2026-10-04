# AGENTS.md — SSHGate

Tool-agnostic rules for any agent working in this repo (Claude Code, Codex and others).
SSHGate is itself a Claude Code plugin and MCP server, so this file covers both using its
tools and developing it.

## What this is

SSHGate lets an agent SSH into Linux servers. Reads run freely. Writes need one
Telegram-button approval from the operator.

A small Go binary (`gate`) sits between OpenSSH and shell exec on each remote server. A local
daemon (`signer-telegram`, running as a separate Unix user) holds the master Ed25519 signing
key and asks the operator to approve writes via Telegram. The MCP server (`sshgate-mcp`)
exposes the agent tools below. Provisioning a server is a human-only `sshgate` CLI, kept off
the agent surface so the agent can't expand its own reach.

## Agent tool surface (exactly eleven tools)

- `run(alias, command)`: one command on a registered server.
- `run_batch(alias, commands[])`: several commands; writes bulk-approve in one Telegram tap.
- `list_servers()`: registered aliases, each with its `read_only` tier.
- `status()`: signer health and reachability of every server, each with its `read_only` tier.
- `ping(alias)`: READ-class reachability probe of one server. No approval, no signer, no tap;
  cheaper than `status`, which fans out across every server.
- `revoke_server(alias)`: uninstall the gate from a server (needs Telegram approval).
- `request_grant(alias, scope, commands?, duration_hours, reason?)`: ask for a standing grant
  so matching writes auto-sign for a window (≤ 24h). A human approves it separately; the
  agent can only request one.
- `revoke_grant(alias)`: drop a server's standing grant (de-escalation, always safe, no approval).
- `list_grants(alias?)`: the signer's live standing grants (read-only, no approval).
- `update_gate(alias)`: signed, in-place update of the gate binary on a registered server. The
  agent supplies only the alias, never bytes or a hash. The MCP hashes the operator's locally
  staged gate binary and the operator approves a distinct "GATE BINARY UPDATE" banner bound to
  that SHA-256. Fail-closed: a hash mismatch, wrong-arch binary or Tier-1 host refuses and
  writes nothing. It is audited, onboards no new server, and a grant never auto-signs it.
- `transfer(src_alias, src_path, dest_alias, dest_path, mode?)`: move a secret file between two
  registered servers, end-to-end encrypted through the gate (default mode `0600`). The agent
  gives only aliases and absolute paths, never keys, fingerprints or an id. The MCP relays only
  ciphertext, so the plaintext never reaches the agent or any log; you get metadata only (xfer
  id, byte count). One "SECRET TRANSFER" approval covers both legs; a grant never auto-signs
  it; Tier-1 servers are refused before any tap. Both endpoints must be registered for transfer,
  and it needs the local (Tier-2) Telegram signer: the hosted (Tier-3) signer fails closed.

## Operating a server

- Setup walkthrough: `commands/setup.md`. Entry points: `/sshgate:setup` (one-time install),
  `/sshgate:status` (health), `/sshgate:revoke <alias>` (clean removal).
- For "debug X on server Y", read `skills/debugging-remote-servers/SKILL.md` first. The loop:
  1. `list_servers` to confirm the alias is registered.
  2. Diagnose with `run` and read commands (`df -h`, `top -bn1`, `journalctl`); no approval.
  3. Queue fixes into `run_batch` so the user approves them in ONE tap. ALWAYS show the user
     the planned writes before calling it.
  4. After fixes, re-run a read health check.
- A Telegram denial is final. Never re-submit a denied write; ask why and propose alternatives.
- Never log MCP tool args that contain user-supplied secrets to stdout.
- **Phantom-live grant.** If `request_grant` errors or times out, the grant may still be live.
  Call `list_grants` before re-requesting: a re-request prompts the human twice and risks a
  double grant.
- **Verdict undelivered** (`the signer decided but the response did not arrive; a human may
  have DENIED this`): do NOT auto-retry. Check `status` and the Telegram approval thread, and
  resubmit only once you confirm it was not a denial.

## Provisioning is human-only

There is deliberately no `add_server` tool. Provisioning is the control plane: it defines which
machines the agent can reach. Running commands is the data plane. A human onboards a server with
the `sshgate` CLI (installed to `~/go/bin/sshgate` by `make install-local`):

1. `sshgate pubkey`: print SSHGate's dedicated public-key line.
2. Paste that line into the target's `~/.ssh/authorized_keys` by hand, over existing admin access.
3. `sshgate add <alias> <user@host>[:port] [--read-only]`: install the gate and rewrite the
   pasted line into the locked `command="~/.sshgate-gate/gate"` forced command. The alias lands
   in `~/.config/sshgate/servers.json`, the registry the MCP reads.

Transfer keys are enrolled the same way: `sshgate xfer-register <alias>` (`xfer-rotate` to
re-key, `xfer-status` for tier, on-host keys and fingerprint). If asked to add a server or enrol
a transfer key, don't try; give the user these CLI steps. If `sshgate add` fails on their side,
have them check the host's `/var/log/auth.log` and that the key line was pasted first.

## Tiers and write denials

- **Read-only (Tier-1):** gate deployed, no signer pubkey (`gate.pub` absent), every write
  denied. **Signed-write (Tier-2):** a Telegram signer approves writes (`gate.pub` present).
  `list_servers`, `status` and `ping` report the tier as `read_only` (`true` = Tier-1).
- A write to a read-only server is **refused locally before any tap** (`server "<alias>" is
  registered read-only …`). Don't retry; the agent cannot change a tier. A human de-provisions
  by hand and re-adds: on the host, replace SSHGate's forced `command="..."` line in
  `~/.ssh/authorized_keys` with `sshgate pubkey`'s plain line, drop the alias from
  `servers.json`, then re-run `sshgate add` at the new tier (`/sshgate:setup` first if no signer
  exists). `sshgate revoke <alias>` prints the exact commands and changes nothing. A Tier-1 host
  has no working signed revoke, so `/sshgate:revoke` and `revoke_server` refuse it before any
  tap. An in-place tier flip was rejected for security (see #17 in `docs/ROADMAP.md`).
- Gate deny exit codes come back annotated. **77** = missing signature, or the host has no
  signer pubkey (Tier-1): check `status`; with no signer, the user runs `/sshgate:setup` and
  re-tiers as above (a bare re-add of a registered alias is refused). **65** = bad or expired
  signature, usually clock skew or a stale approval: retry once.
- On hosts that support it, reads run in a kernel jail: they cannot write files or reach
  Unix-socket daemons (a few `systemctl`/`docker` read verbs excepted) and may see an empty
  `/tmp`. The network, including localhost TCP services, is not yet restricted.
  A read denied with 77 and `read jail unavailable` means the host's jail could not be
  confirmed or set up, so nothing ran; a human runs `gate doctor` on the host.
- `transfer` failing with `src/dest server not registered for transfer`: that endpoint has no
  transfer key on the signer. The user runs `sshgate xfer-register <alias>`, then you retry.

## Signer problems: when to stop

- After the first `/sshgate:setup` the operator must log out and in (for `sshgatesigner` group
  membership), fully restart Claude Code, and run `/mcp` to confirm `sshgate` is live. A
  `signer socket … permission denied` error means this was skipped; it is NOT a dead daemon.
  STOP and tell the user.
- `status` shows the signer socket UNREACHABLE with `configured:true`: STOP and suggest
  `systemctl status sshgate-signer-telegram` and `journalctl -u sshgate-signer-telegram -n 50`.
- `configured:false` / "not configured" is the NORMAL Tier-1 state, not a fault. Writes wait
  until `/sshgate:setup` adds a signer.

## What to build next

- Read `docs/BUILD-PLAN.md` before starting any development work. It is the committed build
  order: work items and their steps run top to bottom, and each step has its own acceptance.
- Take the first step that is not `done` and whose dependencies are done. Don't start work that
  is not in the plan; unscheduled ideas live in `docs/ROADMAP.md`.
- When a step lands, set its status to `done` in the same commit. A change to the order or
  scope of a step is made in the plan, in the same commit, with the reason in the message.

## Developing SSHGate

- The main session plans, dispatches and verifies, and is accountable for the result. Models
  come from the operator's harness policy, not from this repo. SSHGate is a security backbone
  with real trust boundaries: design, adversarial critique, security analysis and code review
  never go to a weaker model than the rest of the work.
- Verify, never rubber-stamp: read the diffs, run build, vet and tests yourself, and confirm
  green before calling a unit done. The bar is "it works end to end", not "work was dispatched".
- Checks: `make vet`, `make test` (`go test -race ./...`); `make preflight` before any push;
  `make e2e` (needs Docker) before a release.
- This repo is public. Operator notes, per-server inventories and design reviews stay in the
  gitignored `local-workspace/` or `local-notes/`, never in a tracked file.

## Layout

- `src/`: Go packages: `gate`, `mcp`, `signer`, `signer-server`, `cli/cmd/sshgate` (the CLI),
  plus the policy*, *wire, classify, redact, xfer, hostkey and gatever packages.
- `pkg/signerkit/`: shared signer core. `internal/`: internal libraries. `cmd/gate-redteam/`:
  the gate red-team tool.
- `commands/`, `skills/`, `.claude-plugin/`: plugin slash commands, skills and manifest.
- `dist/gate/`: the committed, hash-published gate binary, the release trust anchor. Only
  `make release-gate` writes it; `make verify-dist` checks it. Never edit it by hand.
- `docs/`: design, threat model and testing docs. `docs/BUILD-PLAN.md` is the committed build
  order; `docs/ROADMAP.md` lists unscheduled features; `docs/proposed/` holds dated proposals.
- `packaging/mcpb/`, `scripts/`, `tests/`: MCPB bundle sources, install scripts, integration tests.
- `WORKLOG.md` (local, gitignored): append-only work log; read its header, last five headings,
  then the last entry.
- `local-notes/archive/YYYY-MM-DD/` (gitignored): verbatim copies of what housekeeping cut.
  Search it; never load it.
