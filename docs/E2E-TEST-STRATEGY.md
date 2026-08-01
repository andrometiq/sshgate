# SSHGate end-to-end test strategy

This is the standing verification strategy for SSHGate. Run it as a gate, not
as an afterthought:

| When | Command | Needs Docker |
| --- | --- | --- |
| **Before every push** | `make preflight` | no |
| **After a large build / before a release** | `make e2e` | yes |

Both are real gates. A green `preflight` is the bar for pushing; a green `e2e`
is the bar for declaring a build done or cutting a release. Don't push on a red
preflight, and don't claim an install/feature works end-to-end without an `e2e`
run (the Docker layer is where "deploy the gate and run a command over real SSH"
is actually proven).

## `make preflight` — before every push (fast, no Docker)

The current target requires all of these checks:

1. `make vet` — `go vet ./...`.
2. `make test` — `go test -race ./...` (the full unit + in-process suite,
   including the in-process MCP-client tests that prove the tool surface
   actually serves).
3. `make test-refapp-js` — Node's test runner over the hosted WebAuthn browser
   adapter. Node is required for this gate.
4. `make gitleaks` — scans the commits about to be pushed (`origin/main..HEAD`)
   for secrets. Scanning the push delta (not full history) keeps intentional
   fake-secret test fixtures on other branches from failing an unrelated push.
   Install gitleaks before pushing; the target warns loudly if it is absent.
5. `make build` — a clean `go build` of every binary.
6. `make verify-dist` — the fast verified-release-channel checks: the committed
   `dist/gate` binary still matches its published `.sha256`, and `VERSION` is a
   single clean line. (The reproducible source↔binary rebuild is CI's job —
   `verify-gate.yml`.)
7. `make verify-versions` — builds the MCP, local Telegram signer, and hosted
   signer with their release stamps and confirms each `--version` equals
   `VERSION`.
8. `make verify-repro` — builds the gate twice with the shared flag set into
   throwaway paths and fails if the two hashes differ, catching flag-set
   nondeterminism regressions before push.
9. `make verify-no-sqlite-local` — confirms the local Telegram signer does not
   link the hosted SQLite implementation.
10. `make verify-no-humanauth-local` — confirms the local Telegram signer does
    not link the hosted WebAuthn/TOTP stack.

## `make e2e` — after a large build / before a release (needs Docker)

Runs everything in `preflight`, then:

11. `make test-integration` — `go test -count=1 -p=1 -race -tags=integration
    ./internal/redteam ./tests/integration/... -timeout=300s -v`. It runs
    uncached and serially because both package groups own host port 2222; they
    cannot safely run in parallel. It boots a real `linuxserver/openssh-server`
    container and exercises the full
    path: the provisioning logic (`tools.AddServer`, the shared core the human
    `sshgate` CLI drives) deploys the gate over SSH, a read command streams back,
    a write is denied at the gate (read-only / Tier-1), and the signed/Tier-2
    paths where present. This is the load-bearing "it actually works" layer.
12. `make smoke` — `scripts/smoke-fresh-install.sh`. The headless fresh-user
    regression: spawns `sshgate-mcp` with an empty `HOME` (no config, no key)
    and asserts it reaches `ready` instead of hard-exiting. Guards the
    chicken-and-egg bug where the server refused to start before `/sshgate:setup`
    created the key, leaving a fresh read-only user with a dead tool surface.

## What can't be headless — the manual fresh-user install check

The Claude Code plugin + slash-command layer (`/plugin install`,
`/sshgate:setup`) and the human `sshgate` provisioning CLI can't be driven from
`go test`. After changes to the install flow, the binaries, or the MCP startup,
do one real fresh-user pass on a clean machine (or a throwaway user / container)
and confirm the **Tier-1 read-only** path end-to-end:

1. `go version` ≥ 1.25; `git clone`; `make install-local`; confirm
   `command -v sshgate-mcp` resolves on `$PATH`.
2. `/plugin marketplace add <clone>`, `/plugin install sshgate@sshgate`, then
   **fully quit and relaunch Claude Code** — `/reload-plugins` activates the
   slash commands but does NOT spawn the stdio MCP server; only a fresh start
   does. After relaunch, run `/mcp` and confirm the `sshgate` server is
   connected and its tools appear (the MCP server must come up even though no
   key exists yet — this is what `make smoke` guards headlessly).
3. `/sshgate:setup` → Tier 1. Then provision a server by hand against a
   reachable Linux box: `sshgate pubkey`, paste the line into the target's
   `~/.ssh/authorized_keys`, then `sshgate add <alias> <user@host> --read-only`
   — confirm it deploys and a read (`run df -h`) streams back while a write is
   denied.
4. `/sshgate:status` shows the signer as `not configured (read-only / Tier 1)`
   — that's healthy, not an error.

## Manual pre-release exercises — required before any registry upload

`make e2e` is necessary but cannot exercise real client installations or the
human approval boundary. Before uploading an extension/plugin to any registry,
the release owner must record this manual matrix against a fresh client profile
or disposable user. These are owner and external-resource gates: CI and an
agent cannot provide the Telegram account, approval device, DNS/TLS host, or
registry credentials.

1. **Fresh Claude Code client:** install the release candidate with the current
   `/plugin marketplace add` and `/plugin install sshgate@sshgate` flow; fully
   quit/relaunch; confirm `/mcp` reports `sshgate` connected; then complete the
   Tier-1 read, write-denied, and status checks above.
2. **Fresh Codex client:** install the same candidate using the documented
   `codex plugin marketplace add …` and `codex plugin add sshgate@sshgate`
   flow (or the documented bare `codex mcp add` fallback); start a fresh Codex
   session and prove MCP connection, one Tier-1 read, and one write denial.
3. **Fresh Gemini CLI client:** install the same candidate with the documented
   `gemini extensions install …` flow; start a fresh Gemini CLI session and
   prove MCP connection, one Tier-1 read, and one write denial. Do not infer
   extension success merely from installation output.
4. **Tier 2, owner-operated:** on a disposable or expressly approved local
   systemd host, run the one-pass installer, confirm the daemon is active and
   the caller has activated the `sshgatesigner` group, send `/start` to the
   dedicated Telegram bot, approve one harmless write, deny one harmless
   write, and retain the resulting audit-log evidence. Existing Tier-1 aliases
   must be manually de-provisioned and re-added; staging `gate.pub` alone does
   not upgrade them.
5. **Tier 3, owner-operated, after its release gates close:** deploy
   `sshgate-signer-server` on a separate approved system using
   `src/signer-server/README.md`; complete its DNS/TLS, operator-factor, backup,
   and secure credential-distribution requirements; configure one approved
   laptop for the hosted backend; then approve and deny harmless writes through
   the hosted UI and preserve the audit evidence. Until the policy-authority
   work is complete, this row remains blocked rather than becoming an
   engineering exercise that silently substitutes for release readiness. The
   local setup command does not perform this deployment.

For each row, record the exact candidate revision, client version, operating
system, observed MCP connection state, read/write result, and the owner who
performed the external action. A failed or skipped row is a release blocker
unless the release owner explicitly narrows the release scope; no agent should
silently waive it.

The **Tier-2** signer + Telegram-approval path needs the operator's hardware
(the master key under `sshgatesigner`, a Telegram bot, a real phone tap) and is
verified with the one-time live checklist, not in CI.

> **Tier-2 install is now a single interactive `scripts/install.sh` pass**
> (was a three-step dance: first pass → hand-edit the root-owned config →
> second pass). One run prompts for the Telegram user_id and bot token in the
> same invocation, appends the `[backend.telegram]` block, and flips the
> backend type — idempotently. When re-walking the manual Tier-2 check
> (`docs/install-step-by-step.md` §Manual path — Tier 2 / `commands/setup.md`
> T2.2), confirm ONE `sudo install.sh` reaches both the `user_id` and the
> `token` prompts and the daemon comes up `active` afterward.
