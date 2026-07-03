# SSHGATE_UPDATE — signed in-place gate self-update (design spec)

Status: **proposed** (2026-07). Build gated by adversarial critique + triple
review; **deploy gated by the operator** ("build it out, then I deploy").

## 1. Problem & goal

The gate binary (`~/.sshgate-gate/gate` on each remote, mode 0755) can only be
replaced today by a full human re-provision: revoke the server, re-paste the
SSHGate public key by hand, `sshgate add` again. Every gate change — including
the just-merged output-redaction widening, which is **inert on a box until that
box's gate is redeployed** — pays that cost per server.

`SSHGATE_UPDATE` replaces that dance with a single **signed** operation the
agent can request and the operator approves with one Telegram tap: push the
operator's locally-built gate binary onto an already-registered server, in
place, atomically. This is the mechanism that makes future gate changes
(redaction rules, classifier fixes) deployable without re-provisioning.

A stub already exists — `src/gate/cmd/sshgate-gate/main.go:196-201` logs "not
yet implemented" and exits 1. The verb, its wire path, and its MCP tool are
what this spec builds. The roadmap already **reserves** this feature and its
bar: `docs/ROADMAP.md:157-162` — "a signed control verb to update the gate
binary in place … an update path is a code-execution path, so it must be at
least as strict as the signing model — signed, versioned, fail-closed, and
audited." This design meets each: **signed** (R1), **fail-closed** (hash
mismatch / bad ELF / Tier-1 all refuse and write nothing), **versioned** (the
returned SHA + optional build revision), **audited** (gate + signer records).

### Non-goals (YAGNI)

- No arbitrary-binary push. The agent never supplies binary bytes or a hash;
  the MCP reads the operator's own locally-staged gate binary. See §4.
- No auto-update / version-polling / rollback-on-crash daemon. One-shot,
  operator-approved, per server.
- No stateful version counter on the gate (would break the stateless-gate
  invariant — see §7, replay analysis).
- No Tier-1 self-update: a read-only box has no signer pubkey, so it refuses
  every signed command locally (§6). Updating a Tier-1 gate stays a human
  re-provision.

## 2. Hard security requirements

From the operator, verbatim intent:

- **R1 — signed.** No unsigned update path. An update goes through the signer
  exactly like any other write; the master key must sign it.
- **R2 — scary warning.** The Telegram approval MUST show an alarming banner
  ("This will REPLACE the SSHGate gate binary on `<alias>`. Do you trust
  this?") before the tap.
- **R3 — human-only approval.** The agent can only *request*. Only the operator
  approves. In particular a standing **grant must NEVER auto-sign an update**
  (nor any admin verb) — enforced by the `matchGrant` carve-out (§3, §5.2), the
  single point that actually covers it.

Added by this design (load-bearing, hardened in the critique pass):

- **R4 — approval binds to the exact binary.** The signed authorization commits
  to the **SHA-256 of the exact new binary**. The gate hashes the bytes it
  receives and refuses on mismatch. So an approved update authorizes *that one
  binary* — it can never be swapped, on the wire or by a compromised agent, for
  different code. This is the property that makes R1 meaningful.
- **R5 — the binary is operator-provided, not agent-provided.** The MCP reads
  the staged gate binary from a local path (`~/.config/sshgate/bin/sshgate-gate-linux-amd64`,
  or `$SSHGATE_GATE_BIN` if set), computes its hash, and shows that hash + build
  revision to the operator. The agent chooses only the target alias — never bytes
  or a hash. *Caveat (Finding 2):* by default that path is in the agent user's
  own home, so R5 is enforced by the human tap + revision banner, not
  structurally; the hardened staging option (§10.2b) makes it structural.
- **R6 — no new unsigned-exec surface.** The binary bytes travel on the gate
  process's **own** stdin and are consumed by the update handler itself; they
  never reach a `/bin/sh` child. The executor's `c.Stdin = nil` hardening
  (executor.go:214, task #44) stays untouched.
- **R7 — gate stays stateless & the trust anchor is preserved.** The update
  replaces only the binary inode; `gate.pub` (the verification anchor) and the
  `~/.sshgate-gate/` layout are untouched. No new persistent decision state.

## 3. Where each guarantee lives (threat model)

| Threat | Control | Where |
| --- | --- | --- |
| Agent pushes arbitrary code (post-approval) | Approval commits to SHA-256; gate refuses on hash mismatch | Gate handler §6 (R4) |
| Agent stages malware **before** the human hashes it | Residual: reduces to "human approves an opaque hash" — mitigated by revision-in-banner (Finding 4) + recommended operator-owned staging dir (§10) | §5.1, §7, §10 (R5, **not fully structural**) |
| Wire tamper of the binary | Gate re-hashes received bytes vs the **signed** hash | Gate handler §6 (R4) |
| Wire tamper of the hash | Hash rides inside the Ed25519-signed `Cmd` (`SSHGATE_SIG` verify) | `gate.VerifySigned` verify.go:64-68 (unchanged) |
| Replay on another server | Per-server host-key binding (`payload.Host`) | verify.go:107-109 (unchanged) |
| Replay later | ≤5-min validity window (`MaxSigValidity`); default request TTL | verify.go:82-91 (unchanged) |
| Grant auto-signs an update | `matchGrant` admin-verb carve-out: any `SSHGATE_`-prefixed command short-circuits to "always prompt" | signer §5.2 (R3) |
| Unsigned/Tier-1 update | Signed line on `pubkey==nil` → exit 77 before dispatch | main.go:129-136 (unchanged, R3 boundary) |
| Binary-via-stdin exec vector | Bytes read by the gate itself, never fed to `sh -c` | Gate handler §6 (R6) |
| Stdin memory-exhaustion DoS | Hard read cap (§6) | Gate handler (new) |
| Bricking the gate (wrong-arch binary) | ELF **architecture** check (`e_machine` vs GOARCH), not just magic; size sanity; `.bak` (out-of-band recovery only — the gated key can't self-heal); post-update liveness re-probe | Gate handler §6 (Finding 3) |

**Asymmetry to record (load-bearing):** the gate dispatches on the `Cmd` prefix
(`SSHGATE_UPDATE `) and cannot tell a human-approved signature from a
grant-auto-signed one — they are byte-identical by design, and both carry the
same `Cmd`. So an update signed via *any* signer path the gate will honour. That
means R3 ("no grant signs an update") **cannot** be made structural by giving
update a separate signer request kind: an attacker could still send the update
`Cmd` on the ordinary `sign` kind, a `scope=all` grant would auto-sign it
(`matchGrant` covers any command on the sign path, daemon.go:393/877-893), and
the gate would honour it — with **no scary warning** (a grant prompts no one).
The only enforcement point that actually covers this is a **carve-out inside
`matchGrant` itself** (§5.2): reject any `SSHGATE_`-prefixed command from
grant auto-sign, exactly like the existing reveal short-circuit. That is
necessary and sufficient; a separate kind is neither, so this design does not
add one.

**Bonus:** the same carve-out closes a pre-existing gap — `SSHGATE_REVOKE` is
signed through the ordinary sign path today (revoke_server.go:88), so a
`scope=all` grant currently auto-signs a *revoke* with no fresh tap. Excluding
all admin verbs from grants (like reveals are excluded) fixes revoke too.

## 4. Wire design — the hash rides inside the signed command

**Decision: the signed payload is NOT extended. The commitment is the command
string `SSHGATE_UPDATE <sha256hex>` inside the already-signed `SigPayload.Cmd`.**

This mirrors the existing `SSHGATE_REVOKE` admin verb, which also rides inside
`Cmd` and dispatches in gate `main()` after `VerifySigned`. Consequences:

- **Zero change** to `sigwire.SigPayload` (payload.go:25-56), the canonical
  golden test (payload_golden_test.go), or the single strict payload decoder
  (`DisallowUnknownFields`, payload.go:133). The hash is covered by the same
  Ed25519 signature over `json.Marshal(payload)` that already protects `Cmd`
  (tamper the hash ⇒ `ErrBadSig`, verify_test.go).
- The gate's `VerifySigned` path is **unchanged**; the verb is a `strings.HasPrefix`
  dispatch on the already-verified inner command (the stub at main.go:196).

This is strictly less surface than adding a typed `sha256` payload field (which
would pull in payload.go, both golden/omitempty tests, the strict decoder, and
verify-thread changes) for **no security gain** — the hash is equally signed
either way. Rejected: adding a payload field.

Wire form (identical shape to a normal signed write):

```
SSHGATE_SIG:<sigB64>:<payloadB64> SSHGATE_UPDATE <sha256hex>
                                  └──────────── readability trailer, ignored by DecodeSigned
```

The authoritative command is `payload.Cmd == "SSHGATE_UPDATE <sha256hex>"`. The
binary **bytes** do not ride here (SSH_ORIGINAL_COMMAND is bounded by ARG_MAX
~128 KB and is the command line) — they stream on stdin (§5, §6).

`<sha256hex>` is exactly 64 lowercase hex chars. A lowercase-hex string is
2-class (digit+lower, no upper), so the widened generic redactor's `has3Class`
gate (scanner_generic.go) does **not** touch it — the operator sees the real
hash. A regression test pins that `redactForDisplay` leaves the hash intact
(§9); if any named rule ever matches it, the display path switches to rendering
the hash from a field outside the redaction sink.

## 5. Component design

### 5.1 MCP — new `update_gate` tool (agent surface goes 8 → 9)

`sshgate.update_gate(alias)`:

1. Resolve `alias` from the registry (fail on unknown / Tier-1 read-only —
   short-circuit with the same actionable error `runWrite` uses, run.go:237, so
   no tap is wasted).
2. Read the locally-staged gate binary from the **trusted** path. The production
   MCP builds its `Runner` **without** `AddServerCfg` (sshgate-mcp/main.go:156-162),
   so `cfg.GateBinaryPath` is empty at runtime — the tool must resolve the path
   itself as `filepath.Join(cfgRoot, "bin", "sshgate-gate-linux-amd64")`, where
   `cfgRoot = $XDG_CONFIG_HOME/sshgate` (default `~/.config/sshgate`), the exact
   path `make install-local` stages to (Makefile install-local target) and the
   CLI provisioner reads (provision.go:230). Wire this into a new
   `Runner.StagedGatePath` field set in sshgate-mcp/main.go. **Never** an agent
   parameter (R5). Fail fast if absent with "run `make install-local` first".
   Read the file **once** (bytes + hash from the same read) so there is no
   window between hashing and sending.
3. Compute `sha256hex` (lowercase, `hex.EncodeToString`) of those bytes; build
   `cmd = "SSHGATE_UPDATE <sha256hex>"`.
4. Request a signature via the **ordinary sign path** — reuse `r.Sign.Sign(ctx,
   reqID, []signpkg.CmdReq{{Server: alias, Cmd: cmd, TTLSec: UpdateTTLSec, Host:
   entry.Fingerprint}})`, exactly the pattern `revoke_server.go:88` uses (no new
   sign-client method). `Host` comes from the trusted registry (mirrors
   run.go:267 / revoke_server.go:92) so the approval binds to this one server.
   `UpdateTTLSec = 300` (the `MaxSigValidity` cap) for ample post-tap transfer
   margin; a longer window is harmless here because an update replay re-installs
   the identical approved binary (§7). The signer's `matchGrant` carve-out
   (§5.2) forces a human tap; `formatApprovalMessage` shows the scary banner.
5. On approval, open **one** SSH session that runs the signed `wireCmd` (`sig + "
   " + cmd`) while streaming the binary bytes on stdin — a new `ssh.Client`
   method `RunWithStdin` (§5.3). Use a generous per-call ctx (the write path has
   no exec cap; `ssh.Client.Run` bounds only dial+handshake) sized for a
   multi-MB transfer.
6. Parse the gate's success marker `SSHGATE_UPDATED sha256=<hash> size=<n>
   [rev=<vcs>]`; confirm the returned hash equals the requested hash. Then
   re-probe the server (empty-cmd → `SSHGATE_OK`, mirroring
   `verifyProvision` provision.go:313) to confirm the **new** gate is alive.
7. Return `{alias, newHash, size, revision, verifiedAlive}`.

Tool placement rationale: `update_gate` does **not** expand the agent's reach
(no new server is onboarded — provisioning stays the human-only CLI). It acts on
an already-registered server and requires a human tap bound to an
operator-built binary hash, so the agent can never cause arbitrary code to run.
It therefore belongs on the data-plane MCP surface, which is what the operator
asked for. (`TestServe_RegistersExactlyAgentTools`, server_test.go:262, updates
8 → 9; all "eight tools" docs update to nine — §8.)

### 5.2 Signer — `matchGrant` admin-verb carve-out + scary banner

Update rides the **ordinary sign path** (like revoke). Two changes make it safe:

- **`matchGrant` admin-verb carve-out (R3, the load-bearing control).** Add a
  short-circuit at the top of `matchGrant` (daemon.go:836), mirroring the
  existing reveal short-circuit (daemon.go:837-842): if ANY command's `Cmd` has
  an `SSHGATE_` admin-verb prefix (`SSHGATE_UPDATE `, `SSHGATE_REVOKE`, and
  defensively any `SSHGATE_` prefix), return `("", false)` so the whole request
  always routes to the human prompt. This is the single point that actually
  prevents a `scope=all` grant from auto-signing an update (or a revoke — §3
  bonus). Because it is checked first/outermost, no later grant logic can
  re-admit it. `authMode` (daemon.go:169-180) then resolves to `human` for the
  approved update (no `grant:` prefix), which the audit + response both record.
- **Scary warning (R2), with human-verifiable build identity.** `formatApprovalMessage`
  (telegram.go:846) gains an update banner, keyed on
  `strings.HasPrefix(c.Cmd, "SSHGATE_UPDATE ")` — derived from the exact signed
  command, so the displayed warning can never disagree with what is signed and
  executed. The banner renders the hash **and the staged binary's build revision
  + build-time** (`vcs.revision` / `vcs.time` via `debug/buildinfo`), because an
  opaque hash gives the operator nothing to judge — a build revision lets them
  catch a *downgrade to an older binary* (Finding 4, §7). The MCP passes these
  display fields alongside the command; the hash itself is rendered **outside**
  `redactForDisplay` (a hash is not a secret — render it unconditionally raw, so
  "what you see is what you approve" holds regardless of ruleset drift; §4).
  Banner (plain text, no parse-mode, like the reveal/grant banners; well under
  Telegram's 4096-char limit — only the short hash + metadata, never the bytes):

  ```
  ⚠️ GATE BINARY UPDATE — approving this REPLACES the SSHGate gate binary on
  <alias> with a new build. The new gate governs every future command on this
  server. Only approve an update you initiated.

  🔐 SSHGate GATE UPDATE — <alias>
  New gate SHA-256: <64hex>
  Build: rev <vcs-short> · <vcs-time> · <n> bytes
  Currently on <alias>: rev <running-rev-or-unknown>   ← from SSHGATE_VERSION probe
  Request ID: …   Expires in 5m0s
  ```

  The "Currently on `<alias>`" line (from a pre-sign `SSHGATE_VERSION` read, §6)
  puts the staged and running build revisions side by side at approval time.
  (Git revisions are not orderable, so the tool does **not** claim "older/newer";
  it presents both so the operator can recognise an unexpected or unfamiliar
  build before tapping — which is what catches an agent-staged downgrade.)

No new signer request kind, and **`sigwire.ProtoVersion` is not touched** — the
update is a normal `sign` request whose `Cmd` is an admin verb, so the socket
protocol is unchanged. Audit: the standard `AuditEvent` (daemon.go:944) records
the `SSHGATE_UPDATE <hash>` command string, status, and `auth_mode=human`; the
SHA lives in the command string, no new audit field.

**Why not a separate `kind:"update"`?** Because the gate honours the update
`Cmd` no matter which signer kind minted the signature (§3), a separate kind
would not stop the sign-path/grant bypass — only the `matchGrant` carve-out
does. Adding a kind would be extra surface (a ProtoVersion question, a new
decoder) for no security gain, so it is deliberately omitted.

### 5.3 MCP SSH transport — `RunWithStdin`

`ssh.Client.Run` (client.go:47) never sets `sess.Stdin`. Add a sibling
`RunWithStdin(ctx, host, user, port, cmd string, stdin io.Reader)` that is
identical except it wires `sess.Stdin = stdin` (or `StdinPipe` + `io.Copy` +
close, template `uploadFile` add_server.go:474-511) before `sess.Run`. Used by
`update_gate` only. Documented as the one gated command that carries channel
stdin — and it carries **data the gate authenticates by hash**, not a program.

**Read-once (Finding 5, hard requirement).** `update_gate` MUST `os.ReadFile`
the staged binary **once** into a buffer, hash *that buffer*, and stream
`bytes.NewReader(thatBuffer)` to `RunWithStdin`. It must NOT re-`os.Open` the
path for the stream — a concurrent overwrite between hashing and streaming would
otherwise send bytes the human never approved (the gate's re-hash catches it and
refuses, so it fails safe, but "what was approved == what was streamed" must be
guaranteed by construction, not by the gate's backstop).

### 5.4 Gate — implement the `SSHGATE_UPDATE` handler (§6)

## 6. Gate handler algorithm (`main.go:196`, replacing the stub)

Reached only when `signed && VerifySigned` passed (⇒ authentic, unexpired,
host-bound) and `pubkey != nil` (⇒ Tier-2). On a Tier-1 box the signed line was
already denied at main.go:129-136 (exit 77) — no handler code runs (R3 boundary,
free).

```
handleUpdate(innerCmd):
  0. This function ALWAYS returns an exit code — it must NEVER fall through to
     classify.Classify / the exec switch (Finding 6). The bytes it reads are
     hash-pinned DATA, never a program; the executor is never invoked, so the
     c.Stdin=nil hardening (executor.go:214) is on a different path and untouched.
  1. want := parse the sha256 with an ANCHORED match: innerCmd must equal
     `^SSHGATE_UPDATE [0-9a-f]{64}$` EXACTLY — reject any trailing bytes (e.g.
     "SSHGATE_UPDATE <hex>; rm -rf /") with exit 65. (Belt: even a lax parse
     would leave the suffix inert per step 0, but anchor it anyway.)
  2. body := io.ReadAll(io.LimitReader(os.Stdin, maxGateBinaryBytes+1)) — a
     BOUNDED read (NOT bare io.ReadAll). maxGateBinaryBytes = 64 MiB. If
     len(body) == 0 → refuse (exit 65). If len(body) > maxGateBinaryBytes (the
     +1 tripped) → refuse (exit 65). ONLY place the gate reads its own stdin.
  3. got := sha256(body). If got != want → refuse, write NOTHING (exit 65).
     (R4: the operator approved `want`; only `want` may ever be installed.)
  4. Sanity BEFORE any write (fail-closed, exit 65 on any):
       - body starts with ELF magic \x7fELF;
       - parse debug/elf.NewFile(bytes.NewReader(body)); e_machine MUST match
         the running gate's arch (EM_X86_64 for GOARCH=amd64) and OSABI/class be
         sane — a wrong-arch ELF passes the magic check but BRICKS the gate on the
         next exec (Finding 3); reject it here;
       - size within [minGateBinaryBytes(=256 KiB), maxGateBinaryBytes].
     Best-effort (non-fatal): debug/buildinfo.Read(bytes.NewReader(body)) →
     vcs.revision/time for the success marker.
  5. Locate the running gate path via gateDirFn() (main.go:415) / defaultGateDir
     → os.Executable (main.go:432) → dir = ~/.sshgate-gate, bin = dir/gate.
  6. Back up: copy current bin → dir/gate.bak (best-effort; log on failure but
     proceed). NOTE: gate.bak is out-of-band recovery ONLY — the forced command
     pins `~/.sshgate-gate/gate`, so a bricked gate CANNOT self-heal via the
     gated key; restoring gate.bak needs separate shell/console access (§10, §7).
  7. Atomic replace: gate.AtomicReplace(bin, body, 0o755) — exported wrapper over
     the tmp+fsync+rename+parent-fsync helper (revoke.go:195, already takes a
     mode param), tmp created INSIDE dir (same filesystem ⇒ atomic rename; rename
     over the running binary is safe on Linux — the running process keeps its old
     inode, the NEXT SSH connection execs the new one). gate.pub + dir untouched (R7).
     On any filesystem/replace error → exit 70, leaving the old gate in place.
  8. Audit via auditNoExec(innerCmd, "write", "signed", 0).
  9. Print success marker to stdout, exit 0:
     "SSHGATE_UPDATED sha256=<got> size=<len(body)> rev=<vcs-or-unknown>"
```

Exit codes: 65 for hash/format/anchor/ELF/arch/size refusals (write nothing),
70 for a filesystem/replace failure (old gate intact), 0 on success. (All
`VerifySigned` failures already collapse to 65 upstream at main.go:171-181.)

**Companion — `SSHGATE_VERSION` read verb (now load-bearing, not optional).** A
tiny verb (recognized early like the empty-cmd `SSHGATE_OK` probe) that prints
the running gate's `runtime/debug.ReadBuildInfo()` vcs.revision to stdout and
exits 0. The MCP reads it BEFORE an update to show "currently on `<alias>`: rev
…" in the approval banner (downgrade visibility, Finding 4) and AFTER to confirm
the update took. It exposes only a build revision to the (semi-trusted)
gated-key holder — consistent with `status` being unsigned. Promoted from
optional because the downgrade mitigation depends on it.

## 7. Replay & downgrade analysis (stateless gate)

The gate holds no nonce store (deliberate — task #43, statelessness). So an
approved `SSHGATE_UPDATE` envelope **plus** its binary bytes are replayable to
the **same** host within the validity window. For an update specifically this is
**benign**:

- A replay re-sends the **same** bytes, which hash to the **same** `want`, and
  installs the **identical** operator-approved binary — an idempotent no-op.
- A replay with **different** bytes fails the hash check (step 3) and installs
  nothing. So even a captured envelope authorizes exactly one binary.
- Cross-host replay is blocked by host-key binding (`payload.Host`, verify.go).
- Later replay (past ≤5 min) is blocked by expiry (`MaxSigValidity`).

**Wire-replay residual (accepted, matches the existing all-writes residual):**
if the operator approves two *different* updates on one host within 300 s **and**
an attacker can read the encrypted SSH channel, a captured earlier envelope+bytes
could be replayed to "downgrade" to the earlier of the two within that window.
Requires (a) two updates in 5 min and (b) breaking SSH transport encryption — the
latter is already total compromise. A monotonic version counter would close it
but is the first persistent decision-state the gate would hold, breaking the
stateless-gate invariant; deliberately **not** built (YAGNI + statelessness).

**Agent-chosen-downgrade (Finding 4 — the cheaper, real one, MITIGATED not just
recorded):** the gate has no version floor, so an *older* validly-built gate
installs fine. A compromised agent could stage an old, known-vulnerable gate
(e.g. a pre-redaction-widening build) and get the human to approve its opaque
hash. This needs **no** wire capture. Mitigation: the approval banner shows the
staged build's `vcs.revision`/`vcs.time` **and** the currently-running revision
(from the pre-sign `SSHGATE_VERSION` probe, §6), so a downgrade is visible at
approval time; the tool result flags "staged build is older than what's running"
explicitly. This is human-verifiable defense, not a hard block (a determined
agent with a Go toolchain could build a same-revision-looking binary — see
the staging-trust residual next). A hard version floor on the gate is
possible later but is deferred (statelessness).

**Staging-trust residual (Finding 2 — where R5 actually bottoms out):** the gate's
re-hash guarantees *what's installed == what was approved*. It does NOT guarantee
*what was approved == the operator's real binary*: the staged file
(`~/.config/sshgate/bin/sshgate-gate-linux-amd64`) lives in the **agent's own
user's** home, so a compromised agent could overwrite it before the MCP hashes
it, and the human would approve an opaque hash of agent-chosen bytes. The human
tap still gates it (unlike Finding 1), and the revision banner helps, but R5 is
**not structurally enforced** by default. The clean fix is to stage the gate
binary somewhere the agent's uid **cannot write** (operator- or
`sshgatesigner`-owned, mode 0644 — agent reads to hash+stream, only the operator
writes), mirroring SSHGate's separate-user posture for the master key. This is a
**deploy decision** (§10) because it changes where `make install-local` stages
the binary and needs a root/operator-owned path; recommended, but presented for
your call rather than silently chosen.

## 8. File-by-file touch list

New / changed (production):
- `src/gate/cmd/sshgate-gate/main.go` — replace the stub (main.go:196-201) with
  the handler (§6); add `SSHGATE_VERSION` early-recognition; **update the package
  doc-comment exit-code table (main.go:10-12)** which currently says the
  UPDATE/REVOKE stubs "fall here" at exit 1 (Pass-1 F5 — goes stale once the
  handler returns 0/65/70).
- `src/gate/replace.go` (new) — exported `gate.AtomicReplace(path, body, mode)`
  wrapping the revoke.go:195 `atomicWriteFile` helper (already takes a `mode`
  param → 0755 works); `.bak` copy of the current binary.
- `src/sigwire/…` — **no change** (the hash rides in `Cmd`; ProtoVersion
  untouched; §4, §5.2).
- `src/signer/daemon.go` — `matchGrant` admin-verb carve-out (§5.2). No new kind.
- `src/signer/backend/telegram.go` — update banner in `formatApprovalMessage`
  (telegram.go:846) keyed on the `SSHGATE_UPDATE ` prefix.
- `src/mcp/ssh/client.go` — `RunWithStdin` (§5.3); the `SSHRunner`-style call
  site in `update_gate` uses it directly (avoid widening the shared `SSHRunner`
  interface at run.go:94, which every tools-package fake implements — add the
  method on `*ssh.Client` and call it from the tool without touching the
  interface).
- `src/mcp/tools/update_gate.go` (new) — the tool (§5.1); reuse `r.Sign.Sign`
  (no new sign-client method); resolve the staged binary via `Runner.StagedGatePath`.
- `src/mcp/tools/run.go` — add `Runner.StagedGatePath` field.
- `src/mcp/cmd/sshgate-mcp/main.go` — set `StagedGatePath =
  filepath.Join(cfgRoot,"bin","sshgate-gate-linux-amd64")` on the Runner; register
  `update_gate`.
- `src/mcp/server.go` — register the tool (const `ToolNameUpdateGate`);
  server-instructions text.

Docs (8 → 9 tools — every hard-coded "eight tools" site):
- `CLAUDE.md:7`, `AGENTS.md:11`, `README.md:37`, `docs/design.md:201-212`,
  `docs/ROADMAP.md:16-19` (+ mark the reserved item ROADMAP.md:157-162 shipped),
  `docs/FUTURE.md:76` & `:125`, `docs/TESTING.md:451-452`,
  `skills/debugging-remote-servers/SKILL.md:9` — tool count + list + a
  `update_gate` description.
- Drive-by: fix the stale `main.go:117` stub citation in
  `docs/redaction-architecture.md:547` and the gate docstring → `main.go:196`.

Tests: §9.

## 9. Test plan

Unit / package (run in `make preflight`):
- **sigwire/gate wire**: `SSHGATE_UPDATE <hash>` round-trips through
  sign→VerifySigned unchanged; tamper of the hash ⇒ `ErrBadSig`.
- **gate handler** (in-package, `gateDirFn`/`hostKeyFPsFn` seams, t.TempDir):
  - hash-match → binary replaced (0755), `SSHGATE_UPDATED` marker, exit 0, old
    binary at `.bak`, `gate.pub` untouched.
  - hash-mismatch → nothing written, exit 65.
  - non-ELF / **wrong-arch ELF** (Finding 3) / oversize / undersize / empty-stdin
    → nothing written, exit 65.
  - anchored parse: `SSHGATE_UPDATE <hex>; rm -rf /` (trailing bytes) → exit 65,
    nothing written, and the suffix never reaches a shell (Finding 6).
  - stdin over cap → refuse (bounded `io.LimitReader`, not `io.ReadAll`), no OOM.
  - Tier-1 (pubkey nil) → the signed line is denied at 77 upstream (existing
    test path) — assert the handler is unreachable.
  - `gate.AtomicReplace` crash-safety: partial tmp never becomes `gate`.
- **signer** (`matchGrant` carve-out, R3 regression — the highest-value tests):
  with a live `scope=all` grant, an `SSHGATE_UPDATE <hash>` command sent on the
  **ordinary sign path** is **not** auto-signed — it routes to the human prompt
  (`matchGrant` returns ok=false); `auth_mode=human` on approval. The same for
  `SSHGATE_REVOKE` (pins the incidental pre-existing-gap fix). A benign write
  under the same grant still auto-signs (carve-out doesn't over-reach).
- **telegram**: `formatApprovalMessage` emits the ⚠️ update banner + shows the
  full 64-hex hash **and** the staged/running build revisions; the hash renders
  raw (outside `redactForDisplay`, Finding 7) — pin against the real
  `redactrules.Combined()` ruleset, not a stub, that the hash is never masked.
- **mcp**: `TestServe_RegistersExactlyAgentTools` → 9 incl. `update_gate`;
  `update_gate` resolves the staged binary from `Runner.StagedGatePath` (not an
  agent param); read-only alias short-circuits before signing; read-once (hash
  and stream the same buffer, Finding 5); success parses the marker + re-probes.

Integration (`//go:build integration`, Docker, `make test-integration`) — new
`tests/integration/phase5_update_test.go`:
- Provision a Tier-2 gate in the container; `update_gate` with a **known**
  rebuilt gate (e.g. one whose `SSHGATE_VERSION` differs), approve via the fake
  Telegram backend, assert: marker hash matches, the container's
  `~/.sshgate-gate/gate` bytes now equal the pushed binary, a follow-up command
  runs on the **new** gate, `gate.pub` unchanged, `.bak` present.
- Negative: a tampered byte stream (hash mismatch) leaves the old gate in place.

## 10. Decisions for the operator (deploy-time)

1. **This is the last manual redeploy.** Building this does not deploy it — the
   updated **signer** (new `update` kind) and the updated **gate** (handler)
   must first reach the boxes the old way (`make install-local` + signer
   restart; gate via one re-provision or the current bootstrap). After that,
   every future gate change uses `update_gate`.
2. **`update_gate` is on the agent MCP surface** (agent requests, operator
   approves a specific hash bound to an operator-built binary). If you'd rather
   it also exist as a human-only `sshgate update <alias>` CLI, that's a small
   add on top — say the word.
2b. **Where the staged gate binary lives (Finding 2 — security vs. convenience).**
   Default keeps it at `~/.config/sshgate/bin/` (agent-user-writable) — simplest,
   but it means a compromised agent could stage bytes the human then approves as
   an opaque hash (the revision banner is the mitigation). The hardened option
   stages it to an operator/`sshgatesigner`-owned path (mode 0644) the agent
   can't write, making R5 structural — but that needs a root-owned staging step
   in the install. **Recommend the hardened path; defaulting to the convenient
   one for the first cut. Your call at deploy.**
3. **This work also closes a pre-existing gap:** the `matchGrant` admin-verb
   carve-out means a `scope=all` grant will no longer auto-sign a
   `SSHGATE_REVOKE` either (today it can — revoke_server.go:88). This is a
   security improvement to the revoke path; flag it so you know revoke now always
   needs a fresh tap even under a grant. (Say if you'd rather keep revoke
   grant-auto-signable — I recommend the carve-out.)
4. **Accepted residual:** within-window same-host replay of an update is a
   benign no-op; the two-updates-in-5-min downgrade edge (requires breaking SSH
   encryption) is recorded, not mitigated (§7). Because the scary banner shows
   only the SHA, consider whether it should also show the binary's build
   revision (via `debug/buildinfo` parse) so you can spot a *downgrade to an
   older staged binary* at approval time — a cheap, no-wire-capture concern
   raised for your call (default: show `rev=` if buildinfo parses).
