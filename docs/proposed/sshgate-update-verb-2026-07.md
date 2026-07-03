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
  or a hash. *Caveat (Finding 2):* that path is in the agent user's own home, so
  the *local* enforcement of R5 is the human tap + version banner, not staging-path
  ownership. R5 is made **externally verifiable** by the verified release channel (§11): the
  operator cross-checks the banner hash against the CI-verified hash published on
  github.com, so swapped staging bytes match nothing published and are denied.
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
| Agent stages malware **before** the human hashes it | Closed by the verified release channel (§11): the human cross-checks the banner hash against the CI-verified hash published on github.com, so swapped staging bytes match nothing published | §11 (R5 **externally verifiable**, resolves §10.2b) |
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
  executed. The banner renders the hash **and the staged binary's build version**
  (the build-injected version marker, §11.2 — NOT `debug/buildinfo` vcs stamping,
  which the verified-release recipe turns off), because an opaque hash gives the
  operator nothing to judge — a build version lets them catch a *downgrade to an
  older binary* (Finding 4, §7). The MCP passes these
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
  Build: <Reason>
  Request ID: …   Expires in 5m0s
  ```

  `Build:` is a **single** line rendering `updateReason` verbatim
  (telegram.go:908-909), **omitted entirely when `updateReason` is empty** — there
  is no byte-size field and no separate "Currently on `<alias>`" line (the earlier
  two-line sketch had drifted from the code — MED-5). `updateReason`
  (update_gate.go:277-285) is the MCP-constructed string
  `"<artifact-basename> · version <staged> · running version <running-or-unknown>"`:
  its version fields come from the build-injected marker (§11.2), not vcs stamping,
  so the old `rev X (time)` shape loses **both** the git-sha *value* (now a version,
  §11.2) **and** the `(time)` component (`-buildvcs=false` leaves no timestamp —
  `updateReason` drops it). The arch-bearing artifact basename
  (`sshgate-gate-linux-amd64`) is included so a future multi-arch operator checks
  the right `.sha256` (LOW-5). The running version comes from a pre-sign
  `SSHGATE_VERSION` read (§6), putting staged and running versions side by side at
  approval time so the operator can recognise an unexpected build before tapping —
  which is what catches an agent-staged downgrade. This whole line is only an
  **unsigned, MCP-constructed, spoofable** cue; the authoritative cross-check is the
  hash against the github.com **default-branch HEAD** per the §11.5 runbook — the
  hash is the only trusted field.

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
     Best-effort (non-fatal): scan `body` for the build-injected version marker
     (§11.2) → version string for the success marker's `rev=` field. (Under the
     verified-release recipe `debug/buildinfo` carries no `vcs.revision`, §11.2.)
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
the running gate's **build-injected version** (§11.2 marker — not
`debug/buildinfo` vcs.revision, which is empty under `-buildvcs=false`) to stdout
and exits 0. The MCP reads it BEFORE an update to show "currently on `<alias>`:
version …" in the approval banner (downgrade visibility, Finding 4) and AFTER to
confirm the update took. It exposes only a build version to the (semi-trusted)
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
staged build's **version** (§11.2 marker) **and** the currently-running version
(from the pre-sign `SSHGATE_VERSION` probe, §6), so a downgrade is visible at
approval time; the operator confirms the version is the one intended (§11.5
runbook step 6). A *forged* same-version binary is caught harder: its bytes hash
to something that does NOT match the published hash for that version, so the
§11.5 hash cross-check fails. A downgrade to a *genuinely older published*
version is caught by the version line + the operator's intent check, not by the
hash (an old version's hash is itself published). A hard version floor on the gate
is possible later but is deferred (statelessness).

**Staging-trust residual (Finding 2) — RESOLVED by the verified release channel
(§11).** The gate's re-hash guarantees *what's installed == what was approved*. It
does NOT guarantee *what was approved == the operator's real binary*: the staged
file (`~/.config/sshgate/bin/sshgate-gate-linux-amd64`) lives in the **agent's own
user's** home, so a compromised agent could overwrite it before the MCP hashes it,
and the human would approve an opaque hash of agent-chosen bytes. Rather than
harden the *local* path (a root-owned staging dir — §10.2b option B, rejected),
§11 moves the trust anchor **off the machine**: the operator cross-checks the
banner hash against the CI-verified hash published on github.com (§11.5). Swapped
staging bytes then match nothing published and are denied, so R5 is **externally verifiable**
without any root-owned local path — the residual reduces to "the human actually
performs the cross-check" (§11.6).

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

The **verified release channel (§11)** adds its own set of new/changed files
(`VERSION`, `go.mod` toolchain, `dist/gate/*`, `.github/workflows/verify-gate.yml`,
`.gitattributes`, `Makefile` `release-gate` + `install-local` copy, and the
`vcs.revision → version-marker` rework of gate `update.go` + `update_gate.go`) —
enumerated as its own build brief in **§11.8**, not duplicated here.

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
   updated **signer** (admin-verb carve-out + update banner; no new request
   kind, §5.2) and the updated **gate** (handler)
   must first reach the boxes the old way (`make install-local` + signer
   restart; gate via one re-provision or the current bootstrap). After that,
   every future gate change uses `update_gate`.
2. **`update_gate` is on the agent MCP surface** (agent requests, operator
   approves a specific hash bound to an operator-built binary). If you'd rather
   it also exist as a human-only `sshgate update <alias>` CLI, that's a small
   add on top — say the word.
2b. **Where the staged gate binary lives (Finding 2) — RESOLVED: move the trust
   anchor off the machine (§11).** The staged file sits in the agent user's own
   home, so a compromised agent could swap its bytes before the MCP hashes them
   and the operator would approve an opaque SHA-256 of attacker-chosen bytes. Two
   alternatives were considered and **rejected**:
   - **(A) Trust the agent / accept the staging path as-is.** Rejected: R5 would
     rest on nothing externally verifiable — a single compromised agent defeats it,
     and the operator has no independent way to tell a legitimate hash from an
     opaque one.
   - **(B) Root- or `sshgatesigner`-owned staging dir (mode 0644, agent can't
     write).** Rejected: it needs a root-owned step in the install, and the trust
     anchor still lives *on the same possibly-compromised machine* — it hardens
     one path but gives the operator no external reference to verify against.
   - **(C, CHOSEN) Off-machine trust anchor — the verified release channel (§11).**
     The built gate binary and its SHA-256 are **committed to the public repo**;
     a **CI reproducible-build check** proves the committed binary is exactly what
     the audited source produces; the approver **cross-checks the banner hash
     against that published hash on a separate trusted device** (github.com)
     before tapping. Staging-path integrity then stops being load-bearing: the
     human validates the hash against an independent source, and the remote gate
     still enforces exact-hash install (R4). This makes agent-home staging
     acceptable and R5 **externally verifiable without a root-owned path**. Full spec: §11.
3. **This work also closes a pre-existing gap:** the `matchGrant` admin-verb
   carve-out means a `scope=all` grant will no longer auto-sign a
   `SSHGATE_REVOKE` either (today it can — revoke_server.go:88). This is a
   security improvement to the revoke path; flag it so you know revoke now always
   needs a fresh tap even under a grant. (Say if you'd rather keep revoke
   grant-auto-signable — I recommend the carve-out.)
4. **Accepted residual:** within-window same-host replay of an update is a
   benign no-op; the two-updates-in-5-min downgrade edge (requires breaking SSH
   encryption) is recorded, not mitigated (§7). The banner's build-identity line
   (which lets you spot a *downgrade to an older build* at approval time) is now
   sourced from the build-injected version marker, not `debug/buildinfo` vcs
   stamping — because the verified-release recipe turns vcs stamping OFF (§11.2).

## 11. Verified release channel — off-machine trust anchor (resolves §10.2b)

This section resolves §10.2b. The gate's re-hash (R4) guarantees *what is
installed == what was approved*; it does NOT guarantee *what was approved == the
operator's real, audited gate*, because the staged binary lives in the agent
user's own home (§7 staging-trust residual). Rather than trust the agent (A) or a
root-owned staging dir (B), the trust anchor moves **off the machine entirely**:

- **R-A — committed binary + hash.** Whenever the gate's code changes, the built
  gate binary is committed to the repo alongside a file holding its SHA-256.
- **R-B — CI reproducible-build gate.** A GitHub Actions check rebuilds the gate
  from source on every push/PR and FAILS unless the freshly-built hash matches
  the committed hash. A green tick ⇒ the committed binary is exactly what the
  audited source produces. (The gate source tree is small and deliberately
  auditable — that is what makes this credible — but state its extent honestly: the
  ~28 `.go` files under `src/gate` include tests (≈10 are non-test), and the
  **linked** gate binary transitively pulls in `src/classify`, `src/hostkey`,
  `src/sigwire`, and `src/redact` — the last vendoring the gitleaks rule set. The
  real audit surface is that whole transitive set, not just the non-test files
  under `src/gate`.)
- **R-C — versioned.** The gate carries a version matching the repo's `VERSION`;
  each version has a published hash (its committed `.sha256`, visible on the
  commit).
- **R-D — approver cross-check.** Before tapping approve, the human checks — on a
  SEPARATE trusted device (github.com) — that the hash in the Telegram banner
  matches the published hash for that version, and that CI is green (§11.5). If it
  matches, approve; the remote gate then enforces that the installed bytes hash to
  exactly the approved hash (R4). The chain is closed end-to-end with **no trust
  in the local staging path** — so agent-home staging (§10.2b default) becomes
  acceptable and R5 is externally verifiable.

### 11.1 Reproducible build recipe

The build must be **byte-identical** on any machine with the pinned toolchain, so
CI's rebuild can match the committed hash. Flags (over today's
`sshgate-gate-linux` recipe, Makefile:24-28):

- **Full build environment, not just flags (MED-1).** `release-gate` MUST
  **export the complete env**, explicitly overriding whatever the builder's shell
  already holds: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64= GOEXPERIMENT=
  GOFLAGS=-mod=readonly`. Any of `GOAMD64` (microarch level), `GOEXPERIMENT`
  (toolchain experiments), or a stray inherited `GOFLAGS` silently changes the
  emitted bytes, so a local build under an inherited value hashes differently from
  CI. The empty assignments (`GOAMD64=` / `GOEXPERIMENT=`) pin the defaults rather
  than trusting the environment.
- `CGO_ENABLED=0` — pure-Go, no host C-toolchain variance *(already set)*.
- `-trimpath` — strip local filesystem paths *(already set)*.
- `-ldflags "-s -w -buildid= -X 'main.versionMarker=SSHGATE_GATE_VERSION{<VERSION>}'"`
  — `-s -w` strip symbol/debug tables *(already set)*; **`-buildid=`** empties the
  Go build ID (removes an input-hash source of nondeterminism); **`-X`** injects
  the version marker (§11.2).
- **`-buildvcs=false`** — VCS stamping MUST be off. The binary is committed *in* a
  commit whose hash it cannot contain (chicken-and-egg), and `vcs.time` /
  `vcs.modified` make the output non-reproducible. This is the flag that kills the
  `debug/buildinfo` vcs read the banner used (§11.2 replaces it).
- **Pinned toolchain** — add a `toolchain` directive to `go.mod` (currently only
  `go 1.25.0`, no `toolchain` line) pinning the exact patch the recipe
  standardizes on, e.g. `toolchain go1.25.6` (illustrative — pin whatever exact
  patch is actually released and installed at build time, NIT-4). Reproducible
  output is tied to the exact compiler version, so pin the patch, not just the
  minor. CI selects the same toolchain via `actions/setup-go` with
  `go-version-file: go.mod` + `check-latest: false`.
- **Assert the toolchain before building (MED-2).** `GOTOOLCHAIN=local` with a
  local `go` newer-than-or-equal to the pinned patch makes Go **ignore** the
  `go.mod` `toolchain` directive and build with the local compiler → different
  bytes → CI red against any machine that honoured the directive. So `release-gate`
  MUST **assert first**: parse `go version` and fail with a clear message (e.g.
  `"toolchain mismatch: need go1.X.Y, have <...> — install it or unset
  GOTOOLCHAIN=local"`) unless it reports **exactly** the pinned patch, before it
  compiles anything.
- **Dependency pinning** — `GOFLAGS=-mod=readonly` with the committed `go.sum`
  (already authoritative) so the same module bytes link in every build.
- **GOOS/GOARCH matrix** — `linux/amd64` today. Leave room for `linux/arm64`
  (the gate already maps `arm64 → EM_AARCH64`, update.go archMachine) by
  parameterizing the target and emitting `dist/gate/sshgate-gate-linux-<arch>`.

Go embeds no wall-clock timestamps once vcs stamping is off, so no
`SOURCE_DATE_EPOCH` handling is needed.

### 11.2 Versioning & banner display (the `debug/buildinfo` nuance)

`update_gate` today reads the staged binary's `vcs.revision` via `debug/buildinfo`
(update_gate.go:245 `stagedBuildInfo`), the gate prints `vcs.revision` for
`SSHGATE_VERSION` (update.go:218 `runningGateVersion`) and for the success
marker's `rev=` (update.go:208 `binaryRevision`). Under `-buildvcs=false` all
three read **nothing** → `"unknown"`, so the banner's build line goes dead.

**Decision: a build-injected, byte-scannable version marker.** Options weighed:

- **(a) CHOSEN — sentinel-wrapped marker embedded via `-ldflags -X`.** Bake
  `main.versionMarker = "SSHGATE_GATE_VERSION{<VERSION>}"` at build time. The
  running gate prints it via `SSHGATE_VERSION`; `update_gate` **scans the staged
  bytes it already read** for the marker prefix, reading the token to the closing
  `}` (version chars `[A-Za-z0-9._+-]`). No sidecar, no second read, one source of
  truth (`VERSION` → `-X`), and it survives `-trimpath -s -w`. This is why the
  `{…}` delimiters exist: they make the raw-byte grep unambiguous. **The scan is
  NOT a naive first-match — see "Scanning the marker safely" below (HIGH-1); that
  rule is load-bearing, not an implementation detail.**
- **(b) `.version` sidecar file** shipped next to the binary. Rejected: a second
  artifact to keep in lockstep with the bytes, and the staged path is a single
  file today.
- **(c) "hash is the identity; version display best-effort."** Rejected as the
  *sole* mechanism — the downgrade cue (Finding 4) needs a human-readable version
  — but it is the fallback: a stripped/absent marker renders `unknown`.

**Scanning the marker safely (HIGH-1 — mandatory, both scanners).** Two paths scan
for the marker: the gate's `binaryRevision(body)` (over incoming update bytes) and
the MCP's staged-bytes scan (replacing `stagedBuildInfo`). Each ships **inside a
gate binary that itself carries the prefix at least twice** — once as the
`-X`-injected `versionMarker` value, and once as the search-prefix constant
compiled into the scanner's own code. Go **constant-folds** compile-time string
concatenation, so splitting the literal in source (`"SSHGATE_GATE" + "_VERSION{"`)
does **not** keep the naked prefix out of `.rodata`. A naive first-match scan can
therefore lock onto the scanner's **own** constant and read adjacent `.rodata`
garbage as the "version", silently defeating the downgrade cue. Two rules close
this and **both** are required:

1. **Construct the search prefix at runtime.** Every scanner builds the prefix
   from non-constant expressions (append bytes / join parts through a variable) so
   the folded literal never lands in `.rodata`. A source-level split alone is
   insufficient — the constant folder undoes it.
2. **All-occurrences scan with an acceptance rule, not first-match.** Scan for
   **every** occurrence. A candidate is *valid* iff it is the prefix followed by
   1..64 chars of `[A-Za-z0-9._+-]` then a closing `}`. Then: exactly one distinct
   valid value → that is the version; zero valid, or two-or-more **conflicting**
   distinct valid values → `"unknown"`. (Repeat occurrences of the *same* value
   collapse to one and are fine.)

This is **UX-only.** The security property rides on the SHA-256 alone: a forged
or stripped marker changes only what the banner *displays*, never what the gate
*enforces* (R4). Both `stagedBuildInfo` (MCP) and `runningGateVersion` /
`binaryRevision` (gate) switch from the vcs read to the marker.

**Frozen wire contract (HIGH-2).** The `SSHGATE_VERSION` verb prints the line
`SSHGATE_VERSION rev=<value>` and the success marker carries `… rev=<value>`. The
**key stays `rev=`** — only the *value* changes (git-sha hex → injected version
string). That `rev=` line shape is **frozen** with **three consumers** that must
all keep parsing the same key and move together:

- `probeRunningRev` (update_gate.go:292-301) — reads `SSHGATE_VERSION` for the
  banner's running-version and the post-update confirm;
- `probeGateAnswers` (provision.go:412-418) — provisioning **idempotency** for an
  already-gated host (added after this spec's first draft);
- `parseUpdatedMarker`'s `rev` field (update_gate.go:328+) — parses the
  `SSHGATE_UPDATED … rev=` success marker.

There is **no `ver=` alternative**: the earlier "`rev=`/`ver=`" wording is
withdrawn — `ver=` must never appear. (`updateReason` losing its `(time)`
component under `-buildvcs=false`, §5.2, is a display-string change, not a
wire-key change.)

**Out of scope (NIT-2).** The pre-existing `mcp.Version` (`"0.2.0"`,
src/mcp/server.go:48) is a **separate identity** — the MCP server's own
protocol/product version. The top-level `VERSION` here is the **repo/gate** version
(owner's decision). Unifying the two is explicitly **out of scope**, recorded as a
follow-up.

### 11.3 Repo layout & Makefile target

```
VERSION                                        # top-level, one line (e.g. v1.3.0)
dist/gate/sshgate-gate-linux-amd64             # committed, reproducibly-built gate
dist/gate/sshgate-gate-linux-amd64.sha256      # its hash, sha256sum-compatible
```

- `.sha256` format: a single line, `sha256sum`-compatible — `<64-lowercase-hex><two
  spaces><basename>\n`, e.g. `ab…f0  sshgate-gate-linux-amd64`. The basename (not a
  path) so `sha256sum -c` passes when run from inside `dist/gate/`.
- New `make release-gate` target: builds with the §11.1 recipe into
  `dist/gate/sshgate-gate-linux-amd64`, then regenerates the sidecar via
  `cd dist/gate && sha256sum sshgate-gate-linux-amd64 > sshgate-gate-linux-amd64.sha256`.
  **Share the flag set between `sshgate-gate-linux` and `release-gate` via a common
  make variable** (e.g. `GATE_BUILD_FLAGS`) — do **not** make `sshgate-gate-linux`
  *call* `release-gate` (LOW-4): the dev `build`/`sshgate-gate-linux` targets that
  `make preflight` runs must keep a **separate output path** and must **never**
  rewrite the committed `dist/gate/` artifact, or every dev build dirties the tree
  (perpetually-dirty `git status`, accidental dev-binary commits). Same recipe,
  different destinations, one shared variable so they can't drift.
- **`release-gate` validates `VERSION` before building (LOW-3).** Assert the file
  is a **single line** matching `^v[0-9A-Za-z._+-]+$` (no CRLF, no spaces, no
  trailing comment) and fail loudly otherwise. A stray `\r` or space lands
  **outside** the marker's `[A-Za-z0-9._+-]` charset, pushing the closing `}` out
  of range and turning **every** marker scan `unknown`.
- **`install-local` must COPY the committed artifact, not rebuild it**
  (Makefile:67-70 currently rebuilds into `~/.config/sshgate/bin/`). To close the
  chain, the bytes the MCP hashes and streams MUST be the exact bytes CI verified
  and published — so `install-local` copies `dist/gate/sshgate-gate-linux-amd64`
  into `<cfgRoot>/bin/`. (Power option: point `$SSHGATE_GATE_BIN` — honored by
  `stagedGatePath`, main.go:223-228 — directly at the clone's
  `dist/gate/sshgate-gate-linux-amd64`.) A local *rebuild* on a
  slightly-different toolchain would produce a hash that matches nothing published
  and fail the §11.5 check.
- **`scripts/install.sh` must ship the verified artifact too (MED-3).** Today it
  installs the locally-rebuilt `bin/sshgate-gate-linux-amd64` (from the `build`
  target) into `/usr/local/share/sshgate/` (install.sh:61, 149-151) — a **second,
  unverified gate copy outside the channel**. Change it to install
  `dist/gate/sshgate-gate-linux-amd64` (the CI-verified, published bytes), so no
  install path ships gate bytes that were never cross-checked.
- **`$SSHGATE_GATE_BIN` is dev-only (LOW-6).** The dev override (honored by
  `stagedGatePath`, main.go:223-228) points the MCP at an arbitrary local binary
  and therefore **by definition** fails the §11.5 published-hash cross-check. That
  is expected on a dev box; on a **production** box a hash mismatch must **never**
  be approved — treat it as the compromise signal the runbook says it is (§11.5
  step 7).
- `.gitattributes`: mark `dist/gate/*` as `binary` so no CRLF/normalization ever
  mutates the committed bytes.

### 11.4 CI — `.github/workflows/verify-gate.yml`

- **Triggers:** `push` and `pull_request`. Run **unfiltered** (the build is
  seconds) rather than path-filtered: correctly path-filtering the gate's
  *transitive* import set (it links `src/redact/**` etc.) is fragile — a missed
  package yields a false green on the one check that must never false-green. If
  minutes matter, filter only to *exclude* docs-only diffs; never to enumerate the
  build's dependency set.
- **Steps:**
  1. `actions/checkout@v4`.
  2. `actions/setup-go@v5` with `go-version-file: go.mod`, `check-latest: false`
     (the pinned toolchain, §11.1).
  3. **Committed binary matches its own hash file:**
     `cd dist/gate && sha256sum -c sshgate-gate-linux-amd64.sha256`.
  4. **Reproducible rebuild matches the committed artifact:** `make release-gate`
     (rebuilds the binary AND regenerates the `.sha256` in place), then **both**
     `git diff --exit-code -- dist/gate/` **and** `test -z "$(git status
     --porcelain -- dist/gate/)"` (LOW-1). The `diff` alone catches only changes to
     *tracked* files — a brand-new **untracked** artifact (e.g. a freshly-added
     `linux/arm64` build that was never committed) slips past it; the porcelain
     check fails closed on any untracked-or-modified path under `dist/gate/`.
     Together they verify *both* directions: the rebuilt **binary** is
     byte-identical to the committed one AND its **hash file** matches — fail-closed
     on any diff.
- **Inverse guard (the forcing function) — state explicitly:** if gate sources
  changed but `dist/` was NOT refreshed, the fresh rebuild differs from the stale
  committed binary, `git diff --exit-code` fails, and CI goes red. That is exactly
  the desired behavior: **you cannot change the gate's code without also
  re-committing (and re-publishing the hash of) the built binary.** A green tick
  therefore certifies the committed binary == the current source.

### 11.5 Approver runbook (do this on your phone before tapping)

When the "⚠️ GATE BINARY UPDATE" banner arrives, BEFORE tapping
"✓ Approve GATE UPDATE":

1. Read from the banner: the target `<alias>`, the `New gate SHA-256: <64hex>`,
   and the `Build:` version line.
2. On a **separate trusted device** (phone browser or a different machine — NOT
   the machine running the agent), open the SSHGate repo on **github.com**.
3. Confirm the commit for that gate version shows a **green CI tick**
   (`verify-gate` passed) — this proves the committed binary reproducibly builds
   from the audited source.
4. Open `dist/gate/sshgate-gate-linux-amd64.sha256` **at the default-branch HEAD**
   (github.com `main`) and read the **published hash**. HEAD is the default because
   it is the current audited gate; looking up *some older version's* hash instead is
   a **deliberate downgrade path** — do it only when **you** initiated the downgrade
   and know why (out-of-band confirmation), never as the routine lookup (MED-4).
5. Compare the published hash to `New gate SHA-256` in the banner — the **full 64
   hex characters**, not a prefix (a prefix collision is cheap). They must be
   identical.
6. Treat the banner's `Build:` version as **untrusted context, not proof**: it is
   MCP-constructed, unsigned, and spoofable (§5.2). The **only** trusted field is
   the hash, so the decisive test is step 5 against **HEAD's** published hash — a
   banner whose hash matches only an *older* commit's published `.sha256` and
   **not** HEAD's is a **downgrade signal** a spoofed "version" line cannot hide
   (the hash it must match is HEAD's). Confirm the version reads as expected too,
   but let the hash rule (MED-4).
7. **Only if** hash matches AND CI is green AND version is expected → tap Approve.
   Otherwise tap **Deny** and investigate: a mismatch means the staged binary is
   NOT the audited gate — treat it as a compromise signal, not a retry.

### 11.6 Threat model

**Defends against:**
- A compromised agent swapping the staged bytes before the MCP hashes them
  (Finding 2's core): the banner hash won't match any published hash → the
  operator denies at step 7.
- A compromised laptop / tampered local staging path: same — the reference the
  operator trusts is off-machine (github.com), not any local file.
- (Layered on top of R4, which already blocks wire tamper and post-approval
  arbitrary-code swaps: the verified channel adds the "is this approved hash even
  a *legitimate* gate?" check that R4 alone cannot make.)

**Does NOT defend against:**
- A compromised GitHub account/repo that publishes a malicious binary *with* a
  matching `.sha256` *and* a subverted-but-green CI (an attacker holding push +
  Actions control). The operator would compare and see a match. Mitigation is
  GitHub account hygiene — 2FA, branch protection, required status checks,
  restricted Actions — and is out of this mechanism's scope.
- An approver who **skips** the cross-check and taps through on muscle memory (the
  distinct scary banner + "GATE BINARY UPDATE" button label reduce, but cannot
  eliminate, this).
- An approver who compares **carelessly** (first 4 chars only) — the runbook
  mandates full-hash comparison for this reason.

**Residual:** the scheme converts an *unfalsifiable* opaque hash into a
*falsifiable* one, but ultimately relies on the human actually performing the
cross-check. It does not remove the human from the loop; it gives the human
something real to check.

### 11.7 Alternative considered — GitHub Release assets

Instead of committing the binary + hash into the tree, attach
`sshgate-gate-linux-amd64` and its `.sha256` to a **tagged GitHub Release** per
gate version and have the approver check the release page's hash. **Pro:** avoids
permanent clone-size growth — every committed gate version (a few MB) lives in
history forever. **Con:** the hash then sits on the mutable Releases surface
(editable by any maintainer with write) rather than the immutable, CI-verified
commit tree, and the green tick is on the *commit*, not the release asset — a
weaker binding between "audited source" and "published artifact." **Rejected for
now** in favor of the committed-binary scheme (hash file in the audited tree, CI
tick on the commit itself). Revisit if repo bloat becomes real — a shallow-clone
default, or periodically pruning old `dist/` versions from history, is the natural
mitigation.

### 11.8 Build tasks (the brief)

1. Add a top-level **`VERSION`** file (one line, e.g. `v1.3.0`).
2. Add a **`toolchain`** directive to `go.mod` (e.g. `toolchain go1.25.6` —
   illustrative; pin whatever exact patch is actually released/installed at build
   time, §11.1 NIT-4).
3. **gate `main.go` / `update.go`:** add `var versionMarker =
   "SSHGATE_GATE_VERSION{dev}"`; rework `runningGateVersion()` (update.go:218) to
   print the marker's version (not `vcs.revision`) and `binaryRevision(body)`
   (update.go:208) to parse the marker from `body` for the `SSHGATE_UPDATED … rev=`
   field. **Both scanners MUST follow the safe-scan rules (HIGH-1, §11.2):** build
   the search prefix **at runtime** (non-constant expression, so the folded literal
   never lands in `.rodata`) and do an **all-occurrences** scan with the acceptance
   rule (prefix + 1..64 `[A-Za-z0-9._+-]` + `}`; exactly-one-distinct-valid →
   version, else `unknown`) — never first-match. Keep the `SSHGATE_VERSION` output
   line `SSHGATE_VERSION rev=<value>` and the success marker's `rev=` **key** frozen
   (HIGH-2) — only the value changes.
4. **`update_gate.go`:** replace `stagedBuildInfo` (update_gate.go:245, vcs read)
   with a marker-scan over the already-read staged bytes, applying the **same**
   runtime-prefix + all-occurrences safe-scan rules as task 3 (HIGH-1). Rework
   `updateReason` (update_gate.go:277-285) to the new shape
   `"<artifact-basename> · version <staged> · running version <running>"` — no
   `(time)` (gone under `-buildvcs=false`), and include the arch-bearing basename
   (LOW-5). The three frozen `rev=` consumers keep parsing the same key and move
   together (HIGH-2): `probeRunningRev` (update_gate.go:292-301), `probeGateAnswers`
   (provision.go:412-418, provisioning idempotency), and `parseUpdatedMarker`'s
   `rev` field (update_gate.go:328+).
5. **Makefile — `release-gate`:** the reproducible recipe (§11.1) → `dist/gate/…` +
   regenerate `.sha256`. It MUST (a) **export the full build env** overriding the
   shell — `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64= GOEXPERIMENT=
   GOFLAGS=-mod=readonly` (MED-1); (b) **assert `go version` == the pinned
   toolchain** before compiling, failing with a clear message (defends the
   `GOTOOLCHAIN=local` trap, MED-2); (c) **validate `VERSION`** against
   `^v[0-9A-Za-z._+-]+$`, single line, no CRLF/spaces/comments (LOW-3). Share the
   flag set with `sshgate-gate-linux` via a common make variable and keep
   **separate output paths** — dev `build`/`sshgate-gate-linux` (run by
   `make preflight`) must **not** rewrite the committed `dist/gate/` artifact and
   must **not** *call* `release-gate` (LOW-4).
6. **Makefile — `install-local`:** **copy** `dist/gate/sshgate-gate-linux-amd64`
   into `<cfgRoot>/bin/` instead of rebuilding it (Makefile:67-70).
7. **`scripts/install.sh`:** ship the verified `dist/gate/sshgate-gate-linux-amd64`
   into `/usr/local/share/sshgate/`, replacing the locally-rebuilt `bin/…` copy
   (install.sh:61, 149-151) so no second, unverified gate copy exists outside the
   channel (MED-3).
8. Commit the first **`dist/gate/sshgate-gate-linux-amd64`** + `.sha256` produced
   by `make release-gate`.
9. Add **`.github/workflows/verify-gate.yml`** (§11.4): pinned Go; `sha256sum -c`
   the committed hash; `make release-gate` then **both** `git diff --exit-code --
   dist/gate/` **and** `test -z "$(git status --porcelain -- dist/gate/)"` (the
   porcelain check catches a new **untracked** artifact the diff misses, LOW-1);
   fail-closed.
10. Add **`.gitattributes`** marking `dist/gate/*` as `binary`.
11. **Verify the secret scanners tolerate a multi-MB committed binary (LOW-7):**
    confirm `make preflight`'s gitleaks step (Makefile:116-125) and the external
    `pii-audit` pre-push scan run in sane time with no false positives on
    `dist/gate/`; allowlist `dist/gate/` in the relevant configs (`.gitleaks.toml`
    / pii-audit) if needed.
12. **Docs:** INSTALL/README — describe the verified release channel and the §11.5
    approver runbook (including the **default-branch-HEAD** hash-lookup default and
    the downgrade path, MED-4); update this spec's §3 table row, R5 caveat, §5.2
    banner note, §6 `SSHGATE_VERSION` note, and §7 staging-trust residual to record
    that staging-path integrity is no longer load-bearing (done in this revision).
13. **Update the pinned-format tests (LOW-8) — enumerate exactly:**
    `update_gate_internal_test.go:26-54` (the `updateReason` pins; the
    `stagedTime`/`(time)` branch is **removed** under `-buildvcs=false`),
    `telegram_update_test.go:32/59`, and `update_gate_test.go:284` — all currently
    pin the old `"rev X (time) · running rev Y"` shape and must move to the new
    version-based, time-less, basename-bearing shape.
14. **New tests (add to `make preflight`):** a reproducibility assertion (two builds
    → identical hash); a committed-dist-matches-its-`.sha256` check — but scope the
    claim honestly (NIT-1): `sha256sum -c` catches only **binary↔sidecar** drift
    locally, while **source↔binary** drift is caught **only** by CI (§11.4); a
    `update_gate` marker-scan unit test including the **self-match** case (a scanner
    whose own prefix constant is present must still resolve the injected version,
    not garbage — HIGH-1); and a gate `SSHGATE_VERSION` test asserting it prints the
    injected version, not `unknown`.
