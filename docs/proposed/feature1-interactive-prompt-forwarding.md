# SSHGate Feature 1 — Interactive Prompt & Password Forwarding

> **Status: OPEN PROPOSAL, not scheduled.** Nothing here is built. It is "Feature 1" (#23) in
> [ROADMAP.md](../ROADMAP.md); [BUILD-PLAN.md](../BUILD-PLAN.md) does not schedule it (work item 3,
> the signature terminal, only has to decide how it relates to this). Read
> [Constraints added since this was written](#constraints-added-since-this-was-written) first:
> the shipped forced-command key line and the read jail change parts of the design below.

## Summary

A gate-executed remote command can stop on an interactive prompt — a `sudo` / passphrase password read, an `apt` `[Y/n]`, a deploy script's `Are you sure? (yes/no)`, an SSH `known_hosts` `(yes/no/[fingerprint])`. Today the gate runs the command with **no PTY** and its stdin set to `/dev/null` (`ExecWithRedaction` in `src/gate/executor.go`; the `/dev/null` stdin is a deliberate hardening, so the agent cannot feed bytes to a program through the SSH channel). The MCP side (`src/mcp/ssh/client.go`) is fully buffered and has no PTY; its only stdin path, `RunWithStdin`, is reserved for `update_gate` and `transfer`. So a prompt is either refused ("no tty present") or reads end-of-file, the command fails, and the operator's only recourse is to leave SSHGate and `ssh` in by hand. Feature 1 closes that gap: allocate a PTY so prompts actually render and echo-state is observable, detect the input-stall, surface the (redacted, sanitized) prompt to the authorized operator, capture their answer, and write it to the child's stdin — without anyone touching a terminal.

This design builds the **channel-agnostic gate half once** (PTY + termios echo-off detection + fail-loud stall + safe redactor flush), and use a **hybrid channel** — **Telegram for confirm / `[Y/n]` / host-key prompts** (reuse, zero setup, instant phone push) and a **masked, non-persistent secure surface for every echo-off secret** (passwords never enter Telegram chat). The relay is a **separate service** and **never touches the signing daemon's socket or loop**. The two make-or-break properties are (a) detection that is *false-negative-safe and never auto-answers*, and (b) defense against *attacker-controlled prompt text* phishing the operator. A threat analysis of the design produced 18 required mitigations (M1–M18). Each is defined in the security section, next to the threat it answers (C1–C4 critical, H1–H7 high, then the medium ones).

## Goals & Non-goals

**Goals**
- Let an authorized operator answer a blocked interactive prompt (confirm or password) so the command completes, without leaving SSHGate.
- Detect input-stalls reliably enough to be useful, while *never* depending on detection for safety (fail loud, never auto-answer).
- Keep passwords out of any durable log, chat history, or third-party store; keep the remote host credential-free.
- Preserve every existing gate invariant: single exec site, group-kill on cancel, Layer-1 redaction choke point, sysexit codes, and a clean non-interactive path that passes the red-team rig with **0 new bypasses**.
- Leave the master-key signing daemon (`HandleSignRequest`, one-shot) completely untouched.

**Non-goals**
- No auto-answering, answer-guessing, or "inject a newline to probe" behavior. The system detects *that* input is needed; a human supplies every byte (M8).
- No full interactive terminal / shell session (no vim, no `top`, no REPL streaming). This is single-prompt request/response, not a TTY multiplexer.
- No replacement of the classifier or Feature 2 SQL adapter (separate roadmap items).
- No new inbound network port or new key material on remote hosts.
- Not a defense against a fully-compromised host damaging *itself within the already-authorized command* — only against that host phishing the *operator's* secrets via prompt text (partial; residual acknowledged).

## Constraints added since this was written

These facts postdate the design and must be resolved before any phase is built.

- **The forced-command key line pins `no-pty`.** `sshgate add` installs
  `restrict,command="~/.sshgate-gate/gate",no-pty,no-port-forwarding,…` (golden-pinned in
  `src/mcp/tools/authorizedkeys.go`). With that line the client cannot get a PTY, and because
  OpenSSH replaces whatever the client asks to run with the forced command, the client also
  cannot launch the gate in a separate `--prompt-relay` mode. The sideband in
  [Transport to operator](#transport-to-operator) therefore needs a different key line (or a
  different relay design). Work item 3 in [BUILD-PLAN.md](../BUILD-PLAN.md) has the same
  constraint, so the two should share one answer.
- **Stdin is `/dev/null` on purpose.** Injecting answers into the child's stdin reverses that
  hardening. The design must keep the non-interactive path exactly as it is and open stdin only
  for an opted-in, signed interactive command.
- **Reads now run in the `ro-v1` kernel read jail** (`src/gate/confine/`). Its seccomp filter
  blocks named `ioctl` groups and every capability is dropped. Whether an interactive command
  could ever run in the jail (PTY allocation, `TIOCSCTTY`, termios reads) is not designed. The
  simplest answer is that interactive mode exists only for signed writes, which run outside the
  jail.
- **The executor still has no wall-clock deadline for reads**, so the `T_cmd` deadline below is
  still new work.

## Architecture

### Topology

```
 Operator phone (Telegram)        Operator browser (passkey)
   confirm / [Y/n] / host-key        password / passphrase ONLY
        ▲    │ tap / verbatim reply        ▲    │ masked field, TLS, step-up
        │    ▼                             │    ▼
 ┌──────┴─────────────────────────────────┴──────────────────────┐
 │   PROMPTWIRE relay service  (operator box, NEW, separate)      │
 │   - own Unix socket (0660, dedicated group) — NOT the signer's │
 │   - reuses signer AuditLog + AllowedUserID posture             │
 │   - Telegram backend (confirm) + masked secure surface (secret)│
 └───────────────────────────────▲───────────────────────────────┘
                                  │ local Unix socket (multi-turn)
 ┌────────────────────────────────┴──────────────────────────────┐
 │   MCP runner (runRead / runWrite)                              │
 │   - registers interactive session_id with promptwire          │
 │   - bridges SSH relay channel ↔ promptwire socket             │
 │   ssh/client.go: NEW RequestPty + stdin pipe + streaming      │
 └───────────────────────────────┬───────────────────────────────┘
                                  │ SSH conn: command channel + relay sideband
 ┌────────────────────────────────▼──────────────────────────────┐
 │   gate (remote host)  — credential-free                        │
 │   ExecWithRedaction → PTY master ↔ /bin/sh -c <cmd> (slave)    │
 │   stall detector taps master read loop; frames prompt up;      │
 │   re-verifies + injects answer on stdin; redact.Writer kept    │
 └───────────────────────────────────────────────────────────────┘
```

Three boundaries change independently and must be respected as independent:
1. **Gate (remote host)** — produces the real TTY prompt, detects the stall, frames the prompt up the channel, re-verifies and injects the answer. The PTY lives here; the host holds **zero** Telegram/portal credentials.
2. **MCP (operator box)** — bridges the SSH relay sideband to the local promptwire socket, and registers each interactive `session_id` so the relay can drop unsolicited prompt frames.
3. **Promptwire relay (operator box)** — a **new, separate** operator-side service that authenticates the operator, routes confirm prompts to Telegram and secret prompts to the masked surface, and reuses the signer's `AuditLog`. It does **not** share the signing daemon's socket, loop, or process (M6).

### PTY allocation (gate side)

Inside `ExecWithRedaction` (the single exec site — preserve that property), behind a per-invocation `interactive` flag that defaults **off** (M12):

- `ptmx, tty, err := pty.Open()` (vendored `creack/pty`) — open the master/slave pair explicitly. Do **not** use `pty.Start`: it overwrites stdio and `SysProcAttr` and would clobber the custom `c.Cancel` group-kill and redact wiring.
- Wire the **slave** as the child's three fds: `c.Stdin = tty; c.Stdout = tty; c.Stderr = tty`.
- Extend `c.SysProcAttr` (today `{Setpgid: true}` in `ExecWithRedaction`) to `{Setpgid: true, Setsid: true, Setctty: true}`. `Setsid` makes the child a session leader; `Setctty` makes the slave its controlling terminal — this is what makes `sudo`/`ssh` believe they have a real terminal and prompt (with echo off) instead of failing "no tty present."
- Keep the existing group-kill `c.Cancel` in `ExecWithRedaction` verbatim — controlling-terminal does not change pgroup semantics; we still `Kill(-pid, SIGKILL)`.
- Parent closes its copy of `tty` after `Start()`; keeps `ptmx`.

**Documented cost — stdout/stderr merge.** A PTY collapses stdout+stderr onto one stream, so the current "two independent `redact.Writer`, no cross-stream coupling" in `ExecWithRedaction` becomes **one** writer in interactive mode. This is accepted *only* in PTY mode; the non-interactive path keeps two clean streams and pays zero cost. The combined stream still flows through a single `redact.Writer`, preserving the Layer-1 choke point.

### Prompt / stall detection (gate side)

This is the section that decides whether the feature is usable or maddening, and it is held to a hard rule: **bias to false-negative-safe; never auto-answer; regexes are advisory only.** The detector decides *that* input is needed, never *what* the answer is (M8). A prompt is surfaced only when independent signals agree; otherwise a long stall degrades to a neutral "command appears blocked — inspect/abort?" nudge, never a fabricated yes/no.

Four signals, combined into a confidence verdict:

- **S1 — read-stall timer (necessary, never sufficient).** The child emitted bytes, then `ptmx.Read` blocks with no new bytes. Two-stage: a *soft* stall at `T_soft = 1.5s` (arm the other detectors, do not notify) and a *hard* stall at `T_hard = 8s` of total quiescence (escalate). A bare timer is the classic false-positive generator, so it is always gated by S2–S4.
- **S2 — no-trailing-newline (strong).** A slow-but-working command has usually emitted a complete line ending in `\n`; a prompt almost universally leaves the cursor on the same line (`Password: `, `Continue? [Y/n] `). Last byte `!= '\n'` is a strong prompt indicator; last byte `== '\n'` strongly argues *not a prompt* and suppresses notification (worst case: a quiet "still running (Ns)…" heartbeat after 30s). This kills most slow-streaming false positives.
- **S3 — termios echo-off (decisive for passwords).** We own the PTY master, so we read the slave's termios. `getpass()`/password reads set `~ECHO` in `c_lflag`. Echo-off + hard-stall + no-newline ⇒ **password, near-certain**, and flips the relay to secret mode (M3). This is the cleanest machine-readable prompt signal and exists *only* because we allocated a PTY. It is the **trust anchor of secret-mode classification — not a regex** (M3). We deliberately do **not** rely on `/proc/wchan` (kernel-version dependent, container/permission-fragile, and the blocking reader is often a grandchild — `sudo`/`ssh`/`apt` fork helpers — so the shell PID reads `wait4`, not `n_tty_read`); echo-off via termios is the robust, portable signal.
- **S4 — known-prompt regexes (advisory only; never a gate, never a safety boundary).** A conservative allowlist (`(?i)\bpassword\b.*: *$`, `(?i)\[sudo\] password for`, `(?i)(continue|proceed|are you sure|overwrite|do you want)\b.*\?\s*(\[[yYnN/]+\])?\s*$`, `(?i)\(yes/no(/\[fingerprint\])?\)\s*$`, apt/dpkg `do you want to continue\? \[y/n\]`) **raises** confidence and pre-fills suggested answers, but a miss never suppresses and a hit never auto-answers. Prompt-shape regexes have the same weakness as the regex-based command classifier (an attacker can always shape text to match or miss), so they stay strictly advisory.

**Decision matrix (what fires):**

| hard-stall | no-newline | echo-off | regex | → action |
|---|---|---|---|---|
| yes | yes | yes | (password) | **PASSWORD prompt** → secure masked surface (secret mode) |
| yes | yes | no | hit | **CONFIRM prompt** → Telegram with suggested-answer buttons |
| yes | yes | no | miss | **GENERIC prompt** → Telegram, raw (sanitized) tail shown, free-text/abort |
| yes | **no** (ends `\n`) | no | — | **Do NOT surface.** Likely slow command; quiet heartbeat after 30s only |
| no | — | — | — | wait |

**Explicitly rejected:** any heuristic that *guesses the answer*; any "inject a newline to test if it unblocks" probe (it mutates a possibly-running program). Read-only observation until a human answers.

### Transport to operator

The relay session is **anchored at the MCP**, not the gate, because the host must stay credential-free and the relay socket lives on the operator box. Flow:

1. **Gate → MCP (SSH sideband).** On the same SSH connection the MCP already holds, the MCP opens a **second multiplexed channel** as a prompt-relay sideband (the gate launched in a `--prompt-relay` mode alongside the command channel). On detecting a prompt, the gate writes a framed, line-delimited JSON record to this sideband — **not** inline on the merged PTY stream — so prompt control data is structurally separated from program output. This needs **no new inbound port and no new key** on the remote host; it rides the existing authenticated, encrypted SSH tunnel.
2. **MCP → promptwire (local Unix socket).** The MCP forwards the frame to the **separate** promptwire service over a local Unix socket (mode `0660`, dedicated group — same hardened model as the signer socket, but a *different* socket and a *different* service). The MCP has already **registered** this `session_id` with promptwire at run start, so promptwire drops any prompt frame whose `session_id` it never authorized (anti-fabrication).
3. **promptwire → operator.** Confirm prompts go to **Telegram** (reusing the bot/DM/`AllowedUserID`/`pendingState`/message-edit machinery); secret prompts go to the **masked secure surface** (below). The answer returns the reverse path: operator → promptwire → MCP → SSH sideband → gate.

**Frame schema (line-delimited JSON, multi-turn — the genuinely new protocol):**
```
gate→relay:  {"v":1,"type":"prompt","session_id":"…","seq":3,"host":"prod-db",
              "cmd_summary":"apt-get upgrade","prompt_type":"password|confirm|generic",
              "prompt_text":"<post-redaction, sanitized>","prompt_hash":"<sha256>",
              "attempt":1,"expires_at":<unix>}
relay→gate:  {"v":1,"type":"answer","session_id":"…","seq":3,"answer_ref":"<opaque>"}  # secret value NOT in cleartext on disk
relay→gate:  {"v":1,"type":"abort","session_id":"…","seq":3,"reason":"operator|timeout|cap"}
```
`session_id` ties the prompt to the originating authorized run; `seq` orders multiple prompts within one command; `prompt_hash` binds the answer to exactly the prompt the operator was shown (TOCTOU defense, M9); `attempt` bounds retries.

### Answer relay to stdin (gate side)

When the answer returns, the gate **re-verifies before injecting (M9):** immediately before writing, it confirms the child is *still* blocked on the *same* prompt — echo state unchanged **and** the current pre-injection prompt bytes still hash to `prompt_hash`. On mismatch ⇒ **abort + audit, never inject** (defeats swap-the-question / TOCTOU). On match ⇒ write `answer + "\n"` to `ptmx`, reset the stall detector (bytes-since-input counter, quiet timer), resume streaming. A re-appearing prompt (e.g. `sudo`'s "Sorry, try again.") is just the next prompt, detected the same way with a bounded `attempt` counter.

**Surfaced message (Telegram confirm):**
```
🔐 SSHGate — "prod-db" is asking for input
command: apt-get upgrade        ← what YOU authorized (from MCP record, not the host)
prompt:
> Do you want to continue? [Y/n]
Reply y / n, or tap below.
⚠ This text is from the REMOTE host — treat as adversarial.
⏱ 120s · Cancel to abort
[ Yes ]  [ No ]  [ Cancel ]
```
Confirm prompts get one-tap Yes/No/Cancel buttons (reusing callback machinery, `relay:<sid>:<seq>:yes` namespace) plus verbatim free-text fallback for odd prompts (`Please type 'yes' exactly`). **Generic/unknown** prompts: same frame, sanitized raw tail, free-text + Cancel only.

### Password handling

Passwords are a distinct mode with hard rules — and they **never enter Telegram chat** (M5). Echo-off (S3) flips the relay to `Secret=true`, which routes the prompt to a **masked, non-persistent secure surface** instead of the DM:

- **Surface choice (see DECISIONS).** Default proposal: a small **operator-box-local web field** served by promptwire — `<input type="password">`, `autocomplete="off"`, TLS, WebAuthn/passkey auth with **step-up user-verification per secret answer** (M13), value cleared from the DOM and zeroed on submit, never persisted. Telegram's role for secrets is reduced to a **deep-link nudge** ("a password is needed for `sudo` on prod-db — tap to answer securely") so we keep Telegram's instant phone push for *attention* while the secret stays out of chat.
- **Never logged anywhere (M4):** secret reply bytes are never written to any gate/MCP/relay/audit log, transcript, or message footer. Audit records `password supplied by <user> at <ts>`, never the value. Proven by a **grep-the-logs CI test** asserting the secret string appears in no log/audit/redact output.
- **Never echoed (M4):** echo-off on the slave means the value never enters the child's terminal output → never the redacted stdout → never surfaced. Belt-and-suspenders: the stdout pump is **suppressed** between secret-prompt detection and answer-write, defending against a misbehaving program that echoes what it reads.
- **In-memory hygiene (M4):** the secret travels as `[]byte`, zeroed immediately after write to `ptmx`, never interned as `string`, never placed in an `error`. The frame field is marked secret so no layer logs the frame body. Transport is encrypted on every hop (TLS browser↔promptwire; Unix socket promptwire↔MCP; SSH MCP↔gate).
- **Mandatory fallback if no secure surface is provisioned:** **refuse** to relay echo-off prompts and instruct the operator to switch to manual SSH (M5). `deleteMessage` of a typed password is explicitly **rejected** as a credential-persistence mitigation.

### Timeouts, cancel, multiple prompts

Three nested timeouts, all new (the gate has none today), all **fail-closed (M17):**
- **Per-reply** `T_reply` (default 120s — typing a password on a phone/field is slower than a tap). On expiry: inject nothing, group-SIGTERM the child, surface "no answer — aborted."
- **Overall command deadline** `T_cmd` (default 15min, configurable) via `context.WithTimeout` — the deadline the executor lacks today. On expiry: group-SIGKILL.
- **Relay-channel idle/health** — if the sideband goes silent (MCP died, SSH dropped), the gate aborts the child rather than hang forever.

**Cancel/abort:** operator `/cancel` or Cancel button → `abort` frame → gate group-SIGTERM→SIGKILL (reuse `c.Cancel`); channel drop → gate sees EOF/ctx-cancel → existing group-kill (no orphan, pgroup guarantee preserved). Resolution is **idempotent** (reuse the Telegram backend's already-resolved guard in `src/signer/backend/telegram.go`) so a late tap after timeout is answered "expired," never double-written.

**Multiple sequential prompts** (`sudo` then `apt`'s `[Y/n]`): the relay is a **session**, not a single request. **Strict single-outstanding-prompt serialization** — prompt `seq+1` is never surfaced until `seq` is answered/aborted, so a reply binds unambiguously to one `(session_id, seq)`. **Loop guard (M14):** cap prompts-per-command (default 8) and prompts-per-minute; breach ⇒ abort "too many prompts," preventing DM/notification flood and approval-fatigue.

## Security model & threat mitigations

Each threat is listed with the mitigations (M1–M18) that answer it.

**C1 — Password phishing via attacker-controlled prompt text.** The prompt text is authored by a process on a host the operator may be repairing *because* it is suspect. Defense-in-depth (none complete; residual acknowledged):
- **M1** Permanent, non-removable provenance banner on every prompt: *this text is from the REMOTE host; treat as adversarial.*
- **M2** Always show the originally-authorized command, sourced from the **MCP run record, never the host**, and visibly flag when a read-only/unexpected command suddenly requests a password. (Caveat honestly stated: the MCP record reflects what the *agent* submitted, which is the semi-trusted party the gate exists to contain — so a crafted `sudo -k true; <evil>` can look benign. This is reduced, not eliminated; the password step-up adds a human-friction beat.)
- **M3** Secret vs confirm is decided by **termios echo-off**, not regex.
- Routing secrets to a masked surface with **step-up auth** (M13) inserts a deliberate friction beat absent from a one-tap channel.

**C2 — Password persists in Telegram cloud.** `deleteMessage` is best-effort against multi-device cloud sync and fails silently; a typed password is effectively exfiltrated to a third party forever. **M5:** passwords MUST NOT be entered into Telegram chat — route to the masked non-persistent surface, or refuse and require manual SSH.

**C3 — Multi-turn protocol welded onto the signing socket.** **M6:** the relay is a **separate service with its own socket, loop, and process**. The signer's `HandleSignRequest` stays strictly one-shot, `DisallowUnknownFields`, always-respond-always-audit, **untouched**. A relay bug can never wedge or starve the signing/approval path.

**C4 — Silent hang reported as success.** **M7:** a stall-aborted / timed-out / channel-dropped command surfaces a **distinct non-success exit status** the agent treats as "aborted/unknown," never "completed." We adopt a dedicated code (propose `EX_TEMPFAIL = 75`, added to the exit-code constants in `src/gate/cmd/sshgate-gate/main.go`) rather than the ambiguous `128+SIGKILL`, so an agent can never read a killed-on-stall command as done.

**H1 — False-positive newline into a live command.** **M8:** never auto-answer, never newline-probe; a human supplies every byte. Regexes advisory only. S2 (no-newline) + S3 (echo) gate the timer so a slow command is not mistaken for a prompt.

**H2 — `/proc/wchan` is fragile.** Rejected as a load-bearing signal (grandchild-blocked case, kernel-version/permission/container fragility, Linux-only). Detection rests on termios echo-off + no-newline + timer, which are robust and portable.

**H3 — TOCTOU swap-the-question.** **M9:** before injecting, the gate re-verifies echo state **and** that current prompt bytes still hash to the shown `prompt_hash`; mismatch ⇒ abort + audit, never inject.

**H4 — Prompt text as UI-spoofing / injection.** **M10:** strip ANSI/control chars; normalize and visibly flag bidi/homoglyph Unicode; length-cap; render inert — Telegram in **plain text, no parse mode** (the existing discipline in `src/signer/backend/telegram.go`), the web surface as a text node (never `innerHTML`). The bot/portal chrome cannot be impersonated by injected bytes.

**H5 — Redactor tail-trap (missed prompt AND leak).** The redactor holds the last 4 KiB safe-prefix and flushes only on `Close()` after `Wait()` — but a prompt is un-terminated output that can sit inside that held tail forever (the process won't exit; it's blocked). **M11:** a new additive `redact.Writer.FlushPending()` emits the held tail **through a full scan with no straddle-bypass**, so the secret-straddle protection is not defeated; detection *timing* may read the raw stream, but surfaced *content* is always **post-redaction**. (A simpler "single redact.Writer" design inherits a latent deadlock here; this design makes the flush explicit.)

**H6 — Transport rebuild is larger than it looks.** `Run` in `src/mcp/ssh/client.go` is fully buffered: no stream, no PTY, and no stdin except the narrow `RunWithStdin` path used by `update_gate` and `transfer`. The entire `client.go` Run contract and its callers (`run.go`, `run_batch.go`) move to a streaming model. **M12:** the PTY/interactive path is **opt-in per invocation**; the non-interactive path stays byte-for-byte identical and must pass the red-team rig with **0 new bypasses** and all READ controls still `executed` before any relay lands. Phase 0 de-risks this in isolation.

**H7 — Auth asymmetry.** Telegram inherits the signer's single-factor `from.id == AllowedUserID` check — adequate for **confirm** prompts (a tap can't be socially-engineered into leaking a secret). Secrets get the stronger surface: **M13** — WebAuthn/origin-bound passkey auth, `__Host-`/`Secure`/`HttpOnly`/`SameSite=Strict` session cookie, **step-up user-verification per secret answer**, CSRF token + Origin check on the answer POST, SSE GET side-effect-free, portal not internet-exposed by default.

**Medium findings.**
- **M14** prompts-per-command + prompts-per-minute caps → abort on breach (anti-flood/anti-fatigue).
- **M15** every reply carries an unambiguous binding to exactly one outstanding `(session_id, seq)`; strict single-outstanding serialization; unbound free-text rejected. Closes reply-misrouting and replay across concurrent commands.
- **M16** (Telegram free-text) while a prompt is outstanding, the **next** operator message is the answer **verbatim** — including a leading `/` or a literal `yes`/`no`; exactly one reserved abort affordance (a button, not a parsed word); a password beginning with `/` is never mis-parsed as a command. (Note: passwords route to the secure surface, so the `/`-password case mainly guards generic free-text confirms.)
- **M17** three nested fail-closed timeouts (above).
- **M18** every prompt + answer is an audit event in the reused mutex-protected append-only `AuditLog`: `{ts, session_id, host, prompt_type, prompt_text_hash, outcome, answered_by}` — **secret value excluded**; an "answered" row implies the answer actually left the relay.

**Why this is not a second signing flow.** Confirm/password replies are **inputs to an already-authorized, already-running command**, not authorizations to run new commands. They correctly do **not** go through `Sign`→`SSHGATE_SIG` (which would force a 5-min signature window onto a sub-second interaction). The signer channel is reused only for *identity + transport patterns*; the relay is its own service. **Open question:** whether a *secret* reply should additionally be wrapped in a short-lived signer-issued token so a compromised MCP cannot silently substitute a password. Since the MCP is already trusted to run the command, the lean is *no extra signing* — but because the MCP is the exact component the write-boundary distrusts, this trust delta is listed under Open questions.

**Residual risk (honest framing).** Feature 1 converts SSHGate from authorize-then-execute into a system that types operator-supplied input into an attacker-influenced channel. The banner + command-context + sanitization + echo-off-routing + step-up reduce but do **not** eliminate operator-phishing. Detection is best-effort by construction; safety rests on **M7 (fail loud)** and **M8 (never auto-answer)**, not on detection being perfect.

## Phased build plan

Each phase is independently shippable and leaves the system safe. Phases 0–2 are channel-agnostic gate work and are worth doing first regardless of the final channel mix.

**Phase 0 — Spec and threat-model sign-off (no code).** Freeze the promptwire frame schema, PromptType taxonomy, timeout defaults, exit-code (`EX_TEMPFAIL=75`), and the password-non-residency rule into a decision doc. Get maintainer approval before any code (this touches the box that holds the signing key).

**Phase 1 — PTY behind a flag, no relay (gate).** Allocate the PTY in `ExecWithRedaction` (opt-in flag default off; `creack/pty`; `Setsid`+`Setctty`; single combined `redact.Writer` in PTY mode; keep group-kill; add `T_cmd` `context.WithTimeout`; add the `EX_TEMPFAIL` exit path). **Acceptance:** interactive commands now render prompts (`sudo` actually asks); non-interactive output byte-for-byte unchanged; redaction green; **red-team rig 0 new bypasses, all READ controls still `executed`** (M12). No relay yet: prompts are detected nowhere and still go unanswered.

**Phase 2 — Stall detection + safe redactor flush, log-only (gate).** Implement the four-signal detector (S1–S4), termios echo-off read, and `redact.Writer.FlushPending()` with full-scan no-straddle-bypass (M11). On detection, **log** "prompt detected: `<scrubbed tail>`, secret=`<bool>`" and keep blocking on real stdin. Build a false-positive/false-negative corpus (model on the classifier corpus discipline). **Acceptance:** fires on `sudo`/`apt`-confirm/ssh-host-key/`rm -i`; does **not** fire on slow `find /` / `apt download` / streaming logs; flushed tail is fully scrubbed.

**Phase 3 — Streaming transport + sideband, local loopback (gate↔MCP).** Convert `ssh/client.go` from buffered `Run` to a streaming model: `RequestPty`, wire `sess.Stdin`, and open the second multiplexed relay sideband; update callers (`run.go`, `run_batch.go`). Gate frames prompts onto the sideband; MCP recognizes them and, for now, a **CLI stub** prints the prompt and reads a line to send back. Implement `session_id`/`seq`/`prompt_hash` binding, the M9 re-verify-before-inject, abort, and the three timeouts. **Acceptance:** a prompt round-trips host→MCP→host without Telegram; TOCTOU mismatch aborts; timeouts fail-closed with `EX_TEMPFAIL`.

**Phase 4 — promptwire service + Telegram confirm channel.** Stand up the **separate** promptwire service (own socket `0660`+group, own process; reuse signer `AuditLog` and systemd/deploy shape; **do not touch the signing daemon**, M6). Add the multi-turn socket protocol, MCP session-registration (drop unsolicited frames), and the Telegram backend: free-text inbound router (M16), Yes/No/Cancel callback namespace, message-edit outcome UX — reusing `AllowedUserID`/`pendingState`. **Acceptance:** `[Y/n]` arrives in DM, tap Yes → command proceeds; `/cancel` and timeout abort; concurrent commands route by `session_id` with single-outstanding serialization (M15); plain-text no-parse-mode + sanitization (M10).

**Phase 5 — Secure masked surface + password mode + hardening.** Build the masked secret surface (default: operator-box-local web field) with WebAuthn auth + **step-up per secret answer**, `__Host-`/Secure/HttpOnly/SameSite cookie, CSRF + Origin check, SSE side-effect-free, not internet-exposed (M13). Wire echo-off→secret routing, Telegram deep-link nudge, output-pump suppression during the secret window, `[]byte` zeroing, and the **grep-the-logs CI test** proving no secret value in any log/audit/redact stream (M4). Implement the M5 refuse-if-no-secure-surface fallback. Provenance banner + escape-sanitization + command-context + loop/rate caps finalized (M1/M2/M10/M14). **Acceptance:** `sudo` password relayed via masked field, never logged/echoed (CI grep proves absence); attacker-prompt corpus renders inert; loop-cap aborts a prompt-spammer.

**Phase 6 — Sequential prompts + final review.** Multi-prompt-per-command serialization end-to-end, full failure-mode matrix, audit completeness (M18). Then a full correctness, spec-conformance and security review, with an explicit decision on the C1 residual and the "secret-reply signer-token: yes/no" open question.

## Open questions

- **Channel model: hybrid (recommended) vs single-channel.** Proposed: Telegram for confirm/`[Y/n]`/host-key, a masked secure surface for passwords. The alternative is one channel for everything (note: Telegram-only is **unsafe for passwords**, M5; portal-only loses Telegram's instant phone push for attention).
- **Password entry surface.** Pick one: (a) operator-box-local **web field** (WebAuthn + step-up, recommended); (b) some other ephemeral one-time field; (c) **no secret relay at all** — refuse echo-off prompts and require manual SSH (most conservative, defeats the password use-case). `deleteMessage`-in-Telegram is **off the table** for secrets.
- **Auth model for the secure surface.** Confirm WebAuthn/passkey with **step-up user-verification per secret answer** (M13), single-operator posture mirroring `AllowedUserID` — or specify an alternative (e.g. TOTP step-up).
- **Portal placement: confirm central-on-operator-box** (recommended; no per-host portals, no credential sprawl, host stays credential-free) vs any per-host notion (discouraged).
- **Secret-reply integrity: extra signer-issued token, yes/no.** Should a password reply be wrapped in a short-lived signer token so a compromised MCP can't silently substitute it? Lean **no** (MCP already runs the command), but it is the one place the relay trusts the MCP with a secret.
- **Timeout defaults.** Proposed: `T_reply=120s`, `T_cmd=15min`, `T_soft=1.5s` / `T_hard=8s`, prompts-per-command cap `8`.
- **Stall-abort exit code.** Proposed: `EX_TEMPFAIL=75` as the distinct "aborted/unknown, not done" status (M7) vs an alternative sysexit.
- **Scope of secret relay at v1.** Recommended: ship confirm prompts first and treat **password relay as a separate follow-on** with its own approval, rather than both at once.

## Open design question — auto-confirm mode

During an install a command may fire many routine `[Y/n]` confirms; tapping each is annoying. The desired affordance is an **auto-confirm mode** the operator can enable/disable (e.g. a Telegram slash command) so the agent proceeds without a tap. Requirements: the mode must not let the agent get the arm's-length **deterministic signer** to sign anything it would not sign otherwise, and the agent must not be able to learn that the mode is on and use that to slip a malicious command in mid-stream.

**Structural fact that makes this tractable:** a confirm is **stdin to an already-authorized, already-running command, not a signing event** (see "Why this is not a second signing flow"). The signer is not in the confirm path, so auto-confirm can never cause the signer to authorize a new/different command. Every command still clears the normal bar (Tier-2 signature / Tier-1 read-classification) before it can run; auto-mode only changes *who answers prompts inside* an already-cleared command.

**Load-bearing invariant:** *auto-mode never widens what can run — it only auto-answers prompts within an already-authorized command.* This is also the defense against the "inject mid-stream" worry. The toggle MUST live on the **deterministic side** (human-set from Telegram, authenticated as the operator) and be neither settable nor readable by the AI/MCP.

**Residual risk to contain:** a prompt *inside* a legitimately-approved command can itself be consequential (e.g. apt's "replace edited `/etc/ssh/sshd_config` with maintainer version? [Y/n]"), and a blind auto-yes makes that call. **Mitigation rule:** auto-mode auto-answers only prompts matching a **tight allowlist of known-safe standard confirmations**; anything unrecognized, any config-overwrite-style prompt, and **anything echo-off (password) is never auto-answered** and always escalates to the human.

**Two toggle shapes (decide together):**
1. **Per-command auto-confirm scope (tighter):** approving/signing a command also authorizes "auto-answer its standard confirmations." Binds auto-answering to the specific vetted command; no standing state for the AI to exploit. Best security story.
2. **Global time-boxed toggle + safe-shape allowlist (better ergonomics):** human-set on/off from Telegram, hard-limited to the allowlist, time-boxed. Convenient but blankets a window.

Likely a hybrid. **Open:** to be decided in the design review before any build. **Build the confirm path so the auto-answer policy is a pluggable, deterministic-side decision point** (don't hardcode "always ask").
