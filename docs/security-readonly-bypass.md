# Security research — read-only gate bypass landscape

A survey of the industry pattern of "let SSH through but only execute reads", the bypass categories that pattern has historically failed under, and how each one applied to SSHGate's classifier (`classify.Classify`) and gate.

## How to read this document (status as of v0.1.5, 2026-10)

**This is a historical survey.** It was written in 2026-06, when the
read/write classifier was the only thing that stopped a disguised write, and
the sections below are kept as written then, in the present tense of that
time. "VULNERABLE", "BLOCKER" and "today" describe the classifier as it was
in 2026-06, not as it is now. Line-number citations from that version have
been replaced with function and file names, because the rules have since
moved out of `classifier.go` into `src/classify/rules_text.go`,
`rules_net.go`, `rules_system.go`, `rules_probe.go` and `env.go`
(`hasTopLevelRedirect`, mentioned below, is now `hasWritingRedirect`).

**What has changed since:**

- **Every BLOCKER and MAJOR finding below was fixed in the classifier**, and
  the fixes have rows in `tests/testdata/classifier-corpus.txt` (see the
  table).
- **Reads now run in a kernel jail on hosts that support it.** Since v0.1.5
  the gate runs every command the classifier calls a read inside a jail
  (profile `ro-v1`) on any host with unprivileged user namespaces and
  Landlock. There, a read cannot write files or file metadata on the host,
  connect to a local daemon over a Unix socket, or signal or trace other
  processes. So a classifier miss of the kind surveyed here no longer turns
  into a write on such a host: the command runs, but inside the jail. Reads
  in the jail keep network access, and a few `systemctl`/`docker` read
  commands run outside it from a fixed list. `gate doctor` on the host says
  whether the jail applies; see
  [install-step-by-step.md](install-step-by-step.md#5-check-the-servers-read-jail).
- **The security boundary for writes is unchanged:** an Ed25519 signature
  checked by the gate under an OpenSSH forced command. The classifier only
  decides which commands need a signature.

**What is still open (honest residuals):**

- **On hosts without the jail, the classifier is still the only wall** for
  unsigned commands. Any command it wrongly calls a read runs with the SSH
  user's full rights. Operators can pin `jail-floor` so such hosts refuse
  reads instead (see the install guide).
- **The classifier parses shell text, and parsers have gaps.** Two classes
  stay open by the nature of the approach: GNU long-option abbreviations of
  options the rules do not list, and environment-variable prefixes the
  deny-list does not name (the env check is a deny-list, not the allowlist
  this survey recommended). Either can let a command that writes or runs
  something else pass as a read. On a jailed host that command is still
  confined by the jail.
- The gate does not filter the environment that sshd passes in; the install
  guide now covers `AcceptEnv` (MINOR-5).
- The full list of what the jail does not cover is in
  [THREAT-MODEL.md](THREAT-MODEL.md).

| Finding | What it was | Status now |
| --- | --- | --- |
| BLOCKER-1 | `sed` `e` / `s///e` executes commands | Fixed: `sedRule` (`rules_text.go`) |
| BLOCKER-2 | `find -fprint*` / `-fls` write files | Fixed: `findRule` (`rules_text.go`) |
| BLOCKER-3 | `KEY=VAL cmd` env smuggling | Fixed for the listed keys: `dangerousEnvVars` deny-list (`env.go`); unlisted keys remain a residual |
| BLOCKER-4 | `awk` `system()` / `getline` | Fixed: `awkRule` (`rules_text.go`) |
| MAJOR-1 | `env` as a wrapper | Fixed: `envRule` (`env.go`) classifies the wrapped command |
| MAJOR-2 | `journalctl --rotate` / `--vacuum-*` | Fixed: `journalctlRule` (`rules_system.go`), abbreviations included |
| MAJOR-3 | `git -c` config injection | Fixed: `gitRule` (`rules_system.go`) treats `-c` / `--config-env` as writes |
| MAJOR-4 | `sed --in-pl` abbreviation | Fixed for listed options (prefix matching, `matchesAbbrev`); unlisted options remain a residual |
| MAJOR-5 | `curl -K` / `--config` | Fixed: `curlRule` (`rules_net.go`) |
| MINOR-1 | `no-pty` in `authorized_keys` | Fixed: `restrict` + `no-pty`, golden-pinned |
| MINOR-2 | corpus rows | Done: `tests/testdata/classifier-corpus.txt` |
| MINOR-5 | `AcceptEnv` guidance | Documented in the install guide |
| others | MINOR-3, MINOR-4, MINOR-6, NITs | Low risk; see each section |

## Summary

- **Tools surveyed:** 5 top + 5 brief notes (rbash/rzsh, scponly, Cursor "Agent SSH", Hoop.dev session brokers, Sandfly).
- **SSHGate-applicable findings at survey time: 4 BLOCKER, 5 MAJOR, 6 MINOR, 4 NIT** (see the table above for where each stands now).
- **Verdict at survey time (2026-06), since addressed:** SSHGate's classifier is in roughly the same shape as lshell / OpenClaw v1 — it gets the "obvious" shell metacharacters right (subst, redirect, pipe), but the read-side surface has at least two **direct, no-clever-shell-tricks** vehicles to arbitrary code execution (sed `e` flag, find `-fprintf`/`-fprint`), plus environment-variable smuggling that GNU long-option abbreviation will let through. None of these required the operator to mistype. The survey's conclusion was that the BLOCKERs had to be closed before SSHGate could be offered against a hostile-LLM threat model; they were, and the kernel read jail was later added as a second layer.

The single most useful insight from the OpenClaw arxiv paper [3, 4]: "The exec allowlist was designed as a string-matching system operating on static representations of command text, while the actual security boundary requires reasoning about command **semantics** — how the shell will interpret the string at runtime, what executable the invocation will actually dispatch to, and what the effective set of active options will be after GNU abbreviation expansion." SSHGate's classifier sits exactly in that gap, which is why reads on capable hosts now also run in a kernel jail.

---

## Top 5 tools in this category

### Tool: lshell (Limited Shell)
- **What it does:** Python-based login shell that restricts the user to an allowlisted command list, configurable per-user, with timing/scp/sftp gating. The closest direct analogue to SSHGate's classifier.
- **Maintainer:** an individual open-source maintainer; still tagged in 2025. Real production users on Debian/Ubuntu repos. [1]
- **Documented threat model:** `SECURITY.md` in repo enumerates "shell escape via allowed editors / pagers / scripting binaries" as explicitly out-of-scope and the operator's responsibility. [9]
- **Known bypass categories:**
  1. **Allowed editor/pager escapes** — `vim :!sh`, `less !sh`, `man <foo>` → `!sh`. lshell does not block these even with hardcoded `forbidden` lists; the binary is "allowed" and the *interactive* escape is internal to it. [GTFOBins less [13]; lshell issue #148]
  2. **Interactive subshell via `expect` / `python -c`** — `python -c "import pty;pty.spawn('/bin/bash')"` if python is allowed. [1, 8]
  3. **Argument-injection via allowed binaries** — `awk 'BEGIN{system("sh")}'` (GTFOArgs); `find / -exec /bin/sh \; -quit`. [11]
  4. **Custom alias / function definition** — if the shell still sources `~/.bashrc`, `alias` and shell functions can rewrite the allowlist behind lshell's back.
  5. **CVE-history**: lshell 0.9.15 RCE (Exploit-DB 39632) — exact path-of-bytes escape in the argument validator. [1]
- **Lessons for SSHGate:** Allowlisting a binary is allowlisting *its entire feature surface*. `less`, `awk`, `sed`, `find`, `git` each carry first-party shell-execution features. SSHGate must classify by **(binary, sub-feature)** not by binary alone — or it must run inside a sandbox that contains the escape. (At survey time SSHGate had no sandbox; since v0.1.5 it runs reads in a kernel jail on hosts that support it.)

### Tool: rssh (Restricted Secure Shell)
- **What it does:** Wrapper login shell whitelisting only SCP / SFTP / rsync / cvs / svnserve / rdist subcommands. Was the de-facto choice for "ssh-but-only-for-file-transfer" for ~15 years. **Now unmaintained**, included here as a cautionary precedent.
- **Maintainer:** declared end-of-life by its maintainer. Still in Debian oldstable. [2]
- **Documented threat model:** README + man page; effectively "we filter the subcommand head and trust the helper to behave."
- **Known bypass categories / CVEs:**
  1. **CVE-2012-2252** — incomplete blacklist when rsync enabled; `--rsh` argument lets the user supply an arbitrary "ssh" replacement and rsync execs it. *Exact analogue to argument-injection through an allowed read binary.*
  2. **CVE-2012-2251** — `-e` and `--` long-option separators bypass the same argument filter.
  3. **CVE-2012-3478** — crafted environment variables bypass restricted shell. *Direct relevance to SSHGate's `FOO=bar cmd` env-prefix stripping.*
  4. **CVE-2019-1000018** — `allowscp` argument-injection RCE; researcher controlled exactly which scp command ran on the server. [12]
- **Lessons for SSHGate:** Argument allowlists are deceptively hard. Every wrapped binary needs a *deny-by-default* flag scan with knowledge of GNU `--` long-option semantics, GNU prefix abbreviation, short-flag clusters, and `--option=value` vs `--option value` forms.

### Tool: git-shell
- **What it does:** Git's bundled login shell. Restricts SSH to `git-upload-pack` / `git-receive-pack` / `git-upload-archive` subcommands. Used by GitHub, GitLab, Gitea, Forgejo in production for "SSH-as-git-only" termination.
- **Maintainer:** Git project. Mainline, actively reviewed.
- **Documented threat model:** `git-shell(1)` manpage. Threat model is intentionally narrow: "only these four executables, with no shell."
- **Known bypass categories:**
  1. **CVE-2017-8386** — `git-shell` could be coerced to run `git ... --help`, which spawned `man` → `less` → interactive `!sh`. [5, 6] Mitigation: disable PTY in sshd (`no-pty`).
  2. **Argument-injection via `--upload-pack=<cmd>`** in older git clients on the server side (paired vuln).
- **Lessons for SSHGate:** SSHGate's `authorized_keys` forces `restrict,no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding` on every provisioned key — `commandForcingFmt` in `src/mcp/tools/authorizedkeys.go` leads with `restrict` (the OpenSSH ≥ 7.2 deny-all catch-all, which also blocks `~/.ssh/rc` execution and any future capability) and pins `no-pty`, so a classified-read pager (`less` of a large file, `man`, `git log`) can never allocate a TTY to go interactive and open `!sh`. (The template's option list is golden-pinned by a test so `restrict`/`no-pty` cannot be silently dropped.)

### Tool: OpenClaw exec policy engine
- **What it does:** Auto-approve allowlist for LLM-driven shell commands. Same shape as SSHGate's classifier: read-by-default-allowed, write-needs-approval. Production-deployed by ~the entire personal-AI-agent ecosystem in 2026.
- **Maintainer:** OpenClaw project. [7]
- **Documented threat model:** "Exec Approvals" docs page. Threat model assumes the model is potentially adversarial (prompt injection).
- **Known bypass categories (from arXiv 2603.27517 and 2603.10387, both published in early 2026):** [3, 4, 7]
  1. **Line-continuation injection** — `echo "ok \<newline>$(id)"` — the lexical parser saw `\n` inside a quoted string as the literal `\n` escape, not as the POSIX-shell line-continuation that removes the backslash-newline. Patched upstream.
  2. **Busybox / toybox multiplexer dispatch** — `busybox sh -c '<arbitrary>'`. Allowlist saw "busybox" as a known-safe binary; busybox dispatches to `sh`. Patched by writing an entire new `unwrapKnownShellMultiplexerInvocation()` module. *Toybox is the same; many embedded distros have one or both.*
  3. **GNU long-option abbreviation** — `--compress-prog` accepted when `--compress-program` denied. Glibc/GNU getopt accepts unambiguous prefix abbreviations; the allowlist used exact-string match against the canonical form. Patched upstream.
  4. **Environment-variable smuggling** — sensitive config (e.g. `LD_PRELOAD`, `IFS`, `PATH`, `GIT_SSH_COMMAND`, `GIT_EXTERNAL_DIFF`, `PAGER`, `SYSTEMD_PAGER`, `EDITOR`/`VISUAL`) passed via `FOO=bar cmd` prefix, escaping command-line argument filters.
  5. **Wrapper-binary unwrap gaps** — `env`, `nice`, `nohup`, `time`, `taskset`, `chroot`, `unshare`, `setsid` strip the leading wrapper and the *real* command is what executes. Allowlist needs to unwrap recursively.
- **Lessons for SSHGate:** *At survey time, every one of OpenClaw's allowlist CVEs mapped to a corresponding hole in SSHGate.* See the cross-reference below — at least 4 of the 5 categories were present in the classifier then.

### Tool: Teleport (gravitational.io / goteleport)
- **What it does:** Enterprise SSH/RDP/Kubernetes session broker with policy-as-code, session recording, just-in-time access approvals. **Different category than SSHGate** — Teleport records and approves *sessions*, not individual commands — but it's the most-cited "secure SSH bastion" in 2025-2026 enterprise reviews.
- **Maintainer:** Teleport (formerly Gravitational). Funded, audited yearly. [10]
- **Documented threat model:** Public threat-model doc + annual third-party penetration tests published.
- **Known bypass categories / CVEs:**
  1. **CVE-2025-49825 (CVSS 9.8)** — full SSH authentication bypass against OpenSSH-integration and Git proxy modes. Patched June 2025. Demonstrates: even a heavily-audited, security-focused vendor ships a complete auth-bypass in the *boring layer* (signature verification / state machine).
  2. **Session-recording bypass via RemoteCommand / exec mode** — Boundary has the same caveat: command-exec sessions don't get full session-recording asciicasts. [Documented as design limitation]
- **Lessons for SSHGate:** (a) Even mature audited code ships pre-auth bypasses — SSHGate's signature-verification path (`src/gate/verify.go`) deserves extra fuzzing (still to do as of this status note); (b) recording/visibility is a separate axis from gating — the operator's Telegram approvals provide the audit log SSHGate has no other source of truth for.

### Brief notes on other relevant tools
- **rbash / rzsh** — `bash --restricted` and zsh equivalent. Bypassable via every "allowed binary's internal shell escape" trick; well-known to be a porous defense. Used historically by ISPs. [8]
- **scponly** — same family as rssh; CVE-2007-6415 (subcommand-injection: invoking `unison`/`rsync`/`svn` from scponly to get arbitrary execution).
- **Cursor "Agent SSH" / Codex "remote dev"** — newer, less documented. Mostly relies on container isolation + per-tool RPC instead of "SSH but classified". Not a direct analogue.
- **Hoop.dev session brokers** — proxy with session recording; relies on policy rules rather than command classification. Adjacent rather than analogous.
- **Sandfly Security** — Linux IR/EDR; documented integration with Tailscale SSH (re-auth as a check-mode policy). Defense-in-depth pattern: gate first, then EDR sees what got through.

---

## Bypass categories cross-referenced with SSHGate

For each row: **status** = COVERED / VULNERABLE / PARTIAL **at survey time (2026-06)**. Citations name the function; the rule functions now live in `src/classify/rules_*.go` and `env.go`, the parsing helpers in `src/classify/classifier.go`. For the current status of each finding, see the table at the top.

### B1 — Command substitution `$(...)` and backticks
- **Status:** **COVERED.** `containsSubstitution` (`classifier.go`) detects `$(`, `` ` ``, `<(`, `>(` at top level (outside quotes) and forces KindWrite. Corpus row 178-180 verifies. **No regression risk** unless someone weakens the quote tracking.
- **Caveat:** `containsSubstitution` only tracks `'`/`"` quote state, not heredoc state. If the line is `cat <<EOF$(rm /tmp/x)EOF`, the `$(` is inside what bash treats as a heredoc terminator but the classifier still flags substitution and routes to write — accidentally correct. Heredoc *body* is not parsed by classifier at all — see B11.

### B2 — Pipe smuggling (read | write)
- **Status:** **COVERED** per-segment. `splitSegments` (`classifier.go`) splits on `|`, `||`, `&`, `&&`, `;` outside quotes; `Classify` returns KindWrite if any segment is write. Top-level `>` redirect short-circuits the whole line.
- **Caveat:** `|&` (bash's stderr-pipe shorthand for `2>&1 |`) is **not** explicitly split. Walking the code: at `|`, the classifier looks at the next char for `|`; if it's `&`, it currently treats the `&` as the *start* of the next segment, so the segmentation is preserved but the `&` becomes a stray leading character of the next segment. **MINOR**: stray `&` likely confuses `tokenize`. The behavior is "fail-safe" (most likely write classification on the trailing-`&` head), so I'm calling it NIT not BLOCKER.

### B3 — Quoting tricks, ANSI-C `$'\\x...'`, unicode look-alikes
- **Status:** **PARTIAL / MAJOR.** `tokenize` (`classifier.go`) only knows about `'` and `"`. **It does not understand `$'...'` (ANSI-C quoting) at all.** A command like `$'rm\\x20-rf' /tmp/x` would tokenize as two tokens: `$rm\\x20-rf` (the `$` is not stripped, the `'`s are stripped as if regular quotes) and `/tmp/x`. The head becomes `$rm\\x20-rf`, which is not in the allowlist → KindWrite. **Accidentally safe** in this direction.
- **The other direction is the danger**: `$'\\x73h'` is `sh`. So `$'\\x73h' -c 'rm /tmp/x'` tokenizes head = `$\\x73h`, not `sh`, → not in allowlist → KindWrite. Again accidentally safe.
- **Real concern:** `cat $'/tmp/\\x66' >&2 </dev/zero` — head is `cat` (allowed); no top-level redirect output (`>&2` *is* a `>` so it triggers `hasTopLevelRedirect` → write). Accidentally safe.
- **The actual unicode look-alike trap:** classifier compares byte-by-byte against ASCII strings like `"git"`, `"docker"`. A Cyrillic `с` (U+0441) followed by `at` won't equal `cat` so it'll be unknown → write. Safe direction.
- **Verdict:** No active bypass found via quoting tricks. Logging this as **NIT — add `$'...'` test cases to the corpus** to lock in the behavior.

### B4 — Env-var injection (`LD_PRELOAD=...cmd`, `IFS=...cmd`, `PATH=...cmd`)
- **Status:** **VULNERABLE — MAJOR.** `classifySegment` (`classifier.go`) explicitly *strips* leading `KEY=VALUE` env assignments via `isAssignment` and reclassifies the remaining tokens. The leading env is **not** examined for dangerous keys.
  - `LD_PRELOAD=/tmp/evil.so cat /etc/hosts` — classifier strips `LD_PRELOAD=...`, sees `cat /etc/hosts`, returns KindRead. **Gate runs `/bin/sh -c "LD_PRELOAD=/tmp/evil.so cat /etc/hosts"`**. The shell honors LD_PRELOAD on the cat process.
  - To actually get RCE: attacker first needs `/tmp/evil.so` on disk. **But**: the same approach with `GIT_EXTERNAL_DIFF=/tmp/payload git log` (where `/tmp/payload` is anything the attacker controls — including just `/bin/sh -c 'rm /tmp/x'` if the attacker can write that string into a file). They need a write to disk first — but **what about reading via curl into a tmpfile from a stripped env that ALLOWS write through env vars?** Examples:
    - `GIT_EXTERNAL_DIFF=$'\\x73h\\x20-c\\x20rm /tmp/x' git log -p HEAD` — git's diff machinery forks the value as the diff driver. Classifier sees `git log -p HEAD` (read) → executes; shell honors GIT_EXTERNAL_DIFF → RCE. **No filesystem write needed prior.**
    - `GIT_SSH_COMMAND='sh -c "rm /tmp/x"' git fetch origin` — `git fetch` is currently classified as **WRITE** (not in the gitRule read list), so this path is safe. But `git ls-remote` is **READ** in the classifier (`gitRule`). `GIT_SSH_COMMAND='sh -c "id>/tmp/p"' git ls-remote origin` → classifier says read, git forks the SSH command → **RCE.** [Verified by reading `gitRule` at survey time.]
    - `PAGER='sh -c "id"' git log` — classifier sees git log = read; git forks PAGER for interactive output, value treated as `sh -c '...'` because git uses `system(3)`. RCE.
    - `PAGER='sh -c "id"' systemctl status nginx` — same shape; systemctl uses pager if stdout is a tty. With `no-pty` set, stdout is NOT a tty → PAGER not invoked. **`no-pty` is load-bearing for this whole class**, and it is enforced by `commandForcingFmt` in `src/mcp/tools/authorizedkeys.go`.
    - `SYSTEMD_PAGER='sh -c "id"' SYSTEMD_PAGERSECURE=0 journalctl -u nginx` — same shape; systemd recommends "secure mode" but the default depends on `journalctl`'s detection of elevated privileges. journalctl in `no-pty` may also short-circuit, but **the attacker controls both env vars**, so they can force pager invocation if any code path inside journalctl uses it without checking ttyness. [14]
    - `IFS=$'\\n'; cmd` — IFS injection is a parameter-expansion concern, only relevant if classifier-allowed commands have unquoted variable expansions internally. Not a direct vehicle on its own; defer.
- **Severity:** **BLOCKER for the GIT_EXTERNAL_DIFF / GIT_SSH_COMMAND / PAGER vectors.** These work today against `git log` / `git ls-remote` / any read-allowlisted command that respects pagers. No additional capabilities required beyond what the gate already grants.
- **Where:** the env-prefix strip in `classifySegment` (`classifier.go`), plus the read-allowlist entries for git/journalctl/systemctl. Now closed for the listed keys by `dangerousEnvVars` in `env.go`.
- **Fix sketch (research, not code):** maintain a **deny-list of dangerous env keys** that, if set in the prefix, force KindWrite regardless of head. Minimal initial list: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `PATH`, `IFS`, `BASH_ENV`, `ENV`, `SHELLOPTS`, `PROMPT_COMMAND`, `PAGER`, `MANPAGER`, `LESS`, `LESSOPEN`, `EDITOR`, `VISUAL`, `SYSTEMD_PAGER`, `SYSTEMD_PAGERSECURE`, `GIT_*` (anything starting with `GIT_`), `GIT_EXTERNAL_DIFF`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_PAGER`, `GIT_EDITOR`. Better yet: an **allowlist** of safe env vars (e.g. `LC_*`, `LANG`, `TZ`) and deny everything else.

### B5 — Heredoc and herestring
- **Status:** **PARTIAL / MAJOR.** Classifier does not parse heredoc syntax at all. `cat <<EOF >/tmp/x` has the `>` at top level, so `hasTopLevelRedirect` catches it → write. **But** `cat /etc/hosts <<<"$(rm /tmp/x)"` — the herestring `<<<` introduces a string that bash evaluates with full expansion. The `<` triggers the `containsSubstitution` check only if followed by `(`. `<<<` has `<<<"$(...)"` — the `$(` *is* inside the string, **but at byte-level scan it's still `<` `<` `<` `"` `$(` ...** the classifier walks left-to-right and sees `$(` at some index → `containsSubstitution` returns true → KindWrite. Accidentally safe.
- **Counter-case:** `cat <<<"$VAR"` — no `$(`, just `$V`. classifier passes it to /bin/sh. Whatever bash does with `$VAR` is whatever bash does. If `$VAR` happened to be set by the attacker via env (`VAR='$(rm /tmp/x)' cat <<<"$VAR"`), the classifier sees env-strip leaves `cat <<<"$VAR"` — head `cat` (allowed), no `$(`. → READ → executed. **But**: bash's `<<<` does NOT recursively expand `$(...)`. It does parameter expansion (`$VAR` → the literal string `$(rm /tmp/x)` as set), and the resulting string goes to cat's stdin. cat just prints it. **Safe** but only by bash semantics, not by classifier check.
- **Real concern with heredocs:** `cat <<EOF; rm /tmp/x; EOF` — classifier splits on `;` so segment 1 = `cat <<EOF`, segment 2 = `rm /tmp/x`, segment 3 = `EOF`. The bash semantics: `<<EOF; rm /tmp/x; EOF` is invalid syntax (bash will error). Accidentally safe.
- **Verdict:** No exploitable direct path. **MINOR** — add corpus rows for `<<`, `<<-`, `<<<` with substitution and without.

### B6 — Brace expansion `cp {a,b,c} d`
- **Status:** **N/A.** `cp` isn't in the read allowlist anyway; entire line classified as write. NIT.

### B7 — Glob abuse `cat /tmp/*`
- **Status:** **NIT.** Glob expansion is done by shell after classifier sees the line. Classifier sees `cat /tmp/*` → head `cat` (allowed) → READ. Shell expands `/tmp/*` and runs `cat file1 file2 ...`. No write happens because cat doesn't write. **Real glob-abuse concern**: globs that *trick the read into a write* would require an allowed command that takes filenames as flags. E.g. if attacker stages a file named `--in-place` in cwd, then `sed -e s/a/b/ *` could expand `*` to include `--in-place`. **VULNERABLE — MAJOR.** Worked exploit: attacker writes a file `-i` in cwd (write requires approval but `touch -- '-i'` requires `touch` which is write). So they'd need write first. **NIT-MAJOR borderline**: theoretically real, requires a prior write that already requires approval. Mark MINOR.

### B8 — Rare control operators: `|&`, `&>`, `>(...)`, `<>`
- `|&` — see B2. Stray `&` survives segmentation; head of the trailing segment is whatever followed `&`, likely unknown → write. NIT.
- `&>` — `&` followed by `>`. `splitSegments` flushes at `&`, then the `&` advances by 1. Next char `>` is read as a regular char by segmentation, and `>` at any unquoted position triggers `hasTopLevelRedirect` → write. **COVERED.**
- `>(...)` — process substitution; `containsSubstitution` catches it. **COVERED.**
- `<>` — file open for read+write. classifier walks bytes: at `<`, next byte must be `(` for it to trip substitution; `>` follows but `<` already incremented past. Then `>` triggers `hasTopLevelRedirect` → write. **COVERED.**

### B9 — Editor / pager interactive escapes (`less !sh`, `vim :!sh`, `man → less !sh`, `git log → less !sh`, `journalctl → less !sh`)
- **Status:** **MITIGATED — `no-pty` is enforced.** SSHGate's `sshgate add` provisioning writes `restrict,command="...",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding` (`commandForcingFmt` in src/mcp/tools/authorizedkeys.go; `restrict` also blocks `~/.ssh/rc` execution and future capabilities), so the interactive-escape class below is short-circuited: no PTY is ever allocated. Were `no-pty` ever dropped from the template, every one of these would work against the gate:
  - `less /var/log/syslog` — classifier returns READ → shell runs less. On a PTY, type `v` → opens `$EDITOR` (default vim) → `:!rm /tmp/x` → RCE. Or `!sh` directly.
  - `git log` — same path, `git` pipes to less.
  - `journalctl -u nginx` — same.
  - `man <foo>` — `man` isn't allowlisted (good), but `less /usr/share/man/...gz` is. NIT.
- **Where:** the `less` read-allowlist entry (now `lessRule`, `rules_system.go`), and `commandForcingFmt` in **src/mcp/tools/authorizedkeys.go** (which now emits `no-pty`, closing this class).

### B10 — Read commands that mutate state (the find / awk / sed / journalctl class)
This is the highest-yield bypass class — every entry below is a direct, no-clever-shell, single-command path from "classified read" to "writes to disk" or "executes arbitrary command":

#### B10a — **`sed e` flag (the `s/x/y/e` GNU substitution flag) executes the replacement as a shell command**
- **Status (2026-06): BLOCKER. Now fixed.** `sedRule` (now in `rules_text.go`) only checked for `-i` / `--in-place`. The `e` flag is *inside the sed program* (the script argument), not a command-line flag. Example:
  - `sed 's/.*/id/e' /etc/hosts` — runs `id` for every line in /etc/hosts. Classifier returns READ.
  - `echo nothing | sed 's/.*/rm \/tmp\/x/e'` — runs `rm /tmp/x`.
  - Also the standalone `e` sed command: `sed -n '1e rm /tmp/x' /etc/hosts`.
- **Where:** `sedRule`, `src/classify/rules_text.go`.
- **Source:** [15] GNU sed manual.

#### B10b — **`find -fprintf` / `-fprint` / `-fls` write arbitrary files**
- **Status (2026-06): BLOCKER. Now fixed.** `findRule` (now in `rules_text.go`) blocked `-delete`, `-exec`, `-execdir`, `-ok`, `-okdir`. It does **not** block:
  - `-fprintf FILE FORMAT` — like `-printf` but writes to FILE.
  - `-fprint FILE` — writes matched paths to FILE.
  - `-fprint0 FILE` — same with null delimiters.
  - `-fls FILE` — ls-style listing to FILE.
- Example RCE: `find /etc -name hosts -fprintf /tmp/x "evil content"` — classifier says read; find writes `/tmp/x`. Pair with `-fprintf ~/.ssh/authorized_keys "ssh-rsa AAAA..."` (the file is path-traversable by the gate user) → persistent backdoor. **No env vars, no quotes, no chaining needed.**
- **Where:** `findRule`, `src/classify/rules_text.go`.
- **Source:** GNU find(1) manpage.

#### B10c — **`awk` system() / getline pipe / -v assigning ENVIRON**
- **Status (2026-06): BLOCKER. Now fixed** by `awkRule` (`rules_text.go`). At survey time `awk` was allowlisted with a `nil` rule — every invocation was read. Examples:
  - `awk 'BEGIN{system("rm /tmp/x")}'` — runs rm. [11]
  - `awk 'BEGIN{while(("id"|getline line)>0) print line}'` — same thing, pipe form.
  - `awk -v cmd='rm /tmp/x' 'BEGIN{system(cmd)}'`.
- **Where:** the `awk` read-allowlist entry, now `awkRule`.

#### B10d — **`git log` with custom format / external diff via env**
- See B4 — env-var injection. **BLOCKER via env, MAJOR via inline:** `git -c core.pager='sh -c "id"' log` — classifier sees `git log` head; `-c` injects config. Classifier doesn't scan past head. Worth confirming whether `git -c ...` reaches gitRule's `firstNonFlag` (which skips `-c`-style flags) — it did at survey time. So `git -c <evil> log` → firstNonFlag returns `log` → READ. Then git honors the injected config. **MAJOR.**

#### B10e — **Pure-data commands that nonetheless write**
- `tar --to-command=CMD` — tar is not allowlisted, but if added → write surface. Currently safe.
- `gzip --list` — read; safe.
- `apt update` — not allowlisted; correctly write.
- `journalctl --rotate` / `journalctl --vacuum-size=...` — at survey time the classifier had `journalctl` as a nil-rule allow (now `journalctlRule`). `journalctl --rotate` IS a write. **MAJOR.** `journalctl --vacuum-time=1s` deletes journal data.
- **Where:** the `journalctl` read-allowlist entry, now `journalctlRule` (`rules_system.go`).

### B11 — TOCTOU between parse and shell
- **Status:** **COVERED-ISH / MINOR.** Classifier parses the literal `SSH_ORIGINAL_COMMAND` string; same string goes verbatim to `/bin/sh -c`. There is no race because there is no separate "fetch the command" step between parse and exec; both consume the same bytes. **However**, if the command contains a path to a script (`bash /tmp/foo.sh`), classifier sees `bash` as not-allowlisted → write. Currently `bash`, `sh`, `source`, `.` are not in the read allowlist — **good**. NIT to double-check `python`, `perl`, `ruby`, `node`, `lua`, `php` — none were in the allowlist at survey time; all defaulted to write. (Today a few interpreters are allowed only for a bare version check, via `interpreterVersionRule` in `rules_probe.go`.) **COVERED.**

### B12 — Aliases / shell functions / `.bashrc` poisoning
- **Status:** **N/A by execution model.** Gate runs `/bin/sh -c <cmd>` (`src/gate/executor.go`; on a jailed host the same `/bin/sh -c` runs inside the jail, and the fixed `systemctl`/`docker` list runs without a shell), which does NOT source the user's `.bashrc`, `.profile`, `.zshrc`. `/bin/sh` non-interactive ignores those. **COVERED.**
- **Caveat:** Some systems symlink `/bin/sh` → `bash`. Bash in `sh` POSIX mode still reads `$ENV` if set. If env-var injection (B4) sets `ENV=/tmp/evil`, the spawned `sh -c` may source it. **Already covered by B4's fix.**

### B13 — `find -exec` / `find -execdir` etc.
- **Status:** **COVERED.** `findRule` blocks these. The bypass is via `-fprintf`, not `-exec` — see B10b.

### B14 — Sourcing files (`source X` or `. X`)
- **Status:** **COVERED.** `source` and `.` are not in the read allowlist; they default to write. NIT to add explicit corpus row.

### B15 — Argument injection via env-injected `$VAR`
- **Status:** **MINOR.** SSHGate forwards `SSH_ORIGINAL_COMMAND` as-is to `/bin/sh -c`. Any other env vars the client sent via `LC_*` / SendEnv channels arrive at gate's process. If sshd `AcceptEnv` is configured permissively, attacker controls them. Recommend an explicit `AcceptEnv` in the install playbook restricting to (or completely disallowing) inbound env. **MINOR docs/install hardening.** (Now documented in the install guide, Tier 1 step 4.)

### B16 — Carriage-return / null-byte tricks
- **Status:** **COVERED.** `hasPrintable` (`classifier.go`) skips `\0`, space, tab, newline, CR. `tokenize` splits on space/tab/newline/CR. Allowlist comparison is exact-string. A command containing `\r` will be tokenized into pieces split by `\r`. If `\r` is inside quotes, `tokenize` keeps it. Head token can contain `\r`, won't match `"cat"`. → write. **COVERED**, but **MINOR** to add a corpus row.

### B17 — Wrapper binaries (`env`, `nice`, `nohup`, `time`, `chroot`, `unshare`, `setsid`, `taskset`)
- **Status (2026-06):** **VULNERABLE — MAJOR. Now fixed** by `envRule` (`env.go`), which classifies the wrapped command. At survey time none of these were in the read allowlist, so `env cat /etc/hosts` → head `env` (allowed as read because it was in the allowlist for "env" the introspection command). **Wait** — `env` is in the allowlist as nil-rule allow. **And `env` is also the wrapper-binary that runs a child command.** Example:
  - `env rm /tmp/x` — classifier sees `env` (allowed) → READ. /bin/sh runs `env rm /tmp/x` → rm executes. **RCE / unauthorized write.**
  - `env -i rm /tmp/x` — same, with cleared env.
  - `env LD_PRELOAD=/tmp/evil.so cat /etc/hosts` — env-var injection (B4) + the env-wrapper double-up.
- **Where:** the `env` read-allowlist entry, now `envRule`.
- This is the OpenClaw "wrapper unwrap" finding [3, 4]. At survey time SSHGate was vulnerable to `env <anything-write>`.

### B18 — Busybox / toybox multiplexers
- **Status:** **NIT** because `busybox` is not in the read allowlist. `busybox cat /etc/hosts` → head `busybox` → not allowed → write. **COVERED accidentally.** But if any future contributor adds `busybox` to the allowlist (e.g. for an Alpine box), it becomes the OpenClaw bypass [3, 4]. Document as a contributor-facing trap.

### B19 — `git log --format='%(reflog:short)'` and other format-string CEs
- **Status:** **MINOR.** `git log --format=...` cannot directly exec, but `--format=%(...)` does evaluate some directives. The risk is bounded; gitRule treats `log` as read.

### B20 — `curl --upload-file` / `curl -K configfile`
- **Status (2026-06):** Mixed; **now fixed** (`curlRule` in `rules_net.go` treats `-K`/`--config` as a write). At survey time `curlRule` caught `-T`/`--upload-file` — write. **COVERED.** `-K`/`--config FILE` reads curl directives from a file — that file can contain `-o /tmp/x` to write. `-K` was **not in curlRule** → curl ran the line as read but actually writes per the configfile. **MAJOR.** Need `-K` / `--config` → write or to require the configfile arg to be `-` only.

### B21 — Long-option abbreviation (GNU getopt)
- **Status (2026-06):** **VULNERABLE — MAJOR. Now fixed for the listed options** (prefix matching; unlisted options remain a residual). Per OpenClaw [3, 4]: GNU getopt accepts `--in` for `--in-place`. At survey time `sedRule` checked exact strings `-i`, `--in-place`, and `--in-place=` prefix. **`sed --in-pl 's/x/y/g' file`** — `--in-pl` is an unambiguous prefix of `--in-place`. GNU sed accepts it. classifier sees no match for `-i*` family. → READ. → file mutated. **BLOCKER-adjacent**, calling MAJOR because the win is "mutate one file via sed" not "arbitrary RCE." Combined with B4/B10a it's BLOCKER.

### B22 — Signature payload re-entry
- **Status:** **COVERED.** The follow-up security audit verified that the trailing-cmd in the wire format never reaches execution; `payload.Cmd` is the only source. **COVERED.**

### B23 — Stdin smuggling
- At survey time the gate forwarded `os.Stdin` to /bin/sh (`src/gate/executor.go`). (Commands now get `/dev/null` as stdin.) If the client sends a here-string via `ssh host 'cat' <<< 'data'`, the data arrives on cat's stdin. Cat prints it. No write. **COVERED** for cat-class commands.
- **However**: `ssh host 'tee /tmp/x' <<< 'data'` — `tee` is not in the allowlist → write. **COVERED.** `ssh host 'dd of=/tmp/x'` — `dd` not allowed → write. **COVERED.**

---

## Recommendations / findings to file

These are the findings as filed in 2026-06; the table at the top gives each one's current status. Severity scale: BLOCKER (exploitable at survey time by reading the classifier), MAJOR (requires modest chaining or operator misconfig), MINOR (defense-in-depth or theoretical), NIT (cosmetic / hardening).

### BLOCKER-1 — `sed` `e` flag and `s///e` substitution execute shell commands
- **Where:** `sedRule` (now `src/classify/rules_text.go`). **Fixed.**
- **Exploit:** `sed 's/.*/id/e' /etc/hosts` → classifier returns READ → gate runs sed → sed runs `id`.
- **Fix sketch:** Walk all non-flag tokens in the sed program; if any contains an unescaped `e` immediately after a `/`-delimited substitution or as a standalone command, return KindWrite. Simpler: route sed through write whenever the program contains any of: `s/.../e`, ` e ` (e command), `/e`, `;e ;`. Cleanest: only allow sed with `-n` and `-e '<regex>p'` patterns matching a strict allowlist; everything else → write. Or just: only allow sed when invoked with `-n` and no script text containing `e` in non-quoted context (hard to parse). The defensible v1.2 fix is to **add `sed` to write unless invoked with a script that the classifier can prove is e-flag-free**. Practical: scan all args; if any contains `/e` or starts with `e` (and is not a flag), → write. Document the conservative rejection rate.

### BLOCKER-2 — `find -fprintf` / `-fprint` / `-fls` / `-fprint0` write arbitrary files
- **Where:** `findRule` (now `src/classify/rules_text.go`). **Fixed.**
- **Exploit:** `find /etc -name hosts -fprintf ~/.ssh/authorized_keys "ssh-rsa AAAA..."` → classifier READ → find writes the file.
- **Fix sketch:** Extend findRule's write-flag set: add `-fprint`, `-fprint0`, `-fprintf`, `-fls`. While in there, also block `-delete` is already there, also consider `-printf '%H'` is harmless but `-printf` itself isn't a write vector.

### BLOCKER-3 — Environment-variable smuggling via `KEY=VAL cmd` and dangerous keys (LD_PRELOAD, GIT_EXTERNAL_DIFF, GIT_SSH_COMMAND, PAGER, etc.)
- **Where:** the env-prefix strip in `classifySegment`. **Fixed** with a deny-list (`dangerousEnvVars`, `src/classify/env.go`), not the stronger allowlist suggested below.
- **Exploit:**
  - `GIT_EXTERNAL_DIFF='sh -c "id"' git log -p HEAD` → classifier strips env, sees `git log -p HEAD` → READ → git forks the diff driver as `sh -c "id"`.
  - `GIT_SSH_COMMAND='sh -c "id"' git ls-remote origin` → classifier READ; git forks the SSH command.
  - `LD_PRELOAD=/tmp/evil.so cat /etc/hosts` (requires prior write of `/tmp/evil.so`, so chained but not theoretical).
- **Fix sketch:** Replace "strip and ignore" with "strip and inspect." Maintain a **deny-list of env keys** that, when present in the leading-assignment prefix, force KindWrite. Minimum viable list:
  - Linker / loader: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG`, `LD_BIND_NOW`.
  - Shell internals: `PATH`, `IFS`, `BASH_ENV`, `ENV`, `SHELLOPTS`, `PROMPT_COMMAND`, `PS4`.
  - Pagers: `PAGER`, `MANPAGER`, `LESS`, `LESSOPEN`, `LESSCLOSE`, `MORE`, `SYSTEMD_PAGER`, `SYSTEMD_PAGERSECURE`.
  - Editors: `EDITOR`, `VISUAL`.
  - Per-tool RCE-via-env: any var matching `GIT_*` (and explicitly `GIT_EXTERNAL_DIFF`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_PAGER`, `GIT_EDITOR`, `GIT_INDEX_FILE`).
- **Stronger alternative:** allow only a hardcoded *allowlist* of safe env keys (`LC_*`, `LANG`, `LANGUAGE`, `TZ`, `TERM`) and reject everything else. This is more robust against future tool additions.

### BLOCKER-4 (borderline-MAJOR) — `awk 'BEGIN{system(...)}'` is direct RCE under a read classification
- **Where:** the `awk` allowlist entry (was `"awk": nil`). **Fixed** by `awkRule`.
- **Exploit:** `awk 'BEGIN{system("rm /tmp/x")}'` → READ → awk forks the shell call.
- **Fix sketch:** Add `awkRule` analogous to `sedRule`: scan all non-flag tokens; if any contains `system(`, `getline`, `"|"`, `printf`-into-file via `>` or `>>` inside an awk string, etc., return write. This is even harder to do robustly than sed; an alternative is to **drop `awk` from the read allowlist** entirely. Pipe-receiving awk is the common safe case (`ps aux | awk '{print $1}'`); standalone-pattern `awk 'BEGIN{...}'` is rare in operator workflows.

I'm classifying this BLOCKER because the exploit string is one-line, no chaining, no env tricks.

### MAJOR-1 — `env` wrapper executes arbitrary commands while classified as read
- **Where:** the `env` allowlist entry (was `"env": nil`). **Fixed** by `envRule`.
- **Exploit:** `env rm /tmp/x` → READ → /bin/sh runs `env rm` → rm executes.
- **Fix sketch:** Treat `env` specially. Either remove from allowlist, or add a rule: `env` is read only when invoked with no positional args (`env` alone prints the environment) or with `-`/`--unset`/`-u`/`-i` and **no trailing command**. The moment a non-flag, non-`KEY=VAL` token appears, treat as a wrapper and classify the trailing command. Even simpler: drop `env` from allowlist; the read use case (print env) is duplicated by `printenv` which is already allowlisted.

### MAJOR-2 — `journalctl --rotate` / `--vacuum-*` are writes classified as read
- **Where:** the `journalctl` allowlist entry (was `"journalctl": nil`). **Fixed** by `journalctlRule`.
- **Exploit:** `journalctl --rotate` rotates the journal; `journalctl --vacuum-time=1s` deletes journal data.
- **Fix sketch:** Add `journalctlRule` rejecting `--rotate`, `--vacuum-size`, `--vacuum-time`, `--vacuum-files`, `--flush`, `--relinquish-var`, `--smart-relinquish-var`, `--sync`, `--update-catalog`.

### MAJOR-3 — `git -c <key>=<val>` config injection bypasses gitRule
- **Where:** `gitRule` and `firstNonFlag`. **Fixed:** `-c` / `--config-env` now make the command a write.
- **Exploit:** `git -c core.pager='sh -c "id"' log` → firstNonFlag skips `-c <kv>` and returns `log` → READ. Git honors `core.pager` and runs `sh -c "id"`.
- **Fix sketch:** When `git -c` appears in args, scan the `-c key=val` pair; if `key` matches any RCE-relevant config (`core.pager`, `core.editor`, `core.sshCommand`, `diff.external`, `pager.*`, `alias.*`), force write. Easier: any `git -c` invocation → write (lose a small power-user surface, gain a definite property).

### MAJOR-4 — GNU long-option abbreviation: `sed --in-pl` bypasses sedRule
- **Where:** `sedRule`. **Fixed** for listed options.
- **Exploit:** `sed --in-pl 's/foo/bar/g' /etc/hosts` — `--in-pl` is unambiguous prefix of `--in-place`; GNU sed accepts; classifier compares exact strings and finds no match → READ → file mutated.
- **Fix sketch:** Implement GNU prefix-match for known dangerous long options. Build a per-binary list of "dangerous long options" and reject any token that is a non-ambiguous prefix of one (`startsWith(canonical, token[2:])`). Or canonicalize tokens first via a binary-specific table.

### MAJOR-5 — `curl -K`/`--config FILE` runs directives that can write
- **Where:** `curlRule` (now `src/classify/rules_net.go`). **Fixed.**
- **Exploit:** Stage a file with `output = /tmp/x`; `curl -K /tmp/config https://example.com` → classifier read; curl writes per config. Requires prior file write but those happen via the same gate.
- **Fix sketch:** Add `-K`, `--config` to curlRule; require operand to be `-` (stdin) only, else write.

### MINOR-1 — `no-pty` in the authorized_keys writer — RESOLVED
- **File:** `commandForcingFmt` in `src/mcp/tools/authorizedkeys.go`.
- **Exploit (historical):** Without `no-pty`, every classified-read pager (`less`, `more`, `journalctl`, `git log`, `systemctl status`) gained its interactive escape (`!sh`, `v`-to-editor). With `no-pty`, those are short-circuited.
- **Resolution:** `no-pty` is now part of the canonical forced-command line and is golden-pinned by a test (`TestRewriteAuthorizedKeys_ForcedOptionsGoldenPin`) so it cannot be silently dropped.

### MINOR-2 — Read-side `find /tmp/* -fprint*` write categories not in corpus — DONE
- **File:** `tests/testdata/classifier-corpus.txt` (these rows now exist).
- **Fix sketch:** Add corpus rows for `-fprint`, `-fprintf`, `-fls`, sed `e` flag, awk `BEGIN{system(...)}`, `env rm`, `git -c core.pager=...`, `curl -K`, `sed --in-pl`.

### MINOR-3 — `|&` segmentation edge case
- **Where:** `splitSegments` (`src/classify/classifier.go`).
- Stray `&` becomes leading char of next segment. Defensive: handle `|&` explicitly.

### MINOR-4 — Heredoc / herestring corpus coverage
- Add `cat <<<EOF` / `cat <<<"$VAR"` / `cat <<EOF` rows to lock current behavior.

### MINOR-5 — `AcceptEnv` install-side guidance — DONE
- Now documented in `docs/install-step-by-step.md` (Tier 1 step 4). Original finding: document in the install guide that the sshd_config for the gate-using host should set `AcceptEnv` to empty (or omit entirely). Otherwise client-passed env vars bypass even a fixed env deny-list.

### MINOR-6 — Glob expanding into flag-like filenames
- **Where:** the classifier in general.
- Add corpus row `sed -e s/a/b/ *` with note: if cwd contains a file `-i`, sed picks it up as a flag. Bounded by prior-write requirement.

### NIT-1 — `$'...'` ANSI-C quoting not modeled by tokenize.
### NIT-2 — Heredoc body not parsed; substitution inside heredoc body unchecked. (Bash semantics make most cases inert; document.)
### NIT-3 — `busybox` / `toybox` not in allowlist now; add a contributor-facing comment "never add these without unwrap logic."
### NIT-4 — `man` not allowlisted; `info` not allowlisted; ensure docs note these are deliberately omitted.

---

## Open research questions

1. **Does the gate's `/bin/sh` ever symlink to bash?** On Debian/Ubuntu it's dash; on RHEL it's bash. Bash in `sh` mode honors `ENV=$file` which adds another RCE-via-env vector (covered by BLOCKER-3's fix: `ENV` and `BASH_ENV` are on the deny-list). Still an open question; on a jailed host such a file would still run inside the jail.
2. **Does sshd `AcceptEnv` default block all client env?** OpenSSH's built-in default accepts nothing, but many distributions ship `AcceptEnv LANG LC_*`. SSHGate does not change `sshd_config`; the install guide now tells operators to keep it narrow.
3. **`no-pty` audit** — RESOLVED: the canonical `command="..."` line (`commandForcingFmt` in `src/mcp/tools/authorizedkeys.go`) now includes `no-pty`, golden-pinned by a test so a provisioning flow can never emit a line without it. MINOR-1 closed.
4. **`sigwire` payload size limits / canonical JSON re-marshaling determinism.** Out-of-scope here but: `json.Marshal(payload)` (in `VerifySigned`, `src/gate/verify.go`) round-trips through Go's encoder. If a future Go version changes encoder behavior (e.g. omitempty handling, map ordering, escape policy), signatures stop verifying. This is unrelated to this research's classifier-bypass scope but worth raising.
5. **Are there other Linux tools in the allowlist with an "exec on read" hidden feature that I haven't caught?** Candidates to audit: `wc -L --files0-from=...`, `du --files0-from=...`, `find ... -newer`, `dig +sigchase` (DNS exec hooks), `lsof` (none known). The exhaustive sweep needs a per-binary read of GTFOBins + manpage.
6. **Carriage return + line-continuation inside SSH_ORIGINAL_COMMAND**: did not exhaustively test what happens when the classified line ends with `\` and continues on the next "line" (sshd typically joins to one line, but `tr` and quoting can re-introduce). OpenClaw's line-continuation CVE [3, 4] suggests this surface is non-empty; corpus needs coverage.

---

## Sources

[1] [ghantoos/lshell on GitHub](https://github.com/ghantoos/lshell)
[2] [rssh CVE-2012-2252 — Gentoo security advisory](https://security.gentoo.org/glsa/201311-19)
[3] [Don't Let the Claw Grip Your Hand: A Security Analysis and Defense Framework for OpenClaw (arxiv 2603.10387)](https://arxiv.org/pdf/2603.10387)
[4] [A Systematic Taxonomy of Security Vulnerabilities in the OpenClaw AI Agent Framework (arxiv 2603.27517)](https://arxiv.org/html/2603.27517v3)
[5] [Git Shell Bypass by abusing less (CVE-2017-8386) — Insinuator.net](https://insinuator.net/2017/05/git-shell-bypass-by-abusing-less-cve-2017-8386/)
[6] [Git Shell Bypass, Less Is More — Hackaday](https://hackaday.com/2017/05/10/git-shell-bypass-less-is-more/)
[7] [OpenClaw Exec Approvals documentation](https://docs.openclaw.ai/tools/exec-approvals)
[8] [Linux Restricted Shell Bypass guide (Exploit-DB 44592)](https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf)
[9] [lshell SECURITY.md](https://github.com/ghantoos/lshell/blob/master/SECURITY.md)
[10] [Critical Authentication Bypass Vulnerability in Teleport (CVE-2025-49825)](https://www.securityweek.com/critical-authentication-bypass-flaw-patched-in-teleport/)
[11] [GTFOBins awk entry](https://gtfobins.org/gtfobins/awk/)
[12] [Command Execution Vulnerability in rssh (CVE-2019-1000018)](https://esnet-security.github.io/vulnerabilities/20190115_rssh.html)
[13] [GTFOBins less entry](https://gtfobins.org/gtfobins/less/)
[14] [journalctl pager / SYSTEMD_PAGERSECURE — systemd issue #23019](https://github.com/systemd/systemd/issues/23019)
[15] [GNU sed manual — `e` command and `s///e` flag](https://www.gnu.org/software/sed/manual/sed.html)
[16] [HashiCorp Boundary session recording](https://developer.hashicorp.com/boundary/docs/operations/session-recordings)
[17] [Tailscale SSH check mode](https://tailscale.com/docs/features/tailscale-ssh)
[18] [OpenSSH ForceCommand bypass via Shellshock — Baeldung](https://www.baeldung.com/linux/ssh-shellshock-exploit)
[19] [bash specially-crafted env vars code injection — Red Hat blog](https://www.redhat.com/en/blog/bash-specially-crafted-environment-variables-code-injection-attack)
[20] [Allowlisting some Bash commands is often the same as allowlisting all — HN](https://news.ycombinator.com/item?id=46800451)
