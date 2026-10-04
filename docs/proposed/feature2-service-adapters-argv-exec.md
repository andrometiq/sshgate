# SSHGate — Per-Service Adapters & argv-exec (a shell-free read path + read-only SQL)

> **Status: OPEN PROPOSAL, not scheduled, and partly overtaken.** It is "Feature 2" in
> [ROADMAP.md](../ROADMAP.md); [BUILD-PLAN.md](../BUILD-PLAN.md) does not schedule the adapters,
> `lex.Parse`, the in-Go pipeline runner or the SQL adapters, and none of them exist in the code.
> The `SSHGATE_ADAPTER_CLASSIFY` and `SSHGATE_ARGV_EXEC` flags below are proposed names only.
>
> What changed since this was written:
> - **The kernel sandbox shipped first, as the primary read wall, not as a phase-6 follow-on.**
>   v0.1.5 runs every read in the `ro-v1` jail (`src/gate/confine/`) on hosts that support it:
>   user, mount and IPC namespaces, a read-only view of the host, Landlock, and a seccomp table
>   whose default is `ENOSYS`. It does not deny `execve`, so the `git`/pager concern below does not
>   apply, and it needs both user namespaces and Landlock; hosts without them run reads
>   classifier-only. "#22" in [BUILD-PLAN.md](../BUILD-PLAN.md) now names that jail work
>   (work item 1), not this design. The [sandbox section](#sandbox--defense-in-depth-recommendation),
>   open question 2 and task T9 are kept for the reasoning only.
> - **Shell-free exec exists for one narrow case.** A fixed allowlist of `systemctl`/`docker` read
>   verbs ("Lane 2", `src/gate/cmd/sshgate-gate/lane2.go`) runs as argv with no shell, no jail
>   and an environment built from nothing (`ExecArgvWithRedaction` in `src/gate/executor.go`).
>   BUILD-PLAN step P3.1 builds a canonical-argv grammar for those verbs; any adapter work here
>   should reuse it rather than design a second one.
> - Every other read still runs through `/bin/sh -c` (inside the jail when there is one), so the
>   two-parser mismatch this design attacks still exists; the jail now bounds what a mismatch can
>   do on jailed hosts.

## Summary

SSHGate's read-only classifier is a heuristic re-implementation of `/bin/sh`'s grammar placed *in front of* a real `/bin/sh -c` (`ExecWithRedaction` in `src/gate/executor.go`). Every documented bypass — the backslash-escape RCE, newline-split, `$()`-in-double-quotes, top-level redirect — is the same root cause: **two parsers see the same string and disagree**, and the shell wins. You cannot win an arms-race against `/bin/sh` with a string heuristic feeding `/bin/sh`.

This design retires that arms-race **structurally** by deleting `/bin/sh` from the *unsigned read path*: the gate lexes the command once into clean argv, classifies that argv, and `execve`s **byte-for-byte that same argv** with no shell. Classification view ≡ execution view by construction — the mismatch class cannot be expressed. On top of this, the per-binary rules are repackaged as a **per-service Adapter registry** with a *fail-closed unknown-flag posture* for enumerated-surface binaries, which is the one idea that actually retires the recurring per-tool flag-leak race (`sort -o`, `curl -D`, the next `--compress-program`). Feature 2 (read-only SQL) is then **three more adapters** (`psql`, `mysql`/`mariadb`, `sqlite3`) that rewrite the invocation into a server-enforced read-only form, parse the SQL as a cheap outer gate, and route write-SQL through the existing Telegram signer.

Three approaches were compared: **A**, argv-exec with fail-closed adapters; **B**, a kernel sandbox (seccomp, Landlock, user namespaces) as the primary boundary; **C**, keep the shell and make every read pipeline a signed command. This design chose **Approach A** as the primary, phase-1 fix — the best risk-for-cost path in the threat analysis — and staged the kernel sandbox (Approach B) as an explicit **defense-in-depth follow-on (phase 6)**, *not* as the primary boundary, because its core `execve`-deny conflicts with the legitimate read corpus (`git`/`journalctl` fork helpers) and its FS protection vanishes on the hardened hosts where it would matter most. The signed path keeps `/bin/sh -c` (a human approved the literal bytes); only the unsigned read path — the entire historical attack surface — loses the shell.

A threat analysis of the three approaches produced a list of required mitigations, referenced below by number:

1. A single classifier source of truth shared by the MCP client and the gate, pinned by a CI
   differential test.
2. Tighten per-binary posture to fail-closed, one binary at a time, each with red-team rows.
3. Trusted absolute-path resolution and an explicitly scrubbed child environment.
4. SQL clients resolved by trusted path/inode, with the whole argv built by the adapter.
5. A wall-clock timeout, a correct process group for every pipeline stage, and teardown on a
   partial start.
6. Redaction parity on the new exec path, proven by a test.
7. If argv is ever signed, the envelope type is part of the signed payload and cross-type
   execution is refused.
8. Sandbox profiles chosen from a parent-controlled fd, never from child-influenced argv, and a
   loud failure when the filesystem backstop is missing.
9. Lexer-seam hardening: assignment detection on the pre-unescape lexeme; empty tokens preserved.

The most load-bearing is **#1** — without it, the "view ≡ exec" claim is true only inside the gate and a MCP↔gate drift in the write→read direction is a silent unsigned write.

---

## Goals & Non-goals

### Goals
- **G1.** Structurally eliminate the shell-parse-mismatch bypass family (separator/quote/redirect/substitution/backslash-escape/env-prefix/wrapper-unwrap) on the unsigned read path — make it inexpressible, not merely patched.
- **G2.** Retire the recurring **per-tool write-flag-leak** family via a fail-closed unknown-flag posture for enumerated-surface binaries (the next unknown write flag fails closed instead of being a CVE).
- **G3.** Ship Feature 2: read-only SQL over `psql`/`mysql`/`sqlite3` executed without a Telegram tap, with writes routed to the existing signer.
- **G4.** Preserve every existing constraint: the redactor choke point, process-group cancellation, exit-code mapping (128+signum / 65/70/77), and the full `classify` + red-team test surface staying green throughout.
- **G5.** Keep the single-static-binary install model (no `bwrap`, no per-host runtime dependency).
- **G6.** Add an explicit **scrubbed child env** and a **wall-clock timeout** to the read path. (Today only the Lane-2 daemon reads get an environment built from nothing; jailed reads inherit the gate's environment with the temp and history variables pointed at `/dev/shm`; no read has a wall-clock deadline.)

### Non-goals
- **N1.** Sandboxing reads against *content* exposure. A correctly-classified read that prints `id_rsa` is the redactor's job, unchanged; the adapter/sandbox does not make reads safe content-wise.
- **N2.** Touching the signed path's grammar. A verified `SSHGATE_SIG` keeps full `/bin/sh -c` power (globbing, redirects, write-pipelines) — a human vouched for the exact bytes.
- **N3.** Re-implementing SQL wire protocols. We wrap the CLI clients, not libpq/the MySQL protocol.
- **N4.** Auto-provisioning DB read-only roles/users. Server-side read-only roles and settings (`secure_file_priv`, role grants) are a **documented operator prerequisite verified at `sshgate add` time**, not an adapter guarantee.
- **N5.** Shipping the kernel sandbox in phase 1. It is a layered follow-on after the adapters soak green.
- **N6.** Restoring globbing / `$()` / `&&` on the *unsigned* read path. These become a clear "sign this command" refusal.

---

## The argv-exec + adapter architecture

```
SSH_ORIGINAL_COMMAND (raw string)
        │
        ▼
 ┌──────────────────┐   ONE lexer, no shell — the promoted classify front-end
 │  lex.Parse        │ → Pipeline{ []Stage{ Assignments[], Argv[] } }
 └──────────────────┘   rejects up front: $() ` <() >()  > >> <  ;  && || &  newline
        │                (rejection is a routing signal, not a hard failure — see Read-pipeline §)
        ▼  for each stage
 ┌──────────────────┐   keyed by basename(argv[0]) resolved to a trusted absolute path
 │  ADAPTER REGISTRY │   shell │ sql(psql,mysql,sqlite3) │ env(recursive)
 │  Inspect(Stage)   │ → Decision{ Verdict: READ|WRITE|DENY, Plan{Path,Argv,Env}, Reason }
 └──────────────────┘
        │
   ┌────┴───────────────┬────────────────────────┐
   ▼                    ▼                         ▼
 READ (all stages)    WRITE (any stage)         DENY (any stage)
   │                    │                         │
   ▼                    ▼                         ▼
 argv pipeline        route to signer           exit 77 / 65
 (os.Pipe in Go,      (Telegram approve →        (structured, fix-suggesting
  no /bin/sh,          SSHGATE_SIG; signed        stderr)
  scrubbed env,        path keeps /bin/sh)
  redact on stdio,
  timeout, sandbox*)
                                        *sandbox = phase-6 defense-in-depth
```

**The hinge.** Today the gate classifies one string and then `/bin/sh -c`'s the *raw* string — classify-one-thing-exec-another *is* every bypass. Here the adapter that decides "READ" is the same code that produces the exact `Plan.Argv` the kernel runs. There is no second string and no second interpreter on the unsigned read path.

**What is reused vs. new.**
- *Promoted, not rewritten:* the battle-tested shell-deconstruction front-end (`containsSubstitution`, `hasTopLevelRedirect`, `splitSegments`, `tokenize`, `isAssignment` from `classifier.go`) becomes `lex.Parse` — the safe argv-extractor, the most-tested code in the repo, kept verbatim in behavior.
- *Repackaged, not re-authored:* the `readAllowlist`/`argRule` rules (`rules_text.go`, `rules_net.go`, `rules_system.go`, `env.go`) move *inside* `ShellAdapter` unchanged in logic, gaining only the fail-closed posture flip in a later phase.
- *New:* `lex.Parse`'s structured `[]Stage` output, the `Adapter` interface + registry, the in-Go pipeline runner replacing the single shell exec, the three SQL adapters, the scrubbed-env + trusted-path + timeout hardening, and (phase 6) the sandbox package.

**Single source of truth (mitigation #1).** The classifier is consumed by the gate (`classify.Classify` in `src/gate/cmd/sshgate-gate/main.go`) and by the MCP (`classify.Explain`, which returns the same `Kind` plus a reason, in `src/mcp/tools/run.go` and `run_batch.go`). The adapter registry's `Inspect` would be the **one** code path behind all of them; the public `Classify` shim folds `Decision → Kind` for the MCP call sites and the test corpus. A CI **differential test** runs the entire corpus through both the MCP-side and gate-side entry and asserts byte-identical verdicts, failing the build on any drift. This closes the #1 risk: a MCP-stricter-than-gate drift is a silent unsigned-write bypass; sharing the literal code path makes it inexpressible.

---

## Adapter interface / contract

```go
package adapter

// Stage is one pipeline element: a binary + argv + leading KEY=VAL assignments,
// already lexed (quotes/backslashes resolved, no shell metachars left inside).
// argv[0] is the program; argv[1:] are the literal arguments execve will see.
type Stage struct {
    Assignments []Assignment // leading FOO=bar, structured (never re-shelled)
    Argv        []string     // exactly what execve receives
}
type Assignment struct{ Key, Value string }

type Verdict int
const (
    VerdictDeny  Verdict = iota // structurally refuse: never exec, never sign
    VerdictRead                 // safe to exec unsigned, now
    VerdictWrite                // mutating: route to signer/approval
)

type Context struct {
    Tier                     Tier   // Tier1ReadOnly | Tier2Signed
    Signed                   bool   // did the whole command arrive with a valid SIG?
    ServerAlias              string
    PipelinePos, PipelineLen int
}

// Plan tells the executor HOW to run an approved stage. The ADAPTER owns argv
// construction — this is what lets the SQL adapter REWRITE psql -c "select 1"
// into a hardened read-only invocation.
type Plan struct {
    Path    string   // absolute, trusted-table-resolved execve target (never /bin/sh, never $PATH)
    Argv    []string // final argv (argv[0] convention preserved)
    Env     []string // explicit scrubbed env for THIS stage (adapter may add PGOPTIONS, LESSSECURE)
    NoStdin bool      // e.g. SQL fed via -c wants no stdin
}

type Decision struct {
    Verdict Verdict
    Plan    Plan   // populated for READ and (post-approval) WRITE
    Reason  string // human-facing; shown in deny stderr + Telegram card
}

type Adapter interface {
    // Names returns the basenames this adapter claims, e.g. ["psql"] or ["grep","egrep","fgrep"].
    Names() []string

    // Inspect classifies one already-lexed stage and, for READ/WRITE, produces the
    // exact exec Plan. MUST be PURE (no I/O, no exec) so it backs the gate AND the
    // MCP pre-flight from one code path, and stays unit-testable like today's argRule.
    Inspect(s Stage, ctx Context) Decision
}
```

### Load-bearing invariants
1. **Default-deny on unknown binary.** `basename(argv[0])` absent from the registry ⇒ `VerdictDeny` in read mode.
2. **Default-read within a known adapter, upgrade on a mutating signal** — preserves today's `argRule` posture so the corpus stays green.
3. **`Inspect` is pure.** No exec, fs, or network — this is what lets it be the single source of truth across the three call sites.
4. **The adapter owns the Plan.** The caller never builds argv from the raw string. This is the hinge enabling SQL rewrite.
5. **Fail-closed on the unknown-within-known.** For enumerated-surface binaries, any flag/subcommand the adapter does not explicitly know ⇒ `VerdictDeny` in read mode (NOT silent-read). This is the structural cure for the per-tool flag-leak class: the next coreutils write flag fails closed. (Inverts today's allow-by-default-scan-for-bad denylist to an allowlist where the safe surface is enumerable; binaries with no write surface — `whoami`, `id`, `uname`, `cat`, `head`, `ls`, `ps`, `grep` — keep allow-by-default.)
6. **Read-Plan argv may only add *vetted* hardening to Stage.Argv, never silently drop an un-understood flag.** Additive (e.g. SQL read-only wrappers) is allowed; an unrecognized flag in read mode ⇒ DENY (invariant 5).
7. **Trusted-path resolution + explicit scrubbed env (mitigation #3).** `Plan.Path` is resolved from a gate-owned absolute-path table, never inherited `$PATH`; `Plan.Env` is built from a scrubbed base (drop `LD_*`, `IFS`, `GIT_*`, `PAGER`, `*_OPTIONS`; keep a vetted minimal `PATH`/`LANG`/`TERM` + adapter additions). Closes basename-spoofing and the current `c.Env`-never-set inheritance leak.

---

## Shell adapter (reusing the hardened rules on clean argv)

`ShellAdapter` *is* today's `readAllowlist` + `argRule` set, repackaged behind `Adapter` and fed clean argv instead of a substring of the raw string.

```go
func (a *ShellAdapter) Inspect(s Stage, ctx Context) Decision {
    // 1. Dangerous leading assignments => DENY (today: WRITE-then-sign; these are
    //    pure exec-hijack vectors with no legitimate read use, so DENY is tighter+correct).
    for _, kv := range s.Assignments {
        if dangerousEnvVars[kv.Key] { return deny("env var %q is an exec vector", kv.Key) }
    }
    head := basename(s.Argv[0])
    rule, ok := a.rules[head]
    if !ok { return deny("binary %q not in read allowlist", head) }

    // 2. Resolve to an absolute path from the trusted table (NOT $PATH).
    abs, err := resolveTrusted(head)
    if err != nil { return deny("cannot resolve %q to a trusted path", head) }

    // 3. Apply the per-binary rule over the CLEAN argv (no shell tokens to re-split).
    switch ruleVerdict(rule, s.Argv[1:]) { // rule==nil => Read; enumerated-surface => fail-closed
    case KindWrite: return Decision{VerdictWrite, planFor(abs, s, ctx), "mutating flag/arg"}
    case KindRead:  return Decision{VerdictRead,  planFor(abs, s, ctx), ""}
    }
}
```

What changes structurally:
- **Rules run over real argv.** `sortRule` sees the exact `[]string` `execve(sort,…)` will receive. The whole "tokenizer ≠ sh" leak class (bundled `-no`, backslash-hidden `>`, `\'`-escape RCE, substitution-in-double-quotes) cannot reach this path — `lex.Parse` already rejected substitution/redirects and `tokenize` produced *the* argv the kernel runs.
- **Fail-closed posture (invariant 5)** for `sort, curl, wget, sed, awk, find, ip, ss, git, systemctl, journalctl, dmesg, docker, less` — closes GNU-abbreviation and unknown-flag leaks. The red-team corpus is the gate that proves each binary's posture.
- **`env` is a first-class recursive adapter:** its `Inspect` re-lexes the trailing argv into a sub-stage and re-dispatches through the registry — `env rm x` ⇒ `rm` not in read allowlist ⇒ DENY, with no shell to "unwrap."
- **awk in read mode:** the awk adapter denies opaque `-f FILE` and scans the (single-token) program text for `>`/`>>`/`print … >`/`system(`/`| "cmd"`; because the program is one argv token, the scan is exact, not heuristic.
- **Pager/PTY escape (`less !sh`):** `less`/`more` launched with `LESSSECURE=1` (and `-n`) in `Plan.Env` — the adapter owns the env, so this is enforced, not advisory.
- **Lexer-seam hardening (mitigation #9):** assignment detection runs on the **pre-unescape lexeme** with sh's escaping rules (so `FOO\=bar` is a command word, not an assignment), and empty `''` tokens are **preserved** so positional-arity rules (`uniqRule`, `findRule`) count the same positionals sh would. New corpus rows: `find -name ''`, `FOO\=bar cmd`, `uniq '' out`.

---

## SQL adapter (read-only model)

The SQL adapter (`psql`, `mysql`/`mariadb`, `sqlite3`) is the proof the abstraction earns its cost: it **rewrites** the invocation into a server-enforced read-only form and **parses** the SQL payload. It composes naturally because, like every read, it never touches `/bin/sh` — it constructs the final argv and the executor `execve`s it verbatim.

```go
func (a *SQLAdapter) Inspect(s Stage, ctx Context) Decision {
    eng := engineOf(basename(s.Argv[0]))      // pg | mysql | sqlite
    // Trusted-inode resolution (mitigation #4): a `psql` that doesn't resolve to a
    // known-good absolute path/inode => DENY (defeats basename-spoofing wrappers).
    abs, err := resolveTrustedSQL(eng)
    if err != nil { return deny("untrusted %s client", eng) }

    inv, err := parseInvocation(eng, s.Argv)  // pull out -c/-e SQL, target alias, flags
    if err != nil { return deny("unparseable %s invocation: %v", eng, err) }

    // (A) No interactive sessions in read mode — SQL must arrive via -c/--execute/here-string.
    if inv.Interactive { return deny("interactive %s not allowed read-only; pass -c \"...\"", eng) }
    // (B) Refuse ALL client meta/dot-commands (psql \!,\copy,\o,\g|,\gset; mysql system,\!,source,\T;
    //     sqlite .shell/.system/.import/.output/.read/.load/.backup/.open/...).
    if hasClientEscape(eng, inv) { return deny("client meta/dot-command blocked") }
    // (C) Parse the SQL. Single statement only. Reject ; multi, data-modifying CTEs,
    //     COPY ... TO/FROM PROGRAM/file, pg_read_file/lo_export, INTO OUTFILE/DUMPFILE,
    //     LOAD_FILE, ATTACH, load_extension, CREATE/CALL/DO, SET-writes.
    stmt, err := parseSingleSQL(eng, inv.SQL)
    switch {
    case err != nil:        return deny("SQL parse: %v", err)
    case stmt.IsReadOnly(): return Decision{VerdictRead,  a.hardenedReadPlan(eng, abs, inv, ctx), ""}
    default:                return Decision{VerdictWrite, a.signedWritePlan(eng, abs, inv, ctx), stmt.Why()}
    }
}
```

### Forced server-side read-only — the trust anchor (parsing is the cheap outer gate)
A Postgres read-only *transaction does NOT block* `COPY TO PROGRAM`/`pg_read_file`/`lo_export` — the load-bearing finding. So the **role** is primary; our parse is the fail-closed outer gate with clean UX. `hardenedReadPlan` **constructs the entire argv from scratch (mitigation #4)** — copying only the vetted single SQL statement and the registered target alias, refusing *all* operator-supplied connection/`-c`/`-o`/`-v`/`--set`/`-f`/`-P` flags (never merging):

- **Postgres:** connect as a **dedicated read-only ROLE** — `NOINHERIT`, no membership in any writable role (cannot `SET ROLE`/`SET SESSION AUTHORIZATION` to escalate), no `pg_read_server_files`/`pg_execute_server_program`/`pg_write_server_files`/`lo_*` grants. Argv: `psql --no-psqlrc -X -v ON_ERROR_STOP=1 -c "BEGIN READ ONLY; <stmt>; COMMIT"`, with `PGOPTIONS=-c default_transaction_read_only=on` in `Plan.Env`. `--no-psqlrc` kills startup-file meta-command injection.
- **SQLite:** Argv: `sqlite3 -readonly -safe -batch -cmd "PRAGMA query_only=ON" <DBPATH> "<stmt>"`. **`-readonly`/`-safe` are the load-bearing controls** (they block `.shell/.import/.load/ATTACH` and friends; `load_extension` stays disabled). The `file:DB?mode=ro&immutable=1` URI is treated as **belt-only** because URI filenames aren't enabled in all sqlite3 builds (mitigation #4); on a URI-disabled build it degrades silently to a literal filename, so we do not rely on it.
- **MySQL/MariaDB:** dedicated `SELECT`-only user (no `FILE` priv). Argv: `mysql --batch --raw --disable-named-commands -e "START TRANSACTION READ ONLY; <stmt>"`. **`secure_file_priv=NULL` + the no-`FILE`-priv user are server-side prerequisites** (the client argv cannot set them) verified at `sshgate add` time, documented as operator provisioning — NOT claimed as an adapter guarantee.

Because the adapter constructs `Plan.Argv` and the executor runs it verbatim via `execve` (no shell), the hardening flags cannot be stripped or reinterpreted en route.

### Write-SQL via the signing path
A statement classified WRITE is **not** blanket-denied — `signedWritePlan` packages the **adapter-normalized statement** for SSHGate's existing signer (`Sign.Sign` → Telegram approve → `SSHGATE_SIG`), which is classifier-agnostic: it signs whatever command string it is asked to approve. The human approves *exactly the normalized form* that will run, and the gate's `VerifySigned` re-runs that form.

**Two-increment shippability + the envelope decision (mitigation #7).** Signing a normalized *argv* (not the raw string) introduces a second signed-execution path alongside the existing signed-*string* path — a confusion/replay surface. If the normalized-argv envelope is chosen, the **envelope type (string vs normalized-argv) MUST be part of the signed payload, and the gate MUST refuse cross-type execution** (a string-signed payload cannot run as argv, and vice-versa). The signer has no argv-envelope kind today, so until that envelope work lands, **fallback:** write-SQL is `DENY`-with-hint ("write SQL must be signed; envelope signing not yet enabled"); **read-SQL ships fully in increment 1.** This is an Open questions item (string-envelope vs new argv-envelope).

---

## Read-pipeline handling

Read pipelines (`ps aux | grep sshd`, `journalctl -u x | tail`, `dmesg | grep -i error`) are the single most common diagnostic idiom; forcing a Telegram tap for every `| grep` would gut the read experience and push operators toward "sign everything," defeating the gate. **Decision (recommended): a safe in-process pipeline executor — keep read pipelines unsigned, but run them with NO shell.** (This is an Open questions item; the fallback is sign-only pipelines as in Approach C, deferring the mini-executor.) Note that today's classifier already treats a pipe, `&&`, `;` or `||` between recognised reads as a read; the shell still runs it.

```go
func runPipeline(ctx context.Context, plans []adapter.Plan, io StdIO) (int, error) {
    // ctx carries context.WithTimeout (mitigation #5) — the executor has NO timeout today.
    cmds := make([]*exec.Cmd, len(plans))
    for i, p := range plans {
        c := exec.CommandContext(ctx, p.Path) // Path explicit...
        c.Args, c.Env = p.Argv, p.Env         // ...argv[0] preserved, NO "sh -c", scrubbed env
        cmds[i] = c
    }
    // Wire stage[i].Stdout -> stage[i+1].Stdin via os.Pipe(); first stdin = io.In (unless NoStdin);
    // last stdout + EVERY stage stderr -> redact.NewWriter (Redaction handling §).
    ...
}
```

Rules and correctness requirements:
- **READ iff *all* stages are READ.** Any WRITE stage routes the whole pipeline to signing; any DENY stage ⇒ DENY (mirrors today's "any write segment wins," now over real argv).
- **There is no `|` for a tool to reinterpret** — the pipe is an OS-level fd connection made in Go. `grep "a | rm b"` is one literal argv token to `grep`. This structurally kills the separator/quote-mismatch class for pipelines.
- **Bounded:** `lex.Parse` caps pipeline length (≤ 8 stages) and total argv bytes; over-limit ⇒ DENY with a "sign this" hint.
- **Correct process group (mitigation #5):** only the leader sets `Setpgid: true`; stages 2..N set `Pgid = leader.Process.Pid` **after the leader's `Start()`** (the pgid is unknown until then). `c.Cancel` SIGKILLs `-pgid` for the whole pipeline. The naive `Setpgid: i==0` snippet would leave later stages in the gate's group — a cancellation/cleanup bug and a sandbox-escape-adjacent issue; this design fixes and tests it with a hung middle stage.
- **Explicit teardown on partial start (mitigation #5):** if stage k fails to `Start()`, close all already-created pipe fds and SIGKILL all already-started stages; `ExtraFiles=nil` and parent-side pipe ends closed after each `Start`. Tested with an unresolvable middle stage.
- **Deadlock avoidance:** the redact writer on last-stdout must keep draining even when an upstream stage errors; the timeout bounds any residual hang.

### Routing of lexer rejections
`lex.Parse` returning an error is a **routing signal**, not a hard failure:

| Lexer outcome | Tier-1 (read-only host) | Tier-2, unsigned input | Signed input |
|---|---|---|---|
| Clean read pipeline, all stages READ | exec (argv pipeline) | exec | exec |
| Any stage WRITE | DENY (exit 77) | route to signer → Telegram | exec (sig verifies exact bytes) |
| Any stage DENY (unknown binary/flag) | DENY (exit 77) | DENY (exit 77) | exec only if sig covers it |
| `$()` / `>` / `;` / `&&` (opaque) | DENY | route to signer (treat as write) | exec via `/bin/sh -c` (operator vouched) |

**Opaque constructs are never executed unsigned.** On Tier-2 they become a signing request the operator approves as the exact literal string (then run via `/bin/sh -c` *on the signed path only* — that path keeps the shell because a human authorized the bytes). On Tier-1 they are flatly denied. This preserves today's "fail-safe to write" while deleting the unsigned shell exec.

---

## How this kills the documented bypass classes

| Bypass class (history) | Killed by | Structural reason |
|---|---|---|
| **Shell-parse mismatch** (newline split, bundled `sed -ni`, `$()`-in-dquotes, top-level redirect) | argv-exec (**by construction**) | The classifier's argv *is* the exec argv. `lex.Parse` rejects `$()`/redirect/multi-command up front (route to sign/deny); no `/bin/sh` second pass exists to diverge. No two parsers ⇒ no mismatch. |
| **Backslash-escape RCE** (`ls \' && rm`, `head f \" >x`) | argv-exec (**by construction**) | Whatever `tokenize` decides `\'`/`\"` means is also what runs; the `&&`/`>` were rejected by `lex.Parse` or are literal argv bytes. The divergence has no surface. |
| **Per-tool write-flag leaks** (`sort -o`, `curl -D/-c`, `--compress-program`, `ss -K`, `journalctl --vacuum`) | adapter **fail-closed posture** (invariant 5) | argv-exec alone does NOT fix these. For enumerated-surface binaries, any unknown flag ⇒ DENY; the next coreutils write flag fails closed. Red-team corpus pins each known one. |
| **Output-positional writes** (`uniq IN OUT`, `sort -o auth_keys`) | adapter, over clean argv | Token boundaries are the kernel's, not a guess; the output positional reliably upgrades to WRITE/DENY. Empty-token preservation (§Shell adapter) keeps arity faithful. |
| **Env-var RCE/redirect** (`LD_PRELOAD=`, `GIT_SSH_COMMAND=`, `HOME=`) | structured assignments + explicit scrubbed child env (invariant 7) | Assignments are lexed into `Stage.Assignments`, `dangerousEnvVars` ⇒ DENY *before* exec; the child env is set explicitly, so even a non-flagged var can't leak through. No shell to smuggle `KEY=VAL cmd`. |
| **GNU long-option abbreviation** (`--compress-prog`, `--in-pl`) | adapter allowlist inversion | Abbreviations aren't in the known-flag set ⇒ DENY. The exact-match denylist that made abbreviation dangerous is inverted to an allowlist. |
| **Wrapper-binary unwrap** (`env rm x`) | recursive `env` adapter | Re-lexes trailing argv, re-dispatches through the registry; `rm` not read-allowlisted ⇒ DENY. No shell to unwrap. |
| **awk `print x > var` residual** | awk adapter, exact program scan | The program is one argv token (not re-split by sh), so the `>`/`system(`/`| "cmd"` scan is exact, not heuristic. |
| **Pager/PTY escape** (`less !sh`) | `LESSSECURE=1`+`-n` in `Plan.Env` | Adapter owns the env; `!`/`|`/`:e`/`v` structurally disabled. |
| **SQL** (`\!`, `\copy`, `COPY TO PROGRAM`, `pg_read_file`, `lo_export`, `.shell`, `load_extension`, `INTO OUTFILE`, `ATTACH`, multi-`;`) | SQL adapter + server read-only role + the read jail | Adapter rejects meta/dot-commands + DDL/DML and builds the whole argv; the read-only role lacks `pg_execute_server_program`. (This design assumed a phase-6 seccomp would deny the psql child's `fork`/`execve`. The shipped jail does not deny `execve`, and it cannot stop a database server, which runs outside the jail, from acting on what a jailed client sends it over TCP; a jailed client also cannot reach a server's Unix socket at all. The server-side read-only role stays the trust anchor.) |
| **Unknown future flag-leak** (the open tail) | adapter fail-closed (phase 1); the read jail | Phase 1 fails closed for enumerated binaries. On hosts with the jail, the open-ended tail is already contained: a mis-classified read cannot write to the host filesystem. |

**Meta-point.** The shell-mismatch / escape / env / wrapper families (rows 1, 2, 5, 7) are killed *by construction* — argv-exec removes the second interpreter, so "the classifier saw X but sh did Y" is inexpressible. The per-tool surface (rows 3, 4, 6, 8, 9) is killed by the **adapter fail-closed posture**, which argv-exec *enables* by handing the adapter clean, exact tokens. Neither half suffices alone; together they retire the documented history in pure userspace. The single remaining open tail (an undiscovered write-flag on an *allow-by-default* binary) is what the shipped read jail now backstops on hosts that support it.

---

## Sandbox / defense-in-depth recommendation

> **Superseded.** The project chose the opposite order: the `ro-v1` read jail shipped in v0.1.5 as
> the primary read wall (see the status note at the top and work item 1 in
> [BUILD-PLAN.md](../BUILD-PLAN.md)). It avoids the first objection below by not denying `execve`,
> and handles the second by being all-or-nothing: a host without user namespaces and Landlock runs
> reads classifier-only, and the operator can pin a `jail-floor` so such a host refuses reads
> instead. The original reasoning follows for the record.

**Recommendation (original): the kernel sandbox is a phase-6 defense-in-depth follow-on, NOT the primary phase-1 boundary.** The threat analysis argued that Approach B's sandbox is *not* the strict superset it presents as.

- **Its core mechanism conflicts with the legitimate read corpus.** seccomp `execve`-deny breaks `git` (execs `git-log`/pager), `journalctl`/`git` pagers, `docker`, `systemctl`. You cannot deny `execve` wholesale without regressing reads; allowing it per-tool means the sandbox *profile selection is itself classifier output* — the very fallibility the sandbox claims to transcend reappears at the syscall layer.
- **Its FS protection vanishes where it matters most.** On hardened RHEL (user namespaces disabled) with an older kernel (no Landlock), B degrades to seccomp-only, and `sort -o authorized_keys` is a plain `write()`, not `execve` — so B collapses to A on exactly the hosts you'd most want a backstop. "Logged loudly" is honest but the value is host-dependent and absent there.
- **It adds the most code and per-host variance** for marginal safety that phase-1's fail-closed posture already largely provides.

So phase 1 ships A's userspace fix, whose fail-closed posture *is* the correct structural answer to the flag-leak family. The sandbox is then added — after the adapters soak green in the red-team rig — as a **second, independent boundary that backstops the one residual: an undiscovered write-flag on an allow-by-default binary**, converting "remote write" into "EPERM + logged anomaly."

**Phase-6 sandbox shape (when built), with mitigation #8 baked in:**
- **seccomp-bpf as the unprivileged floor** (no root, Linux ≥3.17, universal): deny write/exec syscalls per a **per-adapter profile selected from a parent-controlled fd — never the child-influenced argv in the re-exec stub.** Tools needing helper-exec (`git`→`git-*`/pager, `journalctl`→pager) either get an explicit per-tool helper-exec allowlist or run un-paged (`--no-pager`, `GIT_PAGER=cat`).
- **Landlock for read-only FS when present** (Linux ≥5.13/6.1, unprivileged); **user-ns RO bind-mounts** where user-ns is enabled and Landlock absent.
- **Feature-probe + monotonic degradation, but FAIL LOUD (not just log):** when neither Landlock nor user-ns is available, the startup probe surfaces a hard, visible warning that the FS backstop is off — operators must know the suspender is missing, not discover it in a log.
- **No `bwrap`/external dependency** — implemented natively in Go (`golang.org/x/sys/unix`), preserving the single-static-binary install.
- Composes with the executor's pgroup/cancel/redactor/timeout constraints; the re-exec stub installs filters between fork and exec, the redactor stays on the gate's side of the pipe (untouched).

---

## Migration plan

**Guiding constraint:** keep `Classify(string) Kind`'s public contract (3 call sites, ~10 table-driven test files) intact and migrate *underneath* it; every phase ends with the full `classify` corpus + the red-team rig (`internal/redteam`, `BYPASS = executed && (fs_changed || write_alert)`) green. Each phase has an **independent on/off switch and an independent green gate**, so classification, exec, and posture-tightening are decoupled and a regression in one can't be confused with another. The red-team rig — which runs *real* writes at *real* beacons — is the acceptance gate at every exec-changing phase.

- **Phase 0 — scaffolding behind a flag (no behavior change).** Introduce the `adapter` package + `lex.Parse` + registry; implement `ShellAdapter` by wrapping the existing `argRule` funcs verbatim (no rule changes). Add `classifyViaAdapters(raw) Kind` (DENY folds to WRITE so the old contract is byte-identical). **Differential test (mitigation #1):** run the entire corpus through both `Classify` and `classifyViaAdapters` *and* through the MCP-side and gate-side entry points; assert byte-identical. This is the safety net and the single-source-of-truth enforcement. Gated by `SSHGATE_ADAPTER_CLASSIFY=0|1`, default 0.
- **Phase 1 — switch read *classification* (still shell-exec).** Default `SSHGATE_ADAPTER_CLASSIFY=1`; `Classify` delegates to adapters but the executor still runs `/bin/sh -c`, isolating "did we break classification?" from "did we break exec?" Green gate: classifier corpus + all bypass/harden files + red-team rig (0 bypasses, all READ controls still `executed`). **Fallback:** flip env var to 0, zero code revert.
- **Phase 2 — switch read *exec* to the argv pipeline.** Replace the unsigned-READ path's `ExecWithRedaction` with `runPipeline(plans)`; signed-write path keeps `/bin/sh -c`. Preserve all executor invariants and **add** the scrubbed env + trusted-path resolution + `context.WithTimeout` + correct pgroup + partial-start teardown (mitigations #3, #5). Redaction parity is a hard gate (mitigation #6): last-stage stdout + every stage stderr through `redact.NewWriter` with post-`Wait()` `Close()`, plus a test asserting a known secret is redacted through the new path. Gated by `SSHGATE_ARGV_EXEC=0|1`, default 0→1 after soak. New corpus rows: glob-disabled, pipeline-with-write-stage routes-to-sign, unknown-flag-denies. **Fallback:** `SSHGATE_ARGV_EXEC=0` reverts to shell-exec instantly.
- **Phase 3 — tighten per-binary posture (mitigation #2).** Flip enumerated-surface binaries from allow-by-default to fail-closed unknown-flag→DENY, **one binary per commit**, each with red-team rows (existing harden/bypass rows stay WRITE/DENY; READ controls stay `executed`; add a "novel write flag denies" row). **Fallback:** posture is per-binary data — revert one entry.
- **Phase 4 — land the SQL adapter (Feature 2).** Add `SQLAdapter` (read classification + hardened read Plans + trusted-inode resolution + whole-argv construction). Wire write-SQL to the signer; if the normalized-argv envelope (mitigation #7) isn't ready, **fallback:** write-SQL is DENY-with-hint while read-SQL ships fully. Add SQL beacon targets (`COPY TO PROGRAM`/`\!`/`.shell`/`INTO OUTFILE`/`lo_export`/`ATTACH`/multi-`;`) to the red-team canary zone; green gate = each dangerous escape is WRITE/deny producing 0 fs/inotify writes, every plain `SELECT` is an executed READ.
- **Phase 5 — remove the legacy shell-exec read path + flags.** After phases 1–3 soak green, delete the old `Classify` internals' role as exec authority and remove the env flags; the front-end survives only as the lexer, `argRule` funcs survive inside `ShellAdapter`, and `Classify` remains a thin `Kind` shim over the adapter fold (for the MCP call sites + test surface).
- **Phase 6 — sandbox defense-in-depth (follow-on; superseded by the shipped read jail).** Add the `src/sandbox` package (seccomp floor + Landlock/user-ns FS + per-adapter profiles + fail-loud probe), gated, after the adapters are proven. Red-team gains a deliberately-holed adapter behind the sandbox asserting `executed && fs_unchanged` (write attempted, EPERM'd) — the test only this layer can pass.

---

## Build tasks

1. **T0 — lexer promotion.** Extract `containsSubstitution`/`hasTopLevelRedirect`/`splitSegments`/`tokenize`/`isAssignment` into `src/classify/lex` as `Parse(raw) (Pipeline, error)` emitting `[]Stage` + typed rejections (`ErrSubstitution`/`ErrRedirect`/`ErrMultiCommand`). **Mitigation #9:** assignment detection on the pre-unescape lexeme; preserve empty `''` tokens. Add corpus rows `find -name ''`, `FOO\=bar cmd`, `uniq '' out`. Gate: existing `classifier_*_test.go` green (tokenization output unchanged).
2. **T1 — adapter package + registry.** Define `Adapter`/`Stage`/`Decision`/`Plan`/`Context` in `src/adapter`; registry keyed by basename. Implement `resolveTrusted`/`resolveTrustedSQL` (gate-owned absolute-path/inode table) and the scrubbed-env builder (mitigations #3, #7-env).
3. **T2 — ShellAdapter (verbatim rules).** Move `readAllowlist` + each `*Rule` + `dangerousEnvVars` + `env` recursion into `ShellAdapter`, logic unchanged. Add `classifyViaAdapters` + the **differential test** across `Classify`/adapters/MCP-entry/gate-entry (mitigation #1). Gate behind `SSHGATE_ADAPTER_CLASSIFY`.
4. **T3 — wire classification (phase 1).** Point the gate's `classify.Classify` calls and the MCP's `classify.Explain` calls at the shared `Inspect`-backed path via the `Classify` shim. Default `SSHGATE_ADAPTER_CLASSIFY=1`. Gate: full corpus + red-team rig.
5. **T4 — pipeline executor (phase 2).** Implement `runPipeline` in `src/gate/executor.go` for the unsigned-READ path: `os.Pipe` wiring, correct leader-pgroup + post-`Start` `Pgid`, partial-start teardown, `ExtraFiles=nil`, redaction parity on last-stdout + all-stderr with post-`Wait` `Close()`, `context.WithTimeout`, scrubbed `Plan.Env`, trusted `Plan.Path`. Keep `ExecWithRedaction`/`/bin/sh -c` for the signed path. Gate behind `SSHGATE_ARGV_EXEC`; tests: hung middle stage, unresolvable middle stage, secret-redaction-through-new-path, exit-code mapping (128+signum, 65/70/77).
6. **T5 — posture tightening (phase 3).** One commit per enumerated-surface binary flipping to fail-closed unknown-flag→DENY, each with red-team rows. (mitigation #2.)
7. **T6 — SQL adapters (phase 4).** `src/adapter/sql_{psql,mysql,sqlite}.go`: `parseInvocation`, `hasClientEscape`, `parseSingleSQL` (dialect-aware, single-statement, read-only classification), whole-argv `hardenedReadPlan`, trusted-inode resolution (mitigation #4). `signedWritePlan` → existing signer; if envelope not ready, DENY-with-hint fallback. SQL red-team beacons + corpus.
8. **T7 — envelope plumbing (conditional, mitigation #7).** Only if the maintainer chooses the normalized-argv envelope: add envelope-type to the signed payload; gate refuses cross-type execution; daemon accepts the new kind. Otherwise sign the normalized string via the existing path.
9. **T8 — legacy removal (phase 5).** Delete old exec-authority internals + env flags once soaked; `Classify` remains the shim.
10. **T9 — sandbox (phase 6, follow-on; superseded by the shipped read jail).** `src/sandbox`: seccomp floor + Landlock/user-ns FS + per-adapter profiles selected from a parent-controlled fd + fail-loud probe + re-exec stub (mitigation #8); deliberately-holed-adapter red-team row.

**Standing acceptance gate at every exec-changing task (T4, T5, T6, T9):** the red-team rig at 0 bypasses on all WRITE rows + all READ controls still `executed`, plus the differential test (mitigation #1) and redaction-parity test (mitigation #6) green.

---

## Open questions

1. **Read pipelines — safe in-process executor vs. sign-only?** Recommended: build the in-Go `os.Pipe` pipeline executor so `ps aux | grep x` stays an unsigned read (no shell). Cheaper alternative (Approach C): defer the mini-executor and make every read *pipeline* a one-tap signed command. The recommended path costs the pipeline-correctness engineering in T4 (pgroup/teardown/deadlock); the cheaper path costs diagnostic ergonomics and risks "sign everything" drift.

2. **Sandbox now vs. later?** *(Resolved the other way: the read jail shipped first, in v0.1.5.)* Original recommendation: **later (phase 6)** — ship A's userspace fix first; add seccomp/Landlock as a backstop after the adapters soak green. This accepts that phase 1 has no kernel net under an *allow-by-default* binary's undiscovered write-flag (mitigated by fail-closed posture on enumerated binaries + the red-team rig as a standing gate).

3. **SQL write path — reuse the existing string-signer, or build the normalized-argv envelope?** Recommended for increment 1: **read-SQL ships now; write-SQL via the existing string-signer** (sign the adapter-normalized statement as a string). The cleaner-but-new normalized-argv envelope (so the human approves the exact argv, with an envelope-type tag + cross-type refusal) is a separate increment requiring new daemon `kind` plumbing — build it only if argv-level approval fidelity is wanted now.

4. **SQL read enforcement — parse-only, server-read-only-mode, or both?** Recommended: **both** (parse as the fail-closed outer gate; server-side read-only role/user as the trust anchor). The consequence to accept: the **dedicated read-only role/user + server settings (`secure_file_priv`, `NOINHERIT`, no `FILE`/`pg_*` grants) are an operator-provisioning prerequisite verified at `sshgate add` time**, documented, *not* an adapter guarantee — and whether `sshgate add` should *verify* these at registration (recommended) or merely *document* them.

5. **Which SQL engines first?** Recommended rollout order: **`sqlite3` → `postgres` → `mysql`** (sqlite's `-readonly`/`-safe` is the simplest, fully client-side trust anchor; postgres needs the role; mysql needs the most server-side provisioning). Confirm or reorder.

6. **Adapter posture rollout order (phase 3).** Recommended: tighten the historically-leaky binaries first — **`sort`, `curl`, `wget`, `sed`, `awk`** — then `find`, `ip`, `ss`, `git`, `systemctl`, `journalctl`, `dmesg`, `docker`, `less`, one commit each. Confirm the set and order, and confirm `less` should be launched with `LESSSECURE=1` (disabling its shell/edit escapes) in read mode.

7. **Env scrub aggressiveness.** Recommended: drop `LD_*`, `IFS`, `GIT_*`, `PAGER`, `*_OPTIONS`; keep a vetted minimal `PATH` (fixed safe value) + `LANG` + `TERM` + adapter additions (`PGOPTIONS`, `LESSSECURE`). Confirm nothing in operator workflows needs a forwarded env var that this would strip.
