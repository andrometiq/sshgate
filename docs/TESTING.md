# SSHGate — Developer Testing Guide

This is a part-by-part guide to testing SSHGate **with zero sudo, Docker,
network, systemd, or CGO**. The standing invariant is:

> `go test ./...` must stay green with none of those at every commit (~11s of
> per-package work, parallelised to ~8s wall).

The only thing that needs real hosts is the Docker integration/e2e suite under
`tests/integration` — it is gated behind `//go:build integration` and is **not**
part of the unit gate (see §11).

Everything below is grounded in the actual tree as of this writing. File:func
citations are exact; if you change the code, re-derive them.

---

## 0. TL;DR / quickstart

```sh
go test ./...            # full unit suite — no sudo/Docker/network/systemd/CGO
go test -count=1 ./...   # same, but defeat the build/test cache when verifying
go test -race ./...      # run this before merge (needs CGO; see §10)
```

What is **not** in the unit gate:

- The Docker integration suite (`tests/integration`, `//go:build integration`)
  — real `sshd` in a container, real `ssh` client. Run via `make test-integration`.
- The fresh-install keyless-startup smoke (`scripts/smoke-fresh-install.sh`,
  `make smoke`).
- The full `make e2e` target (preflight + integration + smoke), for after a
  large build or before a release.

The standing gates live in `docs/E2E-TEST-STRATEGY.md`:

| When | Command | Needs Docker |
| --- | --- | --- |
| Before every push | `make preflight` (`vet test gitleaks build verify-dist verify-repro`) | no |
| After a large build / before release | `make e2e` (`preflight test-integration smoke`) | yes |

> Note on `make test`: the Makefile's `test:` target is `go test -race ./...`,
> which **does** require CGO (the race detector needs it). The *no-CGO
> invariant* is about plain `go test ./...` — proven below — which `make
> preflight` depends on via `make test`. If you are on a machine without a C
> toolchain, run plain `go test ./...` directly; it is green with
> `CGO_ENABLED=0` (verified).

---

## 1. The no-sudo mandate & why

Five things are **never** required to run the unit suite, and here is how each
is structurally avoided:

| Never required | How it's avoided |
| --- | --- |
| **sudo / root** | Permission assertions run as the ordinary test user; tests that depend on unix perms being *enforced* skip when `os.Geteuid() == 0` (root bypasses mode bits — see §10). Components that refuse to run as root are tested via `assertNonRoot()`, not by actually being root. |
| **Docker** | The only Docker is `tests/integration` (`//go:build integration`), excluded from `go test ./...` by the build tag. |
| **network** | Every "socket" is a Unix-domain socket on `t.TempDir()` or a loopback `127.0.0.1:0` listener. The three HTTP collaborators (Telegram Bot API, OpenAI-compatible LLM, hosted v2 signer) are faked with `httptest.Server` on loopback. The MCP server uses the SDK **in-memory** transport — no TCP at all. |
| **systemd** | Nothing under test talks to systemd. The signer's single-instance guarantee is a `flock` on a lockfile in `t.TempDir()` (`TestFlockOrFail_SecondLockBlocks`), not a unit. |
| **CGO** | `sqlite` is pure-Go: `modernc.org/sqlite` in `go.mod` (no `mattn/go-sqlite3`). Plain `go test ./...` passes with `CGO_ENABLED=0`. CGO is only pulled in by `-race`. |

---

## 2. The fake / seam catalogue

### 2.1 Collaborator → fake map

| Real collaborator | Fake / stand-in | Module(s) served | Where it lives |
| --- | --- | --- | --- |
| Unix socket to the signer daemon | `startFakeSigner` (unix listener on `t.TempDir()/sock`) | `src/mcp/sign` | `sign/client_test.go:28` |
| …raw-bytes control of that socket | `startRawSigner` (write fragments, no `\n`, drive EOF) | `src/mcp/sign` | `sign/rawsigner_test.go:28` |
| `net.Dialer.DialContext("unix", …)` | `dialWithCtx` package-var override (inject `net.Conn`, e.g. `writeFailConn`) | `src/mcp/sign` | `sign/client.go` `var dialWithCtx` (prod), `sign/client_internal_test.go:56` (swap) |
| Telegram Bot API (HTTPS) | `newFakeTelegram` → `httptest.Server` | `src/signer/backend` | `backend/telegram_test.go:79` |
| OpenAI-compatible LLM (`/v1/chat/completions`) | `newFakeChat` → `httptest.Server` | `src/signer/backend` | `backend/explainer_test.go:43` |
| Hosted v2 signer server (`/v1/sign`, `/v1/poll/<id>`) | `newFakeServerBackend` → `httptest.Server` | `src/signer/backend` | `backend/hosted_test.go:191` |
| Approval channel (any) | `MockBackend` (drive Approve/Deny/Timeout) / `StubBackend` (always deny) | `src/signer`, cmd | `backend/mock.go:19`, `backend/stub.go:15` |
| Signer client + SSH runner (for tools) | `fakeSign` + `fakeSSH` | `src/mcp/tools` | `tools/run_test.go:21`, `tools/run_test.go:40` |
| Remote sshd for the gate-deploy path | `fakeBootstrapSession` via `newBootstrapSession` seam | `src/mcp/tools` | `tools/add_server_bootstrap_test.go` (fake), `tools/add_server.go` `var newBootstrapSession` (seam) |
| `ssh-agent` unix socket | `dialAgentSock` package-var override (`net.Pipe()`) | `src/mcp/tools` | `tools/add_server.go` (`var dialAgentSock`) |
| `ssh.ParsePrivateKey` | `parsePrivateKey` package-var override | `src/mcp/tools` | `tools/add_server.go` (`var parsePrivateKey`) |
| Entropy / nonce RNG | `randRead` package-var (`= rand.Read`) | `src/signer` | `signer/daemon.go` `var randRead` |
| Real sshd (in-process, for the ssh client pkg) | `testServer` — minimal SSH server on `127.0.0.1:0` | `src/mcp/ssh` | `ssh/client_test.go:36` |
| MCP transport | SDK in-memory transport `mcpsdk.NewInMemoryTransports()` | `src/mcp` | `server_test.go:61` |
| Audit log sink | `NewMemAuditLog` (os.Pipe, drained by goroutine) | `src/signer` | `signer/audit.go:75` |
| Persisted chat-id store | `MemChatStore` (in-mem) / `FileChatStore` on `t.TempDir()` | `src/signer/backend` | `backend/chatstore.go` |
| Wall clock | `Daemon.NowFunc` fixed to `time.Unix(1000,0)` | `src/signer` | set in `daemon_test.go` newDaemon helper |
| Time/registry FS | `t.TempDir()` everywhere | all | — |

### 2.2 The two seam **patterns**

**Pattern A — package-var function/var override.** A production identifier is a
`var` set to the real implementation, swapped only inside `_test.go` (save
original → assign → restore via `defer`/`t.Cleanup`). Used for narrow,
single-call indirections:

- `gateDirFn` / `homeDirFn` — `src/gate/cmd/sshgate-gate/main.go` (`var gateDirFn`, `var homeDirFn`)
- `dialWithCtx` — `src/mcp/sign/client.go` (`var dialWithCtx`)
- `randRead` — `src/signer/daemon.go` (`var randRead`)
- `dialAgentSock`, `parsePrivateKey` — `src/mcp/tools/add_server.go` (package vars)

**Pattern B — interface + factory `var`.** When the thing being faked is a
*session* with several methods (a whole pipeline, not one call), define an
interface plus a factory `var`, and let the fake implement the interface. Used
for the gate-deploy path:

- `bootstrapSession` interface — `src/mcp/tools/add_server.go`
  (`Run` / `Upload` / `Close`)
- `var newBootstrapSession` factory — `src/mcp/tools/add_server.go`
- fake: `fakeBootstrapSession` — `tools/add_server_bootstrap_test.go`,
  installed via `installFakeBootstrapSession` — `tools/add_server_bootstrap_test.go`

Use Pattern A for a single seam point; Pattern B when you need to fake a
multi-step remote conversation in memory rather than against a real sshd.

### 2.3 Security rule: trust anchors are never env-overridable

These are **package-var** seams, not env vars, and that is deliberate. The
clearest case: `gateDirFn` resolves where the gate reads `gate.pub` (the
signature-verification trust anchor). If that location were `$ENV`-overridable,
an attacker who controlled the environment could point the gate at a `gate.pub`
they own and **forge signatures** — every "signed" admin command would verify.
So the seam exists *only* so in-package tests can point resolution at a
`t.TempDir()` without re-exec'ing the test binary; production always uses
`defaultGateDir` (`os.Executable()`-relative). The comment on
`var gateDirFn` in `src/gate/cmd/sshgate-gate/main.go` documents this. Same rationale for any
future trust-anchor location: test seam yes, env override never.

---

## 3. Pure modules: `classify` and `sigwire`

Both are pure functions over strings/bytes — fastest, most deterministic tests
in the tree.

### 3.1 `src/classify` — command read/write classification

- Entry point: `func Classify(cmd string) Kind` (`classifier.go`), returning
  `KindUnknown` / `KindRead` / `KindWrite`.
- The corpus test `TestClassify_Corpus` (`classifier_test.go`) is **table-driven
  from a file**: `tests/testdata/classifier-corpus.txt`. Each non-blank,
  non-`#` line is `<EXPECTED>\t<cmd>` where `EXPECTED` is `READ` or `WRITE`;
  `loadCorpus()` parses it and creates one subtest per row.

**Adding a corpus row:** append a line to
`tests/testdata/classifier-corpus.txt`, e.g.

```
WRITE	tee -a /etc/hosts
```

No code change — the next run picks it up as a new subtest. Keep the spec's
"Command Classification" table as the source of truth for the corpus.

**The two read-only-gate bypasses, now fixed and pinned**
(`classifier_bypass_test.go`, `TestClassify_ReadOnlyBypassRegressions`):

1. *Newline command separator* — `"ls\nrm -rf /tmp/x"` used to classify as
   `KindRead` because a bare `\n` was not treated as a top-level separator, so
   the second segment ran unclassified. Now classifies `KindWrite`. (Fixed in
   `splitSegments`.)
2. *Bundled `sed` in-place flag* — `sed -ni …` (the `i` bundled with other short
   flags) was missed by the old `arg[1]=='i'` check and classified `KindRead`.
   The `sed` rule now scans the whole short-flag bundle for `i`, stopping at
   flags that consume an argument (`-e`/`-f`/`-l`). Now classifies `KindWrite`.

`classifier_asymmetry_test.go` pins the deliberate fail-*closed* asymmetry
(unknown → treated as write).

### 3.2 `src/sigwire` — the canonical wire-form golden lock

- Encoder: `func EncodeSigned(sig []byte, payload SigPayload) (string, error)`
  (`payload.go`), producing `SSHGATE_SIG:<sigB64url>:<payloadB64url>`.
- `MaxSigValidity = 5 * time.Minute` (`payload.go:20`) — the `exp - ts < 300s`
  upper bound, enforced by the gate (§4).

**The golden is a hand-verified literal, not a regenerated file.**
`payload_golden_test.go` defines `const wantGolden = "SSHGATE_SIG:" + …` (a
fixed sig of 64 bytes `b[i]=byte(i*7)` and the canonical
`{"cmd":…,"ts":…,"exp":…,"nonce":…}` payload, both URL-safe base64, no `=`
padding). The test asserts `EncodeSigned(...) == wantGolden`. This locks: JSON
field order (`cmd,ts,exp,nonce`), URL-safe alphabet (no `+`/`/`), no padding,
and the `SSHGATE_SIG:<sig>:<payload>` envelope shape.

**There is no `-update` flag and no `UPDATE_GOLDEN` env** — that is the point.
If the canonical form legitimately changes, you must hand-recompute the
envelope, re-verify it against the spec, and edit the `wantGolden` constant.
Any drift in the encoder breaks this test, which is the intended canary.

---

## 4. The gate (library + command halves)

`src/gate` (library) + `src/gate/cmd/sshgate-gate` (the binary deployed to the
remote). Tested entirely unprivileged.

### 4.1 The `gateDirFn` / `homeDirFn` seam

`var gateDirFn = defaultGateDir` and `var homeDirFn = os.UserHomeDir`
(`main.go`). `run_test.go` helpers `withGateDir(t, dir)` and
`withHomeDir(t, dir)` repoint them at a `t.TempDir()` so `run()` / `doRevoke()`
can be exercised (incl. their exit-code mapping) without re-exec'ing the test
binary. See §2.3 for why this is a package var, not an env var.

### 4.2 Exit-code mapping

Constants in `main.go` (sysexits-style); each asserted by a named case in
`run_test.go`:

| Code | Constant | Meaning | Example assertion |
| --- | --- | --- | --- |
| 0 | `exitOK` | success; empty `SSH_ORIGINAL_COMMAND` prints `SSHGATE_OK` (post-install probe) | `TestRunProbeWithKeyPresent`; `TestRunVerifiedPaths` (valid signed read) |
| 1 | `exitGeneric` | generic runtime failure / empty inner command | `TestRunSignedWritePassthrough` (empty inner) |
| 65 | `exitDataErr` (EX_DATAERR) | bad signature, bad envelope, expired sig, validity window too long | `TestRunVerifiedPaths` (bad signature / tampered cmd / expired) |
| 70 | `exitSoftware` (EX_SOFTWARE) | `gate.pub` unreadable / corrupt / insecure mode | `TestRunPubkeyFailures` (corrupt / insecure-mode) |
| 77 | `exitNoPermVal` (EX_NOPERM) | write command without a verified `SSHGATE_SIG` prefix | `TestRunWriteDenial` (unsigned write); `TestRunReadOnlyMode` (write in read-only) |
| 0–255 | passthrough | child's own exit code passed straight through | `TestRunSignedWritePassthrough` (child exits 42 → 42) |
| 128+signum | passthrough | child killed by signal → `128+signal` | `TestRunSignedWritePassthrough` (SIGTERM → 143) |

### 4.3 The unsigned-admin-command guard

`TestRunAdminCommands` ("unsigned admin verb is not honored") pins that an
**unsigned** `SSHGATE_REVOKE` / `SSHGATE_UPDATE` is denied with `exitNoPermVal`
(77), **not** dispatched to `doRevoke()` / the update stub. In production the
admin-verb dispatch lives *inside* the `if signed { … }` block (`main.go`), so
unsigned admin verbs classify as write and hit the write-denial branch first.
The test carries a "SECURITY REGRESSION PIN" comment — do not move admin
dispatch out of the signed branch.

### 4.4 Replay semantics

`TestRunReplayWithinWindow` documents that there is **no per-nonce ledger** on
the gate: the same valid envelope replayed twice within its validity window
succeeds both times. The replay defense is the short (≤5m) `MaxSigValidity`
window *plus* the human Telegram approval gating issuance of any signature —
not server-side nonce tracking. `verify.go` rejects `validity >
sigwire.MaxSigValidity` with `ErrValidityTooLong` (mapped to exit 65).

### 4.5 Executor caveat: real `/bin/sh` + coreutils

`executor.go` runs `exec.CommandContext(ctx, "/bin/sh", "-c", cmd)` — a real
shell. `executor_test.go` therefore genuinely shells out and depends on
coreutils being present: `TestExec` runs `echo hello` and asserts stdout
`"hello\n"`; a large-output case runs `yes x | head -c 65536`; a timeout case
runs `sleep 10`. This is the one place the unit suite assumes a POSIX `/bin/sh`
and `echo`/`yes`/`head`/`sleep` on `PATH` — still no sudo/Docker/network, just
the base userland. (On a stripped container without coreutils these would fail;
that is a documented environmental assumption, not a privilege requirement.)

---

## 5. The signer daemon + cmd (`src/signer`, `src/signer/cmd/sshgate-signer-telegram`)

### 5.1 Daemon test doubles

- `memConn` (`daemon_test.go:26`) — in-memory full-duplex conn (`bytes.Reader`
  in, `bytes.Buffer` out); the request/response transport without a socket.
- `MockBackend` / `NewMockBackend()` (`backend/mock.go:19`) — drive an approval
  outcome programmatically: `Approve` / `ApproveWithSignatures` / `Deny` /
  `Timeout`.
- `StubBackend` (`backend/stub.go:15`) — always denies immediately.
- `NewMemAuditLog()` (`audit.go:75`) — audit sink backed by `os.Pipe`, drained
  by a goroutine; no file needed.
- Fixed clock: the test daemon sets `NowFunc: func() time.Time { return
  time.Unix(1000, 0) }`, so signed payloads have deterministic `ts` (asserted
  e.g. `payload.TS == 1000`).
- `randRead` seam (`var randRead` in `daemon.go`): `TestSignAll_NonceFailure`
  (`daemon_internal_test.go:25`, *not* parallel — mutates a package var) swaps
  it for a reader that returns an error, exercising the nonce-failure path
  (surfaces as a `sign: nonce` error, not a panic).
- goleak: `TestMain` in `src/signer/main_test.go` runs `goleak.VerifyTestMain`
  across the whole signer suite.

### 5.2 Request-validation table

`TestDaemon_RejectsBadRequests` (`daemon_reject_test.go:28`) is table-driven and
validates, per row: `kind == "sign"`; non-empty `request_id`; non-empty
`commands`; non-empty per-command `cmd`; `0 < ttl_seconds ≤ 300`
(`MaxSigValidity`); and **no unknown JSON fields** (`dec.DisallowUnknownFields()`).
Each row asserts the response is `status:"error"` and the audit record matches.

### 5.3 The cmd layer — fully unprivileged

`src/signer/cmd/sshgate-signer-telegram/main_test.go` (+ `init_test.go`):

- `TestLoadConfig_ValidAndEachMissingField` — writes a temp TOML via a
  `writeTOML(t, …) → t.TempDir()` helper; asserts valid config loads and each
  missing field (`paths.key`, `paths.pubkey`, `paths.audit_log`, `paths.socket`,
  `backend.type`) produces a named error.
- `TestDoInitFlow_DevHappyPath` — `doInitFlow(configPath, /*dev*/ true)` against
  a temp path; asserts on-disk modes (keys 0600/0644, config world-bits off,
  audit dir created) and a `loadConfig` round-trip. `TestDoInitFlow_RefusesExistingConfig`
  pins that a second `--init` refuses to overwrite.
- `TestFlockOrFail_SecondLockBlocks` — first `flockOrFail` succeeds, second
  fails ("another signer instance is running"), release re-allows; lockfile
  carries the PID. This is the single-instance guarantee — a `flock`, not
  systemd.
- `TestBuildBackend_StubAndUnknown` — `buildBackend` returns `StubBackend` for
  type `"stub"` and an `"unknown backend type"` error otherwise.
- `TestAssertNonRoot` — `assertNonRoot()` returns nil when not root and a
  refusal when root (this is how root-refusal is tested *without* being root;
  the four `os.Geteuid()==0` skips here are for perm-enforcement cases).

---

## 6. The approval backends (`src/signer/backend`)

All three HTTP collaborators are faked with `httptest.Server` on loopback — no
network egress:

| Collaborator | Fake | Stand-up func |
| --- | --- | --- |
| Telegram Bot API (`getMe`, `getUpdates`, `sendMessage`, `editMessageText`, `answerCallbackQuery`, …) | `fakeTelegram` | `newFakeTelegram` (`telegram_test.go:79`) |
| OpenAI-compatible LLM (`/v1/chat/completions`) | `fakeChatCompletions` | `newFakeChat` (`explainer_test.go:43`) |
| Hosted v2 signer (`/v1/sign`, `/v1/poll/<id>`) | `fakeServer` | `newFakeServerBackend` (`hosted_test.go:191`) |

Chat-id persistence: `MemChatStore` (in-mem, zero value usable) and
`FileChatStore` on `t.TempDir()` (`chatstore.go`). File tests pin mode 0600 and
atomic write (`TestFileChatStore_SaveSetsMode0600`,
`TestFileChatStore_AtomicWrite_NoTempLeak`).

**Security tests:**

- *`allowed_user_id` pinning* — `TestTelegram_StartFromWrongUserDoesNotCapture`
  (`telegram_test.go:657`): a `/start` from a non-allowed user must NOT capture
  their chat_id (`store.Load()` stays `(0, false)`). The matching positive case
  is `TestTelegram_StartFromAllowedUserCapturesChatID`, and
  `TestTelegram_WrongUserCallbackIgnored` covers approval callbacks from the
  wrong user.
- *Credential redaction* — `sanitiseExplainerErr` (`telegram.go`), tested by
  `TestSanitiseExplainerErr` (`internal_test.go:29`): errors containing bearer
  tokens or `http(s)://…` URLs collapse to `"upstream error"`, so signer-side
  credentials never reach a Telegram DM; plain messages pass through.
- *Explainer fail-open + panic recovery* — the LLM explainer is best-effort:
  `TestTelegram_ExplainerErrorFallsBackToFooter` (an explainer error still
  renders commands + a footer), and `TestRunExplainerRecoversPanic`
  (`internal_test.go:118`) — a `panicExplainer` is caught, `PanicsTotal`
  increments, and an error (not nil) is returned so rendering proceeds. The
  explainer can never take down an approval.
- *`maskUserID`* (`telegram.go`), tested by `TestMaskUserID`
  (`internal_test.go:80`): ≤4 digits fully masked, longer IDs show first-2 +
  stars + last-2 (`12345 → 12*45`); the full id never appears verbatim.

goleak: `TestMain` in `backend/main_test.go` runs `goleak.VerifyTestMain` for
the whole backend suite (the telegram-bot-api shutdown channel is benign).

---

## 7. The MCP sign-client (`src/mcp/sign`)

- `startFakeSigner(t, respond)` (`client_test.go:28`) stands up a Unix listener
  at `t.TempDir()/sock`, reads one JSON request line per connection, calls
  `respond(req)` for the wire response (an empty return → write nothing,
  simulating a hung server), and returns a buffered channel of captured
  requests. Tests assert wire-body fidelity by decoding `req["commands"]` and
  checking the per-command fields.
- `startRawSigner` (`rawsigner_test.go:28`) gives the handler raw byte control
  (write a partial line, no trailing `\n`, then close) to drive the client's
  `bufio.ReadBytes('\n')` EOF path deterministically
  (`TestSign_ReadSideEOF_PartialLine_ReadResponseError`).
- `dialWithCtx` seam (`var dialWithCtx` in `client.go`) lets internal tests inject a
  `writeFailConn` etc. to exercise write-side failures with no real socket.
- Error classification (`client.go`): `var ErrUnreachable` vs
  `var ErrSignerPermission`.
  - `TestSign_UnreachableMissingSocket` — missing socket file →
    `errors.Is(err, sign.ErrUnreachable)`.
  - `TestSign_PermissionDenied_MapsToSignerPermission`
    (`client_permission_test.go:24`) — socket chmod `0000` →
    `errors.Is(err, sign.ErrSignerPermission)`. Guarded by
    `if os.Geteuid() == 0 { t.Skip("running as root bypasses unix-socket permission checks") }`
    because root ignores socket perms.

---

## 8. The MCP tools (`src/mcp/tools`)

### 8.1 Fakes and the real registry

- `fakeSign` (`run_test.go:21`) implements the `Sign(ctx, requestID, []CmdReq)`
  SignClient surface, recording whether it was called and with what.
- `fakeSSH` (`run_test.go:40`) implements the `Run(ctx, host, user, port, cmd)`
  SSHRunner surface, returning canned stdout/stderr/exit and recording a
  `callHistory` (used to assert "no dial happened" in pre-flight tests).
- Real registry on `t.TempDir()`: `freshRegistry(t)`
  (`add_server_bootstrap_test.go`) creates `t.TempDir()/servers.json` via
  `registry.New`; `newRegistryWithEntry(t, alias, e)` seeds one entry. Registry
  persistence (atomic write, mode 0600, reload) is itself tested in
  `registry/servers_test.go` (§9).

### 8.2 The `bootstrapSession` seam for `add_server`

This is the **Pattern B** (interface + factory) seam for the gate-deploy path —
use it as the template for testing any future "do a multi-step thing over SSH"
tool:

- Interface `bootstrapSession` (`add_server.go`): `Run` / `Upload` / `Close`.
- Factory `var newBootstrapSession` (`add_server.go`): prod default dials,
  wraps `*ssh.Client` in `sshBootstrapSession`, returns `(session, fingerprint,
  nil)`.
- Fake `fakeBootstrapSession` (`add_server_bootstrap_test.go`): records every
  `Run`/`Upload` in order, can be configured to fail on a command substring or
  upload path, models remote `authorized_keys` so idempotency probes work, and
  captures the rewritten `authorized_keys` bytes for assertion. Installed via
  `installFakeBootstrapSession(t, sess, fp)`, which also captures the
  dial params so tests assert the `ssh.ClientConfig` was correct.
- `TestAddServer_FullBootstrapHappyPath` drives the whole Tier-2 pipeline in
  memory: dial → probe `authorized_keys` → mkdir → upload `gate` → upload
  `gate.pub` → backup → rewrite `authorized_keys` → verify → register, and
  asserts the registry entry has `ReadOnly=false` and the output carries the
  fingerprint. Companion sub-seams: `dialAgentSock` (`add_server.go`, fake
  `$SSH_AUTH_SOCK` via `net.Pipe`) and `parsePrivateKey` (`add_server.go`,
  inject a failing parser).

### 8.3 What's testable **without** the seam — the pre-flight guards

`add_server_preflight_test.go` proves every guard fires **before any dial** (each
asserts `len(ssh.callHistory) == 0`):

| Test | Guard |
| --- | --- |
| `TestAddServer_BootstrapMethodExactlyOne` | exactly one of `bootstrap_key_path` / `bootstrap_agent` |
| `TestAddServer_AliasAlreadyRegistered` | duplicate alias → "revoke_server first" |
| `TestAddServer_BootstrapAgentEmptySocket` | empty `$SSH_AUTH_SOCK` |
| `TestAddServer_InsecureBootstrapKeyRejected` | bootstrap key mode 0644 rejected |
| `TestAddServer_MissingBootstrapKeyRejected` | bootstrap key file missing |
| `TestAddServer_MissingLocalMaterials` | gate binary / `gate.pub` / sshgate pubkey not found (table swaps one path per row) |
| `TestAddServer_ReadOnlySkipsGatePub` | Tier-1 read-only path does **not** read `gate.pub` |

### 8.4 Status: permission vs unreachable

`status_permission_test.go` `TestProbeSignerSocket_PermissionDenied`: real
listener at a temp socket, `chmod 0o000`, then `probeSignerSocket` →
`Configured=true`, `Reachable=false`, `Permission=true` (EACCES detected, not
mistaken for a dead daemon). Skip-if-root guarded. The render side of this
distinction is pinned in `src/mcp/format_status_permission_test.go` (§9).

---

## 9. The MCP server / registry / ssh (`src/mcp`, `src/mcp/registry`, `src/mcp/ssh`)

### 9.1 Server wiring — SDK in-memory transport (no TCP)

`connectInProcess` (`server_test.go:58`) wires the server over
`mcpsdk.NewInMemoryTransports()` (line 61) — channel-based JSON-RPC, no socket.
`connectAllTools` (`server_alltools_test.go:29`) exercises a tool surface through
the SDK using local shim handlers: the eleven agent tools are `list_servers`,
`status`, `ping`, `revoke_server`, `run`, `run_batch`, `request_grant`,
`revoke_grant`, `list_grants`, `update_gate`, `transfer` (`mcp.ToolName*`). Provisioning is
the human-only `sshgate` CLI and is deliberately not an agent tool. The
authoritative "exactly these tools are registered" guard drives the real
`Serve()`: `TestServe_RegistersExactlyAgentTools` (`server_test.go`). goleak runs
via `TestMain` in `server_test.go:26` (the server spawns goroutines, so the
helper waits for counts to settle).

### 9.2 White-box format tests

In `package mcp` (not `mcp_test`) so they reach unexported helpers directly —
no production seam added:

- `format_internal_test.go` `TestFormatStatusSummary_Branches` — the three
  mutually-exclusive signer branches: reachable / not-configured (Tier 1) /
  configured-but-unreachable (Tier 2 down).
- `format_status_permission_test.go` `TestFormatStatusSummary_Permission` — a
  permission-denied socket renders the actionable "sshgatesigner group /
  relaunch / NOT a dead daemon" guidance and must **not** say `UNREACHABLE`.

### 9.3 SSH client — real in-process sshd on loopback

`src/mcp/ssh/client_test.go` uses a real SSH protocol exchange against an
in-process server: `testServer` (`client_test.go:36`) listens on
`127.0.0.1:0` (TCP loopback), accepts pubkey auth against a supplied key, and
runs commands via a handler. This is loopback, not network — still in the unit
gate. goleak via `TestMain` (`client_test.go:28`). known_hosts tests
(`known_hosts_test.go`, `_edge_test.go`) use real files on `t.TempDir()` —
`TestTOFU_FirstContactAppends` writes via `TOFU(khPath)` and asserts mode 0600;
the edge file has an `os.Geteuid()==0` skip for a perm case.

### 9.4 Registry

`registry/servers_test.go` (+ `_edge_test.go`) exercises `registry.New` on
`t.TempDir()/servers.json`: missing file → empty, JSON round-trip, atomic
persist at mode 0600, reload-after-`Add`. The edge test has an
`os.Geteuid()==0` skip for an unwritable-dir case.

---

## 10. Running & CI conventions

- **`-count=1`** — defeat the test cache when you actually want to re-run (the
  cache will report `(cached)` otherwise). Use it whenever you are verifying a
  change.
- **`-race`** — run before merge. It needs CGO (a C toolchain). This is the
  Makefile `test:` target and is part of `make preflight`. Plain `go test ./...`
  stays CGO-free for machines without a C toolchain.
- **skip-if-root** — permission-rollback / perm-enforcement tests can't assert
  anything meaningful as root (root bypasses unix mode bits), so they
  `if os.Geteuid() == 0 { t.Skip(...) }`. Present in: `sign/client_permission_test.go`,
  `tools/status_permission_test.go`, `tools/run_batch_guards_test.go`,
  `signer/cmd/.../main_test.go` (×4), `backend/chatstore_extra_test.go`,
  `mcp/cmd/.../main_known_hosts_test.go`, `registry/servers_edge_test.go`,
  `ssh/known_hosts_edge_test.go`. Run the suite as a non-root user to actually
  exercise these.
- **goleak** — `TestMain` runs `goleak.VerifyTestMain(m)` for the packages that
  spawn goroutines: `src/signer` (`main_test.go`), `src/signer/backend`
  (`main_test.go`), `src/mcp` (`server_test.go`), `src/mcp/ssh`
  (`client_test.go`). If you add goroutine-spawning code to one of these
  packages, expect goleak to catch leaks.

**Keeping a new package no-sudo** (checklist):

1. All filesystem under `t.TempDir()` — never a fixed path, never `$HOME`.
2. All sockets Unix-domain on `t.TempDir()`, or loopback `127.0.0.1:0`.
3. Any HTTP collaborator → `httptest.Server`; any in-process RPC → SDK in-memory
   transport.
4. Indirection you must control → a package-var seam (Pattern A) or interface +
   factory (Pattern B), swapped only in `_test.go`. **Never** make a trust-anchor
   location env-overridable (§2.3).
5. Perm-enforcement assertions → guard with `os.Geteuid()==0` skip.
6. Need to refuse-as-root? Test the refusal function (`assertNonRoot`-style),
   don't become root.
7. No `sqlite3` cgo driver — use `modernc.org/sqlite`.
8. Verify with `CGO_ENABLED=0 go test -count=1 ./yourpkg/...`.

---

## 11. The integration / e2e boundary

Real hosts and Docker live **only** in `tests/integration`, behind
`//go:build integration` (e.g. `e2e_test.go`, `phase2/3/4_test.go`,
`helpers_test.go`, `setup_test.go`). The build tag means `go test ./...` never
compiles or runs them — that is structurally why they can never be part of the
unit gate.

What they need and prove (per `tests/integration/README.md`): a throwaway
`linuxserver/openssh-server` container (rootless, pubkey auth, host port 2222),
that a real `ssh` client connects to, so SSHGate is exercised end-to-end —
deploy the gate over real SSH, run a read, and confirm write-denial against live
`sshd`. Keys are generated into `fixtures/keys/` (empty-but-`.gitkeep` in git)
at setup and deleted at tear-down.

Makefile targets (and `docs/E2E-TEST-STRATEGY.md`):

| Target | What it runs | Docker? | When |
| --- | --- | --- | --- |
| `make test` | `go test -race ./...` (the unit gate, CGO) | no | always |
| `make preflight` | `vet test gitleaks build verify-dist verify-repro` | no | before every push |
| `make test-integration` | `go test -race -tags=integration ./tests/integration/...` | **yes** | exercising real hosts |
| `make smoke` | `scripts/smoke-fresh-install.sh` (keyless first-run startup) | no | fresh-user regression |
| `make e2e` | `preflight test-integration smoke` | **yes** | after a large build / before release |

The rule of thumb: a green `make preflight` is the bar to push; a green
`make e2e` (which alone touches Docker) is the bar to call an install or feature
"works end-to-end."

---

## Section index

0. TL;DR / quickstart
1. The no-sudo mandate & why
2. The fake / seam catalogue (collaborator map, the two seam patterns, the
   trust-anchor env-override rule)
3. Pure modules — `classify` (corpus + the two fixed bypasses) and `sigwire`
   (the golden lock)
4. The gate — `gateDirFn`/`homeDirFn` seam, exit-code mapping, unsigned-admin
   guard, replay semantics, the `/bin/sh`+coreutils caveat
5. The signer daemon + cmd — doubles, validation table, unprivileged cmd layer
6. The approval backends — the 3 httptest fakes, chat stores, security tests
7. The MCP sign-client — fake/raw signers, `dialWithCtx`, error classification
8. The MCP tools — fakes + real registry, the `bootstrapSession` seam, pre-flight
   guards, status permission-vs-unreachable
9. The MCP server / registry / ssh — SDK in-memory transport, white-box format
   tests, real loopback sshd
10. Running & CI conventions
11. The integration / e2e boundary
