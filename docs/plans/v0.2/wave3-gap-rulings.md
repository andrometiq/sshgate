# WI2 gap rulings: all 43 sweep items (2026-10-22, revision 4)

## Revision 4 changelog (third verify: 5 points, all checked against code and accepted)
- **#34:** the interim refusal is gone. C2 builds the command-job paths in isolation. Production
  admission is unchanged and stays gated on Q3. Existing admission tests
  (`src/executor/submit_linux_test.go:245`) are untouched.
- **Q4 premise corrected:** hosted grant and transfer requests fail before any HTTP call and
  create no rows (`pkg/signerkit/hosted.go:369-381`). Only accepted v1 **sign** requests make
  24 h hosted rows (`sqlite.go:280-283`). The recommendation is unchanged, because those rows
  still need cancel.
- **#31:** `null` evidence (an expiry with no votes marshals a nil slice,
  `sqlitestore/legacy.go:81`) is accepted as an empty legacy vote list.
- **Q5:** r3's page could exceed its own bound: executor-only jobs aren't capped by live slots,
  because refused Submits leave final jobs (`approvalplan/jobnext.go:152`,
  `executor/submit_linux.go:153`). **The recommendation is now a cut:** list only signer records,
  in pages of 100 with the signer's cursor; executor-only jobs are reached by ID. The
  alternative is one combined, phase-tagged cursor. Its "one bounded call" claim is withdrawn.


## Revision 3 changelog (second X-High verify: 7 narrow points, all accepted after checking)
- **#4:** a refusal audit line sets `AuditEvent.TS`. `AuditLog.Write` marshals the event as
  given (`pkg/signerkit/audit.go:118-121`), so an unset TS would be written as zero.
- **#16:** A1a-auth and its edges no longer depend on which way Q3 goes. Both Q3 options keep
  `auth_mode`.
- **Q4 changed:** hosted v1 rows default to 24 h expiry (`sqlitestore/sqlite.go:280-283`), and
  accepted v1 sign requests create them (r4 correction: grant and transfer fail before HTTP). Cutting hosted v1 cancel would
  leave day-long requests with no admin cancel. **The recommendation now keeps hosted
  per-request cancel for v1 and v2** (v1 with durable cancel evidence) and cuts only hosted
  deny-all. That loss is stated plainly.
- **#34:** names the C2 commits that are independent of Q3, and gates the rest.
- **Q5 changed:** "settled in the last 24 h" can't be implemented: neither Summary nor Job
  carries a settle time (`approvalplan/viewtypes.go:163-187`, `executorwire/response.go:9-21`).
  Live caps also don't bound settled records (65,536 local and 200,000 hosted, `bounds.go:79-89`).
  **The recommendation is now a bounded page (100) with a continuation cursor over the signer's
  existing List**. That needs no new wire fields: both sides already page, `approvalwire/local.go:30-35`
  and `executorwire/wire.go:71-72`. Executor execution facts win when present, and signer state
  is the fallback. r2's unconditional "no new wire fields" claim is removed.

## Revision 2 changelog
- I re-checked every point of the X-High verification (`WI2-GAP-RULINGS-VERIFY.md`) against the
  code. I accept all of them except 3, which I rebut in part: #4 (no new audit field is needed), #6 (the
  custody and daemon writers are not reachable from signer-server, so the seam shrinks) and #12
  (one constructor covers both paths).
- 16 items are now OWNER (7, 8, 10, 16, 17, 18, 25, 27, 28, 30, 31, 32, 34, 37, 38, 43); #4 stays ORCH
  because it no longer adds any persisted field.
  They are grouped into **5 one-tap questions**. Three of the questions recommend cutting scope to
  v0.3 where that makes v0.2 smaller and safer: transfer, revoke and update stay on today's path;
  v1 requests leave deny-all and cancel; and the async surface is minimal.
- I fixed the ORCH rulings the verification found broken: 1, 3/5, 6, 11, 12, 15, 22, 26, 29, 35,
  36, 41. #35 now follows the spec (`sending` at the bound) and no longer needs the owner.
- I redid "startable now": each lane names the question it waits on.

Abbreviations: **S** `docs/plans/v0.2/approval-lifecycle-spec.md`, **W**
`docs/plans/v0.2/wave3-lanes.md`, **A** `a10-audit-model.md`, **J** `journey-e2e-plan.md`,
**P** `phase-a-plan.md`, **BP** `docs/BUILD-PLAN.md`. Code paths are relative to the
integration worktree at `2b54fd4`. Quoted blocks are ready to append to `wave3-lanes.md` (no
person names, personal paths or infrastructure). "Check" lines are working notes and are not for
committing.

**Result:** 27 ORCH, 16 OWNER (5 questions). The critical path's first owner gate is **Q1**
(A8 commit 6, the config section).

---

## Owner questions (5, in critical-path order)

**Q1 — Config file grammar (blocks A8 c6, then B1w; item 25).**
Durations in `[approvals]` are written Go-style (`"24h"`, `"168h"`). An empty, zero, negative
or out-of-range value refuses to start and names the key. `retention` (when settled records lose
their details) is limited to 1h..168h, so it can never outlast the fixed 7-day deletion.
`allowed_uids` is a list of whole numbers.
- **Recommended: yes.** One strict format. A typo stops the signer loudly instead of silently
  keeping data longer or shorter.
- Alternative: also accept day units (`"7d"`). Friendlier, but we would write and test our own
  parser.

**Q2 — Hosted signer refusals and lists (blocks A10 c6, then A11; items 7, 8, 10).**
(a) When the new approvals endpoint is over its rate limit, it answers "busy — retry", the
answer it already gives under database contention. The budget is its own bucket of 600/min,
like `/v1/poll`, and the agent-side coordinators retry with their usual backoff. (b) A vote
whose challenge is stale, from another login session, from before a restart, or forged is
refused and logged as one reason, "stale_challenge". The server can't tell these apart. (c) The
operator's pending list pages with an opaque cursor in a `v2_cursor` parameter, 50 per page; a
bad cursor gets a 400.
- **Recommended: yes to all three.** No new error code. Every bad vote is still refused; only
  the log reason is less specific, as v1 rows already are. The cursor stays opaque to the UI.
- Alternative: a new `rate_limited` error code, and a larger vote token that carries its own
  binding so "other session" can be logged separately.

**Q3 — Scope of the new approval path in v0.2 (blocks A13b, and C2's execution of
non-command kinds; A1a-auth needs any answer; items 16, 17, 18, 34).**
`run`, `run_batch` and `request_grant` move to the new path (sync, and async for run/run_batch).
**`transfer`, `revoke_server` and `update_gate` stay on today's v1 path, synchronous only**,
exactly as network reads already do. Their cards still get the new challenge and legacy label.
The executor refuses them. **Under either answer** the agent's result keeps showing *how* a
write was authorized (`auth_mode` = human or grant, approved records only, one new field on the
unshipped v2 wire). Answering either way approves that field.
- **Recommended: yes.** It cuts the two-leg transfer report, the "exit 0 but not confirmed"
  rules and executor admin/transfer support to v0.3. None of them is needed for the v0.2
  journey, and today's paths for them already work and are tested.
- Alternative: port all six tools to the new path now. That needs a new transfer
  success/failure table (including receipt checks) and new meanings for "failed" on admin tools.

**Q4 — Cancel and deny-all scope (blocks D1a, then D2; items 26-32).**
Background: an old-style v1 request on the **local** Telegram signer lives at most 5 minutes.
On the **hosted** signer, each accepted v1 **sign** request is a row that lives **24 hours** by
default. Hosted grant and transfer requests are refused before any network call and create no
row.
Proposal:
- Telegram `/deny_all` and `/cancel` cover new-path records only; local v1 requests expire within
  5 minutes and can be denied with one tap.
- The hosted signer keeps **per-request admin cancel for both v1 and v2 rows**. A v1 cancel's
  audit record survives a crash: it uses the expiry outbox, with a versioned evidence object
  naming the admin.
- **Hosted deny-all ("cancel everything pending") moves to v0.3.**
- The `/deny_all` confirmation is one button under the full list. It works only for you, in your
  private chat, within 5 minutes, and once. If the list is too long to show in full, deny-all
  refuses rather than truncating.
- **Recommended: yes.** Nothing that can live for a day loses its cancel button. What we give up
  is hosted one-click cancel-all: in an emergency, a hosted admin cancels row by row (each row
  also expires within 24 h). That avoids a whole snapshot API, and the v1 snapshot binding on
  Telegram.
- Alternative: build all of it as specified. Local v1 requests join snapshots and get a
  "canceled" result (answered to old clients as "denied"), and hosted deny-all gets its HTTP API.

**Q5 — Async results surface for the agent (blocks C3, then D3; items 37, 38, 43).**
- **Cut to the simple form.** `list_pending_approvals` lists **signer records only**: one page
  of at most 100, in the signer's List order, with the signer's own `cursor` as the only
  continuation. Each record's execution facts come from the executor when it holds that job
  (joined by request ID), otherwise from the signer, tagged with their source. Approval status
  always comes from the signer.
- Jobs the signer never recorded aren't listed. These are a Submit still in flight, or one the
  signer refused. They are reached only through `await_approvals` with their ID. Such a job has
  no card and can't run until the signer records it. After an MCP restart, an agent that
  resubmits while the executor is still retrying could cause a second card. The docs say so.
- `status` shows only the agent's own queue counts; signer-wide health goes to the operator's
  logs.
- The MCP live log records an async result only in the MCP process that submitted it.
- **Recommended: yes.** One bound (100), one continuation, no new wire fields, no producer
  change.
- Alternative: one combined, phase-tagged cursor. It walks the signer's records first, then the
  executor's jobs that have no signer record. Every page holds at most 100 items across both
  phases. That needs a per-page signer lookup for the executor phase. Adding settle and creation
  times (wire fields) would allow a time filter, but the result still has to be paged: the
  stores hold up to 65,536 local and 200,000 hosted records.

---

## Items

### A8

**1. Early taps on lifecycle cards: ORCH (fixed in r2: edits covered).**
Check: `pkg/signerkit/lifecycle/legacy_prepare.go:173-184` (`live` is set after `Deliver`);
`notify.go:290-294` (`SendCard` before `CardDone`); `notify.go:177-180` (`EditCard` before its
confirmation is committed); S:692 (the new challenge is valid only once the edit is confirmed).
The carry-forward fix exists only on the direct path (`6851765` on `wi2/a8`).
> **Ruling 2026-10-22 — early taps on lifecycle cards (orchestrator).** A8 carries the
> early-callback fix onto three cases: a legacy request still delivering, a v2 card whose
> `CardDone` is not committed, and a v2 edit entry whose confirmation is not committed. The tap
> must already match the destination's user and chat; it is then held in a per-handle FIFO
> (4 per handle, 64 in total). The lifecycle signals readiness per handle (legacy live,
> `CardDone` committed, edit confirmed). Held taps then go through the normal
> `VoteLegacy`/`Vote` path in arrival order, before any later tap on that handle, with every E51
> check re-run on committed state. A tap that overflows the FIFO is answered "not ready — tap
> again" and changes nothing. A failed delivery, send or edit, retirement, recovery (a new
> generation), Close, or 10 s → each held tap is refused like a stale tap (one audit line). A held
> tap never makes a revision-0 Approve valid. **Lane:** A8. **OWNS exception:** readiness hooks
> in `pkg/signerkit/lifecycle/{legacy.go,legacy_prepare.go,notify.go}` and their tests.
> **Tests:** Approve and Deny before registration on the legacy path, the first-card path and
> the edit path; edit failure; retirement; recovery. The preparing-refusal tests stay unedited.

**2. Legacy terminal edit: ORCH (verify: fine).**
> **Ruling 2026-10-22 — legacy terminal edit (orchestrator).** The resolution that wins in
> `LegacyService` (approved, denied, deadline/disconnect → "expired") schedules exactly one
> `LegacyNotifier.EditStatus` call. It runs only for a request that reached `live`, outside the
> service mutex, on a goroutine in the service's join group, and Close cancels it. Its error is
> logged and ignored. **Lane:** A8. **OWNS exception:** `pkg/signerkit/lifecycle/legacy.go` and
> its tests.

**3. Record handle and status reasons: ORCH (fixed in r2: adapters named, serialized with #5).**
Check: as in r1. The verification is right that the interface change touches three test
adapters: `pkg/signerkit/daemon_approvals_test.go:342`, `lifecycle/close_test.go:437` and
`lifecycle/lifecycletest/notifier.go:49`.
> **Ruling 2026-10-22 — card display inputs (orchestrator).** `Notification` gains
> `RecordHandle` (memory only). `Notifier.EditStatus` takes a `StatusDisplay{State, Reason,
> Provenance}`, built by a new pure `approvalplan.DisplayStatus(rec, now, s)`. `DisplayState`
> stays unchanged and remains the dedup key. The renderer adds a `Record: <handle>` line to
> every v2 card (a legacy card shows its legacy handle), and the E49 edit renderer prints the
> reason. R1 is unchanged. **Lane:** A8. **OWNS exception:** the additive function in
> `src/approvalplan/notify.go`; `lifecycle/{deps,notify}.go`; the three test adapters named above
> (signature only); `src/approvalreview/telegram.go` with **named** golden updates. **Order:**
> this commit merges before A10 c8 is cut (see #5).

**4. Slash-command refusal audit: ORCH (rebutted in r2: no new field needed; r3: TS set).**
> **Superseded in part 2026-10-23** by the A8 command-gate security ruling in `wave3-lanes.md` (Rulings 2026-10-23 — A8): `wrong_user` and `not_private` refusals are silent and coalesced, authenticated refusals are rate-limited, and `replay` is set only for `redelivered`.
Check: the verification is right that no existing structure has command, sender or chat fields
(`src/approvalplan/audit.go:11-26`, `pkg/signerkit/audit.go:39-50`). r2 drops those fields, so
nothing new is persisted.
> **Ruling 2026-10-22 — E64 refusal audit and reply (orchestrator).** Each slash command the E64
> gate refuses writes one fail-open local AuditLog line in A6E's existing inert encoding: an
> `AuditEvent` with `status = approval-command_refused{<reason>}` and `approval = {transition:
> "command_refused{<reason>}", replay: true}`. `<reason>` is one of `wrong_user`, `not_private`,
> `forwarded`, `redelivered`, `unknown_command`, `ambiguous_id`. `ts` is set to the signer's
> wall-clock time at refusal (`AuditLog.Write` marshals the event as given). `request_id`,
> `commands` and `servers` are empty, and no command text, arguments, sender ID or chat ID is
> written. A reply is sent only when the linked chat ID
> equals `allowed_user_id`; otherwise nothing is sent. `/start` is unchanged. **Lane:** A8 (the
> gate).

### A10 commits 6-8

**5. `lifecycletest` against hosted: ORCH (fixed in r2: serialized with #3).**
> **Ruling 2026-10-22 — hosted conformance (orchestrator).** A10 c8 may refactor
> `pkg/signerkit/lifecycle/lifecycletest/**` (except `runtime.go`) so that the store-agnostic R1
> properties sit behind a small engine interface: replay and idempotence, clock facts, crash
> prefixes through an uncertain-commit wrapper, stop, and flush recovery. Every existing subtest
> name and every local `Run` behaviour stays. Local-only: `Grants`, `EditRetry`,
> `LiveFailureContrast`, notifier. New `pkg/signerkit/hosted/approvals_v2_conformance_test.go`
> runs the common set against `ApprovalV2Engine`, with a counting wrapper showing each mutation
> went through `BeginV2`. **Order:** A10 c8 is cut after A8's `EditStatus` interface commit (#3)
> merges. From then, no other lane writes `lifecycletest` until c8 merges.

**6. Hosted diagnostic writers: ORCH (fixed in r2: reachability corrected).**
Check: signer-server never calls the custody or v1 socket handlers. Custody events come only
from `Service.Lock/Unlock/RotateTo*` (`service.go:191-237`), and nothing under
`pkg/signerkit/hosted/` or `src/signer-server/` calls them (grep finds none). The `daemon.go`
stderr lines (`:745,779,1056,1085,1100,1340,1471`) sit in local socket handlers. Hosted signing
goes through `hosted_sign.go:56` and the sink (`:138`). So r1's `custody.go`/`daemon.go` edits
are dropped. The reachable writers are `main.go:257,264,884`, `http.Server.ErrorLog`
(`main.go:354`) and `approvals_v2_engine.go:106`.
> **Ruling 2026-10-22 — hosted diagnostics (orchestrator).** A10 c7 routes every writer on the
> signer-server path through the process transport (A item 1): the append-only sink at
> `main.go:257`, the logger at `:264`, `logf` at `:884`, `http.Server.ErrorLog`, the engine's
> `log.Default()` fallback and `log.SetOutput`. `custody.go`, `daemon.go` and `socket.go` don't
> change: signer-server never reaches them. The commit's fd-2 test proves this. If an embedder
> later calls custody methods on a hosted `Service`, that is a D3 note, not v0.2 code. **Lane:**
> A10 c7; no exception beyond its OWNS.

**7. Approvals limiter: OWNER → Q2(a).**
Check: the existing limits are 120/min for sign and 600/min for poll (`hosted/server.go:164-165`).
`src/mcp/sign/approval_client.go:28` "never retries" (r1's claim that clients retry was wrong;
the coordinators retry, E25). The spec pins `busy` to `SQLITE_BUSY` (S:456). If Q2(a) is yes: A10
c6 adds the bucket and the refusal, and the busy-detection text in S:456 gains "or the
approvals rate limit".

**8. Challenge refusal classes: OWNER → Q2(b).** If yes: as r1's ruling, with
`session_mismatch` not emitted for v2 and A11's other-session test expecting `stale_challenge`.

**9. Operator-role check: ORCH (verify: fine).**
> **Ruling 2026-10-22 — v2 operator role (orchestrator).** E7's HTTP step 4 stays for both
> planes. In addition, `ApprovalV2Engine.Vote` re-reads the voter's role inside its transaction
> and refuses a non-`operator` with `invalid_request` and no event. **Lane:** A10 c6.

### A11

**10. Global v2 pending pagination: OWNER → Q2(c).** If yes: as r1's ruling (A11 owns a new
`sqlitestore/approvals_v2_pending.go`; ordered by `created_at, client_id, sub_principal,
request_id`; opaque base64url cursor; D2 reuses it).

**11. v1 UI redaction: ORCH (fixed in r2: the sweep was right).**
The spec's unconditional byte requirement (S:1843) conflicts with redaction. This ruling grants
an acceptance exception; it does not reconcile the two.
> **Ruling 2026-10-22 — v1 human-UI redaction (orchestrator; named acceptance exception).**
> `/ui/pending` and the v1 detail view put the redacted command in both `commands[]` and
> `command_details[].cmd`; `sha256` stays the hash of the raw bytes. S:1843's "v1 bytes
> unchanged" is narrowed to rows whose commands the redactor leaves unchanged. A named golden pins
> a secret-bearing row. Machine `/v1/*` bytes are untouched. **Lane:** A11.

**12. Vote MAC key: ORCH (fixed in r2; partly rebutted).**
Check: `hosted.New` (`config.go:104`) builds through `NewServer` (`config.go:129`), and direct
embedders call `NewServer` (`server.go:114`) and then `AttachHuman` (`server.go:211`). So one
point covers both paths. With Go 1.25 (`go.mod:3`), `crypto/rand.Read` cannot return an error:
the runtime crashes instead. So there is no failure path and no zero key.
> **Ruling 2026-10-22 — vote key placement (orchestrator).** `NewServer` fills a 32-byte key
> from `crypto/rand`. It is never persisted, never lazy and never global. `AttachHuman` uses that
> key. **Tests:** two servers get different, non-zero keys; a challenge from one fails on the
> other; both `New` and `NewServer`+`AttachHuman` construction issue verifiable challenges.
> **Lane:** A11. **OWNS exception:** that hunk in `pkg/signerkit/hosted/server.go`.

**13. Duplicate POSTs: ORCH (verify: fine).** As r1: the core's precedence (`apply.go:497-509`)
decides; the A11 acceptance cases are amended as listed in r1.
> **Ruling 2026-10-22 — v2 vote replay precedence (orchestrator).** E7 step 3's v2 refusal is
> `vote_refused` or `vote_replay` as the frozen core classifies it. A11 tests: N=1 approve, then a
> same-operator POST → 409 and `vote_replay`; another operator → 409 and `vote_refused{resolved}`;
> N>1 pending, a stale challenge → `vote_refused{stale_challenge}`, a fresh one → `vote_replay`.

### A12

**14. Malformed IDs: ORCH (verify: fine).**
> **Ruling 2026-10-22 — malformed IDs (orchestrator).** Strict decoding stays. A malformed ID
> through the daemon gets local `invalid_request` with zero hosted requests. The grammar 404s are
> tested at A10's HTTP boundary (c6). The proxy test uses a valid ID answered with the hosted
> `not_found` envelope. S:1862 is amended to this.

**15. Hosted forwarder: ORCH (fixed in r2: grant handlers and the legacy switch).**
Check: `daemon.go:917-925` and `:992-995` call `caller.runtime.Current()` whenever a runtime is
attached; `daemon_approvals.go:607` keeps the direct path only when `PrepareLegacy == nil`.
Hosted holds no v2 grants (S:1866: "v2 reveal, grant and transfer fail closed" through the
proxy).
> **Ruling 2026-10-22 — hosted forwarder runtime (orchestrator).** `ApprovalRuntimeConfig` gains
> `Forwarder`. `NewApprovalRuntime` requires exactly one of {`Forwarder`} or {`Store`, `Legacy`,
> `NewEngine`}, and refuses `PrepareLegacy` in forwarder mode, so v1 stays on `d.Backend`. Peer
> and `AllowedUIDs` checks run as today. No engine, Reopen or recovery loop; `Run` returns when
> its context ends; Close joins in-flight calls; Status reports "hosted forwarder". `revoke_grant`
> and `list_grants` in forwarder mode act on the v1 map only, as with no runtime: hosted mode
> holds no v2 grants. **Lane:** A12. **OWNS exception:** a mode check in `daemon.go`'s
> `handleRevokeGrant`/`handleListGrants` (the two `caller.runtime != nil` branches).

### A13b

**16. Authorization provenance: OWNER → Q3 (either answer approves it).** One-commit lane **A1a-auth** adds
`Summary.auth_mode` (omitempty), set **only when the decision is `approved`**: `grant:<id>` when
`DecidedBy` carries the grant prefix, otherwise `human`. This matches `daemon.go:320`'s
`authMode`. A deny has an operator in `DecidedBy` (`apply.go:521`) and gets no `auth_mode`.
Named view and `approvalwire` golden updates, and a critique pass.

**17. Transfer two-leg report: OWNER → Q3 (recommended cut).** If transfer stays on v1, no
reduction is needed. If the owner ports it, the table must also cover missing, malformed or
wrong-transfer-ID receipts (`transfer.go:184`) and amend E28/E29, since `failed` means a known
non-zero exit (S:554-561). The jobplan annotation edits would need an exception for A13b.

**18. Exit-zero postconditions: OWNER → Q3 (recommended cut).** If revoke and update stay on v1,
`StepOutcome` never sees them. Otherwise an E29 amendment must cover a missing marker, a
malformed marker and a confirmed hash that differs from the approved one (`update_gate.go:219`).

**19. OQ1 fold: ORCH (verify: fine).**
> **Ruling 2026-10-22 — OQ1 in A13b (orchestrator).** Synchronous drafts carry
> `requested_validity_seconds = 300`. One named edit to `src/mcp/jobplan/draft.go` is allowed if
> `DraftOptions` must carry it. Acceptance follows J:79 (frozen expiry, terminal timeout, rejected
> late tap), plus a separate shortened-wait abandonment test.

### A13b-docs

**20. Network keeps v1 guidance: ORCH (verify: fine).**
> **Ruling 2026-10-22 — reason sweep scope (orchestrator).** "Reconcile by Get" applies to v2
> records only. The v1 "verdict undelivered — do not auto-retry" guidance stays for
> `run(network:true)` and reveal+network, and for every tool Q3 keeps on v1.

**21. WI1 writers: ORCH (verify: fine).**
> **Ruling 2026-10-22 — cross-work-item writers (orchestrator).** P5.2 and P7.1 land on main. The
> orchestrator merges main into integration before cutting A13b-docs and before cutting C3. A WI1
> change to `src/mcp/server.go`, `src/mcp/tools/**`, `README.md`, `AGENTS.md` or
> `docs/design.md` that lands while A13b, A13b-docs or C3 is open is merged into that lane's
> branch by the orchestrator before the lane merges.

### B1w and the new lane B1f

**22. Performance gates: ORCH (fixed in r2: cap ownership).**
Check: `src/approvalplan/bounds.go:87` (`LocalRecordsTotal`);
`filestore_acceptance_linux_test.go:207` hard-codes 65 536/512.
> **Ruling 2026-10-22 — B1 performance gates (orchestrator).** Acceptance adds two non-race runs
> under `$LOCK`: `go test -count=1 -run '^TestFileStoreGrantStress$' ./pkg/signerkit/lifecycle/`
> and `go test -count=1 -run '^$' -bench '^BenchmarkFileStoreStartupMeasurement$' -benchtime=1x
> ./pkg/signerkit/lifecycle/`, with filesystem, CPU and disk recorded. If Startup exceeds 10 s,
> B1f lowers `LocalRecordsTotal` (S:2016 already authorizes it) and moves the benchmark's
> population check with it, as one named commit. **Lane:** B1f. **OWNS exception (conditional):**
> that constant in `src/approvalplan/bounds.go` and `filestore_acceptance_linux_test.go`.

**23. Process fault seams: ORCH (verify: fine).**
> **Ruling 2026-10-22 — test-only fault protocol (orchestrator).** New `internal/faultpoint`,
> compiled in only under build tag `sshgate_faults`; untagged it is no-ops. It is activated by
> `SSHGATE_TEST_FAULT=<cutpoint>`; a cutpoint exits with a fixed code or returns an injected error
> (`EBADF` for flock). Release proof: without the tag, `go tool nm` on the signer and executor
> binaries shows no `faultpoint` symbols, and the closure checks stay green. B1f owns the package
> and the file-store cutpoints. B1w adds `src/signer/cmd/sshgate-signer-telegram/process_faults_test.go`.
> B2 adds Renotify/send/edit cutpoints in `lifecycle/notify.go` (narrow exception). C2 adds the
> executor's (item 41).

**24. Typed fatal store errors: ORCH (verify: fine).**
> **Ruling 2026-10-22 — typed fatal store errors (orchestrator).** `AcquireFileStore` also
> fstats the held descriptor and refuses a wrong owner UID or mode. Every acquisition failure
> wraps `lifecycle.ErrStoreFatal`. B1w's `main.go` exits non-zero on `errors.Is(err,
> ErrStoreFatal)` before attach and `Listen`. Later failures stay recoverable (diagnosed
> `lifecycle_unavailable`, ownership kept, retry). Never classified by string. **Lanes:** B1f
> (store; `filestore_linux.go`, `filestore_other.go`), B1w (main.go).

**25. Config grammar: OWNER → Q1.** The spec already sets the `pending_validity` and
`report_horizon` ranges (S:1679). The new choices are the syntax, the zero/empty handling and the
`retention` range. Deletion stays fixed at 7 days.

### B2

**26. `/renotify` and admin resolution: ORCH (fixed in r2: composite resolver).**
Check: `lifecycle/projections.go:169-170` (v2 handle and request-ID indexes only); legacy
requests live in `LegacyService` (`legacy.go:55`).
> **Ruling 2026-10-22 — admin resolution (orchestrator).** New `pkg/signerkit/lifecycle/admin.go`:
> `Engine.ResolveAdmin(handleOrRequestID)` over the v2 indexes, and `Engine.Renotify(handle)`
> through `mutateLocked` (Clock first). `/renotify` is v2-only. The runtime composes the resolver
> for D1b's `/cancel`. If Q4 is answered yes, it is v2-only. If Q4 keeps v1 items, the resolver
> checks both owners: a match in both, or more than one match, → "ambiguous id — use the handle
> from /pending". While the v2 generation is unavailable, every resolution answers "signer
> recovering — try again", because ambiguity can't be ruled out. No machine admin kind. **Lane:**
> B2 (`admin.go`; the composition hunk in `daemon_approvals.go`, which B2 already writes).

### D1a / D1b

**27. Legacy snapshot binding: OWNER → Q4 (recommended: no v1 items).** If v1 is kept: items bind
the live request instance and its handle, compared and canceled under the same `LegacyService`
mutex; preparing requests are excluded.

**28. Local v1 cancel semantics: OWNER → Q4 (recommended: no v1 cancel).** If kept: canceled maps
to the frozen v1 `denied`, the audit reason is `canceled`, and tombstone taps get
`legacy_vote_refused{canceled}`.

**29. Snapshots across recovery: ORCH (fixed in r2: uncertain outcome).**
Check: a commit can land and still return uncertain (`filestore_linux.go:249-255`).
> **Ruling 2026-10-22 — snapshot ownership and per-item outcomes (orchestrator).** The snapshot
> manager (new `lifecycle/snapshots.go`) is held by the stable `ApprovalRuntime`. Publishing a
> new v2 generation invalidates every snapshot; confirming one then answers "snapshot expired —
> send /deny_all again". A confirm applies each item as its own AdminCancel and reports one of
> three outcomes per item: `canceled` (commit confirmed); `not attempted` (with a reason:
> resolved, plan changed, signer recovering, busy); or **`outcome unknown — check /pending`**
> when the AdminCancel returned `storage_uncertain`. An attempted item is never reported "not
> canceled". **Tests:** landed and unlanded uncertain cuts on one item; replacement in the middle
> of a confirm. **Lane:** D1a. **OWNS exception:** a runtime field and the invalidate-on-publish
> hunk in `daemon_approvals.go`.

**30. Selection and confirmation: OWNER → Q4 (the confirmation contract).** Fixed in r2: legacy
reservation has no live cap (`legacy.go:126-151`), so r1's "can't happen" was false. The
12-message overflow refusal stays real, and enumeration is bounded (stop at the render limit plus
one). If v1 items are kept, their hash column shows "—".

### D2

**31. Hosted v1 cancel evidence: OWNER → Q4 (r3: recommended to keep, durable).** Under Q4
yes, D2 builds it to this design: `store.LegacyResolver.CancelLegacy` gains an `admin` parameter
(`store/store.go:329-332`; named change). Its transaction writes an outbox row with event key
`legacy-cancel:<sha256(request_id)>:<unix>`. The `evidence` becomes a versioned object
`{"v":1,"reason":"canceled","admin":…,"votes":[…]}`. A bare JSON array, or `null` (an expiry with
no votes marshals a nil slice), still decodes as v0 expiry evidence: `null` is an empty vote list
(today's format, `sqlitestore/legacy.go:80-84`). Anything else is recorded
as `evidence_malformed` and still flushed. The flusher (`approvals_v2_legacy.go:66-69`) takes
`Lifecycle` from the key namespace and sets `AuditCall.Operator` to the admin. No DDL change; the
frozen-wire checks are extended. **OWNS exception (D2):** `pkg/signerkit/store/store.go` (that
signature), `sqlitestore/legacy.go`, `hosted/approvals_v2_legacy.go`. Critique pass before code.

**32. Hosted deny-all API: OWNER → Q4 (recommended: moves to v0.3).** If kept: the r1 HTTP
schema plus a named `sqlitestore` operation for the cross-plane read (the connection is private,
`sqlite.go:84`), with the specified per-item admin and busy checks preserved.

### C2

**33. Contention test: ORCH (verify: fine).**
> **Ruling 2026-10-22 — C2 contention test (orchestrator).** Run 100 concurrent submitters at
> unchanged production limits and report admitted-job latency and refusals separately, early in
> C2. If the latency gate fails, C2 stops and a separate durable-format design goes to the owner.
> No implicit schema change.

**34. Executor intake scope: OWNER → Q3.** If yes: the executor's admission
(`src/executor/draft_linux.go:34-45`) refuses tools other than `run`/`run_batch` with
`invalid_request` before durable admission or any signer call, and a test pins it. **r4, C2
split:**
- **Independent of Q3 (startable now):**
  - C2a: Submit after the job commit, and the E63 bounded return (#35).
  - C2b: the `WaitMany` waiter and nudges.
  - C2c: `JobNext` execution, Claim, step and report for **command jobs**, built and tested in
    isolation (unit tests on command-job drafts).
  - C2d: retention and E75 storage.
  - The contention test (#33).
  - Production admission (`draft_linux.go`) is not changed, and its existing tests stay
    untouched (`submit_linux_test.go:245`).
- **Gated on Q3:** wiring execution into production admission, and any refusal or support for
  `revoke_server`, `update_gate` and `transfer` jobs.

**35. Submit wait bound: ORCH (fixed in r2: follows the spec).**
Check: S:2082 (at the bound, answer `sending` explicitly) and S:2116 (test: `sending` after 65 s
when the notifier stalls). r1's "omit `notification_status`" was wrong.
> **Ruling 2026-10-22 — exec_submit response bound (orchestrator).** The 65 s starts when the
> executor's local job commit returns, and covers the signer Submit, its retries and
> reconciliation. The answer is the job's committed view. `notification_status` is the observed
> value once the signer record exists, `sending` at the bound when the notifier has not left
> `not_started`/`sending`, and omitted only when no signer record was ever observed. C3's 75 s
> deadline is unchanged. **Tests:** slow Submit, persistent `busy`, lost response, notifier
> stall. C2 commits the response golden before C3 is cut.

**36. Remediation after restart: ORCH (fixed in r2: read-jail only).**
Check: exits 65 and 77 share an annotation but differ in class and retry advice
(`jobplan/outcome.go:86-98`), so a general mapper lacks inputs.
> **Ruling 2026-10-22 — read-jail remediation projection (orchestrator).** jobplan exports its
> three read-jail annotation texts as constants and a pure `ReadJailRemediation(annotation)
> (message string, ok bool)`. The class is `read_jail_unavailable`, with no retry advice. A drift
> test keeps it in step with `StepOutcome`. C3 matches `Results[i].Annotation` exactly; any other
> annotation gets no remediation and is never parsed. No wire change; `Hint` keeps its meaning.
> **Lanes:** C2 (narrow `src/mcp/jobplan` export), C3 (the consumer). **Test:** restart with
> tiny output caps.

### C3

**37. Live-log after collection elsewhere: OWNER → Q5.** The verification is right: `Entry`
has no `request_id` (`livelog.go:33-45`), logging can be off (`:83-85`), and the log rotates.
Under Q5 yes, only the submitting process logs; this needs no schema change.

**38. Joined tools' schema: OWNER → Q5 (r3: made implementable).** There is no time filter: no
settle time is exposed (`viewtypes.go:163-187`, `executorwire/response.go:9-21`). Paging uses
the existing cursors (`approvalwire/local.go:30-35`, `executorwire/wire.go:71-72`). Page = one
signer List page (≤100) in the signer's order. The executor join walks `exec_list`, which the executor's job-file cap bounds
(`ExecutorJobFiles = 10000`, `bounds.go:92`). **r4:** under Q5 yes, the page holds signer
records only (≤100) and the tool's `cursor` is the signer's cursor, passed through opaquely.
Executor-only jobs are not listed. Precedence:
- approval fields come from the signer;
- execution fields come from the executor's `Job` when the executor holds the job
  (`JobState`, steps, class, executed ordinals; `jobview.go:45`);
- otherwise they come from the signer's `ExecutionStatus` (`view.go:62`);
- each field carries a `source` tag.
A signer `executing` or `unreported` never hides an executor `final`. C3 freezes the structs and
goldens with a critique pass before its commit 2.

**39. async + network: ORCH (verify: fine).**
> **Ruling 2026-10-22 — async and network (orchestrator).** OQ2's async+reveal refusal is checked
> first. Otherwise reads ignore `async`, and a network read keeps P4.4's synchronous route. The
> network flag is never dropped while building an executor job. Tested with OQ2.

### C5

**40. C5 contract: ORCH (verify: fine).**
> **Ruling 2026-10-22 — C5 contract (orchestrator).** C5 is cut after the journey branch reaches
> main and integration. It also owns J5's files (`tests/journey/async_test.go` and the durable
> restart cases). Acceptance splits into C5a (async and restart, after C2, C3 and C4) and C5b
> (final card display, merge-only after D1a). The async-reveal success scenarios become OQ2
> refusal tests. The orchestrator reconciles the J4/C4 Makefile and docs at the journey merge.

**41. Executor crash hooks: ORCH (fixed in r2: build gate).**
> **Ruling 2026-10-22 — executor fault hooks (orchestrator).** C2 owns the executor cutpoints on
> `internal/faultpoint` and the executor's release-absence proof; C5 only uses them. B1f is
> merged into C2's branch **before** C2 builds the hook commit, so that commit passes on its own.

### A0b

**42. Gate byte proof: ORCH (verify: fine).**
> **Ruling 2026-10-22 — A0b proof (orchestrator).** BP's proof is authoritative: same sorted
> closure, identical unstripped `.text`, same symbol names, sizes and kinds. P's stripped-hash
> recipe is superseded. The exact commands go into A0b's contract when it is cut (after all of
> WI1), with a re-check then that only `src/redact` changes inside the closure.

### D3

**43. Metrics visibility: OWNER → Q5.**

### Ownership and DAG fold

> **Ruling 2026-10-22 — DAG and ownership fold (orchestrator).** The serial orders A10 → A11 →
> D2, A8 → A12 → B1w and A13b-docs → C3 stand. New edges: A8's `EditStatus` interface commit →
> A10 c8 (cut); B1f → B1w; B1f → C2's hook commit (build, not just merge); journey-on-main → C5;
> D1a → C5b (merge-only); P5.2 and P7.1 writer-serial with A13b, A13b-docs and C3; A1a-auth →
> A13b and C3 (under either Q3 answer). **C2's early start:** cut after C1 and A6; A12 → C2 becomes
> merge-only for its last commit (the hosted-proxy harness). Shared protocol is frozen before its
> consumer is cut: C2's `exec_submit` golden before C3's cut; C3's tool schema before C3 c2.
> Already-adopted prerequisites are written into §2: A1a-oq1 → A7 and A10, the recovery
> ownership ruling, and PhaseB-close → D1a (merge-only).

---

## Startable now (A8 c1 and A10 c5 merging)

- **A8 c2-c5:** go now (rulings 1-4). **c6** (`main.go`, `[approvals]`) waits for **Q1**.
- **A10 c7 and c8:** go now; c8 is cut after A8's `EditStatus` interface commit (#3) merges.
  **c6** goes now except the limiter-refusal hunk, which waits for **Q2(a)**.
- **B1f** (items 22-24): go now.
- **C2a-C2d and the contention test** (#34's r4 split): go now, as command-job paths built and
  tested in isolation. Production admission wiring waits for **Q3**. The hook commit needs B1f merged into C2's branch first; the
  proxy-harness commit needs A12.
- **Orchestrator:** fold the ORCH rulings and the acceptance corrections (13, 14, 19, 20, 40,
  42), and merge the reviewed journey branch to main ahead of C5.
- **After any Q3 answer:** A1a-auth (the wire field is in both options).
- **Not yet:**
  - A11: waits for all of A10 and Q2.
  - A12.
  - A13b: waits for A12 and Q3.
  - A13b-docs: waits for P3's docs on main.
  - B1w: waits for A12, B1f and Q1.
  - B2.
  - D1a, D1b and D2: wait for Q4.
  - C3: waits for A13b-docs and Q5.
  - C5, A0b.
  - D3: waits for Q5.
