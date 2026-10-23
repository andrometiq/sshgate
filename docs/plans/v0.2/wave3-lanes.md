# Work item 2, wave 3: every remaining lane to v0.2 (A6 → D3)

- **Date:** 2026-10-15. **Integration:** `feat/76-65-approval-lifecycle` @ `4262933`
  (worktree `the wi2 worktree`; merged and reviewed: A1a, A1a-net, A1b, A2, A3 + follow-up,
  A4, A5, B0). **main** @ `8d498d5` (#22 P2 + the Telegram callback-binding fix `6cf81a1`/`5bb54bf`).
  **feat/22-p4** @ `2e7951c` (P4.0a-c, lanes S and M; lane G waits for #22 P3).
- **Sources, binding in this order:** `docs/BUILD-PLAN.md` "Work item 2" (`wt-wi2:689-823`);
  `approval-lifecycle-spec.md` r5.8 + r5.9 rulings (`:846`, `:1179-1180`, `:1195`)
  = "the spec"; `WI2-PHASE-A-PLAN.md` §1 (GATE-PROOF), §4 (contract format, common forbidden list),
  §5 Q2 (`LOCK=$LOCK`), §7 (P4 obligations), §8 (review-bounds
  ruling); `P4-PLAN-v7.md` §7.4 (prepared legacy approval, steps 0.1-0.9).
- **Scope:** v0.2 = all of work item 2; the public plan closes it at D3.
- **What this file adds:** base strategy, the wave-3 DAG with early starts, lane contracts in the §4
  format with reviewable commit sequences, and the ambiguities found against the merged code.
  Everything in the spec's sub-phase text not changed here stands; each builder reads its spec
  section in full (line ranges below).

---

## 0. Grounding (read for this plan)

| Fact | Evidence |
|---|---|
| Trial merges are clean: integration+main, integration+feat/22-p4, and (integration+main)+feat/22-p4 | `git merge-tree --write-tree` (no conflicts, no refs moved) |
| The integration branch lacks the callback-binding fix (`ad7407a..5bb54bf` = `telegram.go`, `telegram_cardbind_test.go`, `telegram_transfer_test.go`) and #22 P2; feat/22-p4 has the fix (base `5bb54bf`) but not P2's final commits | `git merge-base`, `git diff --stat` |
| Everything on feat/22-p4 is reviewed GO: `6cf81a1`+`64ec632`+`21c192d` (review note 1-P40-tgfix), P4.0c (`-2-P40c`), lane S @`0e3ca56` (`-1-P4-laneS`), lane M (`-3-P4-laneM`). Lane G and Stage I are open | `local-notes/reviews/` |
| feat/22-p4 changes gate bytes (`src/gate/{verify,errors}.go`, `src/sigwire/{net,payload}.go`), and so does main's P2. GATE-PROOF baselines must be re-measured after each base merge | `git diff --stat` |
| Spec anchors moved (integration+P4 tree): v1 call sites `daemon.go:627,844,1173,1359` (spec `:608,818,1147,1333`); grant short-circuit `:623-626`; `matchGrant :1482`, `isAdminVerb :1535`, `isTransferVerb :1545`, `grantCovers :1552`, `signAll :1573`, `signTransferLegs :1247` (call `:1211`); dispatch switch `:510-523`; `handleRevokeGrant :912`, `handleListGrants :964`; `Service.Close` `service.go:138`; signer `main.go`: explainer block `:129-143`, `signerkit.New :275`, deferred `svc.Close :288-292`, `srv.Listen :321`, TOML decode `:337`, `buildHostedBackend :390`, `buildTelegramBackend :534` with `tb.Run :606`, `doInitFlow :808`; `telegram.go`: `dispatch :437`, `handleCallback :488`, `p:` branch `:503`, `runExplainer :935` | `git grep -n` on the trial tree |
| Hosted anchors hold: `approval.go:94` `Decide`; `server.go:221-223,251,278`; `policy_runtime.go:212` `Server.Close`, `:463` `PolicyRuntime.Close`; signer-server `main.go:214` (spec `:213`), `:340`, `loadAPIKey :782`; `policy_migration_test.go:168` (version-7 "future" row → 8); `main_test.go:349` (`role: "auditor"`) | read |
| A1b's real API (14 declared departures, the reviewer GO joint review 4): `Apply(rec *R1, cmd, now Now, in Inputs) (R1, Answer)`; commands `Submit{Draft, Plan, ReviewSnapshot, RationaleRedacted, RequiredApprovals, AssistDeadline, Allowance}`, `AssistDone`, `CastVote{Card *CardTap \| Hosted *HostedTap}`, `AdminCancel`, `Revoke`, `Tick`, `Flush`, `ShedRecord`, `Delete`, `Claim`, `Report`, `Renotify`, notify steps; `Inputs{Epoch, Settings, GrantLive, Grant *GrantRef, Minted, MintFailed, XferDigests}`; `Answer.MintRequired` (mint, then re-Apply); `View/Class/Next(…, s Settings, grantLive)`; `ApplyJob`, `JobNext(job, now, epoch, JobMemory)`, `JobOnAnswer`, `ExecSubmitAdmit`, `JobRetention`, `JobDeletable`. **Left to engines by A1b:** X5's admission Clock pass, flush-batch ordering, the grant-delete newest-mark | `src/approvalplan/apply.go:53-200`, `review-prompt-A1b.md:5` |
| No draft→plan freeze function exists. `Submit` expects the caller to have frozen `Plan` and built the snapshot; `approvalreview.BuildSnapshot` (`snapshot.go:175`) validates the plan and already refuses Telegram-bound overflow as `request_too_large` (§8 ruling holds) | `plan.go` func list, `snapshot.go:168-238` |
| A3 API: `BuildPreparedSignSnapshot(instance, []LegacySignInput, LegacyMeta, *salt, rules)` `prepared_sign.go:22`; `BuildView(snap, Assist)` `hosted.go:101`; `PackParts(v, handle)` `telegram.go:33`; `DecisionCard(v, handle, parts)` `telegram.go:219`; `BuildLegacySnapshot` `legacy.go:63` | grep |
| `assist.RedactForProvider` takes an `ApprovalPlanV1`; a legacy request is marked only by `RationaleOrigin = synthesized_legacy_v1` with `Rationale = LegacyRationaleText` (`assist/input.go:85-145`). No snapshot-based input exists | read |
| #22 P2 added a second jail line, "the jail failed after the read may have started … its result is not trusted" (`readjail.go:265`, main), and reworded `read_jail_unavailable` (`denial.go:164`) and `runWrite`'s 77 error (`run.go:404`) | `git diff ad7407a main` |
| P4 M added six `network_*` verdicts (`denial.go:23-28`); `denial_shape_test.go:29` still pins 11 | feat/22-p4 |
| srcmut anchors on files wave-3 lanes edit: `P-S-GRANT-NET` (`daemon.go`, `matchGrant`), `P-S-REMOTE-SIGNATURE` (`daemon.go`), `P-S-HOSTED-NET` (`hosted.go`); `P-M-*` in `run.go`, `run_batch.go`, `netroute.go`. Each must match exactly once in HEAD (`scripts/srcmut/main.go:287`) | `scripts/srcmut/sets/p4{3,4}.json` |
| `DurableFileAuditSink` embeds `AuditCall` (`durable_audit_sink_linux.go:88`): A6E's new pointer field must stay `omitempty` so its bytes do not move | read |

---

## 1. Base strategy (orchestrator)

- **M0 — now:** merge `main@8d498d5` into the integration branch. Clean, reviewed, and it brings the
  callback-binding fix A8 builds on and the P2 strings A13a mirrors. Then STD + FROZEN-* and record
  `BASE_GATEHASH` and the sorted gate deps at the new tip (`wi2-baseline/`), since P2 moved the gate.
- **M1 — when A6 has merged, just before cutting A7:** merge `feat/22-p4` (whatever tip is GO then,
  today `2e7951c`) into the integration branch, re-run STD + FROZEN-* + `make test-srcmut
  SRCMUT=P-S-HOSTED-NET,P-S-GRANT-NET,P-S-REMOTE-SIGNATURE` + the seven `P-M-*` IDs, and re-measure
  GATE-PROOF. **Recommended over waiting for main:** main gets P4 only after lane G, which waits for
  #22 P3 (mid-build); waiting would stall the critical path (A7 → A8 → A12 → A13b). It is safe: all
  of it is reviewed GO, the merge is clean, and P4's interim gate refusals keep S+M consistent
  without G. Consequences, accepted: the integration branch cannot reach main before P4 does (v0.2
  needs both anyway), and it uses a real merge, never a cherry-pick, so main later dedupes.
  Merging now instead of at A7's cut is also safe; waiting lets Stage I fixes land first.
- **After M1:** a P4 fix commit that touches `daemon.go`, `backend.go`, `hosted.go`,
  `src/signer/backend/telegram*.go` or `src/mcp/tools/**` is merged into the integration branch by the
  orchestrator before the WI2 lane owning that file is cut, or, if that lane is in flight, before
  that lane merges (the orchestrator merges integration into the lane branch; builders never do).
- **Merge main again** when #22 P3 lands on main and before A13b-docs (§3), so jail doc edits are
  in the base. **A0b** (absolute gate check) stays after work item 1 (WI2 plan §1).

---

## 2. DAG

**This edge list is the one authoritative dependency set** (review-1 #6); every lane's Base in §3
and the merge order in §4 follow it. Edges are "merged into integration before the successor is
cut" unless marked *merge-only* (gates the merge, not the start). `*` = an early start over the
spec's phase gate (spec edge in brackets): B1s, C1, D2 ruled in §5 Q1; **D1a's is new and needs
confirmation (§5 Q10)**.

```
M0  → A6E, A6, A9, A13a, A1a-fr
A6E → A7, A10, A11
A6  → A7, A10, B1s*            [B1: Phase A end]
A1a-fr → A7, A10
M1  (after A6) → A7
A7  → A8, A12
A9  → A10
A10 → A11, A12
A11 → A12, D2*                 [D2: Phase C end]
A12 → D2 (merge-only)
A8  → A12, B2
A12 → A13b, B1w, C2
A13a → A13b, C1*               [C1: Phase B end]
A13b → A13b-docs → C3          (doc-file handoff, review-1 #5)
A13b → PhaseA-close; A6..A13b all → PhaseA-close
B1s → B1w → B2 → PhaseB-close
B2  → D1a* → D1b               [D1a: Phase C end; §5 Q10]
C1  → C2, C3, C4; C2 → C3 (merge-only)
C2, C3, C4 → C5 → PhaseC-close
PhaseA-close, PhaseB-close, PhaseC-close, D1b, D2, A0b → D3
```

| When | Lanes |
|---|---|
| **Now** (after M0, minutes; no P4 dependency) | **A6**, **A6E**, **A9**, **A13a**, **A1a-fr** (if §5 Q2 ruled yes) |
| After A6 merges | M1 (P4) → **A7**; **A10** (also needs A9 and A6E); **B1s*** |
| After A13a merges | **C1*** |
| Wait for P4 S+M on the base (M1) | **A7** → **A8** → **A12** → **A13b** (A12 and A13b also need the hosted chain) |
| Wait for the hosted chain | A10 → A11 → A12 |
| Wait for something else | B1w (main.go writer order: after A12); B2 (after B1w and A8); C2 (A12's proxy harness, real A6, C1); C3 (A13b-docs, C1; merges after C2); C4 (C1; gates Phase C close); C5, D3 (orchestrator, Docker/e2e); A13b-docs (after #22 P3's docs reach main); A0b (work item 1 done) |

Critical path: A6 → A7 → A8 → A12 → A13b → B2 → D1a → D1b → D3, with A9 → A10 → A11 → A12 beside
it. The early starts take B1's store, C1 and D2 off that path.

---

## 3. Lane contracts

**Common to every lane** (WI2 plan §4 unchanged): one worktree `a per-lane git worktree`
on branch `wi2/<lane>`, cut by the orchestrator from the integration tip named in Base; the builder
the builder builds **one numbered commit per run**; the orchestrator reviews the diff and commits each (or tells the
builder to commit in-lane); every commit is green on its own predecessors (spec §0.5). Forbidden for
every lane: `src/gate/**`, `dist/**`, `go.mod`, `go.sum`, `docs/**`, root docs, `.github/**`,
`scripts/**`, `commands/**`, `skills/**`, `Makefile`, `packaging/**`, every other lane's files, and
any frozen test or golden — except where a row below names it.

**ACC** (every commit): `make vet && go vet -tags integration ./... && make build &&
make verify-no-sqlite-local verify-no-humanauth-local verify-gate-closure verify-mcp-closure
verify-lifecycle-closure && GOOS=darwin GOARCH=arm64 go build -o /dev/null ./src/mcp/cmd/sshgate-mcp
&& GOOS=darwin GOARCH=arm64 go build -o /dev/null ./src/signer/cmd/sshgate-signer-telegram`, the
lane's own `flock $LOCK go test -race -count=1 <pkgs>`, GATE-PROOF against the lane's recorded base,
and `git diff --name-only <base>...HEAD | grep -vE '<OWNS>'` empty. **At merge** the orchestrator
adds `flock $LOCK make test` and the FROZEN selectors named per lane. Reviews per spec §4.4 (the reviewer
X-High), plus an second-review diff check of every the reviewer-Low commit (probation).

### 3.1 Starts now

**A6E — approval audit encoding (split out of A6; spec `:1589` owns, `:1632` tests; E23, E62)**
- **Base:** integration after M0. **Deliverable:** `AuditEvent`, `AuditCall`, `AuditVerdict` gain a
  trailing `Approval *approvalplan.AuditMetadata` (`omitempty`); E23's inert-verdict encoding
  (`verdict_inert` on `NewAppendOnlySink`, `approval-<transition>` on `AuditLog`) and the
  `AuditCall{Lifecycle: "approval-…"}` → kind `lifecycle` rule.
- **Owns:** `pkg/signerkit/{audit,audit_sink}.go`, new `pkg/signerkit/audit_approval_test.go`.
- **Commits:** (1) the field and its omitempty proof (durable sink and AuditLog bytes unchanged);
  (2) the inert/lifecycle encodings with one golden per case of spec `:1632`.
- **Accept:** ACC with `./pkg/signerkit/...`; FROZEN-LOCAL; `TestOrdinaryAuditEventJSONRemainsByteFrozen`
  (`service_test.go:211`) unedited. Review: a second reviewer; rides in A6's the reviewer pass.

**A1a-fr — pure draft freeze (only if §5 Q2 is ruled yes)**
- **Base:** after M0. **Deliverable:** `approvalplan.FreezeDraft(d ApprovalDraft, f FreezeInputs)
  (ApprovalPlanV1, error)`, the one draft→plan function both engines call (principal, `sub`,
  `SubmittedAt`, `RequestExpiresAt = now + validity`, origin, E60 TTL ceiling, E33 trusted-display
  check, E34 transfer endpoints from caller-supplied registry snapshots), then `plan.Validate()`.
  **Pure only (Q2 ruling + review-1):** registry access, randomness and transfer-wire construction
  stay in the adapters and arrive as explicit `FreezeInputs` fields; it reuses the existing
  validators and changes no frozen encoding.
- **Owns:** new `src/approvalplan/freeze.go`, `freeze_test.go`. No existing A1a/A1b file, no golden.
- **Commits:** one. **Accept:** ACC with `./src/approvalplan/...`; every existing golden
  byte-identical; stdlib-only check of WI2 plan §2.1. Review: a second reviewer + a focused independent review pass
  (schema-adjacent).

**A6 — lifecycle engine, memory store (spec `:1586-1637`; Ledger `:1634`; SA-1..SA-11; E8b, E13,
E14, E23, E25, E62, E63, E68, E70, E71; K6, K8, K15, K19)**
- **Base:** after M0. Needs A1b, A4 (merged).
- **Deliverable:** spec A6 in full, on A1b's real API (§0), plus: X5's admission Clock pass,
  flush-batch ordering (nearest `next_due_at`, ≤256 per pass) and the grant-delete newest-mark
  (A1b left them to engines); the legacy side of P4 §7.4: `PreparedLegacyApproval` (unexported
  fields, deep copies in and out), `ReserveLegacy(instance, snapshotBytes, assist.Input)` → handle,
  challenge (hash stored), destination, state `preparing`; the one assist attempt to a terminal
  state; activation to `live` only on the notifier's all-delivered report; `LegacyRequest` holds
  exactly one artifact; `LegacyNotifier` gains `Destination()`, `Prepared(instance)` and an
  artifact-only delivery call; a second `preparing`/`live` legacy request with the same
  `(uid, request_id)` is refused (§5 Q6).
- **Owns:** `pkg/signerkit/lifecycle/**` except `filestore*` (B1s), including `lifecycletest/**`.
- **Must not touch:** `daemon.go`, `backend.go`, `service.go`, `audit*.go` (A6E), `src/approval*/**`.
  The lifecycle imports no `approvalreview`: it stores snapshot and payload bytes; the freeze and
  snapshot builders are injected (`Freezer`, `SnapshotBuilder`, E62).
- **Commits (each green):** (1) `doc.go`, `deps.go` (the E62 interfaces), `store.go` (`Store`:
  Load/Commit/List/Remove), `memstore.go` + tests; (2) the single-writer commit function, projections
  (grant, newest-grant mark, card handle, record-handle and request-ID indexes, counters, due index)
  and Submit/Get/List through `Apply`; (3) Vote, Claim (mint via `Answer.MintRequired`, `Minter`
  inside the critical section), Report, AdminCancel, Revoke; (4) the reconciler (`Next` after
  commit, 1 s tick, due index) and `startup.go`; (5) the outbox flusher and the unflushed list, the
  Claim flush wait; (6) assist through `Pool.TrySubmit` (`busy` → `unavailable`, `closed` → no
  commit); (7) notifier actors and `Burst`, edit retry; (8) admission, Shed, Delete, payload
  reservation; (9) waiters (`WaitMany`); (10) `Close` latch, cancel and join; (11) `LegacyRequest`,
  tombstones, legacy audit lines (E8b); (12) `PreparedLegacyApproval`, `ReserveLegacy`, activation;
  (13) `lifecycletest` conformance suite (the SA-11 properties, crash-prefix through `startup.go`,
  the stop property) run against `memstore`.
- **Tests:** spec `:1605-1633`, with `record_corrupt` (not `materialization_error`) for the
  corrupted-XFER first Claim (r5.9 `:846`); P4 §7.4 A6 items (preparing is untappable; delivery
  failure never activates; tap before activation → `legacy_vote_refused{stale_challenge}`).
- **Accept:** ACC with `./pkg/signerkit/lifecycle/...` (now non-trivially checked by
  `verify-lifecycle-closure`); `AssertNoDirectTimeReads` over `pkg/signerkit/lifecycle/*.go`; goleak;
  FROZEN-LOCAL at merge. **§7 obligations:** the A6 bullet and steps 0.4, 0.5, 0.8. Review: the reviewer
  X-High (engine and actors) before merge.

**A9 — hosted migration 7 and v2 row store (spec `:1718-1745`; E4b, E4c, E6, E41, E52, E53, E75)**
- **Base:** after M0. Needs A1a, A1b (merged).
- **Owns:** `pkg/signerkit/sqlitestore/**`, `pkg/signerkit/store/store.go`, and the one line
  `src/signer-server/cmd/sshgate-signer-server/main_test.go:349` (`auditor` → `admin`).
- **Named bump:** `policy_migration_test.go:168` 7 → 8 (E53).
- **Commits:** (1) migration 7 DDL (the `users` guard, role triggers, `requests` columns, backfill)
  + `synchronous(FULL)` DSN + the two named edits; (2) `request_expires_at` on v1 Insert, the E52
  quota predicate, `ExpireLegacy`/`CancelLegacy`; (3) `approvals_v2` primitives (in-tx
  `GetV2/PutV2/DeleteV2/CountV2`, plain reads `ReadV2/ByHandleV2/RecentDecidedV2/ListV2/DueV2/
  UnflushedV2`) with slot columns derived by `approvalplan` and A1b `statetest` properties.
- **Accept:** ACC with `./pkg/signerkit/sqlitestore/... ./pkg/signerkit/store/... ./pkg/signerkit/storetest/...
  ./pkg/signerkit/hosted/... ./src/signer-server/...`; FROZEN-HOSTED. §7: none. Review: independent review
  (migration).

**A13a — jobplan, phased SSH, `registry.ReadCurrent` (spec `:1870-1895`; E10, E28-E30, E33, E35,
E56, E60, E71, E74)**
- **Base:** after M0 (P2's strings must be in the base; §5 Q4).
- **Owns:** `src/mcp/jobplan/**`, `src/mcp/ssh/phased.go`, `src/mcp/ssh/phased_test.go`, additive
  `ReadCurrent`/`Snapshot` in `src/mcp/registry/servers.go` plus new `servers_current_test.go`.
- **Must not touch:** `ssh/client.go` `Run`/`RunWithStdin`, `known_hosts.go`, `Get/List/Load`
  behaviour, anything in `src/mcp/tools/**` (A13b) — `StepOutcome` copies the tools' exit texts,
  and A13b adds the drift test that compares them.
- **Commits:** (1) `ReadCurrent` + `Snapshot` (one descriptor, fail closed, "registry unreadable");
  (2) `RunPhased`, `PhasedError`, the pre-start guard and the nil-guard refusal; (3) `StepOutcome`
  table (§5 Q4 for the after-start line); (4) the draft builder; (5) the runner, K16 on the held
  pair, `StepJournal`, aggregation through `approvalplan`.
- **Accept:** ACC with `./src/mcp/jobplan/... ./src/mcp/ssh/... ./src/mcp/registry/...`; the static
  time-read test over `src/mcp/jobplan`; FROZEN-MCP at merge. §7: none for A13a (its P4 obligation is
  carried by A13b). Review: a second reviewer; in the Phase A end the reviewer pass.

### 3.2 After A6 (and M1 for A7)

**A7 — local daemon: v2 kinds, peer credentials, legacy adapter, grants (spec `:1639-1673`;
E8, E8b, E8e, E13, E21, E24, E34, E71; OQ3 (b))**
- **Base:** integration after A6, A6E, M1 (and A1a-fr if ruled). **§7:** the A7 bullet and steps
  0.1-0.3, 0.6, 0.7, 0.9 (`prepareLegacy` in `daemon_approvals.go`).
- **Owns:** `pkg/signerkit/{socket,service,xferregistry}.go`, new `peercred_{linux,darwin,other}.go`,
  new `daemon_approvals.go` (+ tests), the listed `daemon.go` hunks at the §0 anchors only,
  `src/signer/daemon_grant_test.go`, `src/signer/daemon_authmode_deny_test.go` and
  `src/signer/daemon_net_test.go` (named tests only), comment-only lines in `backend.go` and
  `daemon_internal_test.go`, and **one entry** of `scripts/srcmut/sets/p43.json` (`P-S-GRANT-NET`,
  §5 Q5).
- **Commits:** (1) peer credentials + `PeerAwareHandler`; (2) `signAll→signAt`,
  `signTransferLegs→signTransferLegsAt` with byte-identity tests; (3) `Service.ApprovalMinter`,
  `AttachApprovals`, `Close` closing the lifecycle first; (4) `daemon_approvals.go` adapters
  (`AuditWriter` onto A6E's fields, `Minter` with the E71 re-check, `XferDigests`, `Freezer`,
  `SnapshotBuilder` = `approvalreview.BuildSnapshot`); (5) the six v2 cases, unattached →
  `lifecycle_unavailable`, refusals audited (SA-7); (6) `legacyApprove` + `prepareLegacy` behind
  the four v1 call sites, P4.3's `Net` refusals still first, the legacy assist input built per
  §5 Q3 — that synthesized plan is advisory input only: it never enters v2 persistence,
  authorization or minting (Q3 refinement); (7) `revoke_grant`/`list_grants` over both sources;
  (8) **OQ3, its own named commit:** remove the v1 grant short-circuit, `matchGrant`, `grantCovers`,
  update the comments, the named test rewrites, the `P-S-GRANT-NET` deletion, and the **named
  migration of `TestMatchGrantNeverAutoSignsNet`** (`src/signer/daemon_net_test.go:97`; review-1 #3):
  today its control (`:115`) sends an *unarmed* ordinary v1 request and expects grant auto-signing,
  which would block forever on `MockBackend` once the short-circuit is gone. The migrated test
  (renamed `TestV1GrantNeverAutoSignsPlainOrNet`) keeps both grant scopes (`all`, `commands`),
  arms the mock for **both** the ordinary and the `Net` request, and asserts each reaches the
  backend (one prompt each), resolves as the human's decision, carries no `grant:` auth mode, and
  the `Net` request's prompt has `Net=true`; it replaces the separate `TestV1NetNeverGrantSigned` of
  §5 Q5; (9) the E71 drift test.
- **Tests:** spec `:1654-1668` (`record_corrupt` for the corrupted-XFER case) and P4 §7.4 item 1's
  notifier-seam tests (`TestPreparedLegacy{RefusesMismatch,Authoritative,Sequence,SendsArtifact,
  Immutable}`) and srcmut `P-S-LEGACY-PREPARED` (`legacy-prepared-skip-check`,
  `legacy-prepared-shallow-copy`) — the new srcmut entries are an orchestrator edit to `p43.json`.
- **Accept:** ACC with `./pkg/signerkit/... ./src/signer/...`; FROZEN-LOCAL;
  `make test-srcmut SRCMUT=P-S-HOSTED-NET,P-S-REMOTE-SIGNATURE,P-S-LEGACY-PREPARED`;
  `TestDaemon_SignsNetFlag`, `TestEnvelopeGolden_SignNet`, `TestSignRejectsNet*` unedited (the
  only edited P4 test is the named `TestMatchGrantNeverAutoSignsNet` migration);
  `GOOS=darwin go vet ./pkg/signerkit/`. Review: independent review (peer-credential and grant boundary);
  the orchestrator diff-reviews every `daemon.go` hunk.

**A10 — hosted v2 machine plane, engine, worker, assist (spec `:1747-1801`; E3, E4, E19, E21, E25,
E32, E37, E52, E63, E67, E68, E71, E75)**
- **Base:** after A6, A6E and A9 (+A1a-fr). A6E because the flusher writes `AuditCall` with
  `Approval` and `Lifecycle = "approval-…"` (review-1 #6). No P4 dependency (hosted v1 `Net`
  refusal is S's, untouched).
- **Owns:** `pkg/signerkit/hosted/{server,config,handlers}.go`, new `approvals_v2_{engine,handlers,
  worker}.go` (+ tests), `policy_runtime.go` **only `Server.Close` (`:212`)**, signer-server
  `main.go` (sole writer), `src/signer-server/install/**`, `src/signer-server/README.md`.
- **Commits:** (1) config: `RequiredApprovals > 256` refusal in `New` and in `main.go`, the hosted
  redactor and per-request salt; (2) the engine: Submit (and every later mutation) in its
  prescribed `BEGIN IMMEDIATE` transaction applying Clock first; **Get, List and Wait are plain
  committed-state reads (`ReadV2`, `ListV2`) — never `BeginTx` (the DSN sets `_txlock=immediate`,
  `sqlite.go:192`, so a transaction takes the writer lock), never a transaction held across a Wait,
  and never Clock** (review-1 #2; spec `:1732`, `:1789`); the E21 `busy` classifier (a plain read
  ended by `SQLITE_BUSY` answers `busy`); (3) Vote (effective policy), Claim (mint outside the transaction, CAS),
  Report, the hosted E71 re-check in the minter adapter (r5.9 `:846`); (4) the one flusher and the
  worker (`DueV2`, `UnflushedV2`, `ExpireLegacy`), X5 and the newest-mark; (5) the assist pool and
  `closeOrdinaryWorkers` in `Server.Close`; (6) routing (E3) and the v2 handlers; (7) signer-server
  flags, `defer srv.Close()`, install files, README; (8) `lifecycletest` against hosted.
- **Accept:** ACC with `./pkg/signerkit/hosted/... ./src/signer-server/...`; FROZEN-HOSTED.
  Review: independent review together with A11.

**B1s — file store (proposed split of B1; spec `:1991-2023`; K14, E18, E54, E73, E75)**
- **Base:** after A6 (B0 merged). **Owns:** `pkg/signerkit/lifecycle/filestore_linux.go`,
  `filestore_other.go`, their tests. **Deliverable:** everything in B1 except the `main.go` lines:
  ownership flock on a held descriptor, `RemoveOrphanTemps` + one View transaction behind `List`,
  write-through cache, quarantine, poison + reopen loop through A6's `startup.go`, the two seams,
  caps. **Tests:** spec B1 list except the two-signer-subprocess, `--dev` and `EBADF`-before-`Listen`
  cases (B1w). **Accept:** ACC with `./pkg/signerkit/lifecycle/... ./internal/securestate/...`;
  FROZEN-LOCAL.

### 3.3 After the P4 base and the hosted chain

**A8 — Telegram notifier reconciler (spec `:1675-1716`; K6, K15, K19, K20, E7, E14, E15, E22, E36,
E45-E51, E64, E65)**
- **Base:** after A7 (contains M1 and so the callback-binding fix). **§7:** the A8 bullet, step 0.8.
- **Owns:** `src/signer/backend/**` (first writer of `telegram_v2*.go`), signer `main.go` (first
  writer). **Must not touch:** spec `:1714`, P4 S's `telegram_net_test.go` and the callback-binding
  tests (`telegram_cardbind_test.go`), which stay green unedited.
- **Commits:** (1) `telegram_v2.go` `Notifier` I/O (`Burst` under `policyNotifyMu`, E50 429 budget);
  (2) `telegram_v2_legacy.go`: `Destination`, `Prepared`, artifact-only delivery, the all-delivered
  report, E47 callback encoding of the frozen handle and challenge; (3) `telegram_v2_callback.go` and
  the `v:` hook beside `p:` (`telegram.go:503`), challenge bound to instance, chat and message;
  (4) `telegram_v2_commands.go` E64 gate, no commands, hook in `dispatch` (`:437`); (5) K7 gate in
  `runExplainer` (`:935`) + the named nil-rules explainer test change; (6) `main.go`: `[approvals]`
  TOML, explainer → `assist.OpenAI`, lifecycle construction on `AttachApprovals`, `tb.Run` moved out
  of `buildTelegramBackend` (`:606`) after `lc.Startup()`, linked-chat check.
- **Accept:** ACC with `./src/signer/...`; FROZEN-LOCAL; fake Bot API only. Review: a second reviewer; Phase A
  end the reviewer.

**A11 — hosted human plane and refapp (spec `:1803-1848`; E6, E7, E65, K6, K8, K20)**
- **Base:** after A10 and A6E. **Owns:** spec `:1806-1810` (`human_handlers.go` + test, new
  `vote_challenge.go`, `refapp/**`, the named E7 change in `unit3_wire_ratchet_test.go` and
  `wire_frozen_test.go`).
- **Commits:** (1) `withSession` context + MAC key and `vote_challenge`; (2) v2 routes by handle,
  detail GET challenges; (3) `handleVote` order of checks, inert lines (A6E), `busy` mapping;
  (4) `/ui/pending` `v2_pending`, `/ui/audit` `v2_entries`; (5) `request.js`/`pending.js` + JS tests;
  (6) the named wire-frozen change.
- **Accept:** ACC with `./pkg/signerkit/hosted/...`; `flock $LOCK make test-refapp-js`;
  FROZEN-HOSTED (named bump). Review: independent review with A10.

**A12 — hosted proxy (spec `:1850-1868`; E5, E19, E32, E42, E69)**
- **Base:** after A7, A8, A10, A11. **§7:** A12 bullet (`TestHostedRefusesNet` passes; `net_unsupported:`
  before any HTTP).
- **Owns:** new `pkg/signerkit/hosted_v2_client.go`, the `backend=hosted` branch of
  `daemon_approvals.go`, signer `main.go` (second writer: `buildHostedBackend` `:390`), one comment
  line in `hosted.go` (E42), new `tests/hostedproxy/**` with the orchestrator-captured fixtures
  (§5 Q7).
- **Commits:** (1) the client over `approvalwire`; (2) the forwarder in `daemon_approvals.go`
  (E71 and claim-token checks first, `signer_incompatible` frame + audit row, `busy` and
  `storage_uncertain` pass-through); (3) `main.go` wiring; (4) `tests/hostedproxy` end to end,
  older-server fixtures, contention harness (C2 and A13b reuse it).
- **Accept:** ACC with `./pkg/signerkit/... ./tests/hostedproxy/...`; FROZEN-LOCAL; FROZEN-HOSTED;
  `make test-srcmut SRCMUT=P-S-HOSTED-NET`.

**A13b — MCP synchronous migration, code (spec `:1897-1970`; K3, K12, K13; E10-E12, E25-E27)**
- **Base:** after A12 and A13a (contains M1). **§7:** the A13a/A13b bullet: `run` with
  `network:true` keeps P4.4's routing and its single v1 `Sign` call; `StepOutcome` unused for it.
- **Owns:** `src/mcp/tools/**`, `src/mcp/server.go`, `src/mcp/*_test.go`,
  `src/mcp/cmd/sshgate-mcp/main.go`, `tests/integration/**` **except
  `tests/integration/setup_test.go`** (C4's), and **one entry** of `scripts/srcmut/sets/p44.json`
  (`reveal-net-via-reveal-branch`, only if the port below needs it). Docs move to A13b-docs.
- **Signed network execution stays command-free (review-1 #1).** Today `execNetwork`
  (`netroute.go:79`) sends the signed envelope through `SSH.Run` and wraps its error; `x/crypto/ssh`
  puts the whole command in an exec-request rejection, and `server.go:326` logs the error and returns
  it to the agent, so `run(network:true)` (and reveal+network) can leak the signature and payload.
  A13b owns the fix: the signed network dispatch keeps P4.4's routing and its single v1 `Sign` call,
  but its SSH error reaches the result, the error string, the Denial and every log only as a
  command-free class (the same sanitizer E28 gives `RunPhased`, or `RunPhased` itself with a pre-start
  guard that passes; never the raw `SSH.Run` error). It must not disturb the `P-M-*` anchors in
  `netroute.go`/`run.go` (each still matches exactly once).
- **Commits:** (1) `Runner.Approvals` + the fake + the parity-table comment; (2) the nine Denial
  classes and the two named `Summary` rewordings (§5 Q4); (3) the sync coordinator for `run`
  (Submit/Wait/Claim/Report, retries, budgets on the elapsed pair); (4) `run_batch`; (5)
  `revoke_server`, `update_gate`; (6) `request_grant`, `transfer`; (7) `StepOutcome` adoption and
  the text drift test against A13a's table; (8) the command-free signed-network SSH error path
  above, with `TestRunNetworkSSHErrorsCommandFree`: an in-process `x/crypto/ssh` server rejects the
  exec request for `run(network:true)` and for `run(network:true, reveal:true)`; neither the
  returned error, the `RunOutput` (stdout, stderr, Denial, Diagnostic), the MCP tool result through
  `server.go`, nor any live-log or server log line contains `SSHGATE_SIG:`, the signature base64,
  the payload base64 or the command text; the single v1 `Sign` call and the network envelope are
  unchanged; (9) integration helpers (scripted notifier) and `serverInstructions`/jsonschema text
  (E12).
- **Named port (review-1 #4):** the `reveal-branch` leaf of `TestRunNetworkProtection`
  (`run_network_test.go:~313`, srcmut `reveal-net-via-reveal-branch`, mutation `if in.Network {` →
  `if in.Network && !in.Reveal {` in `run.go`). After A13b a bypassed network request lands on the
  ordinary reveal path, which now goes through `Runner.Approvals`, and the existing fixture has no
  approval client, so the mutant would fail or panic without the marker. In the commit that moves
  `run`'s reveal to `Runner.Approvals` (3), the fixture gains a fake `ApprovalClient`, and the leaf's
  effect becomes "the v2 approval boundary was reached (a Submit with a `signed_reveal` step) or the
  v1 fake saw `Net=false`"; it still prints exactly `MUTATION-EFFECT reveal-branch`; the `ordinary`
  green control and every other leaf stay as they are. If the leaf's path or marker changes, A13b
  edits that one `p44.json` entry in the same commit (named in the message).
- **Accept:** ACC with `./src/mcp/...`; FROZEN-MCP (named bump, §5 Q8; tool count stays 11);
  `make test-srcmut` with all seven `P-M-*` IDs, each reported detected (`reveal-branch` through the
  ported leaf); every `TestRunNetwork*` test unedited except the named `reveal-branch` port; then
  the orchestrator runs `flock $LOCK make test-integration`.

**A13b-docs — the reason sweep (spec §4.1 `:2247-2253`)** — orchestrator-owned or a lane cut after
#22 P3's docs reach main and are merged in: `AGENTS.md` (incl. `:101-102` rewritten against P2's
current text), `README.md`, `commands/{run,run_batch,revoke}.md`, the four skills, `docs/design.md`'s
reason column. One commit. **Hands these files to C3:** C3 is cut only after A13b-docs merges
(§2), so `AGENTS.md`, `README.md`, `docs/design.md` and the two shared skills have one writer at a
time (review-1 #5).

### 3.4 Phases B-D

| Lane | Base | Owns | Commits (each green) | Accept |
|---|---|---|---|---|
| **B1w** | after A12, B1s | signer `main.go` (third writer: `journal_root`, `retention`, `report_horizon`, `doInitFlow` `:808`) | (1) config + store construction + ownership failure before `srv.Listen`; (2) the two-process, symlink/bind-mount, rename-during-reopen, `EBADF`, `--dev` tests | ACC `./pkg/signerkit/lifecycle/... ./src/signer/...`; FROZEN-LOCAL; Phase B end the reviewer after B2 |
| **B2** | after B1w (has A8) | the shutdown part of `daemon_approvals.go`; `src/signer/backend/telegram_v2*.go` (`/renotify`) | (1) `/renotify` behind E64; (2) restart matrix; (3) SIGTERM cases (spec `:2024-2054`) | ACC `./src/signer/... ./pkg/signerkit/...`; FROZEN-LOCAL |
| **C1** | after A13a* (B0 merged) | `src/executorwire/**` (first commit), `src/executor/**`, `src/executor/cmd/sshgate-executor/**` | (1) executorwire + goldens; (2) singleton and ownership flocks, socket peer check; (3) job store, quarantine; (4) `exec_submit` window, admission, `ReadCurrent` + `jobplan` draft, commit; (5) reads, uncertain-commit exit (spec `:2055-2074`) | ACC `./src/executorwire/... ./src/executor/...` |
| **C2** | after C1, A12 | `src/executor/**` | per spec `:2075-2121`: Submit, `JobNext` actor, Claim/step/report, retention, the hosted-proxy harness case | ACC same; independent review |
| **C3** | after C1 and A13b-docs (so after A13b); merges after C2 | spec `:2122-2158` (`src/mcp/execclient/**`, async in `src/mcp/tools/**`, `server.go`, MCP `main.go`, `packaging/mcpb/**`, the 13-tool docs sweep §4.1 **including `docs/TESTING.md:441-456`**: C3 is that file's only writer from its cut to its merge) | (1) execclient; (2) async branch + `executor_unavailable`; (3) **one commit:** the two tools, the guard bump 11→13 and the whole 13-tool docs sweep (spec §4.1 requires them together) | ACC `./src/mcp/...`; FROZEN-MCP (named); `bash scripts/smoke-fresh-install.sh` |
| **C4** | after C1; gates C5 and the Phase C close (so D3) | `Makefile` (`build`, `install-local`, `verify-versions`, `.PHONY`, `verify-executor-closure` in `preflight`), `packaging/systemd/sshgate-executor.service`, `scripts/{install,uninstall}-executor.sh`, `tests/integration/setup_test.go:41-42,64-65`, `.github/workflows/release.yml`, install docs (spec `:2159-2176`) | (1) Makefile targets; (2) unit + scripts; (3) release workflow + docs | ACC; `make verify-versions verify-executor-closure`; never enable/start a unit |
| **C5** | orchestrator, after C2, C3, C4 | `tests/integration/async_*_test.go` | spec `:2178-2196` | `flock $LOCK make e2e` |
| **D1a** | after B2* (spec: Phase C end; early start pending §5 Q10) | new `pkg/signerkit/lifecycle/snapshots.go` (+test), E49 display states in the actor | in-memory deny-all/cancel snapshots; display states | ACC `./pkg/signerkit/lifecycle/...` |
| **D1b** | after D1a | `src/signer/backend/telegram_v2_commands.go`, `telegram.go` `dispatch` hook | `/pending`, `/deny_all`, `/cancel` (spec `:2198-2210`) | ACC `./src/signer/...` |
| **D2** | cut after A11* (Q1); merges only after A12 (merge-only edge, so A12's proxy harness is built on a stable hosted plane) | `pkg/signerkit/hosted/**` incl. `refapp/**` | cancel routes, deny-all snapshot/confirm, v2 pagination, admin UI, contention (spec `:2212-2224`) | ACC `./pkg/signerkit/hosted/...`; `make test-refapp-js`; FROZEN-HOSTED |
| **D3** | orchestrator, last | docs, THREAT-MODEL (incl. the 30 s `sigwire.MaxClockSkew`, §7), metrics, CHANGELOG, ROADMAP v0.3 move | spec `:2226-2241` | PHASE-END, `make e2e`, final triple review + the reviewer |

### 3.5 Disjointness and shared files

- **Concurrent now:** A6 (`lifecycle/**` minus `filestore*`), A6E (`audit*.go`), A9
  (`sqlitestore/**`, `store/store.go`, one signer-server test line), A13a (`jobplan/**`, `ssh/phased*`,
  `registry/servers.go` additive), A1a-fr (`approvalplan/freeze*.go`) — pairwise disjoint, none in a
  P4 or jail file. Later concurrency: A7 ∥ A10 ∥ B1s ∥ C1; A8 ∥ A11; B1w/B2 ∥ C2 ∥ C4 ∥ D2.
- **Serial writers (orchestrator order):** signer `main.go` A8 → A12 → B1w; `daemon_approvals.go`
  A7 → A12 → B2; `telegram_v2_commands.go` + `dispatch` A8 → B2 → D1b; `lifecycle/**` A6 → B1s (own
  files) → D1a; `src/mcp/tools/**` A13b → C3; `pkg/signerkit/hosted/**` A10 → A11 → D2;
  `AGENTS.md`, `README.md`, `docs/design.md`, the shared skills: A13b-docs → C3;
  `tests/integration/**` A13b, except `setup_test.go` (C4 only); `Makefile` C4 only; `p43.json` A7's
  one entry + orchestrator's new entries; `p44.json` A13b's one entry only.
- **`docs/TESTING.md`:** one writer at a time. The orchestrator edits it (WI2 `verify-*` targets,
  status) only outside C3's cut-to-merge window; inside it, C3 is the sole writer (its 13-tool lines).
- **Orchestrator only:** `docs/BUILD-PLAN.md` status/reorder edits (§5 Q1, Q10),
  `.github/workflows/tests.yml` closure checks, base merges M0/M1, fixture capture for A12.

---

## 4. Merge order

A linearisation of §2 (§2 wins on any doubt): M0 → {A6E, A9, A13a, A1a-fr} as ready → A6 → M1 →
{A7, A10, B1s, C1} → {A8, A11} → A12 → {A13b, D2 (merge-only after A12)} → (Phase A close: STD,
FROZEN-*, `make preflight`, `make test-integration`, the reviewer on the full A diff) → B1w → B2 → (Phase B
close) → D1a (Q10) → D1b; C4, C2, then A13b-docs → C3 (after C2) → C5 → (Phase C close) → A0b → D3.
One merge at a time; STD after each.

---

## 5. Questions (Q1-Q9 ruled 2026-10-15, adopted with review-1's refinements; Q10 open)

1. **Early starts against the spec's phase gates.** B1, C1 and D2 depend in the spec on whole phases,
   but their code needs only A6+B0 (B1's store), A13a+B0 (C1) and A10/A11 (D2); B1's only real
   later edge is the `main.go` writer order. **Recommend:** split B1 into B1s/B1w; start B1s after
   A6, C1 after A13a, D2 after A11; phase-end reviews still gate the phase closes. The orchestrator
   records the reorder in `docs/BUILD-PLAN.md` in the same integration commit (repo rule).
2. **One draft freeze for both surfaces.** No `Freeze` exists; E62 puts `Freezer` adapters in A7
   and in hosted, so the local and hosted plans could diverge (K19 parity, E60, E33, E34).
   **Recommend:** A1a-fr, a new pure `approvalplan/freeze.go` (no existing file or golden touched),
   both adapters call it. **Review-1 refinement:** registry access, randomness and transfer-wire
   construction stay in the adapters as explicit inputs; the existing validators and frozen
   encodings are reused unchanged.
3. **Legacy assist input.** P4 §7.4 step 5 runs the assist "on the snapshot", but
   `assist.RedactForProvider` takes an `ApprovalPlanV1` and marks legacy only via
   `synthesized_legacy_v1`; a v1 step cannot carry `Net`. **Recommend:** A7 synthesizes a
   never-stored, never-validated `ApprovalPlanV1` (origin `synthesized_legacy_v1`,
   `LegacyRationaleText`, commands in order) and passes the resulting `assist.Input` to
   `ReserveLegacy`; the provider input omits `Net` (alignment is forced `not_assessed`, and the
   card carries the network banner). Grants, transfers and registrations synthesize their kinds.
   **Review-1 refinement:** valid because `RedactForProvider` never calls `Validate` and the legacy
   origin forces `not_assessed`; the synthesized plan stays advisory input only and never enters v2
   persistence, authorization or minting.
4. **The P2 after-start jail line postdates r5.8.** E10/`StepOutcome` map "exit 77 with the line" on
   `unsigned_read` to `failed_not_started`, but main now prints "the jail failed after the read may
   have started … not trusted" (`readjail.go:265`), and `denial.go:164`/`run.go:404` were reworded
   by P2. **Recommend:** `StepOutcome` maps the after-start line to `failed` (executed, possibly run,
   no retry advice) on every kind; A13b's `read_jail_unavailable` Summary rewording starts from P2's
   text and adds the signed-step clause; A13a is cut after M0 so its mirrored texts are P2's.
5. **`P-S-GRANT-NET` targets `matchGrant`, which A7 deletes.** **Recommend:** A7's OQ3 commit
   deletes that entry from `p43.json` (A7 owns that one hunk) and **migrates
   `TestMatchGrantNeverAutoSignsNet` as named in A7 commit 8** (review-1 #3; this replaces the
   proposed separate `TestV1NetNeverGrantSigned`); the orchestrator adds
   the BUILD-PLAN line "no v1 grant path exists". `P-S-REMOTE-SIGNATURE`'s anchor must survive the
   `signAt` rename (A7 acceptance runs it).
6. **Duplicate pending `request_id` on the lifecycle legacy path.** The callback-binding fix refuses
   a duplicate pending v1 `request_id` on the direct path; §7 says "on every path" but A6's
   `LegacyRequest` table is new. **Recommend:** A6 refuses a second `preparing`/`live` legacy request
   with the same `(uid, request_id)` with today's error text, tested in A6 and through A8.
7. **Older-hosted-server fixtures for A12.** The spec says capture at A0's base `366ba07`.
   **Recommend:** capture from the last pushed `origin/main` (`a8fc4d5`, what operators can run;
   there is no `v0.1.5` tag locally, and `pkg/signerkit/hosted` is unchanged from it to `main`, only a
   busy-timeout hunk in `sqlitestore/migrations.go`), policy plane attached and not.
8. **Denial shape count after P4.** P4 added six `network_*` classes but kept the pin at 11.
   **Recommend:** A13b's named bump is 11 → 20 over the same pinned set (the nine new classes); the
   network classes stay as P4 left them. **Review-1 clarification:** 20 = the existing 11 pinned
   classes + the nine new ones; it is not the total including the six `network_*` classes (26).
9. **Builder model for the concurrency- and boundary-heavy lanes.** A6, A7 and A10 are the largest
   and riskiest; the builder is on probation. **Recommend:** start them on the builder as ruled, with a
   full second-review check after commit 1 of each; move that lane to the builder on the first missed spec
   rule rather than after the lane.
10. **(open) D1a's early start.** The spec gates D1a on Phase C end, but its code needs only the
    lifecycle (A6/B1s) and the notifier display states (A8/B2); the executor is irrelevant to it.
    **Recommend:** cut D1a after B2 (as §2 now draws it), merge after the Phase B close; the
    orchestrator records the reorder in `docs/BUILD-PLAN.md` with Q1's. If not ruled, D1a waits for
    the Phase C close.

### Review-1 resolution (review note 1-WI2-wave3 (not in the repository), NO-GO 4 Major / 2 Minor)

| # | Finding | Resolution (where) |
|---|---|---|
| 1 Major | Signed network reads keep `SSH.Run`'s raw error (`netroute.go:79`, `server.go:326`) and can leak the signature | A13b owns command-free SSH errors for signed network execution, keeping P4.4's routing and the single v1 `Sign`; `TestRunNetworkSSHErrorsCommandFree` with an in-process exec rejection for `network:true` and reveal+network (A13b deliverable, commit 8, Accept) |
| 2 Major | A10 commit 2 put Get/List/Wait in transactions | Get/List/Wait are plain committed-state reads: never `BeginTx`, no transaction across Wait, never Clock; mutations keep their `BEGIN IMMEDIATE` (A10 commit 2) |
| 3 Major | `TestMatchGrantNeverAutoSignsNet` hangs once grant auto-signing is gone | A7 owns `src/signer/daemon_net_test.go` for this test; OQ3 commit migrates it (both scopes, both requests armed, human resolution, no `grant:`); `P-S-GRANT-NET` deleted (A7 Owns, commit 8, Accept; Q5) |
| 4 Major | `reveal-net-via-reveal-branch` can no longer emit its marker once reveal moves to `Runner.Approvals` | Named port of the `reveal-branch` leaf and fixture (fake `ApprovalClient`, exact marker, `ordinary` control kept); A13b owns that one `p44.json` entry if needed (A13b Owns, Named port, Accept) |
| 5 Minor | Shared files had two owners; C3's guard and docs split | A13b-docs → C3 edge; `setup_test.go` excluded from A13b; `docs/TESTING.md` one writer at a time (C3 in its window); C3's tools + guard + docs sweep in one commit (§2, §3.4, §3.5) |
| 6 Minor | DAG and contracts disagreed | §2 is the one authoritative set: A6E → A10, C4 → C5 → Phase C close → D3, phase-close nodes, D2 cut after A11 and merge-only after A12, D1a's early start marked and put to Q10; §4 is a linearisation of §2 |
| Q2, Q3, Q8 | Refinements | Folded into A1a-fr, A7 commit 6 and Q2/Q3/Q8 above |

## 6. Spec text that disagrees with the merged code (resolved here; no ruling needed)

- r5.9 `:846` supersedes the `materialization_error` expectation for a corrupted-XFER first Claim in
  A6 (`:1616`), A7 (`:1664`) and A10 (`:1781`): expect `record_corrupt`, nothing committed.
- A1b left X5's admission Clock pass, flush-batch ordering and the grant-delete newest-mark to the
  engines: they are named A6 and A10 deliverables above.
- A1b's API differs from the WI2 plan §3.1 sketch (`Clock` takes the epoch; `Settings` and
  `grantLive` on views; `CastVote` with `CardTap`/`HostedTap`; `MintRequired`; `JobMemory`). Builders
  code against `src/approvalplan`, not the sketch.
- E23 encoding is split from A6 into A6E (ownership moves, content unchanged); A6 keeps the
  lifecycle free of `pkg/signerkit` (`verify-lifecycle-closure`).
- The lifecycle never imports `approvalreview` (the package map does not list it): snapshot and
  payload are bytes; `BuildSnapshot` is the injected `SnapshotBuilder`, and its existing
  `request_too_large` refusal satisfies the §8 ruling on the local surface.
- Spec anchor drift: §0 table. `service.go:136-144` → `:138`; `telegram.go:470-473` → `:503`;
  `dispatch :404-420` → `:437`; signer-server `:213` → `:214`.
- The docs half of A13b collides with #22 P2/P3 edits to `AGENTS.md`, `README.md`, `commands/run.md`,
  skills and `docs/design.md`: hence A13b-docs after the jail docs land.
- `make test` now includes P4's srcmut self-tests and jail tests; builders run only package-scoped
  tests under `$LOCK`; the full STD runs in the orchestrator at merge (WI2 plan §5 Q2).

## Coordinator rulings 2026-10-15 (on §5 Q1-Q9)

All nine recommendations are adopted as written: Q1 B1 splits into B1s/B1w, C1 starts after A13a and D2 after A11 (the reorder goes into docs/BUILD-PLAN.md in the same commit); Q2 A1a-fr, a new pure `approvalplan/freeze.go` both freezers call, no existing file or golden changes; Q3 A7 builds a `synthesized_legacy_v1` plan for the assist input, the provider never sees Net; Q4 P2's "may have started" jail line maps to executed (`failed`, no retry advice) and A13b builds on P2's current `read_jail_unavailable` text; Q5 A7 deletes the `P-S-GRANT-NET` p43.json entry, adds a test that a live v1 grant never signs Net, and the coordinator adds the BUILD-PLAN line; Q6 A6's legacy table refuses a duplicate pending v1 `request_id`; Q7 A12's older-server fixtures come from `origin/main` a8fc4d5; Q8 A13b bumps the denial-shape pin 11 → 20; Q9 A6, A7 and A10 get a full second-review check after each lane's first commit, and move to the builder on the first missed spec rule.

**Coordinator rulings after review 1:** Q10 adopted: D1a is cut after B2 and merges after the Phase B close, and the reorder goes into docs/BUILD-PLAN.md with Q1's. D2 keeps its merge-only edge after A12. C3 keeps its edge after A13b-docs; revisited only if #22 P3 runs late.

**Review 2 (GO) minors, folded in by the coordinator:** (1) D1a gains a merge-only edge `PhaseB-close → D1a`; Q10 is ruled (above), so its "open" annotations are stale. (2) A13b's reveal-branch fixture port also gives the network fixture a valid `SHA256:` fingerprint so the ordinary reveal draft passes `ValidateRouteSnapshot` and the mutant reaches `MUTATION-EFFECT reveal-branch`; no scope change.

## Owner ruling 2026-10-18 — OQ1 adopted
The owner adopted OQ1 (spec §1.2, `oq1:adopt`): synchronous requests carry `requested_validity_seconds`
= 300 and the signer freezes `min(requested, configured)`, floor 300. Placement: new lane **A1a-oq1**
(one named commit on the merged A1a validator: the optional omit-when-absent draft member, `draft_hash`
/`plan_hash` byte-identical when absent, tests) merges before A7 and A10; A7 and A10 each add the
freeze in their own named commit; A13b's sync adapter sends 300; D3 updates §1.3 item 11 and docs.

## Owner ruling 2026-10-18 — OQ2 adopted (reject)
`async` + `reveal` is refused at input validation (`oq2:reject`). Placement: C3, its own named commit
plus test; D3 carries §1.3 item 12 and the THREAT-MODEL line. No retention change in C2.

## Owner ruling 2026-10-18 — audit-log strength accepted as documented
Gate audit stays gate-user-owned append-only + fsync with a configurable path; the separate-user,
append-only setup stays a documented manual admin step (`aud:accept`). D3 makes sure README/THREAT-MODEL
state this plainly, including why the agent cannot tamper without an approved write (jailed reads).

## Owner ruling 2026-10-18 — real-use acceptance gate for v0.2 (`acc:gate+tester`)
v0.2 is not done until, on clean VMs and following the README verbatim: fresh install → useful
diagnosis → late-approved fix → signer restart with a pending approval → async write + result
collection → live two-server transfer (the owner taps). PLUS one outside tester does a cold install
(the owner to name/arrange). Failures found feed back as fixes before the tag.

## Owner rulings 2026-10-18 — publish timing and an automated journey E2E
- `pub:wait`: main is NOT pushed before v0.2; everything publishes with the release.
- The owner: automate the real-use gate. Simulate the phone taps with a service in the
  middle (fake Telegram Bot API that taps approve/deny/late), so the whole journey has no human
  dependency and runs every time, as part of CI. The manual outside-tester cold install stays.
  Plan: `JOURNEY-E2E-PLAN.md` (this folder).

## Carry-forward 2026-10-18 — Telegram early-callback race (for A8)
The journey E2E review found a production race in `src/signer/backend/telegram.go`: a tap that arrives
before the pending card is registered is answered "expired" and the request times out. Fixed on the
journey line (lane TGR). A8, which ports the Telegram backend onto the lifecycle, must carry the fix and
its regression test (callback before registration, Approve and Deny).

## Coordinator ruling 2026-10-18 — v2 store recovery ownership (amends §3 A6/B1s/A7/B1w/A8)
Basis: `STORE-RECOVERY-MODEL.md` (independent review, this folder). Behaviour is the spec's (S:1274, S:1998-2005,
S:1280-1288); component ownership was underdetermined (P:285-291 gave B1s the whole reopen loop while
restricting it to file-store files). Allocation, adopted as recommended:
- **A6R (new lane, owns lifecycle engine files):** latched stop cause + one `availabilityLocked()` guard;
  storage uncertainty observed and the stop latched inside the same `Engine.mu` critical section before
  `commitLocked` returns (no lock-order-reversing callback); cancel immediately, never join in a committing
  actor; `Run(ctx) error` returns the latched cause after joining; `Availability() error`; extract
  `NewLegacyService(LegacyConfig)` (own mutex, contexts, tables, audit worker, assist pool) so
  `Engine.Close` closes only v2 work. Uncertainty keeps precedence on every v2 path until replacement.
- **B1s part 2:** typed `CodeStorageUncertain` contract; `AcquireFileStore(path, uid)` acquires ownership
  without a successful load; descriptor retained across failed loads; `Reopen`/`Close` kept; no engine
  restart inside FileStore.
- **A7:** stable `ApprovalRuntime` (attached once): `RecoverableStore{Store; Reopen; Close}`, the legacy
  service, `NewEngine func(Store)`; supervises generations (wait joined Run → backoff 1..30 s → Reopen →
  Startup under a fresh epoch → atomic publish); Close cancels recovery, joins, releases storage; recovery
  cause in Status.
- **B1w:** builds the durable runtime and engine factory; each generation gets a fresh v2 assist pool.
- **A8:** callbacks route through the runtime (persistent legacy owner + current v2 generation); never hold
  an engine pointer.
- Initial startup: ownership failure is fatal before Listen; a recoverable listing failure starts in a
  diagnosed `lifecycle_unavailable` state, keeps ownership and retries.
- Acceptance per the model's §5 (fault matrix through the automatic supervisor, legacy across recoveries).

### C4 install/uninstall redesign ruling (2026-10-18, stop-patch-loop at round 3)
Reviews C4, C4-2, C4-3 kept finding systemd edge cases in a design that tried to track every
manager load path. Ruling (from the reviewer's C4-3 proposal): the scripts own exactly one directory,
`${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user`, and nothing else.
- **Install:** before writing anything, refuse if the destination is a symlink, or if the manager
  already loads `sshgate-executor.service` from a path that is not `-ef` the destination. Write the
  unit (restart marker as now), `daemon-reload`, then require `FragmentPath -ef` destination;
  otherwise restore the previous unit (or remove the new one), reload, and refuse with a
  configuration-root mismatch message. Then plain `enable` + start/restart per the marker.
  No absolute-path registration, no `--force`.
- **Uninstall:** stop regardless of the unit file (tolerate only not-found + inactive), disable
  (tolerate only not-found), remove only owned artifacts in that directory: the unit if it is a
  regular file, `*.wants|*.requires/sshgate-executor.service` symlinks whose target (read even when
  dangling) is the owned unit, and the marker; then `daemon-reload`. No busctl, no python3.
- Docs drop the cross-root promise and state the refusal.

### Ruling 2026-10-19 — B1s engine read path (orchestrator)
the reviewer B1S-2 found Engine.mu held across Store.Commit while Get/List/WaitMany take the same mutex, so readers serialize with fsync. That contradicts BUILD-PLAN-76-65.md :2002. the reviewer READPATH judged it an availability issue, not corruption or unauthorized signing, and recommended fixing it before B1 closes. Ruling: fix in B1s (lane b1s-readpath) to the published-state design in review note READPATH (not in the repository). No acceptance amendment. B1s merges only after this lands and gets an the reviewer GO.

### Ruling 2026-10-19 — A7 adds lifecycletest/runtime.go; Darwin vet (orchestrator)
A7 commit 3 adds a new file, `pkg/signerkit/lifecycle/lifecycletest/runtime.go`: test-adapter re-exports and fault support for the ApprovalRuntime conformance tests. Ratified as A7-owned. It is a new path that B1s and D1a don't write. Later writers must coordinate edits to it through the orchestrator.
`GOOS=darwin go vet` fails on integration base 48d86f2: gate code references Linux-only symbols from client_sink_linux.go. A7 didn't introduce this. It is fixed on its own lane, wi2/darwin-vet, which merges into the integration tip before A7 closes its Accept row.

### Ruling 2026-10-19 — A7 commit 4 may touch lifecycle Claim's mint path (orchestrator)
the reviewer A7-4 #2: when enrollment rotates between `XferDigests.Current` and `Mint`, lifecycle reduces the minter's stale-key error to `MintFailed`. The record then persists `signing_failed` instead of E34's `materialization_error{stale_transfer_key}`. Fix: in `pkg/signerkit/lifecycle/mutations.go`'s Claim, on a typed stale-enrollment error from Mint, re-read `XferDigests.Current` and commit with the fresh digests. The frozen core's claim.go:100 check, which runs before MintFailed, then records stale_transfer_key. A7 owns this narrow edit. B1s changes one other line in the same file, and the orchestrator resolves that at integration.
**Refinement (2026-10-19, after the reviewer A7-4-2):** no re-read. The typed stale-enrollment error carries the mismatching digests the minter observed under the registry lock. lifecycle Claim commits those as `XferDigests`, with no second `Current` call, so cancellation or a rotation back can't erase a detected mismatch. The frozen core then persists `stale_transfer_key` and its outbox event. A later Claim answers from that slot and never re-mints.

### Note 2026-10-19 — A7 Minter holds the registry read lock through custody (orchestrator)
The transfer minter keeps the xferregistry RLock from the enrollment check through `signTransferLegsAt`, so signing is atomic with the enrollment it was checked against. The cost: a hung custody call stalls a pending `Register`, and with it new legacy `Lookup` readers queued behind that writer. The lock order is Engine.mu → registry → custodyMu, so this can't deadlock. Accepted on purpose: binding the check to the signature outweighs the availability risk of a custody hang, and a custody hang already stalls signing.

### Ruling 2026-10-19 — v2 local socket, disallowed UIDs (orchestrator)
A peer UID that `allowed_uids` excludes gets `not_found` on every v2 kind, Submit and List included. The spec names no code for this case. One answer for every kind gives an unlisted local user no signal about which kinds or ids exist. That outweighs a clearer error message, since the operator controls `allowed_uids`. A context timeout during Wait or Claim answers `lifecycle_unavailable` and is audited under SA-7. The audit row doesn't separate a timeout from an outage; accepted for v0.2.

### Ruling 2026-10-19 — E15 redaction failure on legacy approvals (orchestrator)
the reviewer A7-6 #1: when provider redaction fails, a v1 approval must still render, with the provider skipped and the assist frozen `AssistUnavailable{ReasonRedaction}`. It must not be refused. A6, whose lifecycle is now merged, owns `ReserveLegacy`. The prerequisite is narrow: a per-request redaction-failure outcome that keeps the normal reservation, deadline and delivery checks and never calls the provider. To avoid cutting a separate A6 lane on the critical path, A7 makes this lifecycle edit inside commit 6 under this ruling. A8 wires it in production. A genuine display or snapshot failure still refuses.

### Ruling 2026-10-19 — A7 commit 7 grant surfaces (orchestrator; corrects my lane prompt)
Per spec E24 (:490-504), :1207, :1250-1258 and SA-6.6:
- `revoke_grant(alias)` is alias-global. It deletes the v1 map entry and applies Revoke to every live v2 grant record for the alias, whatever its principal. Its response is today's frozen bytes (`status: approved`) and reveals nothing about whose grant existed.
- `list_grants` shows the v1 map plus the caller's own live v2 grants only.

My first A7-7 prompt said owner-scoped revoke with `not_found`. That was wrong; the builder caught it and stopped.

Prerequisite: lifecycle gains one read-only API over published grant state, for example `Engine.ListGrants(principal)`, returning alias, scope, commands, hosts and expiry. It serves from B1s's published state and never takes Engine.mu. A7 owns this narrow lifecycle edit.

### D3 carry item 2026-10-19 (from the second-review check of A7 commit 7)
When the approval runtime exists but is degraded or closed, `list_grants` errors instead of returning only the v1 map. `revoke_grant` clears the v1 entry and reports error rather than a partial success. This is fail-closed and consistent with the no-partial-success rule; D3 should document it in one line. A corrupt record of any principal fails list and revoke for every caller. That reveals store corruption only, never ownership.

### Tracking 2026-10-19 (from the second-review check of A7 commit 8)
These references are stale after OQ3 and fall outside A7's files. `docs/BUILD-PLAN.md:513` still names `TestMatchGrantNeverAutoSignsNet`; D3 renames it. `src/mcp/tools/update_gate.go:58,75,166` cites `matchGrant`; A13b fixes those comments.
Scope note: A7 commit 8 includes a comment-only orchestrator edit to `pkg/signerkit/audit.go`, describing `grant:<id>` as v2-only after OQ3. The file is not in A7's Owns list; the edit is accepted as coordinator cleanup.

### Ruling 2026-10-20 — first decision-card handle is derived (orchestrator; amends SA-2/E47 for A8)
The gap: the lifecycle sent review parts before CardStart minted the handle, but K19/A3 require every part to carry it, so every v2 notification failed. the reviewer (review note HANDLE) proposed a durable `Burst.CardHandle` reservation, which changes the frozen R1 encoding. A fresh second-review read chose derivation instead, and I adopt it.
Basis: the handle is not a secret. Parts and cards print `Card: <handle>` in plain text (approvalreview/telegram.go:39,228), and tap authority comes from the 64-bit random challenge, its hash, the MsgID match, the revision checks and the allowlist. SA-2's `RecordHandle` is already derived (`ids.go:148`). R1 has not shipped (not on main), so a schema bump would be pure churn.
Rule:
- The first card handle after a burst is `CardHandleFor(recordKey, gen) = digestBase32("sshgate-v2-card-handle-v1\0", recordKey, "\0", gen)[:12]`. It is a new pure function in `src/approvalplan/ids.go`, domain-separated from RecordHandle, valid under `ValidCardHandle`, and pinned by a golden vector.
- The lifecycle fills `Notification.Handle` with it for SendParts, and uses it at the first CardStart of that gen when no card entry already carries it. A crash between BurstDone and CardStart recomputes the same handle.
- E48 replacement or edit cards in the same gen get fresh random handles, as today. The replacement card shows one line: "Review parts were sent under card <H>" (A3 renderer).
- A committed `/renotify` gives gen+1, so a new derived handle.
- The frozen R1 encoding and Apply stay unchanged. The "first CardStart uses the derived handle" rule is enforced in the lifecycle and pinned by tests, not by a core guard.
Authorized edits for the A8 lane: the new function plus its test in `src/approvalplan/ids.go` (no other approvalplan change), `pkg/signerkit/lifecycle/notify.go` and its tests, and the one-line replacement note in `src/approvalreview/telegram.go`.

### Rulings 2026-10-22 — gap sweep of the remaining lanes (orchestrator)
A read-only sweep listed 43 underdetermined rules across the remaining lanes. The 28 orchestrator
rulings, the new lanes A1a-auth and B1f, the C2a–C2d split and the DAG amendments are in
[wave3-gap-rulings.md](wave3-gap-rulings.md). They passed three independent verification rounds;
the fourth revision's last five fixes were applied without a further round. Its owner questions
are open until answered; a lane blocked by one does not start.

### Rulings 2026-10-23 — A11 (orchestrator)
- **Step-5 reasons.** The vote challenge keeps E7 step 5's split. A MAC failure (forged, from another session or from before a restart) is `stale_challenge`. An authentic but expired challenge is `expired_challenge`. Both answer the same 409 "view changed". Q2(b) changes nothing about expiry.
- **Engine wiring.** A11 may touch `server.go` and `approvals_v2_worker.go` for the human plane's engine wiring only. Handlers reach the ordinary engine through a synchronized accessor. A stopped engine answers 503 "busy — retry".
- **Frozen-test inputs.** The named E7 change to `unit3_wire_ratchet_test.go` and `wire_frozen_test.go` (vote requests carry the challenge) moved from A11 commit 6 to commit 3, to keep every commit green. Response and signature assertions are unchanged.
- **Non-operator noise.** At vote step 3, non-operator sessions append no v2 noise event, as on v1.
- **Cursor key.** The pending-cursor key is derived from the vote MAC key with HKDF-SHA256 under its own label.
- **Pending query scan, deferred.** The v2 pending page query scans `approvals_v2`; at 200k rows that is milliseconds, and only an operator session can trigger it. An indexed keyset waits for the next hosted migration, with an EXPLAIN QUERY PLAN regression.

### Rulings 2026-10-23 — A8 (orchestrator)
- **Command-gate flood resistance** (security review of A8 commit 4; supersedes gap ruling #4 in part). Anyone can message the bot. A `wrong_user` or `not_private` command gets no reply and no per-message audit line. Such refusals are counted, saturating, and summarised in at most one audit line and one log line a minute. The allowed user's own refusals (`forwarded`, `redelivered`, `unknown_command`) still audit and reply, at most once a minute, so they can't starve approval cards. `replay` is set only for `redelivered`. Spec :1698's "replies only to the linked DM" still holds.
- **Legacy `/start` from strangers.** A well-formed `/start` from anyone other than `allowed_user_id` is silent and coalesced the same way. A malformed one (nil `From` or nil `Chat`) keeps the recovered-panic path that the frozen poison-update tests pin.
- **Callback taps from strangers: accepted limitation.** A tap from a non-allowed user, which only members of a group-linked legacy chat can make, is still logged and answered per tap. The callback-binding carry-forward tests pin those answers. Revisit if group-linked legacy chats become common.
- **Legacy notifier release.** A8 may edit the `pkg/signerkit/lifecycle` owner files only to call the legacy notifier's `Release` at a v1 approval's end of life: after the terminal edit, on resolution with no edit, and on cancellation or abandonment. This bounds the signer's memory. The same narrow-exception pattern as ruling #1's readiness hooks covers commit 2's `runLegacyCleanup`.
