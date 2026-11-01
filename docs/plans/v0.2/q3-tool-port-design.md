# Q3 tool port: all six MCP tools on the v2 approval path (design)

- **Status (2026-11-01):** design **GO** after its third independent verify (revision 3, verify r3:
  no P0 or P1; two P2s and four P3s, folded in §8). **Not built.** No lane in §4 has started.
- **Decision basis:** owner decision (2026-11-01) on gap-ruling Q3: **NO** to the recommended cut,
  so all six tools (`run`, `run_batch`, `request_grant`, `transfer`, `revoke_server`,
  `update_gate`) move to the v2 approval path in v0.2. Gap rulings 17, 18 and 34 come into scope
  ([wave3-gap-rulings.md](wave3-gap-rulings.md), "Rulings 2026-11-01").
- **Where this sits:** it amends the spec ([approval-lifecycle-spec.md](approval-lifecycle-spec.md),
  new E29a and the texts in §1.5), the gap rulings and the lane plan
  ([wave3-lanes.md](wave3-lanes.md)). Those amendments are listed in §1.5 and §5 and are folded
  into the spec and rulings before A13c is cut. Until then, this file is the binding text for the
  Q3 port. **§8 overrides earlier sections where they conflict.**
- **Grounded at:** integration `feat/76-65-approval-lifecycle` @ `756298d` (contains A13a, A12, B1w
  and A1a-auth); C2 lane `wi2/c2` @ `b73d629` (cited as `c2:<file>:<line>`); journey branch
  `feat/journey-e2e` @ `bdabdcc` (cited as `J:<file>:<line>`). Spec = `approval-lifecycle-spec.md`
  (S:<line>), rulings = `wave3-gap-rulings.md` (R:<line>), lanes = `wave3-lanes.md` (L:<line>),
  journey plan = `journey-e2e-plan.md` (JP:<line>). Unprefixed `file:line` cites are repository
  paths at `756298d`; short names (`runner.go`, `outcome.go`) are in `src/mcp/jobplan/` unless the
  text says otherwise, and `gate …` cites are in `src/gate/cmd/sshgate-gate/`.
- **Review history:** revision 1 drew a NO-GO critique, revision 2 a NO-GO verify ("verify-r2"),
  revision 3 a GO verify ("verify-r3"). The changelogs below and §7 name their findings by ID
  (P1-1, V1, R3-1 …). The review records themselves are working notes outside the repository; every
  finding that matters is restated here.
- **Async scope:** an orchestrator reading, ruling O12 (§2): `async` stays on `run`/`run_batch`.

- **Line drift:** rulings #17 and #18 cite E28/E29 as "S:554-561". At `756298d`, E28 is S:545-558 and
  E29 is S:560-573. "`failed` (a known non-zero exit)" is at S:562. This document uses the current lines.

## Revision 3 changelog (folds verify-r2; every item re-checked against code)

- **V1 (orchestrator ruling O14):** when `AdminOutcome` or `TransferStepOutcome` lowers a status to
  `indeterminate`, the step stores **no** `exit_code`. The executor store's rule stays unchanged
  (`src/executor/store_linux.go:309-318`: `indeterminate` only with no exit code). The fixed
  annotation now says the gate exited 0 (A4, U3-U5, T14, T15 reworded). Named in §1.2, §1.3, E29a,
  E38(d), A13c c3 and C2g/C2h acceptance (the lowered row commits and reloads).
- **V2:** the sync `Message` after a possible write now says the change may have been applied. Three
  default texts in `outcome.go` (integration lines 101, 137, 158) are reworded by a **named serial
  edit owned by A13c** (§1.6, §4.1), with the matching `outcome_test.go` rows and the A13b tool
  copies.
- **V3:** the journey edits are rewritten from the real v2 audit row shape (several
  `approval-<transition>` rows per request, `commands: []`, `servers: null`, `decided_by` inside
  `approval`). The `sync_test.go` edit is now required, and `transfer_test.go:132` is named. Also new:
  a v2 card's buttons carry `v:a:<handle>:<challenge>` (`telegram_v2.go:106`), not
  `approve:<request_id>`, so the journey cannot take the request ID from the card at all (§4.3a).
- **V4:** A13c's commits are reordered so each commit's acceptance holds at that commit. The receipt
  parsers take `(head, overflow)`, and an overflow is always `malformed` (§1.4), an input
  `AdminOutcome` actually receives.
- **P3 (verify-r2):** a (E10 S:335 carve-out, §1.5k), b (A5 annotation set inside `AdminOutcome` from
  the draft's coordinator), c (T1 is the `signer_incompatible` outcome, the command-job precedent),
  d (RECV body cap), e (integration test ports in A13b c5), f (`draft_test.go` excluded from A13c),
  g (C2i golden test lives in `src/executor`), h (U1a text), i (`OnRelease` is additive), j (C2f
  expected classes), k (cites).
- **Renumbered:** r2's O14 (journey owner) is now O15.

## Revision 2 changelog (folds the revision 1 critique; rejected parts in §7)

- **P1-1:** a SEND-ended transfer step is not executed. This now amends E10 (S:337), E28 (S:551; the
  critique's "S:553"), A13a `StepOutcome` (S:1880) and C-64 (S:2508) explicitly (§1.5 f-i).
  Invariant 3 and E29a state outright that `TransferStepOutcome` maps an executed *leg* status to a
  not-executed *step* status. Ruling O13: a not-executed transfer step stores **no** `exit_code`; only
  the fixed annotation names the SEND exit.
- **P1-2:** A13c no longer edits `outcome.go` (see P2-1). Its Owns excludes `outcome.go`,
  `outcome_test.go`, `remediation_test.go` (C2's ruling-36 hunk, `56b86af`) and `draft.go` (A13b's
  ruling-19 hunk). Serial order and DAG are in §4.1.
- **P1-3:** the journey edits are named (§4.3a), and a JP §4 bullet is added (§5 item 17).
  `TransferOutput.AuthMode` comes from `Summary.AuthMode`.
- **P2-1:** a new `AdminOutcome` (replacing `ConfirmExitZero`) runs on every admin `StepOutcome` result
  that has no `PhasedError`. It keeps `failed` and sets one fixed annotation per exit. It lowers an
  exit-0 `succeeded` to `indeterminate` when the receipt check fails. `StepOutcome` and
  `outcome_test.go` stay byte-unchanged. No annotation holds stdout, stderr or quotes (invariant 6).
- **P2-2:** texts after a possible write now say so. This covers revoke exit 1 and any other
  non-65/77 exit, RECV and update exits other than 65/70/77, and a revoke with a receipt but a
  non-zero exit.
- **P2-3:** the claim that the async revoke job view reads `registry_removed: false` is dropped. A
  `succeeded` executor revoke carries the fixed annotation `AnnRevokeRegistryKept`, which C3 renders
  verbatim.
- **P2-4:** edge C2e → C2h added.
- **P2-5:** the executor gets one shared two-slot large-buffer semaphore for transfer envelopes and
  update bodies (ruling O4, revised).
- **P2-6:** E74 gains one sentence for not-executed results committed beside the transfer marker.
- **P3 folded:** 1 (size check against `len(body)`), 2 (gate-source pin), 3 (bare revoke receipt
  dropped), 4, 5, 6, 7, 8, 9, 10 and 12 (cites). P3-11 is recorded as a pre-existing gap and narrowed
  in A13b c5 (§4.3).
- **Removed:** r1's note that A1a-auth had no lane commits. It merged as `756298d`, so `Summary.AuthMode`
  exists (`approvalplan/viewtypes.go:176`).

## 0. Invariants this amendment keeps (fail-closed bar)

1. **No unconfirmed success.** An exit-0 admin step or RECV leg is `succeeded` only when its receipt
   parses under the strict grammar in §1.4 and matches the approved values. Anything else is
   `indeterminate`.
2. **No auto-retry of an unknown effect.** Every new `indeterminate` row has `Retryable: false`, no
   retry advice, and the verdict class `execution_indeterminate` (`stop_do_not_retry`, E11 S:343).
3. **`failed` keeps its E29 meaning for the step's write:** a known non-zero exit of the dispatch that
   carried the write (S:562).
   - For a command or admin step, that is the step's only dispatch.
   - For a transfer, it is the RECV leg, because SEND only reads (`gate xfer.go:100`). So a transfer
     step that SEND ended is never `failed`, even when SEND had a known non-zero exit (rows T4-T7).
   - E10, E28, E29a, S:1880 and C-64 all say this (§1.5).
   - No new step status, job class or wire field is added. The E29 partition (S:570) and
     `AggregateJobClass` are unchanged, so the signer's report check (`record.go:754-785`) is unchanged
     too.
4. **"Not executed" is used only when the write provably did not reach its host.** For a transfer this
   means the RECV leg's exec request was never sent. This is the S:555 precedent.
5. **The envelope never leaves memory.** SEND stdout is never stored, reported, logged or counted in
   any job-file field (`transfer.go:158-163`).
6. **Every stored annotation is a fixed constant** that passes `StepResult.validate`
   (`record.go:1054-1056`).
   - That means 1-256 bytes of printable ASCII, no leading or trailing space, and none of `"` `\` `<`
     `>` `&` (`bounds.go:189-190`).
   - No annotation embeds stdout, stderr, an exit number not fixed in its text, or any other runtime
     value.
   - The longer v1 texts stay in `Outcome.Message`, which is sync-only and never stored.
7. **A text written after a possible write says the change may have been applied.**
   - "Refused" or "nothing was written" is used only for exits the gate returns before its write:
     SEND (any exit), RECV and update 65, 70 and 77, and revoke 65 and 77.
   - Any other exit gets "may have been applied" wording. That includes a signal-killed gate, which
     x/crypto turns into a known exit (`phased.go:129-130`).
   - This holds for the stored annotation **and** for the sync tool's `Outcome.Message` (§1.6).
8. **An `indeterminate` step stores no `exit_code`** (O14). `failed` stores its known exit (> 0),
   `succeeded` stores 0, and every not-executed status stores none. These are exactly the shapes the
   executor store accepts (`store_linux.go:309-318`), so a lowered row commits and reloads. When the
   gate exited 0 but its receipt failed the check, the fixed annotation says so.

## 1. Outcome tables (ruling 17 and ruling 18)

### 1.1 Mechanism (where the tables live)

- **`StepOutcome` stays as it is.** Its signature, every existing row (`jobplan/outcome.go:45-110`,
  pinned by S:1880 and `outcome_test.go`) and C2's ruling-36 exports (`c2:jobplan/outcome.go`) keep
  the **per-leg / per-dispatch** mapping. The new tables sit on top of it, in new files of
  `src/mcp/jobplan` (lane A13c, §4). `outcome.go` is not edited.
  - **`AdminOutcome(kind StepKind, executorRun bool, phased PhasedResult, ev Evidence, approvedHash string, streamedLen int64, o Outcome) Outcome`**
    is the admin layer. `Evidence` is `{Head []byte; Overflow bool}` from `capture`.
    `executorRun` is `r.draft.Coordinator == approvalplan.CoordinatorExecutor` (`runner.go:89`). `RunStep` calls it right after `StepOutcome` (`runner.go:201`) for
    `AdminRevoke` and `AdminUpdate`, whenever `phased.Err == nil` and the exit is known.
    - On `o.Status == failed` it keeps the status, keeps `o.Message`, and sets the fixed annotation
      for that exit (rows A1, A2a, A2b, U1a-U1d).
    - On `o.Status == succeeded` it runs the receipt check and either keeps `succeeded` (A5, U6) or
      lowers it to `indeterminate` (A3, A4, U2-U5). On A5 with `executorRun`, it sets
      `AnnRevokeRegistryKept`, so the annotation is already in the result that `RunStep` hands to
      `journal.AfterStep` (`runner.go:143`).
    - **Exit code (O14):** `RunStep` sets `result.ExitCode` only after `AdminOutcome` returns, and
      only when the final status is `failed` or `succeeded` (today it sets it on every known exit,
      `runner.go:205-207`). A lowered row therefore stores none.
    - It never raises a status and never touches a `PhasedError` outcome (`outcome.go:46-63`).
  - **`TransferRunner`** is a new two-leg coordinator in `jobplan`.
    - The A13b sync tool and the C2 executor share it.
    - `NewRunner` cannot run a transfer: it refuses drafts without a `CommandJob` (`runner.go:71`), and
      `stepKind` never yields the xfer kinds (`runner.go:237-245`).
    - Each leg goes through `StepOutcome(XferSend|XferRecv, …)`. Then `TransferStepOutcome(send, recv)`
      (table 1.2) gives the one step result.
    - **This is a composition, not a lowering.** The step status describes the RECV write. So a SEND
      leg whose own `StepOutcome` status is `failed` or `indeterminate` gives a not-executed step
      status (T5, T6), because the write was never sent. This is the one place where an executed leg
      status becomes a not-executed step status, and E29a says so (§1.5c).
    - Like `RunStep` (`runner.go:133-136`), `TransferRunner.Run` dispatches once. A second call, or a
      call after an abort, returns an error and dispatches nothing.
- **Receipt fields out of the runner.** `StepExecution` (`runner.go:39-42`) gains a
  `Receipt *Receipt` field.
  - It holds `{XferID, Bytes}`, `{SHA256, Size, Rev}` or `{Lines, Dir}`.
  - It is set only on `succeeded` (T16, U6, A5). It is memory-only, and is never journaled or
    reported.
  - The sync tools read `xfer_id`/`bytes` and the update fields from it.
- **Evidence capture.** The executor caps each stream at `min(max_output_bytes, 1 MiB)` (`runner.go:188-192`),
  so an agent asking for `max_output_bytes: 1` could cut a receipt off before the check.
  - `capture` therefore gains a head-of-stream **evidence buffer**: the first 4096 bytes of stdout,
    kept for every admin step and every RECV leg whatever the body cap. It lives in memory only and is
    never journaled.
  - This is the same "keep the evidence despite the cap" device as the read-jail line
    (`capture.go:29-37`, used for read kinds at `runner.go:197-200`).
  - Receipts are parsed from the evidence buffer, never from the stored body. `capture` also reports
    `Overflow`, true when stdout went past the 4096-byte head. The parsers take `(head, overflow)`,
    and an overflow is always `malformed` (§1.4): a gate prints its one receipt line and nothing else.
- **Annotations** are the fixed constants of invariant 6, exported from `jobplan/annotations.go`.

### 1.2 Transfer: one job step, two legs

A transfer is one job step (`record.go:1061-1067`, `jobview.go:157-171`). Its two signatures arrive in
SEND-then-RECV order (`record.go:476-490`). Both legs have the same window, `decided_at + 300`
(`draft.go:140`; `MaxTransferTTLSeconds`, `bounds.go:64`), but K16 is checked separately for each
leg (S:555).

**Step-result fields (E38):**
- `exit_code`: **the RECV leg's known exit, stored only on `failed` (T12) and `succeeded` (T16).** It
  is omitted when the RECV exec request was never sent (T2-T10, ruling O13: an E38 reader would take a
  not-executed step with "exit 65" as a contradiction, and the T6 annotation already names the SEND
  exit), when RECV has no known completion (T11), and when an exit 0 is lowered to `indeterminate`
  (T13-T15, ruling O14: the annotation says the gate exited 0).
- `stdout`, `stderr` and their counts and digests: **RECV only**. A step that SEND ended stores empty
  bodies with counts 0. SEND stdout is the envelope and SEND stderr was never surfaced in v1
  (`transfer.go:164`, `:208-210`), so neither is stored.
- `truncated`: RECV only.

Rows are evaluated in order. "Dest" means the destination host. Annotations marked *(new)* are A13c
constants; the others already exist. Every text below is the exact constant.

| # | Point reached | Leg result | Step status | Executed? | `exit_code` | Annotation |
|---|---|---|---|---|---|---|
| T1 | Claim → leg check (§3.3) | the envelopes don't decode, a leg's `Cmd` doesn't parse, or it doesn't match the draft | no step result: the job ends with the `signer_incompatible` outcome (all steps `not_run`, no report), as a command job's signature mismatch does (`c2:execute_linux.go:239-241`) | no | — | none (the sync tool returns a `signer_incompatible` Denial; ruling O16) |
| T2 | `ReadCurrent` on source **and** destination, before SEND | either is changed or unreadable | `stale_target` | no | — | existing `target changed before dispatch` / `registry unreadable` (`runner.go:155-158`) |
| T3 | K16 before SEND, and SEND's pre-start guard | refused | `expired_unexecuted` | no | — | existing `signature window closed before dispatch` |
| T4 | SEND `RunPhased` | `failed_not_started` (dial, handshake, session, exec rejected) | `failed_not_started` | no | — | *(new)* `transfer send leg not started; nothing was transferred` |
| T5 | SEND | `indeterminate` (Start I/O error, exit status missing, transport or ctx error after Start) | `failed_not_started` | no | — | *(new)* `transfer send leg lost; the receive leg was never dispatched; nothing was transferred` |
| T6 | SEND | known exit ≠ 0 | `failed_not_started` | no | — | *(new)* four constants: `source gate refused the transfer send (exit 65); the receive leg was never dispatched; nothing was transferred`, the same text with `(exit 70)` and with `(exit 77)`, and for any other exit `source gate send leg ended with an unexpected exit; the receive leg was never dispatched; nothing was transferred`. The sync `Message` is `xferSendExitNote` (`outcome.go:112-123`). |
| T7 | SEND | exit 0, but the envelope is empty or over `MaxTransferEnvelopeBytes` | `failed_not_started` | no | — | *(new)* `source gate returned no usable envelope; the receive leg was never dispatched; nothing was transferred` |
| T8 | `ReadCurrent(destination)` again, immediately before RECV | changed or unreadable | `stale_target` | no | — | *(new)* `destination changed before the receive leg; nothing was transferred` |
| T9 | RECV K16 and pre-start guard | refused | `expired_unexecuted` | no | — | *(new)* `signature window closed before the receive leg; nothing was transferred` (S:555) |
| T10 | RECV `RunPhased` | `failed_not_started` | `failed_not_started` | no | — | *(new)* `transfer receive leg not started; nothing was transferred` |
| T11 | RECV | `indeterminate` | `indeterminate` | **yes** | — | *(new)* `transfer receive leg lost after dispatch; the destination file may have been written` |
| T12 | RECV | known exit ≠ 0 | `failed` | yes | RECV's | *(new)* For 65, 70 and 77, which the gate returns before its write (`AtomicReplace` fails only before its rename, `gate replace.go`): `destination gate refused the transfer receive (exit 65); nothing was written`, and the same with `(exit 70)` and `(exit 77)`. For any other exit, a signal-killed gate included: `destination gate receive leg ended with an unexpected exit; the destination file may have been written; not confirmed`. The sync `Message` is `xferRecvExitNote` plus the trimmed gate stderr, as in v1 (`transfer.go:181`), with its default branch reworded (§1.6). |
| T13 | RECV exit 0 | no overflow, and the prefix appears nowhere in the evidence head | `indeterminate` | yes | — | *(new)* `destination gate exited 0 without a transfer receipt; the file may have been written; not confirmed` |
| T14 | RECV exit 0 | stdout overflowed the head, or the prefix is present but there isn't exactly one line that matches the grammar (§1.4) | `indeterminate` | yes | — | *(new)* `destination gate exited 0 but printed a malformed transfer receipt; the file may have been written; not confirmed` |
| T15 | RECV exit 0 | a valid receipt whose `xfer=` differs from the approved ID, which is the RECV leg's `XferID` (§3.3) | `indeterminate` | yes | — | *(new)* `destination gate exited 0 but confirmed a different transfer id than approved; the file may have been written; not confirmed` |
| T16 | RECV exit 0 | a valid receipt with the approved ID | `succeeded` | yes | 0 | none; `StepExecution.Receipt` carries `xfer_id` and `bytes` |

**Why T13-T15 are `indeterminate` and not `failed`:**
- The gate writes the file (`xfer.go:265`), then audits it (`:272`), and only then prints the receipt
  (`:275`). An exit 0 without a good receipt therefore cannot prove that nothing was written, and
  `failed` means a known non-zero exit (S:562).
- v1 already refused success in each of these cases (`transfer.go:186-194`). v2 keeps that refusal and
  adds the "may have been written" fact.
- The same write-then-print window is why T12's "other exit" text says the file may have been
  written: a gate killed by a signal between `:265` and `:275` yields a known exit 128+n.

**Why T4-T8 are "not executed" even when SEND ran:**
- The only write in a transfer is RECV's. SEND reads the source and prints the sealed envelope.
- The RECV leg's signature was never sent anywhere, and the coordinator drops it (SA-1 rule 3.4).
- S:555 already counts "SEND ran, RECV guard refused" as nothing transferred. T4-T8 extend the same
  rule to every case where RECV never started.
- The alternative, `indeterminate` for T5, would tell the agent "may have run, do not retry" about a
  transfer that provably did not happen.

**Partial transfer:**
- A single-step job can never be `partial` (the E29 partition, S:570).
- The "half-done" cases are T4-T10 (nothing transferred) and T11-T15 (may have been written; for T12,
  only on an unexpected exit).
- The gate writes with `AtomicReplace` (`xfer.go:265`), so a torn destination file is not one of the
  outcomes.

**Markers and recovery:**
- The step marker is committed before SEND's `Start`, as SA-5 orders: one marker per step, before
  `Start` (S:556, E74 S:870).
  - So T4-T16 commit their result beside that marker.
  - T4-T10 are not-executed results beside a marker. `ApplyJob` accepts that (`jobview.go:256-261`),
    and E74 now says so (§1.5j).
  - T2, and a T3 refused before the marker commit, commit with no marker. T1 commits no step result
    at all: the job ends by its outcome at Claim, before any marker.
- A restart that finds the marker with no result records `indeterminate` (E74 recovery, S:872).
  - This also happens when the crash was during SEND. That case is conservative but fail-closed, and
    it needs no new durable shape.
  - Rejected alternative: marking only before RECV. That would leave SEND's `Start` unmarked and
    contradict SA-5's literal rule.

### 1.3 revoke_server and update_gate (ruling 18)

`AdminOutcome` runs on every admin result that has a known exit. A `PhasedError` result keeps
`StepOutcome`'s mapping (`outcome.go:46-63`), including `guard_refused`. `Outcome.Message` keeps v1's
texts, sync-only.

Gate facts used below:
- `doRevoke` returns only 0 or 1 (`main.go:682-702`). Its exit 1 can follow a rewrite of
  `authorized_keys` (`revoke.go:88`) or a partial `RemoveAll` (`revoke.go:97`).
- Exits 65 and 77 are the gate's verify and permission refusals, returned before the verb runs.
- `doUpdate`'s 65 checks and its 70 replace failure come before its atomic rename (`update.go:171`).
  Its receipt follows the replace (`update.go:180`).

| # | Kind | Result | Step status | Executed? | Annotation (new constants, exact) |
|---|---|---|---|---|---|
| A1 | revoke | exit ≠ 0 with a receipt line in stdout | `failed` | yes | `gate printed the revoke receipt but exited non-zero; the server may have been revoked; not confirmed; the registry entry was kept`. **Named change:** v1 counted the marker as success at any exit (`revoke_server.go:117`). A gate killed after `fmt.Println` (`main.go:700`) produces this case, so the revoke may well have happened, but it is still never reported as success. |
| A2a | revoke | exit 65 or 77, no receipt | `failed` | yes | `gate refused the revoke; the registry entry was kept` |
| A2b | revoke | any other non-zero exit, no receipt | `failed` | yes | `gate revoke failed partway; the server may have been partly revoked and may be unreachable; not confirmed; the registry entry was kept` |
| A3 | revoke | exit 0, no overflow, prefix absent from the head | `indeterminate` | yes | `gate exited 0 without the revoke receipt; the server may have been revoked; not confirmed; the registry entry was kept` |
| A4 | revoke | exit 0; stdout overflowed the head, or the prefix is present but there is no single valid receipt line | `indeterminate` | yes | `gate exited 0 but printed a malformed revoke receipt; the server may have been revoked; not confirmed; the registry entry was kept` |
| A5 | revoke | exit 0, exactly one valid receipt | `succeeded` | yes | Sync: none (the tool removes the alias, §1.5c). Executor: `AnnRevokeRegistryKept` = `server revoked; the executor does not edit the registry; remove the alias by hand (sshgate revoke ALIAS prints the steps)` (ruling O5; `src/cli/cmd/sshgate/revoke.go:12-22` is the print-only local-forget helper) |
| U1a | update | exit 65 | `failed` | yes | `gate refused the signed update (exit 65); the old gate is unchanged` (65 is either a failed signature verify, `main.go:263-272`, or a failed binary check; both are pre-write) |
| U1b | update | exit 70 | `failed` | yes | `gate could not replace its binary; the old gate is still in place` |
| U1c | update | exit 77 | `failed` | yes | `server denied the signed update; nothing was changed` |
| U1d | update | any other non-zero exit | `failed` | yes | `gate update ended with an unexpected exit; the new binary may be installed; not confirmed` |
| U2 | update | exit 0, no overflow, prefix absent from the head | `indeterminate` | yes | `gate exited 0 without the update receipt; the new binary may be installed; not confirmed` |
| U3 | update | exit 0; stdout overflowed the head, or the prefix is present but there is no single valid receipt line (bad hex, missing `size=`, duplicates, …) | `indeterminate` | yes | `gate exited 0 but printed a malformed update receipt; the new binary may be installed; not confirmed` |
| U4 | update | valid receipt, `sha256` ≠ the hash in the frozen `ExactCommand` (`SSHGATE_UPDATE <hash>`, `draft.go:63-65`) | `indeterminate` | yes | `gate exited 0 but confirmed a different binary hash than approved; the installed binary is unknown; not confirmed` |
| U5 | update | valid receipt with the approved hash, but `size` ≠ `len(body)` of the approved buffer that was streamed (`Dispatch.StreamedLen`) | `indeterminate` | yes | `gate exited 0 but confirmed a different binary size than was streamed; not confirmed`. Named change: v1 didn't check size. The gate reads all of stdin before hashing (`update.go:107`), so the sizes agree on a real success. The length comes from the buffer, not from a counting reader, because x/crypto copies a non-File stdin in a goroutine that `Wait` does not join (P3-1). |
| U6 | update | valid receipt, hash and size match | `succeeded` | yes | none |
| U7 | update, executor only | at dispatch, before `BeforeStep`, the staged binary is unreadable, empty, over 64 MiB, or its hash differs from `ExactCommand` | `failed_not_started` | no | `staged gate binary changed or unreadable since approval; nothing was dispatched` (§3.4) |

**Every U and A row:**
- `indeterminate` rows: `Retryable: false`, `VerdictClass: execution_indeterminate`, no retry text.
- `failed` rows keep `StepOutcome`'s `Retryable: false` and its sync `Message` (`outcome.go:100-103`),
  with the post-write default texts reworded (§1.6).
- `exit_code` (O14): `failed` rows store the exit; A5 and U6 store 0; every `indeterminate` row and U7
  store none.
- These are single-step jobs, so `partial` is always false, and an `indeterminate` aborts nothing more.
- `Dispatch` gains `StreamedLen int64`, which both callers set to `len(body)`. `RunStep` passes it and
  the approved hash to `AdminOutcome`.

### 1.4 Receipt grammars (one function each, in `jobplan/receipts.go`)

- **Line split:** split the evidence on `\n` and drop one trailing `\r` from each line. A **receipt
  line** is a line that begins with the prefix.
- **Overflow first:** when `capture` reports that stdout went past the 4096-byte head, the class is
  `malformed`, whatever the head holds. A gate prints its one receipt line and nothing else, so a
  longer stdout is never a confirmed receipt.
- **Missing:** no overflow, and the prefix doesn't occur anywhere in the head.
- **Malformed:** no overflow, and the prefix occurs, but the evidence doesn't hold exactly one receipt line matching the
  grammar, or it holds more than one receipt line. This includes the prefix appearing mid-line, which
  v1's `Contains` accepted (`transfer.go:245`, `update_gate.go:318`).
- **Revoke:** `^SSHGATE_REVOKED( lines=[1-9][0-9]{0,9})? dir=(removed|absent)$`.
  - The current format is `revoke.go:237-248`.
  - Every gate since the `SSHGATE_` rename (`7084696`) prints `dir=`, so there is no bare-prefix form.
    r1's "older gates" branch is dropped (P3-3).
- **Update:** `^SSHGATE_UPDATED sha256=([0-9a-f]{64}) size=([1-9][0-9]{0,19}) rev=([!-~]+)( [a-z_]+=[!-~]+)*$`
  - Current format: `update.go:180`.
  - The `rev=` key is frozen (`update_gate.go:314`). Trailing `key=value` tokens are tolerated, as
    the VERSION consumers do (`update.go:235-239`).
  - This replaces `parseUpdatedMarker`'s any-field scan (`update_gate.go:317-342`), where the last
    `sha256=` anywhere in stdout won.
- **Transfer:** `^SSHGATE_XFER_RECEIVED xfer=(\S+) bytes=([1-9][0-9]{0,18})$`
  - Current format: `xfer.go:275`.
  - The ID must also pass `xferwire.ValidXferID` (`xferwire.go:306`).
  - `bytes=0` counts as malformed, because the gate refuses an empty source with SEND exit 65
    (`outcome.go:115`).

### 1.5 Exact spec text

**(a) E28, the end of the S:555 guard bullet.** Append:

> (Q3 port) A transfer step is run by jobplan's `TransferRunner`, never by the command-job runner. Its
> legs, its single marker and its step result follow E29a.

**(b) E29, S:562 (Step status).** After "`failed` (a known non-zero exit);", insert:

> (for a transfer, the exit of the RECV leg, which carries the write; a transfer step that SEND ended
> is never `failed`: E29a. An admin step or a RECV leg that exits 0 without a confirmed receipt is
> `indeterminate`, never `succeeded` or `failed`: E29a);

**(c) A new block after S:573**, before E30 at S:575:

> **E29a — Admin postconditions and the transfer step (Q3 = NO, rulings 17 and 18; new).**
> - `StepOutcome` stays the per-dispatch mapping. Two functions in `src/mcp/jobplan` sit on top of
>   it, and both the sync coordinator and the executor use them:
>   - `AdminOutcome`, for `admin_revoke` and `admin_update` results with a known exit. It keeps a
>     `failed` status and gives it a fixed annotation per exit. It lowers an exit-0 `succeeded` to
>     `indeterminate` when the receipt check fails. It never raises a status.
>   - `TransferStepOutcome`, for the one step a transfer's two legs make. It composes the two legs'
>     `StepOutcome` results into a step status that describes the RECV write. **This is the one
>     place where an executed leg status becomes a not-executed step status:** a SEND leg that is
>     `failed` or `indeterminate` ends the step `failed_not_started`, because the RECV exec request,
>     which carries the only write, was never sent (S:555's rule).
> - Neither adds a status, a class or a wire field. The E29 partition and `AggregateJobClass` are
>   unchanged.
> - **Annotations** are fixed constants that pass `StepResult.validate`: no runtime values, no quotes,
>   no stdout or stderr. The tools' longer texts stay in the sync-only `Message`. A text written after
>   a possible write says the change may have been applied, and so does the sync `Message`. "Refused"
>   or "nothing was written" is used only for exits the gate returns before its write.
> - **Receipts** are parsed from a 4096-byte head-of-stdout evidence buffer that `max_output_bytes`
>   doesn't cap and that is never journaled. A receipt is valid only under its anchored grammar
>   (exactly one matching line).
>   - Admin: an exit-0 step without a valid receipt is `indeterminate`. So is an update whose receipt
>     hash differs from the hash in the step's frozen `ExactCommand`, or whose size differs from the
>     length of the buffer streamed. A stdout longer than the evidence head is a malformed receipt.
>   - **A step lowered to `indeterminate` stores no `exit_code`** (as every `indeterminate` step); its
>     fixed annotation says the gate exited 0 without a valid receipt.
>   - Revoke: a non-zero exit is `failed` even when a receipt line appears, annotated "may have been
>     revoked; not confirmed".
>   - Each `indeterminate` case has its own fixed annotation, `execution_indeterminate`, and no retry
>     advice.
> - **Transfer.** The step's status describes the destination write.
>   - Every outcome in which the RECV leg's exec request was never sent is a not-executed status, and
>     nothing was transferred. That covers a stale endpoint before either leg, either
>     leg's guard, a SEND that was not started, lost, or exited non-zero, and an empty or oversized
>     envelope. The statuses are `failed_not_started`, `stale_target` and `expired_unexecuted`. Legs
>     that disagree with the draft at Claim end the job with the `signer_incompatible` outcome before
>     any step result, as a command job's signature mismatch does.
>   - Once RECV may have run: a lost RECV is `indeterminate`; a known non-zero RECV exit is `failed`;
>     exit 0 is `succeeded` only with a valid receipt whose transfer ID equals the RECV leg's; a
>     missing, malformed or wrong-ID receipt is `indeterminate`.
>   - The step's `exit_code` is the RECV leg's known exit, stored only on `failed` and `succeeded`. It
>     is omitted on every not-executed status and on `indeterminate` (lost RECV, or an exit 0 without
>     a confirmed receipt). Bodies and byte counts are the RECV leg's only. SEND stdout (the
>     envelope) is held in memory up to `MaxTransferEnvelopeBytes` (`2 × 8 MiB + 64 KiB`, the gate's
>     RECV bound) and is never stored, counted or reported.
>   - One marker is committed before SEND's `Start`. A not-executed result after it is committed
>     beside the marker (E74). A crash during either leg recovers as `indeterminate` (E74).
> - **Side effects run only after the step is final, and only on the sync coordinator:**
>   - `revoke_server` removes the registry alias only after `succeeded`. A failed removal keeps the
>     step `succeeded` and reports `registry_removed: false`.
>   - `update_gate` invalidates the capability cache after any executed status. It runs the liveness
>     probe only after `succeeded`.
>   - The executor never writes `servers.json`. Its `succeeded` revoke carries a fixed annotation that
>     names the manual registry step.
> - **Ledger:** C-68 (admin postconditions), C-69 (transfer step), C-70 (the executor runs every kind
>   it admits).

**(d) E38, after "It never carries output bodies." (S:635).** Add:

> An `indeterminate` step carries no `exit_code`. For a transfer's one step, `exit_code` is the RECV
> leg's known exit on `failed` and `succeeded` only (omitted on every other status), and the byte counts, `truncated` and `result_digest` inputs are the RECV
> leg's only (E29a); the SEND envelope is never a body.

**(e) §1.3, after item 39 (S:965).** Add owner-visible item 40:

> 40. (Q3 port) Admin and transfer results are stricter than v1:
>     - A revoke that prints its receipt but exits non-zero is now `failed` ("may have been revoked;
>       not confirmed"); v1 reported success and removed the alias.
>     - An exit 0 without a valid receipt, with a different confirmed hash, or with a different
>       confirmed size is reported as possibly run (`indeterminate`). v1 returned a plain error.
>     - A transfer refused by the source gate is reported as not run (nothing transferred).
>     - An async `revoke_server` job never removes the registry alias; its result says to remove it
>       by hand.

**(f) E10, S:337.** After "a post-dispatch exit 77 is `failed` (executed, in `executed_ordinals`)
whatever its stderr says", insert:

> (for a transfer leg, this is the leg's `StepOutcome` status. The transfer step's status follows
> E29a, so a SEND leg's 77 ends the step `failed_not_started`, nothing transferred, because the RECV
> leg carrying the write was never sent. That rests on the RECV exec request never being sent, not on
> stderr)

**(g) E28, S:551 (`failed_not_started` bullet).** After "the same exit is `failed`, executed (E10)",
append:

> ; for a transfer this is the leg's status, and the step's status follows E29a.

**(h) S:1880 (A13a `StepOutcome`).** After "a known non-zero exit after dispatch is `failed`
(executed) on every route", insert "(per dispatch; a transfer step composes its legs by E29a)". At the
end of the bullet, append:

> (Q3 port) Admin results with a known exit then pass through E29a's `AdminOutcome`, and transfer
> legs through `TransferStepOutcome`. `StepOutcome`'s statuses are unchanged; three of its sync
> texts (the revoke text for exits other than 65 and 77, and the RECV and update default texts) say
> that the change may have been applied (`q3-tool-port-design.md` §1.6).

**(i) C-64, S:2508.** After "it is `failed` and in `executed_ordinals`", insert:

> (per dispatch: a transfer step whose SEND leg exits 77 is `failed_not_started` by E29a, since its
> RECV write was never sent)

**(j) E74, S:870 (Step k).** Append:

> (Q3 port) A transfer step has one marker, committed before SEND's `Start`. A not-executed result
> that ends the step after that marker (SEND not started, lost or refused, no usable envelope, the
> destination re-check, the RECV guard, RECV not started: E29a) is committed beside the marker, as
> the K16 re-check result above is. The marker means only that SEND may have started.

**(k) E10, S:335.** After "A post-dispatch exit 65 or 77 on a signed step is `failed`", insert
"(a transfer step: E29a)".

### 1.6 Sync `Message` texts after a possible write (V2)

`Outcome.Message` is never stored, but it is the sync tool's error text, so invariant 7 applies to it.
Three `StepOutcome` texts can follow a write and say "refused". A13c rewords them in one named serial
edit (§4.1). Line numbers are integration `756298d`'s; on `wi2/c2` the same lines are 117, 153 and
174, and C2's ruling-36 hunk does not touch them.

| `outcome.go` line | Today | Replacement (`Message`, sync-only; `%q` is allowed here) |
|---|---|---|
| 101 (`AdminRevoke`) | `tools: gate did not confirm revoke (stdout=%q stderr=%q exit=%d)` for every non-zero exit | exits 65 and 77 keep today's text. Every other exit: `tools: gate did not confirm revoke; the server may have been partly revoked and may be unreachable; check it before any retry (stdout=%q stderr=%q exit=%d)` |
| 137 (`xferRecvExitNote` default) | `the destination gate refused the transfer receive (exit %d).` | `the destination gate ended the transfer receive with an unexpected exit (exit %d): the destination file may have been written; check it before any retry.` |
| 158 (`updateExitNote` default) | `tools: gate refused the update (exit=%d stdout=%q stderr=%q)` | `tools: gate update ended with an unexpected exit; the new binary may be installed; not confirmed; check the server before any re-run (exit=%d stdout=%q stderr=%q)` |

- `outcome_test.go` rows 115 (`AdminUpdate`, 3) and 117 (`XferRecv`, 3) change to the new texts. Row
  114 (`AdminRevoke`, 77) keeps its text, and a new row pins `AdminRevoke`, 1.
- The 65, 70 and 77 texts of RECV and update, and every SEND text, are pre-write and stay.
- The tools' own copies (`revoke_server.go:119`, `transfer.go:236`, `update_gate.go:214`) are deleted
  by A13b c5/c6, which use `Outcome.Message`. c7's drift test then has nothing left to compare for
  these three.
- A13b c5/c6 tests assert that the tool text for A2b, U1d and T12-other holds no "refused".

## 2. Sync vs async per tool

**Ruling O12 (ORCH): K9 is unchanged.** `async` stays on `run` and `run_batch` only. `request_grant`,
`transfer`, `revoke_server` and `update_gate` run synchronously on the v2 path.
- **Basis:**
  - The owner's choice was Q3's alternative text, "port all six tools to the new path now" (R:101).
    Neither that text nor the rest of Q3 mentions async for those four tools.
  - Q3's own scope line gives async to `run` and `run_batch` only (R:92).
  - K9 adds `async` to `run` and `run_batch` only (S:907; C3 S:2138), and "nothing changes a K-ruling"
    (S:12).
- **Reversible:** the executor runs every kind it admits (§3). Adding the MCP flag later would be a K9
  amendment plus a C3 schema change, with no executor work. The owner is told in one line.

| Tool | Sync (in-process coordinator) | Async (`async:true` → executor) | Basis |
|---|---|---|---|
| `run` | yes | yes, except network, which keeps P4.4's sync route (ruling 39), and reveal, which OQ2 refuses | K9 (S:907, S:2138) |
| `run_batch` | yes | yes | K9 |
| `request_grant` | yes | no: it produces no execution, so it has no executor role | `kinds.go:8-16`; K9 |
| `revoke_server` | yes | **no tool flag** (O12); the executor runs such a job if one is submitted to it (§3) | K9, S:12 |
| `update_gate` | yes | same as `revoke_server` | same |
| `transfer` | yes; **local signer only**, since hosted v2 refuses the transfer kind (S:590), as v1 does (`hosted.go:375-377`) | same as `revoke_server` | same; E32 |

- **Executor support for admin and transfer** covers every job its admission accepts: those it already
  builds (`c2:draft_linux.go:34-50`) and the wire input it validates (`executorwire/wire.go:103-118`).
  Today such a job is admitted, and then no worker ever claims or runs it (§3.1). Under Q3 = NO it must
  execute correctly. The MCP itself never submits one.

## 3. Executor admission and `JobNext` changes (C2, ruling 34)

### 3.1 What blocks today (`wi2/c2`)

- **`commandExecutable`** admits only `unsigned_read`, `signed_write` and `signed_reveal` steps, and
  refuses any draft without a `CommandJob` (`c2:execute_linux.go:62-73`). It is checked at `:171`,
  `:470`, `c2:notify_linux.go:148` and `c2:wait_linux.go:65`.
  - So an admitted admin or transfer job is never claimed or run.
  - It holds its live slot and its reservation until retention removes it.
- **Nil `CommandJob` uses** on a transfer job:
  - `JobActCheck` indexes `job.Draft.CommandJob.Steps` (`c2:execute_linux.go:191`), and so do
    `ensureRunner` (`:352`) and `dispatch` (`:371`).
  - `call()`'s `ensureRunner`/`HoldWindows` on a transfer Claim (`:295-300`) would return
    `NewRunner`'s fatal error.
  - C2f and C2h route transfer jobs away from every one of these.
- **`acceptSignatures`** walks `CommandJob.Steps` and requires `payload.Cmd == step.ExactCommand`
  (`c2:execute_linux.go:308-339`). A transfer draft has no command bytes: the signer builds the legs at
  freeze (`plan.go:113-124`), and neither the Summary nor the Claim answer returns them
  (`viewtypes.go:163-187`, `approvalwire/wire.go:144-150`).
- **`dispatch`** passes no stdin (`c2:execute_linux.go:366`), so `update_gate` cannot stream its binary.
- **The release shim** clears the envelopes when `a.ordinal == a.lastSigned`
  (`c2:execute_linux.go:444-447`). For a transfer, ordinal 1 is the last signed step, so the shim would
  clear the RECV leg's authority at the SEND leg's `Start`.
- **Production `main` never calls `StartCommandJobs`** (`c2:README.md:3-7`; there is no call in
  `c2:src/executor/cmd/**`).

### 3.2 Admission (`c2:draft_linux.go:17-53`)

- **No refusal is added.** Ruling 34's "refuse non-command tools" branch is dead. `TestSubmitBuilders`
  (`submit_linux_test.go:245-290`) already covers all five executable tools and stays unchanged.
- **One added bound:** `update_gate` refuses a staged binary over 64 MiB with `invalid_request` before
  the job commit.
  - 64 MiB is the gate's cap (`gate update.go:35`).
  - Today `os.ReadFile` is unbounded (`draft_linux.go:37`).
  - The check uses a `LimitReader` read of cap + 1 bytes.
- **`RunningVersion` stays `gatever.Unknown`** (`draft_linux.go:42`). The card labels every
  `trusted_display` field client-supplied (E33 S:600). Adding an SSH probe at admission would bring a
  network call into the admission critical section. This is ruling O6.

### 3.3 Signature acceptance for a transfer (shared code in jobplan: `VerifyTransferLegs`)

`VerifyTransferLegs(draft, decidedAt, sigs []string) (TransferLegs, error)` runs these checks, in order:

1. `len(sigs) == 2`.
2. `sigwire.DecodeSigned` succeeds on each envelope (`payload.go:116`). Each signature is 64 bytes,
   `Net` and `Reveal` are false, `TS == decidedAt`, and `Exp == decidedAt + SignatureTTLSeconds`. These
   are the same field checks as `c2:execute_linux.go:326`.
3. `xferwire.ParseSend(p0.Cmd)` and `ParseRecv(p1.Cmd)` succeed (`xferwire.go:175,205`).
4. The legs agree with the draft and with each other:
   - SEND: `SrcPath == draft.Source.Path` and `DestID == destination fingerprint`.
   - RECV: `SrcID == source fingerprint`, `DestID == destination fingerprint`,
     `DestPath == draft.Destination.Path` and `Mode == draft.Mode`.
   - Both legs carry the same `XferID`.
   - The host bindings are `p0.Host == source fingerprint` and `p1.Host == destination fingerprint`.
     The signer binds each leg to its own host (`daemon.go:1228`).
5. On success it returns `{SendWire, RecvWire, XferID}`. Any failure is row T1, before any dial: the `signer_incompatible` outcome (O16).

The RECV leg's `XferID` is the approved ID that T15 checks the receipt against. The gate still owns the
cryptographic checks; this function only refuses legs that disagree with the draft. That is
defence-in-depth against a signer bug, and it fails closed.

### 3.4 `JobNext` actor changes (`src/executor/execute_linux.go` on `wi2/c2`)

- **`commandExecutable` becomes `executable(job)`.** It is true for a `CommandJob` whose every step has
  a valid route, `signed_admin` included, and for a `Transfer`. All four call sites change.
- **`JobActCheck`, transfer:** `ReadCurrent` runs for both endpoints, and each must match its
  `RegistryEntryDigest` (`draft.go:137-138`). `JobOnCheck(ok = both match)`. A failure commits
  `stale_target` (T2) with no marker, as E74 S:870 orders.
- **Claim:**
  - Transfer: `VerifyTransferLegs`. A failure sets `answer.Code = signer_incompatible`, the
    command-job precedent (`c2:execute_linux.go:239-241`): the job ends by outcome, nothing is
    dispatched, and no report is sent (T1, O16). Otherwise `answer.Windows = [decided_at + 300]`. `JobNext` expects one
    window per job step (`jobnext.go:193-201`). The transfer branch never calls `ensureRunner` or
    `Runner.HoldWindows`; it holds the window on the `TransferRunner`.
  - Command jobs: unchanged.
- **Large-buffer bound (ruling O4, revised; P2-5):** one service semaphore with **2 slots** is shared by
  every step that holds a large in-memory buffer.
  - Those are a transfer step (its envelope, up to `MaxTransferEnvelopeBytes`, about 16.06 MiB) and an
    update step (its re-read body, up to 64 MiB).
  - The worst case is about 128 MiB. Without the bound, 100 live jobs × 64 MiB would be 6.4 GiB
    (E75).
  - The slot is taken **before** the step's checks, so before `BeforeStep`. It is released after
    `AfterStep` commits, or at any abort.
  - A job that waited for a slot is still checked by K16 once it gets one. So a long wait ends in T3
    or in an `expired_unexecuted` update with no marker, never in a late dispatch.
- **Dispatch:**
  - **`signed_admin` revoke:** `Runner.RunStep` with no stdin. The postconditions come from A13c.
    - **The executor never calls `registry.Remove`.** `Servers.Remove` writes the process's cached
      map back to disk (`servers.go:323-341`), so an executor with a stale cache would silently drop
      aliases that the MCP or CLI added since.
    - A `succeeded` executor revoke therefore carries `AnnRevokeRegistryKept` (row A5). `AdminOutcome`
      sets it when the draft's coordinator is the executor (§1.1), so it is in the result `RunStep`
      hands to `AfterStep` (`runner.go:143`). The job view and the report carry it like any
      other annotation, and C3 renders it verbatim. No job-view field is added. This is ruling O5.
  - **`signed_admin` update:**
    1. Take a large-buffer slot.
    2. Immediately before `BeforeStep`, re-read `s.stagedGatePath` through a `LimitReader` (64 MiB + 1).
    3. Hash the bytes and compare the hash with `ExactCommand`'s.
    4. A mismatch, an empty file or an unreadable file commits U7 (`failed_not_started`) with no marker.
    5. Otherwise pass `Dispatch{WireCommand, Stdin: bytes.NewReader(body), StreamedLen: len(body)}`,
       where `body` is the buffer just hashed. That keeps v1's "hash this buffer, stream this buffer"
       rule (`update_gate.go:117-122,185`) across the admission-to-dispatch gap.
    6. The binary is never written to the job file. The slot and the buffer are released after
       `AfterStep`.
  - **Transfer:** take a large-buffer slot, then `TransferRunner.Run(ctx, legs, journal)`. The actor is
    the `StepJournal`: `BeforeStep(1)` before SEND's `Start`, and `AfterStep(1, result)` once.
- **Release point:** the `a.ordinal == a.lastSigned` shim is replaced by a jobplan callback,
  `OnRelease func()`. It is additive (P3-i): `(*Runner).SetOnRelease(func())` and a `TransferRunner`
  field. `NewRunner`'s signature (`runner.go:67`) and every existing caller stay unchanged. Both runners call it exactly once: at the last `Start`'s guard pass (the RECV
  leg's, for a transfer), or at any abort. The actor clears `a.signatures` and `a.memory.Held` there.
  This is SA-1 rule 3.4 and S:873.
- **Report:** `JobReport` is unchanged. The transfer step's one entry follows E38(d).
- **RECV bodies (P3-d):** `TransferRunner` captures RECV stdout and stderr at a transfer draft's
  `streamOutputCap`, `MaxStreamOutputBytes` = 1 MiB per stream (`record.go:1009-1013`,
  `bounds.go:73`), with `truncated` set as `RunStep` sets it. The stored step then passes `validate`
  and `PermittedOutputBytes` on both paths. The evidence head is captured separately (§1.1).
- **Store:** `validateStoredJob` already gives a transfer step the empty route
  (`store_linux.go:236-240`), and every transfer row's exit shape (O13, O14) is one it accepts. No
  store change.
- **Production wiring:** `cmd/sshgate-executor` builds the signer `CommandSigner` client and the
  `RunPhased` transport, and calls `StartCommandJobs`.
  - The SSH client uses the same key and known_hosts paths as the MCP
    (`src/mcp/cmd/sshgate-mcp/main.go:127-155`), with the same 0600 checks (`requireFileIfExists`).
    The executor refuses to start when they fail.
  - Both processes then share one TOFU `known_hosts`. `TOFU`'s mutex is per process
    (`known_hosts.go:36`), so C2i tests that concurrent first contacts from two processes leave a file
    that `knownhosts.New` still parses.
  - The README and the `execute_linux.go:27-28` comment are updated.

## 4. Lane breakdown

### 4.1 DAG and jobplan writer order

**Writers of `src/mcp/jobplan/**` (P1-2), in serial order:**
1. **C2's ruling-36 hunk** (`c2:56b86af`, inside C2c): `outcome.go` (the three `ReadJail*` constants and
   `ReadJailRemediation`) and the new `remediation_test.go`. It is complete. C2 makes **no further**
   jobplan edit; C2f-C2i consume A13c.
2. **A13b's ruling-19 hunk:** one named edit to `draft.go` (`DraftOptions` gains
   `requested_validity_seconds`; `draft.go:17-24` still lacks it), in an A13b c1-c4 commit.
3. **A13c:** new files plus `capture.go` and `runner.go`, and one **named serial edit** to
   `outcome.go` lines 101, 137 and 158 with `outcome_test.go` rows 114-117 (§1.6, V2).
   - Serial: C2's ruling-36 hunk is committed and frozen first (C2 makes no further jobplan edit), and
     A13c's edit comes after it in time.
   - Disjoint: C2's hunk is the read-jail constants and block (`c2:outcome.go:43-58,87-99`); A13c's
     lines are the revoke case and two default branches. `outcome_test.go` has no C2 edit.
   - A13c's Owns excludes `remediation_test.go`, `draft.go` and `draft_test.go` (ruling 19's hunk and
     its test, P3-f). A13c compiles against integration's `outcome.go`, because it uses no ruling-36
     symbol.

**Edges:**
- **A13c** (new) is cut now from integration `756298d`.
- A13c → A13b c5 and c6. The orchestrator merges A13c into A13b's branch before c5 is cut. A13b's
  `draft.go` hunk and A13c touch different files.
- A13c → C2f-C2i. The orchestrator merges integration with A13c into `wi2/c2` before C2f.
  - The ruling-36 hunk on `wi2/c2` and A13c's `outcome.go` edit are disjoint hunks of one file;
    nothing else in jobplan is shared.
  - The merge must show no conflict in `src/mcp/jobplan`. After it, the orchestrator checks that
    `outcome.go` holds both C2's read-jail constants and A13c's three texts, and runs
    `go test ./src/mcp/jobplan/...`.
- **C2e → C2h** (P2-4): C2h's crash test uses ruling 41's cutpoints, which C2e adds.
- C2f → C2g → C2h → C2i, in that order (one writer: C2).
- A1a-auth → A13b and C3 is satisfied (merged at `756298d`).
- A13b → A13b-docs → C3 (L:381, R:542-548). C2 → C3 is merge-only (S:2126). C2i's goldens freeze
  before C3's cut (ruling 41's fold).
- C2e (hooks, ruling 41; B1f is merged) and the hosted-proxy harness commit (A12 is merged) can land
  now, before C2f.

**Why a new lane and not "an exception for A13b":** A13b and C2 both need the same jobplan code. One
writer per file means one lane owns the new jobplan code and both consumers merge it. A13c therefore
replaces ruling 17's "jobplan annotation edits need an exception for A13b".

### 4.2 A13c — jobplan v2 completion

- **Base:** integration `756298d`.
- **Owns:** `src/mcp/jobplan/**` **except** `remediation_test.go`, `draft.go` and `draft_test.go`;
  `outcome.go` and `outcome_test.go` only for the named serial edit of §1.6.
  - New files: `receipts.go`, `annotations.go`, `postcond.go`, `transfer.go` and their tests.
  - Edits: `capture.go` (evidence head and overflow) and `runner.go` (the `AdminOutcome` call, the
    exit-code rule of O14, `Dispatch.StreamedLen`, `StepExecution.Receipt`, `SetOnRelease`).
- **Forbidden:** the three excluded jobplan files, any other line of `outcome.go` or
  `outcome_test.go`, `src/mcp/ssh/**` (`RunPhased` already takes stdin, `phased.go:30,38`),
  `src/approvalplan/**`, `src/executor/**`, `src/mcp/tools/**` and `src/gate/**`.
- **Accept:**
  - `flock $LOCK go test -race -count=1 ./src/mcp/jobplan/... ./src/mcp/ssh/...`, plus STD.
  - `go vet ./...` passes, so every existing `NewRunner` caller compiles unchanged (P3-i).
  - `git diff 756298d -- src/mcp/jobplan/draft.go src/mcp/jobplan/draft_test.go` is empty, and
    `git diff 756298d -- src/mcp/jobplan/outcome.go` changes only the three texts of §1.6.

**Commit order (V4):** each commit's acceptance holds at that commit. c2 adds the evidence but
changes no status; the first status change is c3.

| Commit | Content | Acceptance tests (each proves an observable effect) |
|---|---|---|
| c1 | `receipts.go`: `ParseRevokeReceipt`, `ParseUpdateReceipt` and `ParseXferReceipt` take `(head []byte, overflow bool)` and return `{class: missing\|malformed\|ok, fields}`. `annotations.go`: every constant in §1.2 and §1.3. Pure functions; nothing calls them yet. | <ul><li>`TestReceiptsAcceptRealGateOutput` feeds the exact bytes of `gate.FormatRevokeStdout` for {lines 0, 3} × {dir removed, absent} (test import of `src/gate`), plus update and xfer receipts built from sample values, and asserts `ok` with the right fields.</li><li>**Source pin (P3-2):** the test reads `src/gate/cmd/sshgate-gate/update.go` and `xfer.go` and asserts that each holds exactly one copy of the format literal the samples were built from (`"SSHGATE_UPDATED sha256=%s size=%d rev=%s\n"`, `"SSHGATE_XFER_RECEIVED xfer=%s bytes=%d\n"`).</li><li>A table asserts the exact class for: prefix mid-line, two receipt lines, uppercase or 63-character hex, `size=01`, `size=-1`, `bytes=0`, an invalid xfer ID, an extra token on revoke, a bare `SSHGATE_REVOKED`, `\r\n` endings, an empty head (`missing`), and a valid receipt with `overflow = true` (`malformed`).</li><li>`FuzzReceipts`: no panic, and exactly one class per input.</li><li>`TestAnnotationsValidate`: every exported constant passes `StepResult.validate` inside a `StepResult` (at most 256 bytes, no `"` `\` `<` `>` `&`, no edge spaces).</li></ul> |
| c2 | `capture` evidence: an `Evidence{Head, Overflow}` per admin or RECV dispatch (head = the first 4096 stdout bytes, whatever the body cap), kept in memory and never stored. No status changes in this commit. | In-package tests on `capture` and on `RunStep` with `CoordinatorExecutor` and `MaxOutputBytes: 1` against the in-process SSH server:<ul><li>stdout of 4096 bytes → `Head` is all of it and `Overflow` is false; 4097 bytes → `Head` is the first 4096 and `Overflow` is true;</li><li>the stored `Stdout` is 1 byte with `Truncated: true`, and `StdoutSHA256` is the stored body's digest;</li><li>a byte search finds the head's bytes beyond the first nowhere in the `StepResult` or its JSON;</li><li>a non-admin, non-RECV step gets no evidence buffer.</li></ul> |
| c3 | `AdminOutcome` wired into `RunStep` (rows A1-A5 and U1a-U6), with the O14 exit-code rule, `Dispatch.StreamedLen`, `StepExecution.Receipt`, the A5 executor annotation, and the §1.6 named serial edit to `outcome.go` and `outcome_test.go` | <ul><li>In-process SSH server, one subtest per row. Each asserts `Result.Status`, the exact annotation constant, `Outcome.Retryable == false`, `VerdictClass == "execution_indeterminate"` for the `indeterminate` rows, and `JobView` class, `executed_ordinals [1]` and `partial false`.</li><li>**Exit code (O14):** every `indeterminate` row has `ExitCode == nil`; `failed` rows carry their exit; A5 and U6 carry 0. Each row's `StepResult` passes `ApplyJob` (`RecordResult`), and a JSON round trip of it is byte-equal and passes `StepResult.validate` (the commit-and-reload check at the jobplan level; the executor-store check is C2g's).</li><li>**Moved from r2 c2:** `MaxOutputBytes: 1` and a revoke printing a valid receipt with exit 0 → `succeeded`; the same receipt after 4096 bytes of padding → `indeterminate` with A4's constant (overflow).</li><li>A2b and U1d: the server exits 1 and 137 → the "may have been" constants, and `Outcome.Message` holds the §1.6 text, with no "refused".</li><li>A1: a receipt printed, then exit 137 → `failed` with A1's constant.</li><li>A5: with `CoordinatorExecutor` the annotation is `AnnRevokeRegistryKept`; with `CoordinatorInProcessSync` it is empty.</li><li>U6: the server records stdin bytes equal to the dispatched buffer, and `Receipt` holds its hash and size. U5: the server prints `size=` + 1 → `indeterminate`.</li><li>`outcome_test.go`: rows 115 and 117 pin the new texts, row 114 is unchanged, and a new row pins `AdminRevoke`, 1. Every other row passes unedited.</li></ul> |
| c4 | `VerifyTransferLegs`; `TransferRunner` (T1-T16) with the RECV body cap; `TransferStepOutcome`; `SetOnRelease`; `MaxTransferEnvelopeBytes` | Two in-process SSH servers (source and destination) that count connections and exec requests and record stdin, with legs built by `xferwire.EncodeSend/EncodeRecv` and signed with a test key.<ul><li>**T16:** destination stdin is byte-equal to source stdout; `succeeded`; `ExitCode` 0; `Receipt` holds the approved ID and byte count; a byte search finds the envelope nowhere in `StepResult`.</li><li>**T1:** each mismatch field in §3.3 → `VerifyTransferLegs` returns its typed error, no `TransferRunner` is built, zero connections to either server.</li><li>**T4-T10:** destination exec count 0 (T4-T7), and `ExitCode == nil`. **T6:** exits 65, 70, 77 and 2 each give their exact constant.</li><li>**T7:** an envelope over the cap stops being retained at cap + 1 (a buffer-length probe).</li><li>**T9:** an `internal/elapsed` fake moves past the window during the destination handshake → zero destination exec requests, nothing on any stdin, `expired_unexecuted`.</li><li>**T8:** a `ReadCurrent` hook changes the destination between the legs → `stale_target`, zero destination exec requests.</li><li>**T11-T15:** each row's status and annotation, and `ExitCode == nil`; each lowered row passes `ApplyJob` and round-trips. T12 with exits 65 and 137 gives the two texts, and the 137 `Message` holds no "refused".</li><li>**RECV cap:** a RECV that writes 1 MiB + 1 bytes of stderr → stored stderr of 1 MiB, `Truncated: true`, and the step passes `validate` under a transfer draft's `streamOutputCap`.</li><li>A fake `PhasedRunner` fails the test on a nil guard with an `SSHGATE_SIG:` command.</li><li>`OnRelease` is called exactly once on every path: after the RECV guard passes on T11-T16, and never at SEND's `Start`.</li><li>`BeforeStep` is called once, before SEND's `Start`; `AfterStep` once. A second `Run` on the same runner returns an error and makes zero connections.</li></ul> |

### 4.3 A13b — MCP sync migration (scope grows in c2, c5, c6 and c7)

- **Base and ownership:** unchanged (L:338-345), plus the named `tests/journey/sync_test.go` and
  `tests/journey/transfer_test.go` exceptions of §4.3a when their condition holds. c1-c4 can start now: A12, A13a and A1a-auth are merged,
  and Q3 is answered. c5 and c6 start after A13c is merged into the A13b branch.
- **c2 (P3-9):** c2 adds the `execution_indeterminate` class (S:343). Its `Summary` and `HowTo` are
  written so that they are true of both a lost dispatch and an exit 0 without a confirmed receipt:
  "the command may have run; do not re-run; ask a human to check the host". There is no second
  rewording later, so `TestNewDenial_ShapePinned` is pinned once.

| Commit | Change for Q3 = NO | Acceptance tests |
|---|---|---|
| c5 `revoke_server`, `update_gate` | <ul><li>Both tools become in-process coordinators using `jobplan.Runner`: Submit, Wait, Claim, `RunStep`, Report. The guard goes through `RunPhased`.</li><li>`update_gate` reads the staged binary **once**, before the draft is built, and streams that same buffer after Claim, with `StreamedLen = len(body)`.</li><li>Side effects follow E29a: Remove only after `succeeded`; `invalidateCap` (`netcap.go:47`) after any executed status; `probeAlive` only after `succeeded`.</li><li>Before `Remove`, the tool calls `Servers.Get(alias)`, which reloads any out-of-band change (`servers.go:270-276`). That narrows P3-11's pre-existing window (Remove persists the cached map, `servers.go:323-341`) to the moment of removal. It does not close it (§6.3).</li><li>Outputs gain `execution_status`, `executed_ordinals`, `partial` and `annotation` (`partial` and `annotation` are omitempty). Revoke also keeps `registry_removed`.</li><li>Handlers (`server.go:551-561`, `583-594`) return the structured output with `IsError` instead of dropping it.</li><li>Sign errors are mapped by the C-60 rule; `revoke_server` gains `remediateSignErr`-equivalent Denials.</li><li>The tools' copies of the post-write texts (`revoke_server.go:119`, `update_gate.go:214`) are deleted; the tools use `Outcome.Message` (§1.6).</li><li>**Integration tests (P3-e):** `tests/integration/phase4_test.go:220-248` (`TestPhase4RevokeServer_FullCycle`) and `phase5_update_test.go:138-202` (`TestUpdateGate_Integration_HappyPath`) build `tools.Runner` with only the v1 `Sign`; c5 ports them to the v2 `Approvals` client in the same commit.</li></ul> | <ul><li>Revoke A5: `servers.json`, read back from disk, no longer holds the alias; `registry_removed: true`.</li><li>A3 and A4: the alias is still on disk; `IsError`; `execution_status: indeterminate`; no retry text; the fake signer received a report with class `indeterminate` and mask `[1]`.</li><li>A2b: the tool text says the server may have been partly revoked.</li><li>Remove failure (a read-only registry dir): `succeeded` plus `registry_removed: false`, and the error names the manual removal.</li><li>An alias that another process adds to `servers.json` during the approval wait survives the revoke's `Remove`.</li><li>Update read-once: the staged file is overwritten while Wait blocks; the in-process server receives the original bytes, which hash to the approved hash.</li><li>U4: the cap cache is invalidated (the next `status` re-probes, counted on the fake) and the liveness probe is never sent (fake `SSH.Run` count 0).</li><li>Through `server.go`: `CallToolResult.IsError` and `StructuredContent.execution_status` are both present.</li><li>A2b and U1d: the tool text holds no "refused" and says the change may have been applied.</li><li>Parity rows S:1935-1938 are ported.</li></ul> |
| c6 `request_grant`, `transfer` | <ul><li>`transfer` uses `jobplan.VerifyTransferLegs` and `TransferRunner`. `sign/transfer_client.go` stays v1, unused by the tool.</li><li>`TransferOutput` gains `execution_status` and `executed_ordinals`, plus omitempty `partial` and `annotation`. `xfer_id` and `bytes` come from `StepExecution.Receipt`, only on T16.</li><li>`TransferOutput.AuthMode` comes from the approved `Summary.AuthMode` (A1a-auth, `viewtypes.go:176`), not from a constant.</li><li>The success `Content` text stays byte-identical to v1's (`transferred … auth=%s`).</li><li>The handler (`server.go:617-630`) returns structured output on error, and logs metadata only.</li><li>T1 (legs disagree with the draft) returns a `signer_incompatible` Denial with zero SSH connections (O16).</li><li>The tool's copy of the RECV default text (`transfer.go:236`) is deleted (§1.6).</li></ul> | <ul><li>End to end with a fake `ApprovalClient` that returns two real signed legs, against two in-process servers.</li><li>One subtest per row T1-T16 asserts the tool error text, `execution_status` and `executed_ordinals`.</li><li>For every row, a byte search of the returned error, the output JSON, the live log and `s.Logger` finds no envelope bytes, no `SSHGATE_SIG:` and no payload base64.</li><li>`auth_mode` equals the fake Summary's `AuthMode`.</li><li>Hosted backend: the A12 proxy's transfer refusal gives a typed Denial with zero SSH connections.</li><li>Parity rows S:1939-1940 are ported (`transfer_test.go:178-423`).</li></ul> |
| c7 `StepOutcome` adoption and drift | Delete `parseUpdatedMarker` and `parseXferReceivedMarker` from `src/mcp/tools` (`update_gate.go:317-342`, `transfer.go:244-266`) in favour of jobplan's receipts. The drift test also covers the new constants. | <ul><li>The drift test compares tool texts with jobplan's constants.</li><li>`go vet` plus a grep test show no second receipt parser under `src/mcp/tools`.</li><li>The class count is unchanged at 20.</li></ul> |

- **Accept:** unchanged (L:375-378). FROZEN-MCP; the tool count stays 11.

### 4.3a Journey e2e changes (P1-3, V3)

The journey tests live on the journey branch (`feat/journey-e2e` @ `bdabdcc`). It merges to main, and
then to integration, ahead of C5 (ruling 40, R:516-521).

**What a v2 approval leaves behind (checked in code):**
- The signer writes **several** controller audit rows per request, one per outbox event:
  `{request_id, status: "approval-<transition>", commands: [], servers: null, approval: {...}}`
  (`pkg/signerkit/audit_sink.go:371-378`; `servers` has no omitempty, `audit.go:44`).
- Transitions include `submitted`, `card`, `vote`, `decision`, `mint`, `card_outcome` and
  `final_report` (`src/approvalplan/apply.go:14-33`). A transition may carry `{detail}` suffixes
  (`lifecycle/flush.go:131-140`), and noise rows have `approval.replay: true`.
- The decision row has `approval.transition` = `decision` (with any suffix), `approval.decision` = the
  approval status (`approved`, `denied`, `expired`, …; `viewtypes.go:8-15`), and `approval.decided_by`
  (`apply.go:285`). There is no top-level `auth_mode`. "Human" means `decided_by` is non-empty and
  has no `grant:` prefix (`view.go:46-55`, `apply.go:43`).
- Minting signatures writes an `approval-mint{signatures}` row (`claim.go:114`, `record.go:178`).
- `approval.kind` is `transfer` (`kinds.go:9`) or `command_job`.
- A v2 card's buttons carry `v:a:<handle>:<challenge>` and `v:d:…` (`src/signer/backend/telegram_v2.go:106-108`),
  not `approve:<request_id>`. So the journey's card parse (`J:sync_test.go:114-121`) gives an empty
  `requestID` for every v2 card, and `signerDecision` stops at "card has no request identity". The fake
  service taps by button label (`J:faketg/service.go:295-300`), so its policies still work.

**Edits:**
1. **`J:tests/journey/sync_test.go`, new helper (required).**
   `v2Decision(t, since int, kind, decision string) (requestID string)`:
   - It reads the controller audit rows after index `since`, keeps those with an `approval` object,
     `approval.kind == kind` and no `replay`, and groups them by `request_id`.
   - It requires exactly one request ID.
   - For that ID it requires exactly one row whose transition is `decision` (or starts with
     `decision{`) with `approval.decision == decision`.
   - For `approved` it also requires `decided_by` to be non-empty without a `grant:` prefix, and
     exactly one row whose transition starts with `mint{signatures`. For any other decision it
     requires that no such mint row exists.
   - v1's `timeout` is v2's `expired`.
2. **`signerDecision` (`J:sync_test.go:616-637`) and its `run`/`run_batch` callers (`:464`, `:480`,
   `:564`, `:591`)** move to `v2Decision`, and `signerDecision` is deleted. That is A13b c3's debt
   under either Q3 answer (the JP J5 row's "explicit v2 expectation updates"). It is listed here so
   that one change makes it.
3. **`J:tests/journey/transfer_test.go:190-215`, `transferDecision`:**
   - Drop the card `Xfer:` parse (only v1 prints it, `telegram.go:1453`; v2 mints the ID at freeze,
     after the tap, `daemon_approvals.go:475`) and the v1 description
     `transfer src=%s dest=%s xfer=%s mode=%s` (`daemon.go:1325`).
   - Call `v2Decision(t, since, "transfer", status)` instead.
   - The transfer ID comes from the tool output, which `:87-118` already checks against both gate
     audit legs.
   - The caller at `:120` passes the controller audit length taken just before the approved call
     starts (a new `auditBefore`), and the caller at `:131` passes `signerBefore`.
4. **`J:transfer_test.go:132-134`:** `len(r.audit(t, "controller")) != signerBefore+1` assumes one
   v1 row per denied transfer, but v2 writes several. It is replaced by item 3's `v2Decision(…,
   "denied")`, which also proves that nothing was minted. The gate-audit counts at `:138-140` stay.
5. **`J:transfer_test.go:172-188`, `transferMetadataOnly`:**
   - The expected `StructuredContent` map gains `execution_status: "succeeded"` and
     `executed_ordinals: [1]`. `partial` and `annotation` are omitted on success.
   - The `Content` text check stays, because c6 keeps the success text unchanged.
   - `auth_mode` stays `human`, now from the Summary.
6. **`J:sync_test.go:345-349` (`update_gate`):** no edit. The call ignores its result, and the
   host-hash loop at `:352-358` proves the install.
7. **Not checked here:** the v2 card texts that the journey matches (`cardEdit(…, "Approved")` and
   `"Denied"`, the `SECRET TRANSFER` banner). The owner of these edits runs the focused journey and
   fixes any mismatch inside the same two named files.

**Owner (ruling O15):** the edits land in the integration change that first puts the journey together
with A13b's v2 tools: c3 for `run`/`run_batch` (items 1 and 2), c6 for `transfer` (items 3-5).
- If the journey is already on integration when A13b c3 is cut, A13b gets named exceptions for
  `tests/journey/sync_test.go` (c3) and `tests/journey/transfer_test.go` (c6). Each of those commits
  adds a focused `make test-journey` run.
- Otherwise the orchestrator applies all of them in the journey → integration merge commit, as ruling
  40 already has it reconcile J4/C4 there, and runs the focused journey before calling the merge done.
- Basis: one writer per file at each point in time, and JP §4's rule that a conflicting expectation
  is corrected in the same integration change (the OQ2 precedent, JP:80).

### 4.4 C2 — new commits on `wi2/c2`

The orchestrator first merges integration with A13c into `wi2/c2` (§4.1). C2 owns `src/executor/**`,
plus a **named exception for new files only** under `src/executorwire/testdata/` (goldens; no wire
change). C2 makes no `src/mcp/jobplan` edit.

| Commit | Content | Acceptance tests |
|---|---|---|
| **C2f** executable scope | <ul><li>`executable(job)` at all four sites.</li><li>Transfer `JobActCheck` for both endpoints.</li><li>Transfer jobs never reach `ensureRunner`, `dispatch`'s `CommandJob` walk or `Runner.HoldWindows` (`c2:execute_linux.go:191,295-300,352,371`). Until C2h a transfer job, and until C2g an update job, is held without dispatch, so the step check after its window ends it `expired_unexecuted`.</li><li>Delete `TestCommandJobsIgnoreAdminAndTransfer` (`c2:execute_linux_test.go:595-612`) and the scope test at `:725-741`.</li><li>Rewrite `README.md:3-7` and the `execute_linux.go:27-28` comment.</li></ul> | <ul><li>`TestEveryAdmittedKindReachesFinal`: each of the five tools is submitted through `Submit` (the `TestSubmitBuilders` fixtures) against the real A6 memory lifecycle, with an auto-approve notifier and fake SSH.<ul><li>For the transfer, the test enrols both endpoints in the signer's `XferRegistry`, and the fake destination gate echoes the minted `XferID` in its receipt.</li><li>Each job reaches `final` **with its expected class**. At C2f: `run`, `run_batch` and `revoke_server` end `succeeded`. `update_gate` and `transfer` are not dispatched yet, so the test advances the elapsed fake past the window and they end `expired_unexecuted`, with zero exec requests (P3-j). C2g flips `update_gate`, and C2h flips `transfer`, to `succeeded` in the same test.</li><li>The lifecycle accepts each report, and the next admission at the live cap succeeds, so the slot was released.</li></ul></li><li>A transfer whose destination registry entry changed: `stale_target`, no marker, zero dispatches, no panic.</li></ul> |
| **C2g** admin dispatch | <ul><li>Revoke and update dispatch.</li><li>The U7 re-read and hash check, and the 64 MiB admission bound.</li><li>The large-buffer semaphore (used by update here and by transfer in C2h).</li><li>Revoke never touches `servers.json`; a `succeeded` revoke carries `AnnRevokeRegistryKept`.</li></ul> | <ul><li>The staged file is overwritten between admission and dispatch → U7; the in-process server sees zero exec requests; no marker is committed.</li><li>Unchanged file: the server's stdin bytes are byte-equal to the file at dispatch; `succeeded`.</li><li>A 64 MiB + 1 staged file → `invalid_request` and no job file.</li><li>A revoke `succeeded`: `servers.json` is byte-identical before and after; the job view's step annotation equals `jobplan.AnnRevokeRegistryKept`.</li><li>`max_output_bytes: 1` revoke → `succeeded` (A13c's evidence path, end to end).</li><li>**Lowered rows commit and reload (O14):** A3 and U4 → `indeterminate` with no `exit_code`. `AfterStep` commits through the real store (`validateStepResult`, `store_linux.go:309-318`); an executor restart `Load`s the job without quarantine and with the same result; and the report is accepted by the real lifecycle. The store is unchanged.</li><li>Three concurrent update jobs: a hook counter shows at most 2 live large buffers.</li></ul> |
| **C2h** transfer dispatch (after C2e) | <ul><li>Two-envelope Claim acceptance (`VerifyTransferLegs`).</li><li>`TransferRunner` wiring under a large-buffer slot.</li><li>`OnRelease` replaces the ordinal shim.</li></ul> | <ul><li>Against the real A6 lifecycle (which mints both legs, `daemon_approvals.go:309-330`) and two in-process servers: `succeeded`, and a byte scan of the job file, the report body and the executor log finds no envelope bytes and no `SSHGATE_SIG:`.</li><li>Fault hook (ruling 41, from C2e) after the marker, during SEND: restart → `indeterminate`, zero further dispatches, the report is sent.</li><li>Three concurrent jobs mixing transfer and update: at most 2 live large buffers.</li><li>RECV window expiry under the elapsed fake → `expired_unexecuted`, zero destination exec requests.</li><li>A tampered leg (a wrong `DestPath` in the signed RECV) → the job ends with the `signer_incompatible` outcome, zero connections, no report (O16).</li><li>T13 (the fake destination gate exits 0 and prints no receipt) → `indeterminate`, no `exit_code`; the commit, a restart `Load` and the report all succeed.</li></ul> |
| **C2i** production wiring and goldens | <ul><li>`cmd/sshgate-executor` calls `StartCommandJobs` with the real signer client and the `RunPhased` transport, using the MCP's key and known_hosts paths and 0600 checks (§3.4).</li><li>`exec_submit` request goldens for `revoke_server`, `update_gate` and `transfer`.</li><li>`exec_get` response goldens for one final transfer job and one final revoke job (new files under `src/executorwire/testdata/`), for C3 (P3-4).</li><li>These goldens freeze before C3's cut (ruling 41's fold).</li></ul> | <ul><li>`main_test`: the built executor binary, started against a test signer socket and an in-process SSH server, runs one `run` job and one `revoke_server` job to `final`, with the reports accepted.</li><li>A key file with mode 0644 → the executor refuses to start.</li><li>Two processes making first contact with two new hosts at once leave a `known_hosts` that `knownhosts.New` parses, holding both hosts.</li><li>The goldens decode strictly and re-encode byte-equal. That test lives in `src/executor` (C2's), not in `executorwire/wire_test.go` (P3-g).</li></ul> |

- **Spec C2 content (S:2077-2123) gains item 7:** "Every kind admission accepts is executed: the
  admin and transfer paths of E29a, the update re-read (U7), no registry writes, and the two-slot
  large-buffer bound."
- **Tests:** the C2g and C2h rows. **Ledger:** C-52 (executor) gains "the executor's RECV leg guard"
  (the C2h RECV-expiry test), and C-68, C-69 and C-70 are added.
- **Accept:** unchanged (L:394): ACC `./src/executorwire/... ./src/executor/...`, plus an independent
  review.

### 4.5 C3 (small)

- **c1, execclient:** `executorwire.Job` carries no draft (`response.go:9-21`), so decoding is already
  kind-blind. The work is display:
  - **Test:** the C2i `exec_get` response goldens for a transfer job and a revoke job decode, and
    `exec_get` and `exec_await` render their steps and class.
  - **Test:** `await_approvals` renders the stored annotation verbatim, `AnnRevokeRegistryKept`
    included, with no `ReadJailRemediation` applied (ruling 36 matches read-jail texts exactly).
- **c2:** a schema test: the input schemas of `transfer`, `revoke_server`, `update_gate` and
  `request_grant` have no `async` property, and a call that passes `async:true` makes zero
  `exec_submit` calls (a fake execclient counts them).
- No other change. `list_pending_approvals` already shows sync admin and transfer records through the
  signer join (ruling 38).

### 4.6 A13b-docs (same single commit, more text)

- **`AGENTS.md`, `README.md` and `commands/revoke.md`:**
  - Admin and transfer results now carry `execution_status`.
  - `indeterminate` means "may have run: do not re-run; ask a human to check the host
    (`sshgate status`, and for revoke the registry)".
  - A refused transfer send means nothing was transferred.
  - A revoke that failed partway may have left the server unreachable.
- **Ruling 20's v1 guidance** now covers only `run(network:true)` and reveal+network.

## 5. Text that assumed Q3 = yes: edits, with replacements

The changelog entries for revisions 1-4 (R:3-6, R:20-24, R:39) are history. **Do not edit them.** Add
a "Revision 5 changelog" at the top instead (first item below).

1. **R:1 (insert after the title).**
   > ## Revision 5 changelog (owner answered Q3 = NO)
   > - Q3 answered NO: all six tools move to v2 in v0.2. #17 and #18 are now ORCH rulings (design
   >   `q3-tool-port-design.md` §1, spec E29a). #34's refusal branch is dead and the executor runs every
   >   admitted kind (C2f-C2i). A new lane, A13c, owns the shared jobplan code. #20 narrows to network.
   >   `async` stays on run/run_batch (K9 unchanged, ORCH O12).
2. **R:90-102 (Q3).** Keep the question, and append the text below.
   > **Owner answer (2026-11-01): NO**, the alternative "port all six tools to the new path now".
   > ORCH reading (O12): `async` stays on run/run_batch only (K9); the other four tools are sync on the
   > v2 path. The executor executes every kind it admits.
3. **R:318-321 (#17).** Replace with:
   > **17. Transfer two-leg report: ORCH (Q3 = NO).** One job step, two legs. Table T1-T16 (design
   > §1.2; spec E29a): every case where the RECV exec request was never sent is not executed (S:555's
   > rule), with no stored `exit_code`. Exit-0 RECV with a missing, malformed or wrong-ID receipt
   > (`transfer.go:184-194`) is `indeterminate`, never `failed` (`failed` = a known non-zero exit of
   > the write, S:562). E10, E28, S:1880 and C-64 gain the transfer carve-out. The code lives in the
   > new lane A13c (`src/mcp/jobplan`), which replaces the A13b exception.
4. **R:323-325 (#18).** Replace with:
   > **18. Admin postconditions: ORCH (Q3 = NO).** `AdminOutcome` (A13c), rows A1-A5 and U1a-U7
   > (design §1.3). A missing receipt, a malformed receipt, a confirmed hash different from the
   > approved one (`update_gate.go:219-231`), or a size different from the buffer streamed is
   > `indeterminate`, with no retry advice. Revoke with a receipt but a non-zero exit is `failed`,
   > "may have been revoked" (named change). Every non-zero admin exit has a fixed annotation; texts
   > after a possible write say so. Receipts are read from an uncapped 4 KiB evidence buffer.
5. **R:335-338 (#20).** Replace the last sentence with:
   > The v1 "verdict undelivered — do not auto-retry" guidance stays for `run(network:true)` and
   > reveal+network only; Q3 = NO keeps no other tool on v1.
6. **R:450-464 (#34).** Replace with:
   > **34. Executor intake scope: ORCH (Q3 = NO).** Admission (`src/executor/draft_linux.go:17-53`)
   > refuses no tool. It adds one bound: a staged update binary over 64 MiB is `invalid_request`.
   > Already done (C2a-C2d) as before. New: C2f (`executable` covers `signed_admin` and transfer),
   > C2g (admin dispatch, the update re-read check, no registry writes, the two-slot large-buffer
   > bound), C2h (transfer via A13c's `TransferRunner`; after C2e), C2i (production wiring,
   > `exec_submit` and `exec_get` goldens for the admin and transfer tools). `submit_linux_test.go:245`
   > stays; `TestCommandJobsIgnoreAdminAndTransfer` is deleted.
7. **R:546 (DAG fold).** "(under either Q3 answer)" stays true. Add the edges: "A13c → A13b c5/c6;
   A13c → C2f-C2i (merged into `wi2/c2` first); C2e → C2h. jobplan writer order: C2's ruling-36 hunk,
   A13b's ruling-19 `draft.go` hunk, A13c (disjoint files)".
8. **R:560-562 (Startable, C2 bullet).** Replace with:
   > **C2e** (hooks; B1f merged) and the proxy-harness commit (A12 merged): go now. **C2f-C2i**: after
   > A13c merges into `wi2/c2`; C2h also after C2e.
   Add a bullet: "**A13c**: go now (cut from `756298d`)."
9. **R:565.** Replace "After any Q3 answer: A1a-auth" with "A1a-auth: merged (`756298d`)".
10. **R:569.** Replace "A13b: waits for A12 and Q3" with "A13b: c1-c4 go now; c5-c6 after A13c".
11. **L:394 (C2 row).** Replace the Commits cell with:
    > per spec `:2077-2123` plus E29a: C2a Submit, C2b waiter, C2c command-job `JobNext`, C2d retention,
    > C2e fault hooks, proxy harness, C2f executable scope, C2g admin, C2h transfer (after C2e), C2i
    > production wiring and goldens.
    Add `src/executorwire/testdata/**` (new files only) to Owns.
12. **L:654.** Replace "the C2a–C2d split" with "the C2a–C2d split (extended to C2i after Q3 = NO)".
13. **L:338 (A13b Base).** Append: "and, for c5-c6, A13c". After the A13b block, add an A13c block
    with §4.2's contract, and add §4.3a's conditional `tests/journey/transfer_test.go` exception to
    A13b's Owns.
14. **L:240, L:499 and L:524** mention a different "Q3" (review 1's legacy-plan question). **Leave them
    unchanged.**
15. **Spec:** the §1.5(a)-(k) texts above. Also:
    - S:1903 (A13b Content): append "Side effects and outputs per E29a."
    - S:2496 (C-52): append "; C2 also tests the executor's RECV-leg guard".
    - After S:2511, add C-68, C-69 and C-70 with E29a's one-line statements.
16. **Code comments and README that pin the old scope (C2f rewrites them):** `c2:src/executor/README.md:3-7`,
    `c2:src/executor/execute_linux.go:27-28`.
17. **JP §4 (after the OQ2 bullet, JP:80).** Add:
    > - **Q3 = NO wins:** `transfer`, `revoke_server` and `update_gate` run on the v2 path. A v2
    >   approval writes several `approval-<transition>` audit rows per request (`commands: []`,
    >   `servers: null`; the decision and `decided_by` are inside `approval`), and its card carries no
    >   request ID or transfer ID. Journey decisions are matched by a `v2Decision` helper over the
    >   audit rows (one request, one decision row, a mint row only on approval), and the transfer ID
    >   comes from the tool output. `transferMetadataOnly` expects `execution_status` and
    >   `executed_ordinals`. The `update_gate` setup step needs no change. The edits land in the same
    >   integration change that first joins A13b and the journey (`q3-tool-port-design.md` §4.3a).

## 6. Open decisions

### 6.1 ORCH-derivable (rule, record in rulings r5, tell the owner in one line)

| ID | Ruling | Basis |
|---|---|---|
| O1 | Every transfer outcome in which the RECV exec request was never sent is not executed (T4-T10, including a known SEND refusal → `failed_not_started`), and E10, E28, S:1880 and C-64 say so | S:555 already counts SEND-ran/RECV-refused as nothing transferred; SEND only reads (`xfer.go:100`); otherwise the agent would hear "may have run" about a provably absent write. Reversible before release |
| O2 | An exit 0 without a confirmed receipt is `indeterminate` with `execution_indeterminate`; no new verdict class | E29: `failed` = a known non-zero exit (S:562); `indeterminate` is in the executed set (S:570), so it is never reported as not run; this reuses an E11 class (S:343) |
| O3 | Strict anchored receipt grammars (§1.4), plus the update size check against the streamed buffer | v1's any-field scans (`update_gate.go:317-342`, `transfer.go:244-266`) let a stray token decide success. The grammars accept every gate format since `7084696` (A13c c1 test) |
| O4 | At most two large in-memory buffers (transfer envelope or update body) in the executor at once; the slot is taken before the step's checks | envelope bound `2×8 MiB+64 KiB` (`xfer.go:45,52`), update cap 64 MiB (`update.go:35`), 100 live jobs (E75); K16 still guards a slot wait |
| O5 | The executor never writes `servers.json`; a succeeded executor revoke carries `AnnRevokeRegistryKept` | `Servers.Remove` persists the process's cached map (`servers.go:323-341`), which can lose concurrent adds; `executorwire.Job` has no `registry_removed` field and none is added; the MCP never submits async revoke (O12) |
| O6 | Executor update cards show `running_version: unknown` (no SSH probe at admission) | display-only and labelled unverified (E33); keeps SSH out of admission |
| O7 | The executor re-reads and re-hashes the staged binary at dispatch; a mismatch is `failed_not_started` (U7) | keeps v1's read-once rule (`update_gate.go:117-122`) by construction; the gate would refuse a mismatch with 65 anyway (`update.go:130-135`) |
| O8 | One marker before SEND's `Start`; not-executed results after it sit beside it (E74 amended); a crash in either leg recovers as `indeterminate` | SA-5's marker-before-`Start` rule and E74; `ApplyJob` already accepts it (`jobview.go:256-261`); conservative, no new durable shape |
| O9 | `VerifyTransferLegs`: the coordinator refuses signed legs that disagree with the draft before any dial | fail-closed defence in depth; the legs are signer-frozen (E34) and returned only inside the signatures |
| O10 | New lane A13c owns the new jobplan code instead of an A13b exception; writer order as in §4.1 | one writer per file, with two consumers (A13b and C2) and two existing named hunks |
| O11 | Revoke with a receipt but a non-zero exit is `failed`, annotated "may have been revoked; not confirmed" (named change, §1.3 item 40) | a gate killed after printing (`main.go:700`) gives this case, so the revoke may have happened; never report an unconfirmed revoke as success, and never claim it was refused |
| O12 | K9 unchanged: `async` only on `run`/`run_batch`; the other four tools are sync on v2 | the owner chose "port all six tools to the new path now" (R:101), which never mentions async; Q3 gives async to run/run_batch only (R:92); K9 (S:907, S:2138); S:12. Reversible |
| O13 | A not-executed transfer step stores no `exit_code`; SEND's exit appears only in its fixed annotation | E38 readers read `exit_code` as the step's exit, and the step is the RECV write; this avoids "exit 65 + not started"; the executor store already requires it (`store_linux.go:313`) |
| O14 | **(Orchestrator ruling, verify-r2 V1.)** When `AdminOutcome` or `TransferStepOutcome` lowers a status to `indeterminate`, the step stores no `exit_code`; the fixed annotation says the gate exited 0 without a valid receipt | the executor store's rule (`src/executor/store_linux.go:309-318`: `indeterminate` carries no exit code) stays unchanged, so a lowered row commits and reloads; `indeterminate` means the completion is not trusted, so no exit is reported for it |
| O15 | Journey edits land in the change that first joins A13b and the journey: c3 for the shared helper and `run`, c6 for `transfer` (§4.3a) | one writer per file; JP §4's same-integration-change rule (JP:80); ruling 40's reconcile-at-merge precedent |
| O16 | Transfer legs that disagree with the draft (T1) end the job with the `signer_incompatible` outcome, with no step result and no report, on both paths | the command-job precedent for a signature mismatch at Claim (`c2:execute_linux.go:239-241`); nothing was dispatched, so fail-closed either way; one rule for both kinds |
| O17 | A stdout longer than the 4096-byte evidence head is a `malformed` receipt | a gate prints one receipt line and nothing else; `capture` reports the overflow, so `AdminOutcome` and `TransferStepOutcome` can see it |

### 6.2 Owner-level (irreversible or trust-boundary only)

**None.** Every item above stays inside the existing status vocabulary, adds no wire field, changes no
K-ruling, and can be reversed before release. O12 is a reading that is recorded, not asked. If the
owner meant async for the other tools, that would be a K9 amendment only he can make (S:12), and the
executor work above already covers it apart from the MCP flag.

### 6.3 Known pre-existing gap (not caused by Q3; flag only)

- **P3-11:** `Servers.Remove` persists the process's cached map without reloading
  (`servers.go:323-341`), so a sync `revoke_server` can drop an alias that another process added. v1
  has the same window.
  - A13b c5 narrows it by calling `Get` (which reloads) immediately before `Remove`.
  - The full fix (reload and compare under a file lock inside `Remove`) belongs to the
    `src/mcp/registry` owner. The orchestrator names that lane.

## 7. Rejected or partly rejected findings

**verify-r2 (round 3):** none rejected. V1-V4 and P3-a to P3-k were confirmed against the code and
folded. V3 is extended: a v2 card carries no request ID either (`telegram_v2.go:106-108`), so the
journey's card-based correlation is replaced as well as its audit matching.

**Revision 1 critique (folded in r2):**

- **P1-1, cite only:** the E28 `failed_not_started` bullet is S:551, not S:553 (S:553 is the `known:`
  bullet). The finding itself is accepted and folded at S:551 (§1.5g).
- **P1-2, remedy only:** the finding is right, but its premise that A13c "must edit StepOutcome itself"
  (via P2-1) no longer holds.
  - P2-1 is fixed in a new `AdminOutcome`, so A13c doesn't touch `outcome.go` at all, and C2's hunk
    doesn't need to be cherry-picked to integration.
  - The jobplan edit on `wi2/c2` is in C2c (`56b86af`); `b73d629` is only the branch tip that carries
    it.
- **P1-3, `sync_test.go` part:** "sync_test.go:345-349 drives `update_gate` through the same kind of
  assertions" is not accurate.
  - The call passes a nil output and never checks `IsError` (`J:mcp_test.go:110-133`). The only
    assertion is the host-hash loop at `:352-358`, which the v2 path still satisfies through the real
    gate. No edit is needed there.
  - The transfer part is accepted, and strengthened: the v2 card *cannot* carry the transfer ID,
    because the signer mints it at freeze, after the tap (`daemon_approvals.go:475`).
- **P2-2, update and RECV exit 70:** U1b keeps r1's "the old gate is still in place".
  `AtomicReplace` returns an error only before its `rename`; the directory `fsync` after it is
  best-effort and never returns an error (`src/gate/replace.go`). So exit 70 is pre-write. The same
  holds for RECV 70. The rest of P2-2 is accepted.
- All other findings (P2-1, P2-3 to P2-6, P3-1 to P3-10, P3-12) were confirmed against the code and
  folded as written. P3-11 is confirmed and handled as a pre-existing gap (§6.3).

## 8. Verify r3 fold (orchestrator, 2026-11-01; binding, overrides earlier sections)

Verify r3 is **GO** for building A13c, C2f-C2i and A13b c1-c5, with no P0 or P1. Its two P2s are in
§4.3a (journey edits) and must be folded **before** A13b c3 or c6, or the journey merge, touches the
journey files.

- **R3-1 (P2): `v2Decision` takes the request ID from the card.** §4.3a's premise that the journey
  "cannot take the request ID from the card at all" is false: the v2 decision card text carries
  `Request: <request_id> · Card: <handle>` (`src/approvalreview/telegram.go:227`); only the callback
  data lacks it. `v2Decision` as written requires exactly one request ID among the controller rows
  after `since`, which fails in `testJourneyWindow` (`J:tests/journey/sync_test.go:525-591`), where
  three command-job requests are live at once. Fix: `cards()` (`J:sync_test.go:103-139`) parses the
  request ID from the card's `Request:` line, and `v2Decision` filters audit rows by that ID. The
  decision and mint checks stay. The concurrent requests in `testJourneyWindow` must pass.
- **R3-2 (P2): v2 card result texts.** A v2 terminal edit replaces the whole card text with
  `Approval: approved|denied|expired` (`src/signer/backend/telegram_v2.go:240-249`). `cardEdit`
  matches `Approved`/`Denied`/`Expired`, so the matches at `J:transfer_test.go:68`, `:129` and
  `J:sync_test.go:457`, `:477`, `:569`, `:583` change to the v2 text. `assertWindow`
  (`J:sync_test.go:605-609`) checks the card's RFC 3339 `Expires:` line instead of `5m0s`. The
  SECRET TRANSFER banner and the label-based taps of the fake Telegram service still hold.
- **P3: O14 is scoped.** O14's exit-code clearing applies only to rows that `AdminOutcome` or
  `TransferStepOutcome` lowers (admin and transfer steps). It never applies to `RunStep`'s
  `unsigned_read` jail-refusal row, which keeps its exit 77 (`runner.go:205-207`). Invariant 8 and
  the §1.1 exit-code bullet read with this carve-out.
- **P3: stale text to fix when folding into the spec and rulings:** §1.1's "`outcome.go` is not
  edited" (A13c makes the §1.6 named serial edit); §5 item 7's "(disjoint files)" (the A13c and C2
  edits to `outcome.go` are disjoint hunks of one file); §5 item 13 names only the
  `transfer_test.go` exception, but `sync_test.go` is required too (§4.3a).
- **P3: controller audit counts.** The journey's controller `auditCount` (`J:sync_test.go:268-290`)
  matches `row.commands`, which v2 rows leave empty. Its checks move to `v2Decision` and no-mint
  checks keyed by request ID (A13b c3).
- **P3: O16 remedy text.** The `signer_incompatible` Denial for a transfer leg mismatch says
  "transfer legs disagree — do not retry; check both servers", not the version-skew "upgrade the
  signer" advice.
