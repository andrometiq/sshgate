# Work item 2, first lanes: A1a, A2, B0 now; A1b, A4, A5 next

- **Date:** 2026-10-15. **Repo:** this repository, local `main` at `2ffe928` (unpushed).
- **Sources (binding, in this order):** `docs/BUILD-PLAN.md` "Work item 2" (`:539-670`, public);
  the detailed plan `docs/plans/v0.2/approval-lifecycle-spec.md` r5.8 (§0, §1.5 SA-1..SA-12,
  §2 package map `:1360-1389`, §3 sub-phases `:1407-1581` and B0 `:1970-1986`, §5 parallelism
  `:2301-2365`); the spec `local-workspace/release-2026-07-04/SPEC-76-65-approval-lifecycle-2026-07-19.md`
  (v5, K1-K20 ratified 2026-10-02).
- **Owner rulings this plan relies on:** an owner message (WORKLOG 2026-10-04): "#76/#65 builds on r5.8 with
  per-phase reviews" — this supersedes the detailed plan's §11 gate "A1a starts only after an the reviewer
  GO of the contract" (review 9 was the last full-plan round, NO-GO, folded as r5.8). The owner's
  2026-10-15 ruling: A1a, A2, B0 start now on main in worktrees; A1b, A4, A5 when A1a lands; A0's
  gate-hash baseline is recorded after the jail merges; every lane keeps the gate closure unchanged.
- **What this file adds to r5.8:** re-grounding at `2ffe928`, the lane contracts, the disjointness
  proof, the gate proof that replaces A0 for now, and decisions r5.8 left open. Where this file and
  r5.8 differ, this file says so explicitly and why; everything else in r5.8 §3 for these
  sub-phases stands and the builder reads it in full.

---

## 0. Re-grounding at 2ffe928 (done for this plan; no A0 needed to start)

| Fact | Evidence |
|---|---|
| r5.8 was grounded at `366ba07`. Since then nothing changed in `internal/`, `pkg/`, `src/redact`, `src/mcp/sign`, `src/signer`, `src/policywire`, `src/xferwire`, `src/sigwire`, `src/policyreview` except `Makefile` | `git diff --stat 366ba07 2ffe928 -- <those>`: only `Makefile`, `internal/redteam/README.md`, `src/redact/rules/gitleaks/PROVENANCE.md` (docs) |
| Makefile line drift: `preflight` is now `Makefile:275` (r5.8 says `:204`); `release-gate` still `:86`; `.PHONY` block `:1-4` | `grep -n` |
| `internal/securestate` cites in B0 all hold: `withLock` `:190-238` (dir fsync `:231`), `atomicReplace` `:370-438` (temp cleanup `:376-391`), `statPath` `:504-516`, `validateDataName` `:549-557`, open-time fsync `:153`; only importer is `pkg/signerkit/{daemon_policy_linux,policy_journal_linux}.go` | read |
| `src/redact`: `RedactString` `scrub.go:28`, `ExactRedactedBytes` `scrub.go:46`, `rawMatches` `scanner.go:77`, `dedupMatches` (union-merge) `scanner.go:193`, `scanner.redact` `scanner.go:229`, `ringMax = 64 KiB` `writer.go:25`, PEM wholesale markers `writer.go:180-187,239-245,264-269`, `MarkerKey` (HMAC-SHA256, first 4 bytes, first 8 KiB) `markers.go:70` | read |
| Gate closure today (sorted `go list -deps ./src/gate/cmd/sshgate-gate`) includes `src/redact`, `src/redact/rules{,/gitleaks,/sshgate}`, `src/classify`, `src/sigwire`, `src/hostkey`, `src/xfer`, `src/xferwire`, `src/gatever`, `src/gate/confine`, `src/gate/confine/jailmut`, x/crypto, x/sys. It does **not** include `internal/securestate`, `internal/elapsed` (new), `src/mcp/**`, `pkg/**` | `go list -deps`; sha256 of the list output at 2ffe928: `593b10f9cca828e307d444a0871bf5188c4b017f10bb380530bc80efafec2ac9` |
| **GATEHASH at 2ffe928** (r5.8 §0.7 recipe, `GOTOOLCHAIN=go1.26.4`): `fb0603c327878eab38250f91e07cef3001ba10d7f13d7186d94ad44d0bb9af2d`. The committed `dist/gate` sidecar says `c7a4aaa4…`; it is stale (2ffe928 changed confine code), so never compare against `dist/` | measured into the scratchpad |
| Proposed closure targets already pass at 2ffe928: the MCP closure has no `pkg/signerkit`, sqlite, webauthn or otp; the gate closure matches none of `approvalplan|approvalwire|approvalreview|/pkg/signerkit|/src/executor|/src/mcp/` | `go list -deps` + grep (both empty) |
| `golang.org/x/sys v0.45.0` is a direct requirement; `unix.ClockGettime` exists (`zsyscall_linux.go:585`); `go.uber.org/goleak v1.3.0` is already in `go.mod:14`. **No lane needs a `go.mod`/`go.sum` change.** The §0.2 stray `go.sum` hunk is gone (tree clean) | `go.mod`, `git status` |
| Local signer dispatch for a v2 kind on an old daemon: lenient peek, audit-nil guard, proto check, backend-nil guard, then `default:` → `respondError(conn, peek.Kind, "unsupported kind …")` (`pkg/signerkit/daemon.go:452-520`, `respondError` `:762`). The reply is `{"request_id":"<kind>","status":"error","error":"unsupported kind \"…\"","proto_version":1}` — that exact legacy shape is what A5 maps to `ErrSignerIncompatible` | read |
| The MCP has no `ErrResponseLost` today; the precedent r5.8 cites as "the policy_client.go precedent" is `ErrPolicyVerdictUnknown` (`src/mcp/sign/policy_client.go:21`). Dial helpers to reuse: `dialWithCtx` (`client.go:282-294`), `classifyDialError` | read |
| Hosted `Decide` is still `pkg/signerkit/hosted/approval.go:94` (A1b ports it) | grep |
| **The jail lane is not gate-only.** `feat/22-p2.1` (worktree `the p21 worktree`, merge-base `2ffe928`) also edits `Makefile` (the `jail-runner` block, `:175-210` only), `docs/BUILD-PLAN.md` (work item 1 text), `docs/*`, `AGENTS.md`, `README.md`, `CHANGELOG.md`, `INSTALL.md`, `SECURITY.md`, `commands/{run,setup}.md`, `skills/debugging-remote-servers/SKILL.md`, `.github/workflows/{jail,tests}.yml`, `scripts/jailmut/*`, `internal/redteam/README.md` and one string each in `src/mcp/tools/{denial,run}.go` | `git diff --stat 2ffe928...feat/22-p2.1` |

---

## 1. The gate proof while A0 is deferred

r5.8 proves "gate bytes unchanged" against an A0 baseline. With A0 deferred, and with later #22
phases legitimately changing the gate, an absolute baseline is the wrong instrument. Every lane
proves it **relatively, on its own base**:

```sh
S=<lane scratch dir>; TC=$(awk '/^toolchain/{print $2}' go.mod)
gatehash() { GOTOOLCHAIN=$TC CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64= GOEXPERIMENT= GOFLAGS=-mod=readonly \
  go build -trimpath -ldflags "-s -w -buildid= -X main.versionMarker=SSHGATE_GATE_VERSION{$(cat VERSION)}" \
  -buildvcs=false -o "$S/gate" ./src/gate/cmd/sshgate-gate && sha256sum "$S/gate" | cut -d' ' -f1; }
# GATE-PROOF (every lane, at its tip; BASE_* are recorded in the lane contract)
test "$(gatehash)" = "$BASE_GATEHASH"
diff <(go list -deps ./src/gate/cmd/sshgate-gate | sort) "$S/gate-deps.base.sorted"   # must be empty
```

- Lanes cut from `2ffe928` use `BASE_GATEHASH=fb0603c3…af2d` and the sorted deps list captured at
  `2ffe928` (the orchestrator writes it to `local-workspace/release-2026-10-14/wi2-baseline/` once).
- Next-wave lanes re-measure both at their base (the integration tip they are cut from).
- **A0 later (after the jail merges):** the orchestrator merges `main` into the integration
  branch, records GATEHASH and the four closures there (r5.8 A0 step 4), and checks that
  reverting the WI2 diff (`git diff main...integration -- src/redact` is the only closure-touching
  part, i.e. A2's `spans*.go`) leaves GATEHASH unchanged. That is the one absolute check, done once.

Only A2 edits a package inside the closure. For every other lane GATE-PROOF is a cheap tripwire
(it would catch an accidental `go.mod` bump or an import added to a closure package).

---

## 2. Lanes that start now

### 2.1 A1a — `src/approvalplan` contract + `internal/elapsed` + closure targets

r5.8 §3 A1a (`BUILD-PLAN-76-65.md:1407-1440`) is the content spec; the record field lists are §1.5
SA-2 (`:1119`), SA-3 (`:1138`), SA-9 (`:1292`). This section fixes what r5.8 leaves to the builder.

**Package rule.** `src/approvalplan` imports the standard library only (no x/sys, no repo packages);
mirrored constants (the `SSHGATE_`/`SSHGATE_XFER_` prefixes, `xferwire.ValidFingerprint`'s grammar)
are copied with a comment naming the source line and are drift-tested later (A7).

**Files and their exported surface** (names frozen by the A1a goldens; field lists per SA-3):

| File | Exports (signatures) |
|---|---|
| `kinds.go` | `type Kind string` (`command_job`, `standing_grant`, `transfer`, `register_transfer_key`); `type Route string` (`unsigned_read`, `signed_write`, `signed_reveal`, `signed_admin`); `type RationaleOrigin string` (`agent`, `trusted_human_cli`, `synthesized_legacy_v1`); `type Coordinator string` (`in_process_sync`, `executor`) |
| `plan.go` | `type ApprovalDraft struct{…}` (no validity field, E26); `type ApprovalPlanV1 struct{ Version int; Kind Kind; RequestID string; Rationale string; RationaleOrigin RationaleOrigin; ExecutorClaimTokenHash string; SubmitNotAfter time.Time; Coordinator Coordinator; CommandJob *CommandJob; StandingGrant *StandingGrant; Transfer *Transfer; RegisterTransferKey *RegisterTransferKey; …}` (exactly one payload non-nil); `CommandJob{Steps []Step; StopPolicy StopPolicy; MaxOutputBytes int64}`; `Step{Ordinal int; Route Route; Target RouteSnapshot; RegistryEntryDigest string; ExactCommand string; CommandSHA256 string; SignatureTTLSeconds int; TrustedDisplay *TrustedDisplay}`; `RouteSnapshot{ServerAlias, ResolvedHost string; ResolvedPort int; ResolvedUser, TrustedHostFingerprint string; ReadOnly bool; AddedAt time.Time}` with JSON names per spec §5; `StandingGrant{…}`, `Transfer{…E34}`, `RegisterTransferKey{…}`; `func DecodeDraft(b []byte) (ApprovalDraft, error)` (strict: unknown field, trailing data, bounds → `*CodeError{Code: CodeInvalidRequest, Field: …}`); `func (d ApprovalDraft) Validate() error` |
| `codes.go` *(added; see §5 Q5)* | `type Code string` — the **closed** answer/error set shared by `Apply` (A1b) and the wire (A5): `not_found`, `conflict`, `invalid_request`, `reserved_verb`, `request_too_large`, `request_unrenderable`, `submit_window_closed`, `submit_window_ahead`, `queue_full`, `invalid_claim`, `invalid_report`, `storage_uncertain`, `busy`, `record_corrupt`, `lifecycle_unavailable`, `signer_incompatible`; `func (c Code) Retryable() bool`; `type CodeError struct{ Code Code; Field string; Msg string }`; `type ClaimStatus string` (`signatures`, `not_ready`, `denied`, `canceled`, `expired`, `error`, `execution_reported`, `materialization_error`) |
| `viewtypes.go` *(added; see §5 Q5)* | The value types the views return, no logic: `ApprovalStatus`, `ExecutionStatus`, `NotificationStatus`, `AssistState`, `StepStatus`, `JobClass` (closed string enums of SA-6), and `type Summary struct{…}` field set that Get/Wait/List return (handle, `created_at`, `sync_claim_deadline`, `pruned`, views, grant id/expiry). A1b fills them; A5 encodes them |
| `record.go` | `type R1 struct{ Header R1Header; Payload *R1Payload }`, `type R2 struct{…}` per SA-3 (bodies `[]byte`); `func RecordKey(principal, requestID string) string`; `func JobKey(requestID string) string`; `func RecordHandle(recordKey string) string` (SA-2: `base32(SHA-256("sshgate-v2-record-handle-v1\0" ‖ key))[:16]`); `func EncodeR1(R1) ([]byte, error)` / `DecodeR1([]byte) (R1, error)` and the R2 pair (refuse over bound, refuse `required_approvals ∉ 1..256`); consts `R1Max = 512 << 10`, `R2BodyOverhead`, `R2NonBodyMax`, `R2Max`, `OutboxMax`, `ShedMax`; `func R1Reservation(rec R1) int`; `func R2Reservation(d ApprovalDraft, maxOutputBytes int64) int`; `func Shed(rec R1) R1` (the header-only form; pure) |
| `audit.go` | `type AuditMetadata struct{…E23}`; `type OutboxEvent struct{ Seq uint64; Kind string; …}` |
| `rationale.go` | `func ValidateRationale(s string) (string, error)` (trim; 1..500 bytes; valid UTF-8; single line; refuse C0, DEL, C1, U+061C, U+200E/F, U+202A-E, U+2066-9); consts `LabelAgentReason = "Agent-stated reason (unverified)"`, `LabelLegacyIntent`, `LegacyRationaleText = "Legacy v1 request (reason unavailable)"`, the K20 and E8c/E39 labels |
| `bounds.go` | consts `MaxSteps = 32`, `MaxStepBytes = 4096`, `MaxTotalBytes = 24576`, `ValidityMin/Default/Max = 300/86400/604800 s`, `SubmitWindowMax = 3600 s`, `HostedSkew = 300 s`, `LocalSkew = 5 s`, `ReportHorizonDefault/Min/Max`, `MaxRequiredApprovals = 256`, `VoteSlack = 64`, `AwaitMaxIDs = 100`, `AwaitMaxWait = 55 s`; `func VoteCap(rec R1) int`; `func MaxStepTTL(route Route, command string) int` (E60 table); `func ValidateRouteSnapshot(RouteSnapshot) error` (r5.2 field bounds) |
| `ids.go` | `func NewRequestID(r io.Reader) (string, error)` (`a2_` + base64url(16)); `func ValidRequestID(string) bool`; the E47 handle/challenge grammars; `func ValidRequesterSub(string) bool` (E19) |
| `canon.go` | `func Canonical(v any) ([]byte, error)` (strict canonical JSON: the exact `json.Marshal` bytes securestate demands, `store_linux.go:325-331`); `DraftHash`, `PlanHash`, `ClaimTokenHash(token [32]byte) string` (`SHA-256("sshgate-executor-claim-v1" ‖ token)`), `InputHash`, `ChallengeHash`, `LegacyHostedPlanHash`, `ChallengeMACInput(…) []byte` (E7); `func (r RouteSnapshot) Digest() string` (UTC-normalized `added_at`) |
| `assist.go` | `type AssistResult struct{ Alignment Alignment; Summary string; Effects []string; Concerns []Concern; Model, PromptVersion, InputDigest string; GeneratedAt time.Time }`; closed enums plus `not_assessed`; `func ValidateAssist(AssistResult) error` (§8.2 limits, ≤8 KiB canonical); `func AssistDigest(AssistResult) string` |
| `display.go` *(added; see §5 Q6)* | `func HiddenMarker(n int, ruleIDs []string) string` → `⟦hidden N bytes · rule-a,rule-b⟧` (rule list omitted when empty); the glyph constants. One definition for A3's cards and A4's provider input, because the assist `InputDigest` hashes text containing it |
| `verbs.go` | `func ValidateStepBytes(route Route, command string) error`; `func ValidateGrantEntry(command string) error`; mirrored prefix consts |
| `aggregate.go` | `func AggregateJobClass(steps []StepStatus) JobClass`; `func ExecutedOrdinals(steps []StepStatus) []int`; `func Partial(steps []StepStatus) bool` |
| `internal/elapsed/elapsed.go`, `elapsed_linux.go`, `elapsed_other.go` | `type Clock interface{ Wall() time.Time; Elapsed() time.Duration }`; `func Real() Clock` (Linux: `unix.ClockGettime(unix.CLOCK_BOOTTIME, …)`; elsewhere Go's monotonic reading) |
| `internal/elapsed/elapsedtest/fake.go`, `timeread.go` | `type Fake struct{…}` with `StepWall(d)`, `Advance(d)`, `Suspend(d)`; `func AssertNoDirectTimeReads(t testing.TB, files []string, allow ...string)` (go/ast scan for the r5.8 list). Imported by `_test.go` files only |
| `Makefile` | `verify-gate-closure`, `verify-mcp-closure`, `verify-lifecycle-closure` (r5.8 `:1385-1388` regexes; lifecycle is a no-op while `pkg/signerkit/lifecycle` is absent), appended to `preflight` (`:275`) and `.PHONY` (`:1-4`). Nothing else in the Makefile |

**Tests** — all of r5.8 A1a `:1431-1439`, plus: `go list -deps ./src/approvalplan/...` contains no
non-stdlib package other than `approvalplan` itself (a test or a Makefile-free shell check in the
acceptance); goldens in `src/approvalplan/testdata/` (≈10 plans, R1 and R2 records, every `Code`
string, `HiddenMarker` outputs); fuzz seeds for `ValidateRationale`, `DecodeDraft`, the ID grammar.

**Acceptance (A1a):**
```sh
make vet && go vet -tags integration ./... && flock $LOCK make test && make build
make verify-no-sqlite-local verify-no-humanauth-local
make verify-gate-closure verify-mcp-closure verify-lifecycle-closure
GOOS=darwin GOARCH=arm64 go build -o /dev/null ./src/mcp/cmd/sshgate-mcp
GOOS=darwin GOARCH=arm64 go build -o /dev/null ./src/signer/cmd/sshgate-signer-telegram
GOOS=darwin go build ./internal/elapsed/...
flock $LOCK go test -race -count=1 ./src/approvalplan/... ./internal/elapsed/...
test -z "$(go list -deps ./src/approvalplan/... | grep -E '^[^/]*\.' | grep -v '/src/approvalplan')"
# FROZEN-LOCAL / FROZEN-HOSTED / FROZEN-MCP selectors of r5.8 §0.8, unchanged
# GATE-PROOF (§1)
```
Plus **an independent review pass on A1a alone before merge** (§5 Q7), then the joint A1a+A1b+A5 pass.

### 2.2 A2 — `src/redact` span API

r5.8 A2 (`:1491-1507`). Design decision this plan makes (§5 Q8): **derive spans from the canonical
Writer's own output and verify them**, instead of re-implementing the Writer's streaming, PEM and
union-merge behaviour. That makes `RedactSpans(...).Redacted == RedactString(...)` true by
construction; the property test then guards the span mapping, not a second redactor.

```go
// src/redact/spans.go — no package-level vars with non-constant initializers, no init()
// (both would survive the linker and move GATEHASH).
const MaxSpanInput = 64 << 10

type Span struct {
    Start, End int      // byte offsets into the ORIGINAL input; End > Start
    RuleIDs    []string // sorted, deduped; "pem-block" for a PEM wholesale marker
}
type SpanResult struct {
    Redacted    string // == RedactString(s, salt, rules)
    Spans       []Span // ascending, non-overlapping
    HiddenBytes int    // sum of span lengths
}
func RedactSpans(s string, salt [32]byte, rules []Rule) (SpanResult, bool)
```

Algorithm: (1) `len(rules)==0` → `{Redacted: s}`, true (mirrors `scrub.go:29`); `len(s) > MaxSpanInput`
→ false. (2) `out, ok := RedactString(s, salt, rules)`; `!ok` → false. (3) Align `out` to `s`:
literal bytes must be equal; `NeutralizedMarkerPrefix` in `out` aligned with `MarkerPrefix` in `s`
(same 22-byte length) is a literal, not a span ("forgery rewrites are not counted"); every
`MarkerPrefix + 8 hex + MarkerSuffix` in `out` (only the Writer can emit one: input copies are
neutralized) is a span `[i, j)` such that `MarkerKey(salt, s[i:j]) == key` and the rest aligns.
Search with memoized backtracking over `(outPos, inPos)` under a fixed work budget; accept only if
**exactly one** complete alignment exists, otherwise false (fail closed → A3 refuses the v2 plan
`request_unrenderable`). (4) Rule IDs: `newScanner(salt, rules).rawMatches([]byte(s))` (in-package,
`scanner.go:77`); attach every match intersecting a span; a span that came from a PEM wholesale
marker and has no named match gets `pem-block`; a span with no match at all still counts (never
hide less). No edit to `scanner.go`, `writer.go`, `pem.go`, `scrub.go`, `markers.go`.

**Tests (`spans_test.go`):** r5.8 list `:1454-1460`, plus: the corpora inputs from `scrub_test.go`,
`leak_test.go`, `spec_acceptance_test.go`, `pem_test.go` are **copied** into a table in
`spans_test.go` (the existing tests keep their inline literals and stay untouched, §5 Q10); an
ambiguity case (two adjacent equal-key candidates) returns false; the 64 KiB+1 case; the
union-merge stitch case from `dedupMatches`; `FuzzRedactSpans` asserting the property and that
splicing each span back reproduces `s`.

**Acceptance (A2):** STD minus the closure line (A1a may not have merged);
`flock $LOCK go test -race -count=1 ./src/redact/... ./src/policyreview/... ./src/signer/backend/...`;
**GATE-PROOF** (hash quoted in the commit message); `git diff --stat` touches only the two owned
files. Review: an second-review review at merge; independent review together with A3 later (r5.8 §4.4).

### 2.3 B0 — `internal/securestate` additions

r5.8 B0 (`:1970-1986`), with the decisions in §5 Q3/Q4:

```go
// store_linux.go, additive only
func (tx *Transaction) ListNames(max int) ([]string, error)
func (tx *Transaction) Remove(name string) error
func (tx *Transaction) RemoveOrphanTemps() (int, error)
// Store gains one test seam field, like beforeRename (:63): afterUnlink func() error
```

- `ListNames`: `tx.check(false)`; `max <= 0` → error; open a fresh fd `openat(dirFD, ".", O_RDONLY|O_DIRECTORY|O_CLOEXEC)`
  and `fstat`-compare it with `dirFD` (same inode, else `ErrUnsafe`); read with `unix.ReadDirent` +
  `unix.ParseDirent` (never share `dirFD`'s offset); skip `.`, `..`, `lockName`, and names matching
  exactly `^\.tmp-[0-9a-f]{24}$` (the `atomicReplace` grammar, `:373`); any other `.tmp-*` name, or
  any name failing `validateDataName`, is an error; each data name gets `statPath` (`:504`, i.e.
  regular, single-link, owner uid, mode 0600 — stricter than r5.8's "regular-file check", §5 Q3);
  more than `max` names → `ErrTooLarge`; return sorted.
- `Remove`: `tx.check(true)`; `validateDataName`; `statPath`; `unlinkat(dirFD, name, 0)`
  (`ENOENT` → `ErrNotFound`); `afterUnlink` seam; `fsync(dirFD)`; seam or fsync failure →
  `ErrCommitUncertain` (as `atomicReplace`, `:425-436`).
- `RemoveOrphanTemps`: `tx.check(true)`; fresh-fd listing as above; for each name matching the exact
  temp grammar: `fstatat(AT_SYMLINK_NOFOLLOW)`, require regular file and owner uid (mode may be
  ≤0600 because a crash can precede `Fchmod`, `:393`), `unlinkat`; anything else under `.tmp-` →
  error, nothing unlinked; one `fsync(dirFD)` at the end (failure → `ErrCommitUncertain`); returns
  the count.

**Tests:** in a **new** file `internal/securestate/store_names_linux_test.go` (the existing
`store_linux_test.go` is untouched): r5.8's list `:1983`, plus the fresh-descriptor case (a
`ListNames` between `ReadFile` and `WriteFile` in one Update), `ListNames(max)` at max and max+1, a
`.tmp-` name outside the grammar fails both `ListNames` and `RemoveOrphanTemps`, an orphan temp
left by a re-exec'd test subprocess that `os.Exit`s inside `beforeRename`, `afterUnlink` failure →
`ErrCommitUncertain` and the next `Update` confirms, two processes see consistent listings.

**Acceptance (B0):** STD minus the closure line; `flock $LOCK go test -race -count=1 ./internal/securestate/... ./pkg/signerkit/...`;
`GOOS=darwin GOARCH=arm64 go build ./src/signer/cmd/sshgate-signer-telegram` (proves the
Linux-only methods stay out of darwin importers); GATE-PROOF; **its own independent review**
(r5.8 §4.4).

---

## 3. Next wave (start when A1a is merged into the integration branch)

### 3.1 A1b — the pure state core

r5.8 A1b (`:1441-1490`) and §1.5 SA-1..SA-11 are the spec; the rule-by-rule test list there is
the acceptance. Surface (all in `src/approvalplan`, stdlib only, pure — impure inputs are
arguments; time is a `(wall time.Time, elapsed time.Duration)` pair passed in, never read):

| File | Exports |
|---|---|
| `clock.go` | `type Now struct{ Wall time.Time; Elapsed time.Duration }`; `func Clock(rec R1, now Now) (R1, []OutboxEvent)` (the one window function: `first_end`, `last_end`, `claim_end`); `func NextDueAt(rec R1) time.Time` |
| `held.go` | `type Held struct{ WallEnd time.Time; ElapsedEnd time.Duration }`; `func Acquire(now Now, wallEnd time.Time) Held`; `func (h Held) Passed(now Now) bool` |
| `apply.go` | `type Command interface{ isCommand() }` and one struct per SA-4 command (`Submit`, `Vote`, `Claim`, `Report`, `AdminCancel`, `Revoke`, `Renotify`, `AssistDone`, notify-step commits, `Flush`, `Erase`, `Shed`, `Delete`…); `type Inputs struct{ Minted [][]byte; XferDigests …; DecidingGrant *GrantRef; Current *RouteSnapshot; Epoch string }`; `func Apply(rec *R1, cmd Command, now Now, in Inputs) (R1, Answer)` with `Answer{ Code Code; Claim ClaimStatus; …}` |
| `view.go`, `class.go` | `func View(rec R1, now Now, epoch string) Summary`; `func Class(rec R1) …` (fills A1a's `viewtypes.go`) |
| `decide.go` | `func Decide(p Policy, votes []Vote) Decision` (port of `hosted/approval.go:94`); `func EffectivePolicy(rec R1, flags VoteFlags) Policy`; `func VoteRoom(rec R1, flags VoteFlags, v Vote) bool` |
| `grant.go` | `func GrantLive(rec R1, now Now, epoch string, newestForAlias bool) bool` |
| `claim.go` | the Claim answer and the report-acceptance rule (used by `Apply`) |
| `next.go`, `notify.go` | `func Next(rec R1, now Now, epoch string) Work`; `func Unflushed(rec R1) bool`; the notify-step planner |
| `jobview.go`, `jobnext.go` | `func JobView(job R2) JobSummary`; `func JobNext(job R2, now Now, epoch string, held *Held) Action`; `func ExecSubmitAdmit(…) Code`; the retention predicate |
| `statetest/**` | generators, SA-11 properties, the crash-prefix model (stdlib + `approvalplan`) |

**Contract rule:** A1b may not edit any A1a file. If the core needs a schema change, the lane stops
and the orchestrator re-opens A1a (a named golden bump, its own commit, re-review of the bump).

**Acceptance (A1b):** STD (with the closure line); `flock $LOCK go test -race -count=1 ./src/approvalplan/...`;
`AssertNoDirectTimeReads` over `src/approvalplan/*.go` passes; GATE-PROOF; independent review of
A1a+A1b+A5 together.

### 3.2 A4 — `pkg/signerkit/assist`

Depends on A1a **and** A2 being merged. r5.8 A4 (`:1532-1559`).

```go
package assist // imports approvalplan, redact, net/http, stdlib. Never imported by gate or MCP.
type Input struct{ PlanHash string; Reason string; Commands []string } // already provider-safe text
type Assessor interface{ Assess(ctx context.Context, in Input) (approvalplan.AssistResult, error) }
func RedactForProvider(plan approvalplan.ApprovalPlanV1, salt [32]byte, rules []redact.Rule) (Input, error)
    // rules == nil or any RedactSpans ok=false -> ErrNoPolicy / ErrRedactFailed: caller makes ZERO calls (K7)
    // hidden spans rendered with approvalplan.HiddenMarker; never a [SSHGATE_REDACTED key=…] marker or salt
type Snapshot struct{ State approvalplan.AssistState; Result *approvalplan.AssistResult; Reason string }
func Run(ctx context.Context, a Assessor, in Input, deadline time.Time, t Timers) Snapshot
    // absolute deadline (E68); cancels then JOINS the provider goroutine (E70); late result dropped;
    // panics recovered; Timers{ After func(time.Duration) <-chan time.Time; Now func() time.Time } is the injection seam
type Pool struct{…}
func NewPool(n int, t Timers) *Pool
func (p *Pool) TrySubmit(ctx context.Context, a Assessor, in Input, deadline time.Time, done func(Snapshot)) Result // Accepted | Full | Closed, never queues
func (p *Pool) Close() // cancel + join; TrySubmit after Close -> Closed
type OpenAI struct{ Endpoint, Model, APIKeyFile string; HTTPClient *http.Client } // 0600 key file, 64 KiB LimitReader, strict ValidateAssist
const PromptVersion = "assist-v1"
```

Tests: r5.8 `:1543-1555` (httptest provider, goleak, planted-secret absence, zero calls on nil rules,
`Closed` under racing `TrySubmit`/`Close`). **Must not touch** `src/signer/backend/explainer*.go`,
`telegram*` (the port copies, never moves). **Acceptance:** STD; `flock $LOCK go test -race -count=1 ./pkg/signerkit/assist/...`;
`make verify-no-sqlite-local`; GATE-PROOF. Review: a second reviewer at merge; it rides in the later A6/A10 reviews.

### 3.3 A5 — `src/approvalwire` + the MCP approval client

r5.8 A5 (`:1560-1581`) and E13 (`:356-362`), E69 (`:826`). Decisions here (§5 Q9): the typed errors
and the hosted-response classifier live in `approvalwire`, so A12's hosted client in
`pkg/signerkit` and the MCP share one definition without importing each other; the MCP client is
**local-socket only** (the MCP never speaks HTTP to a hosted signer; Tier-3 goes through the A12
proxy).

```go
package approvalwire // imports approvalplan + stdlib only
const Proto = 1
const KindSubmit, KindGet, KindList, KindWait, KindClaim, KindReport =
    "approval_submit_v2", "approval_get_v2", "approval_list_v2", "approval_wait_v2", "approval_claim_v2", "approval_report_v2"
const MaxFrameBytes = …            // own constant, ≤ policywire.MaxSocketFrameBytes (asserted in a test that imports policywire)
type SubmitRequest struct{ ApprovalProto int `json:"approval_proto"`; Kind string `json:"kind"`; Draft approvalplan.ApprovalDraft `json:"draft"` } // no requester_sub, no proto_version
// … Get/List/Wait/Claim/Report requests; Response envelope:
type Response struct{ ApprovalProto int; OK bool; Error *WireError; Summary *approvalplan.Summary; Summaries []approvalplan.Summary; Claim *ClaimAnswer; NextCursor string }
type WireError struct{ Code approvalplan.Code `json:"code"`; Message string `json:"message"` }
func DecodeLocalRequest(line []byte) (any, error)   // strict; refuses requester_sub, unknown fields
func DecodeLocalResponse(line []byte) (Response, error)
    // a legacy {"status":"error","error":"unsupported kind …"} frame -> ErrSignerIncompatible
// hosted bodies for POST/GET /v2/approvals, /wait, /{id}/claim, /{id}/report (requester_sub optional)
func ClassifyHostedResponse(status int, contentType string, body []byte) (Response, error)
    // non-envelope 404 -> ErrSignerIncompatible; 503 busy envelope -> ErrBusy; 503 without envelope -> transport error
var ErrSignerIncompatible, ErrStorageUncertain, ErrBusy, ErrResponseLost error
```

```go
// src/mcp/sign/approval_client.go (package sign; reuses dialWithCtx, classifyDialError)
type ApprovalClient struct{ SocketPath string; CallTimeout time.Duration } // 30 s; Wait: wait + 10 s
func (c *ApprovalClient) Submit(ctx, approvalplan.ApprovalDraft) (approvalplan.Summary, error)
func (c *ApprovalClient) Get(ctx, requestID string) (approvalplan.Summary, error)
func (c *ApprovalClient) List(ctx, limit int, cursor string) ([]approvalplan.Summary, string, error)
func (c *ApprovalClient) Wait(ctx, ids []string, wait time.Duration) ([]approvalplan.Summary, error)
func (c *ApprovalClient) Claim(ctx, requestID string, claimToken [32]byte) (approvalwire.ClaimAnswer, error)
func (c *ApprovalClient) Report(ctx, requestID string, claimToken [32]byte, rep approvalwire.Report) error
// written-but-no-response -> approvalwire.ErrResponseLost; never retries
```

Tests: r5.8 `:1573` in full (byte goldens of every frame and body, the E69 `signer_incompatible`
frame, no golden contains `executor_claim_token_hash` or `draft_hash`), plus: a v2 frame never
contains the token `base_manifest_sign_v1` under `kind` (so `frameDeclaresPolicyKind`,
`daemon.go:632`, never routes it); a fake old daemon built from the real legacy reply shape.
**Must not touch** `src/mcp/sign/{client,grant_client,transfer_client,register_client,policy_client}.go`
and their tests, socketrpc goldens. **Acceptance:** STD; `flock $LOCK go test -race -count=1 ./src/approvalwire/... ./src/mcp/sign/...`;
`make verify-mcp-closure`; FROZEN-MCP and FROZEN-LOCAL selectors unchanged; GATE-PROOF; the reviewer
X-High with A1a+A1b.

---

## 4. Lane contracts

Common to every lane: one worktree per lane at `a per-lane git worktree` on branch
`lane/<id>` (the orchestrator creates both; the builder never runs branch, commit, merge, rebase or
worktree commands unless the orchestrator's prompt says to commit in-lane); builders get
the coding-agent prompt; no push, tag, release, `make release-gate`, `dist/`
edit, live-unit restart, or `go.mod`/`go.sum` edit; tests under `$LOCK` (§5 Q2); frozen tests and
goldens are never weakened. **Forbidden for every lane:** `src/gate/**`, `dist/**`, `go.mod`,
`go.sum`, `docs/**`, `AGENTS.md`, `README.md`, `CHANGELOG.md`, `.github/**`, `scripts/**`,
`commands/**`, `skills/**`, every other lane's owned paths, and `Makefile` (except A1a's named hunk).

| Lane | Base | Deliverable | OWNS (only files it may write) | Acceptance |
|---|---|---|---|---|
| **L-A1a** | `2ffe928` | §2.1 | `src/approvalplan/{kinds,plan,codes,viewtypes,record,audit,rationale,bounds,ids,canon,assist,display,verbs,aggregate}.go` and their `_test.go`, `src/approvalplan/testdata/**`, `src/approvalplan/doc.go`, `internal/elapsed/**`, `Makefile` (only: the three new targets, the `preflight` line `:275`, the `.PHONY` block `:1-4`) | §2.1 block |
| **L-A2** | `2ffe928` | §2.2 | `src/redact/spans.go`, `src/redact/spans_test.go` | §2.2 |
| **L-B0** | `2ffe928` | §2.3 | `internal/securestate/store_linux.go` (additive: three methods, one seam field), `internal/securestate/store_names_linux_test.go` (new) | §2.3 |
| **L-A1b** | integration tip after A1a | §3.1 | `src/approvalplan/{clock,held,apply,view,class,decide,grant,claim,next,notify,jobview,jobnext}.go` and their `_test.go`, `src/approvalplan/statetest/**` | §3.1 |
| **L-A4** | integration tip after A1a and A2 | §3.2 | `pkg/signerkit/assist/**` | §3.2 |
| **L-A5** | integration tip after A1a | §3.3 | `src/approvalwire/**`, `src/mcp/sign/approval_client.go`, `src/mcp/sign/approval_client_test.go` | §3.3 |
| (jail, existing) | `2ffe928` | #22 P2.x | `src/gate/**`, the `jail-runner` hunk of `Makefile` (`:175-210`), `docs/**`, root docs, `.github/**`, `scripts/jailmut/**`, `commands/**`, `skills/**`, `internal/redteam/README.md`, the two strings in `src/mcp/tools/{denial,run}.go` | its own |

**Disjointness proof.**
- Directory partition: `src/approvalplan/` (A1a ∪ A1b), `internal/elapsed/` (A1a), `src/redact/`
  (A2, two new files), `internal/securestate/` (B0), `pkg/signerkit/assist/` (A4),
  `src/approvalwire/` (A5), `src/mcp/sign/approval_client*.go` (A5). These directories are pairwise
  distinct, except `src/approvalplan/`, which A1a and A1b split by **explicit file name**: the two
  name lists above share no element (A1a: kinds, plan, codes, viewtypes, record, audit, rationale,
  bounds, ids, canon, assist, display, verbs, aggregate, doc; A1b: clock, held, apply, view, class,
  decide, grant, claim, next, notify, jobview, jobnext; `testdata/` is A1a's, `statetest/` is
  A1b's). A1b also starts only after A1a merges, so they are never concurrent.
- None of these paths is in the jail lane's set: the jail lane writes no file under `src/approvalplan`,
  `src/approvalwire`, `src/redact`, `internal/`, `pkg/` or `src/mcp/sign/`.
- Every new file in a lane is new at its base (none exists at `2ffe928`), so "owns" cannot collide
  with an existing owner.
- Mechanical check the orchestrator runs before each merge:
  `git diff --name-only <base>...lane/<id> | grep -vE '<lane OWNS regex>'` must print nothing.

**Shared files and hand-offs.**
- `Makefile`: two writers in this window, A1a (targets `:1-4`, `:275`, new block after
  `verify-no-humanauth-local`, before `verify-dist` `:319`) and the jail lane (`:175-210`). The hunks are 60+ lines apart,
  so git merges them cleanly; if not, the orchestrator resolves by hand and re-runs both lanes'
  Makefile targets. Later writers: C4 only (r5.8 §5).
- `go.mod`/`go.sum`: nobody. A lane that finds it needs a module stops and asks.
- `docs/BUILD-PLAN.md`, `docs/TESTING.md`: the **orchestrator** only. It records sub-phase status
  and the three new `verify-*` targets in TESTING.md at integration (the jail lane edits both files
  too, so the orchestrator applies WI2's lines after the jail merge or as a separate commit on the
  integration branch).
- `src/mcp/sign/` package namespace: A5 adds files to a package the jail lane does not touch; A5
  must not add an unexported identifier that collides with existing ones (the compiler proves it).
- `.github/workflows/tests.yml` (adding the closure checks to CI): deferred, orchestrator-only,
  after the jail merge (the jail lane edits that file).

**Merge order** (orchestrator, one at a time, STD + frozen selectors + GATE-PROOF after each):
A1a, A2, B0 (any order among the three), then A1b, A5, A4 (r5.8 order).

---

## 5. Open questions (each with a recommendation)

1. **Where do lanes merge — `main` or an integration branch?** the owner said "on main". Local `main`
   is unpushed and still carries the CI-flake fix that needs pushing; merging half-built WI2
   packages into `main` would ride along on that push. **Recommend:** integration branch
   `feat/76-65-approval-lifecycle` cut from `2ffe928` (r5.8 §0.1's name); lanes cut from it and
   merge into it; `main` gets the integration branch at phase end or on the owner's word. After the
   jail merges to `main`, `main` is merged into the integration branch (that is when A0 runs).
2. **The test lock does not cover the jail lane.** r5.8 §0.3 requires one test process at a time
   (`flock …/release-2026-10-02/.test.lock`), but the running jail builder takes no lock, and the
   jail tests consume user namespaces and run long. **Recommend:** one lock file for every lane
   including the jail builder, `LOCK=$LOCK`; WI2 builders run
   only their package-scoped tests under it; the full `make test`/STD runs only in the orchestrator
   at merge time.
3. **`ListNames` posture.** r5.8 checks only "regular file". **Recommend:** full `statPath`
   (0600, one link, owner uid), matching what every other securestate read demands, so a 0644 or
   hard-linked record fails the store open instead of being half-trusted; and a `max` argument,
   because the package's rule is caller-supplied bounds (B1 passes its 65 536 cap).
4. **`RemoveOrphanTemps` scope.** **Recommend:** unlink only names in the exact
   `.tmp-` + 24 lowercase hex grammar that are regular files of the owner uid (mode ≤ 0600 allowed,
   since a crash can precede `Fchmod`); any other `.tmp-*` entry is an error and nothing is
   unlinked.
5. **View enums, answer codes and Claim statuses have no owner before A1b/A5.** A5's summaries
   carry SA-6's views and `Apply`'s answers carry codes, but r5.8 puts the view functions in A1b
   and the closed code set in A5, while A1b cannot import `approvalwire`. Under r5.8 §0.5 ("each
   commit passes on its own predecessors") A5 and A1b would each invent the types. **Recommend:**
   A1a owns the value types (`codes.go`, `viewtypes.go`); A1b fills them; A5 encodes them.
6. **One hidden-span marker format.** A3 renders `⟦hidden N bytes · rules⟧`, A4's provider input
   `⟦hidden N bytes⟧`, and the assist `InputDigest` hashes that text. **Recommend:**
   `approvalplan.HiddenMarker` (A1a) used by both; the provider gets the same text the operator
   sees (rule IDs are not secret).
7. **the reviewer on A1a before it merges.** r5.8 reviews A1a only jointly with A1b and A5, but A1b, A4 and
   A5 all build on A1a's frozen encodings, and a finding after they build means rework in three
   lanes. **Recommend:** an independent review pass on A1a alone before merge,
   plus the joint pass.
8. **How A2 computes spans.** **Recommend** derive-and-verify (§2.2) over re-implementing the
   Writer from its helpers: equality with `RedactString` holds by construction, every span is
   verified by its HMAC marker key, and any ambiguity fails closed. Cost: an extra alignment pass
   on ≤ 4 KiB commands, negligible.
9. **Which side owns the hosted response mapping.** r5.8 A5 tests "hosted 404 → `ErrSignerIncompatible`"
   inside the MCP client, but the MCP never calls the hosted signer. **Recommend:** the classifier
   and the typed errors live in `approvalwire` (shared by A12's `pkg/signerkit/hosted_v2_client.go`
   and the MCP); the MCP client tests the local paths, `approvalwire` tests the hosted ones.
10. **Property-test corpora for A2.** The redact corpora are inline literals inside existing tests,
    which A2 may not edit. **Recommend:** copy the inputs into `spans_test.go`, with a comment
    naming each source test.
11. **Recording the reorder in `docs/BUILD-PLAN.md`.** The plan's own rule (`:14-15`) says a
    reordered step is changed in the plan in the same commit. A1a/A2/B0 now start before work
    item 1 is done and A0 is split. **Recommend:** the orchestrator commits, on the integration
    branch before the first lane merge, a BUILD-PLAN edit: A0 → "A0a: closure lists and gate hash
    at the WI2 base (done, 2ffe928); A0b: re-ground after the jail merges"; A1a, A2, B0 depend on
    A0a; the acceptance's "gate hash equals the A0 baseline" becomes the relative GATE-PROOF (§1).

---

## 6. Where BUILD-PLAN text is ambiguous or disagrees with the code

1. **"A0 depends on Work item 1"** (`BUILD-PLAN.md:611`) means all of #22 Phases 2-7, not one
   merge; the jail will keep changing gate bytes after any "baseline". The absolute rule
   "the reproducible gate build hash equals the baseline recorded in A0" (`:588-589`) cannot hold
   across later #22 merges. → §1's relative proof, §5 Q11.
2. **The jail lane is not "src/gate/** only"**: it edits `Makefile`, `docs/BUILD-PLAN.md`, and
   `src/mcp/tools/{denial,run}.go` among others (§0). No WI2 first-wave lane writes those, but A13b
   (later) owns `src/mcp/**` and must rebase on whatever the jail leaves in `run.go`/`denial.go`.
3. **Status markers.** Work item 1 steps carry `Status:` lines; work item 2's sub-phase tables have
   no status column, yet "the change that completes a step sets it to done" (`:13-14`). → add a
   Status column in the §5 Q11 edit.
4. **Public A1a omits `internal/elapsed`.** `BUILD-PLAN.md:612` lists only `src/approvalplan` and
   the Makefile targets; r5.8 (`:1411,1424`) puts `internal/elapsed` in A1a. This plan follows r5.8.
5. **r5.8 §11 vs the owner.** §11 says "A1a starts only after GO"; review 9 (the last) is NO-GO and
   r5.8's fold was never re-reviewed. an owner message ruled "per-phase reviews instead". Not a blocker, but
   the A1a-alone the reviewer pass (§5 Q7) is the first independent read of r5.8's schema text.
6. **Stale cites in r5.8:** `preflight` is `Makefile:275` (not `:204`); the "ErrResponseLost
   precedent in policy_client.go" is `ErrPolicyVerdictUnknown` (`policy_client.go:21`); E13's
   `daemon.go:496-500` proto check is now `:492-499` (the `:519` default case is unchanged).
7. **`verify-no-sqlite-local` and the closure targets are not in CI** (`tests.yml` runs only
   `make vet` and `make test`); they run in local `preflight` only. Adding them to CI touches a file
   the jail lane edits → orchestrator, after the jail merge.
8. **`dist/gate` is stale at 2ffe928** (rebuilt `fb0603c3…` vs sidecar `c7a4aaa4…`); r5.8 §0.6
   already says compare against a rebuild. No action for these lanes; the release refresh is a
   separate, owner-gated `make release-gate`.
9. **A2's "64 KiB" bound** (`:1458`) sits exactly at `ringMax`; with derive-and-verify a
   suppression drop would fail alignment anyway, so the bound is a cost cap, not a correctness
   boundary. Keep `len(s) > 64 KiB → false` as written.

## 7. Phase 4 obligations on later WI2 lanes (from P4-PLAN-v6.md §7.4-§7.6, ruled 2026-10-15)

> **Phase-4 network obligations (#22 P4.3/P4.4; coordinator rulings on P4 critiques M1 and N1 and
> the reviewer reviews 1–3).** A network read stays on the v1 `sign` kind for v0.2: work item 2 adds no
> v2 network route, and the A1a contract changes only by the A1a-net mini-commit (shared
> network-card text, `ValidateLegacyNet`, `LegacySignInput` and `LegacySignDigest` in
> `approvalplan`; no existing route, kind, step field, plan field, record field or hash changes;
> every existing golden byte-identical). Lanes **A7, A8, A12 and A13b** are cut only from a base
> that contains P4 lanes S (signer) and M (MCP) and the signer callback-binding security commit
> (callbacks bound to the exact chat and message of the pending card; a duplicate pending
> `request_id` refused on every path). **A7 additionally needs A1a-net, A3's follow-up commit and
> A6's prepared-approval machinery merged on its base; A8 needs A7 and A3's follow-up.**
> - **Prepared legacy approval (A3, A6, A7, A8).** Every v1 `sign` through `legacyApprove` is
>   carried by one immutable `PreparedLegacyApproval` per request instance, built inside the
>   signer in this order: (1) the exact signing inputs (`[]approvalplan.LegacySignInput`: alias,
>   host fingerprint, exact command bytes and SHA-256, TTL, `Reveal`, `Net`, reason), a
>   signer-generated 128-bit instance ID and `LegacySignDigest`; (2) the request metadata
>   (request ID, requester, submitted, expires); (3) the authoritative snapshot from A3's pure
>   `BuildPreparedSignSnapshot`, checked step by step against the inputs; (4) A6 reserves the card
>   handle, the challenge (hash stored) and the destination, with the request `preparing` and not
>   tappable; (5) A6 runs the one assist attempt to a terminal state (`ready` or `unavailable`);
>   (6) the frozen render context {metadata, terminal assist, destination, handle, challenge} and
>   the final render with A3's pure `BuildView`, `PackParts`, `DecisionCard` — the payload is the
>   ordered review parts then the decision card with its labels, and callback data is A8's
>   deterministic encoding of handle, challenge and action; (7) what the notifier reports it holds
>   must equal the artifact completely (snapshot, render context, every message's bytes and
>   labels); (8) A8 delivers exactly those messages in order, and only after every message is
>   delivered does A6 activate the challenge (`live`); a delivery failure never activates it,
>   answers the v1 request with an error and signs nothing; (9) a tap resolves only the `live`
>   instance whose card chat, message and challenge all match, and `signAt` signs exactly the
>   artifact's inputs. A mismatch at (3) or (7) refuses before any card — with
>   `net_unsupported: network reads need a card that shows them` when any input has `Net` (the
>   floor rule), otherwise `legacy approval render does not match the request`. The existing
>   non-sign builder `BuildLegacySnapshot` stays unchanged for grants, transfers and key
>   registrations and is never used for a production v1 `sign`.
> - **A6** (`pkg/signerkit/lifecycle`): `PreparedLegacyApproval` (unexported fields only; deep
>   copies on construction and from every getter); `ReserveLegacy(instance, snapshot)` (handle,
>   challenge, destination; state `preparing`); the assist attempt to a terminal state; activation
>   to `live` only on the notifier's report that every message was delivered; `LegacyRequest`
>   holds exactly one artifact; `LegacyNotifier` gains `Destination()`, `Prepared(instance)` and a
>   delivery call that sends only an artifact's messages.
> - **A7** (`pkg/signerkit/daemon.go`, `daemon_approvals.go`): P4.3's `Net` refusals (sole command,
>   non-empty reason, not an admin verb, a read by `classify.Classify`) still run before
>   `legacyApprove`; `prepareLegacy` runs steps 1–3, 6–7 and 9; no grant path ever signs a `Net`
>   command. **Notifier-seam tests** (A6's real lifecycle, a fake assist provider, a fake
>   `LegacyNotifier`): `TestPreparedLegacyRefusesMismatch` (one subtest per mismatch: command bytes,
>   command hash, host fingerprint, TTL, `Reveal`, `Net`, step count, step order, reason display,
>   headline, approve label, assist, handle, challenge, destination, one review part's bytes,
>   visible segments only, swapped snapshots, missing banner, missing network label),
>   `TestPreparedLegacyAuthoritative`, `TestPreparedLegacySequence` (ready and unavailable assist),
>   `TestPreparedLegacySendsArtifact`, `TestPreparedLegacyImmutable`; srcmut `P-S-LEGACY-PREPARED`
>   (entry `legacy-prepared-skip-check`, whose `red` names each mismatch subtest's full path with
>   its own marker, and entry `legacy-prepared-shallow-copy`). `TestDaemon_SignsNetFlag`,
>   `TestEnvelopeGolden_SignNet` and the `TestSignRejectsNet*` tests pass unedited. The commit that
>   deletes `matchGrant` either moves srcmut entry `P-S-GRANT-NET` (`scripts/srcmut/sets/p43.json`)
>   to the code that decides grant coverage, or deletes it together with a BUILD-PLAN edit stating
>   that no v1 grant path exists. After adding the `src/approvalreview` import,
>   `make verify-no-sqlite-local verify-no-humanauth-local` stay green.
> - **A3** (`src/approvalreview`; a follow-up commit on the A3 branch after A1a-net merges): a new,
>   separately named `BuildPreparedSignSnapshot(instance, []approvalplan.LegacySignInput,
>   LegacyMeta, salt, rules)` setting `ReviewSnapshot.SignDigest` (`json:"sign_digest,omitempty"`);
>   `Step.Net` (`json:"net,omitempty"`); `BuildLegacySnapshot` and `LegacyCommand` unchanged, every
>   existing golden byte-identical; `ValidateLegacyNet` for a `Net` input; the headline
>   `approvalplan.NetworkBanner(alias)` (after the reveal headline); the reason under
>   `approvalplan.LabelNetworkJustification`; the button `… (READ WITH NETWORK)` or
>   `… (SECRET-REVEAL + NETWORK)` in E46's scheme; the builders, `BuildView`, `PackParts` and
>   `DecisionCard` pure (`TestLegacyRenderDeterministic`); goldens `legacy-sign-net.txt`,
>   `legacy-sign-reveal-net.txt`, `legacy-sign-net-assist-unavailable.txt`,
>   `legacy-sign-net-multipart.txt`; the parity table's network row.
> - **A8** (`src/signer/backend/**`): the production `LegacyNotifier` adapter (`Destination`,
>   `Prepared`, delivery of exactly the artifact's messages in order, the callback encoding of the
>   frozen handle and challenge, the report that lets A6 activate, challenge resolution bound to
>   the instance, chat and message). **Through the fake Bot API:** `TestPreparedLegacyBotAPIOutput`,
>   `TestPreparedLegacyAssistReady`, `TestPreparedLegacyAssistUnavailable`,
>   `TestPreparedLegacyMultipart` (including a failure on part 2: no further sends, no activation,
>   an `error` v1 answer, no signature), `TestPreparedLegacyActivationAfterDelivery`,
>   `TestPreparedLegacyChallengeBound`, `TestLegacySignNeverUsesNonSignBuilder`.
> - **A12** (hosted proxy): a `Net` request is refused with an error starting `net_unsupported:`
>   before any HTTP request; `TestHostedRefusesNet` (or its moved equivalent) passes.
> - **A13a / A13b** (`src/mcp/tools/**`, `jobplan`): `run` with `network:true` keeps P4.4's routing
>   and its single v1 `Sign` call (`SignClient` keeps `Sign`); `jobplan.StepOutcome` is not used for
>   it; every `TestRunNetwork*` test and every `P-M-*` srcmut entry (`scripts/srcmut/sets/p44.json`)
>   passes unedited.
> - **D3 / THREAT-MODEL:** the gate's clock-skew allowance is 30 s (`sigwire.MaxClockSkew`); r5.8
>   §1.4 item 5's 60 s proposal is superseded.


## 8. Coordinator ruling 2026-10-15: review bounds overflow (A3 fix round 1)

A3's fix round proved (`src/approvalreview/packing_feasibility_test.go`) that a K19-legal plan
can need more than the Telegram review bounds (40 messages, 128 KiB): six 4,096-byte commands
dense with minimal secrets and maximum route fields render to 163,704 bytes of command display
alone, because each hidden span becomes a marker carrying its byte count and rule IDs. No packing
fixes that. Ruling:

- **A review that does not fit the bounds is refused at submit as `request_too_large`**
  (`stop_do_not_retry`, remedy "split into smaller requests"), never `request_unrenderable`.
  `request_unrenderable` stays reserved for E16's unprovable spans (§9.1). The check runs at
  freeze, on the one frozen snapshot, for every route, so a request accepted on one surface is
  reviewable on the other (K19's surface-parity promise holds: both refuse at the same point).
- **Ordinary batches must fit:** A3 packs greedily (fills each part, splits a long display at the
  remaining space, keeps the continuation header and repeated SHA-256). The sweep test asserts
  every K19-legal plan either fits or is refused `request_too_large` (never `request_unrenderable`,
  never a panic), and that each of these fits: 8×3072 B, 10×2457 B, 20×1228 B and 25×983 B of
  control bytes; 24×~1000 B of multi-byte UTF-8; 32 steps of 768 B plain ASCII with maximum route
  fields; a hidden-span-free 32×768 B plan of `<` bytes. A3 reports the measured envelope (the
  largest hidden-span-free plan and the densest secret plan that fit).
- Marker format and the 40-message / 128 KiB bounds are unchanged.
