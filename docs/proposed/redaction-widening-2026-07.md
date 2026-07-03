# Redaction widening — default-deny output redactor (P1-B)

Status: **approved design, building**. Synthesized 2026-07-03 from two independent,
empirically-grounded proposals (anchored-rules-maximalist vs default-deny-engine);
every load-bearing choice below is backed by a measured run, not intuition.

## Problem

The output redactor is allowlist-of-shapes: 32 named-format rules. A production
multi-server run demonstrated real secrets passing raw into agent context, the
MCP live log, and the approval display: JSON-quoted keys (`"botToken": "…"`),
camelCase keys (`authToken:`), `*_API_HASH`/`*_SESSION` names, Telegram bot
tokens, fine-grained GitHub PATs, and unknown-named high-entropy values. The
operator ratified a default-deny mandate: redact anything that looks like a
secret, preferring false positives over misses, in the default mode, across all
four sinks (agent output, MCP live log, approval-message display, signer/gate
audit command-strings). All four sinks compile `redactrules.Combined()`, so the
widening propagates by rebuilding the three binaries (gate needs per-server
redeploy; MCP/signer need local rebuild + restart).

## Design summary

Three detectors:

1. **Widened name-anchored rule** — `sshgate-sensitive-assignment` regex is
   replaced (same ID) to cover JSON-quoted keys, single-quoted keys, camelCase
   (via a prefix whitelist), and new stems (`API_HASH`, `SESSION`, `COOKIE`),
   plus a newline-crossing fix. Keywords gain `hash`, `session`, `cookie`.
2. **New named rules** — `sshgate-openai-broad` (entropy-gated),
   `sshgate-github-fine-pat`, `sshgate-zoho-token`.
3. **Generic default-deny net** — a hand-rolled O(n) linear pass in
   `scanner.findMatches` (NOT a regex rule) that segments `[A-Za-z0-9_-]` runs
   and emits (a) Telegram-bot-token stitches and (b) generic high-entropy runs
   ≥ 32 chars passing a three-part gate. `Rule.Entropy` becomes a live engine
   feature sharing the same gate.

Why the net is engine code, not a rule: Go's `regexp` is NFA-only (no DFA, no
literal-prefix skip). Measured on the repo's `BenchmarkScannerNoMatch` profile,
the two zero-keyword regex formulations cost **+66% and +73% per MB**; the
linear pass does the same work in **+~2%**. A keyword-scoped regex net was also
rejected: it silently deactivates on keyword-free buffers (an unknown-named
secret in output that never says "key/token/secret" would leak), which defeats
the default-deny mandate — and still measured −53% on keyword-dense output.

## 1. Engine changes (`src/redact/scanner.go`)

### 1a. `Rule.Entropy` consulted in `findMatches`

Between the MaxLen check and the match append (the slot the conflict-resolution
comment already reserves for "Layer 1 entropy"):

```go
if r.Entropy > 0 && !passesSecretGate(buf, matchStart, start, end, r.Entropy) {
    continue
}
```

### 1b. The shared gate

```go
// passesSecretGate is the generic-candidate gate shared by Entropy-bearing
// rules and the generic linear pass. A candidate is dropped unless it
// (a) contains upper+lower+digit (kills lowercase hex — git SHAs, docker
//     digests, sha256sums, nix hashes — and caseless identifiers),
// (b) is not on the same line as an SSH public-key type marker
//     (authorized_keys / known_hosts / ssh-keygen output), and
// (c) has Shannon entropy >= threshold bits/byte (kills repetitive
//     three-class runs like "Test123Test123…").
// Cheapest checks first.
func passesSecretGate(buf []byte, matchStart, start, end int, threshold float64) bool
func has3Class(b []byte) bool          // OR-mask loop, early exit on mask==7
func shannonEntropy(b []byte) float64  // fixed [256]int histogram, no alloc
var sshKeyMarkers = […]string{"ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-"}
// sshLineContext: scan back from matchStart to the previous '\n' (cap 1024
// bytes — an ssh-rsa authorized_keys line is ~560-750 bytes), ASCII case-fold,
// substring-match the markers.
func sshLineContext(buf []byte, matchStart int) bool
```

### 1c. The generic linear pass — scanner step 3

In `findMatches`, immediately before `dedupMatches(out)`. It therefore sits
AFTER the existing `len(s.rules) == 0` early return, preserving the nil-rules
verbatim contract (scrub/pem nil-rules tests).

```go
out = append(out, scanGenericRuns(buf)...)
return dedupMatches(out)
```

```go
const (
    genericEntropyRuleID = "sshgate-generic-high-entropy"
    telegramTokenRuleID  = "sshgate-telegram-bot-token"
    genericMinLen        = 32  // spec floor; the tuning knob for a future FP/miss report
    genericEntropy       = 3.5
)

// scanGenericRuns: ONE allocation-conscious pass segmenting maximal
// [A-Za-z0-9_-] runs. Emits:
//   telegram stitch: an id of 6-10 digits, followed by ':', followed by
//     a run of len 34-36 whose first byte is 'A' (real tokens are exactly
//     <id>:AA<33 base64url>; gitleaks upstream also pins the 'A'; a
//     nonstandard body falls through to the generic branch). The id is
//     EITHER a whole all-digit run OR the trailing 6-10-digit suffix of a
//     longer run — the latter covers the glued URL form
//     `api.telegram.org/bot<id>:<body>/…`, which NO word-boundary regex can
//     match (no \b inside "bot123…"; the operator spec's own regex misses
//     it too). Span = id + ':' + body; MatchStart = id start so the
//     writer's straddler retention keeps the anchor.
//   generic: run NOT starting "_Z" (Itanium-mangled C++ symbols), edge-
//     trimmed of '-' and '_', trimmed length >= genericMinLen, passing
//     passesSecretGate(..., genericEntropy). MatchStart = Start = the
//     TRIMMED run start (there is no anchor prefix). Getting this wrong
//     (e.g. a zero default) makes the writer's ringMax tail path redact
//     from offset 0 and swallow benign output wholesale — a ringMax test
//     with a >64 KiB benign prefix pins it.
// match.Secret is copied exactly as in the regex path; RuleID is set to the
// constants above so markers, audit `why`, and tests name the detector.
func scanGenericRuns(buf []byte) []match
```

Implementation notes (from the adversarial critique; the reference harness
implementation is directionally right but must NOT be copied blind):
- `has3Class` must early-exit on mask==7; `sshLineContext` must be
  allocation-free (reuse `indexFoldASCII` from rules.go — the reference's
  `strings.ToLower(string(…))` allocates twice per candidate).
- `shannonEntropy` runs LAST in the gate (cheapest-first: length →
  3-class → ssh-line → entropy).

Interplay (inherited, verify in tests, no writer changes):
- `dedupMatches` (earliest-start-wins, tie → longest) merges pass output with
  regex matches: a Telegram stitch starting at the digits beats a generic hit
  on the body; an assignment-rule value match and a generic hit on the same
  span collapse to one marker. The pass output need not be pre-sorted —
  dedupMatches sorts.
- Streaming: a token ≤ ~101 bytes always fits the 4 KiB held tail, so an
  incomplete arrival cannot flush early (bytes only flush when ≥4096 bytes sit
  after them, at which point the token is complete and matchable). Runs longer
  than the ring hit the existing ringMax redact-wholesale / partial-redact
  paths — a partial marker is a redaction, not a leak.
- Marker-forgery spans can't collide: `SSHGATE_REDACTED` has no digits →
  3-class fails; the forgery rule also matches earlier (same start, longer).
- Nil-rules contract, stated precisely: `RedactString`'s empty/nil-rules
  fast-path (scrub.go) returns verbatim BEFORE any Writer exists — unchanged.
  A real Writer always carries the prepended marker-forgery rule, so
  `findMatches`' `len(s.rules)==0` early return is unreachable there and the
  generic pass ALWAYS runs inside a Writer — meaning a "forgery-only" Writer
  is no longer pure pass-through for a qualifying ≥32-char 3-class run. That
  is intended (the gate builds its Writer only when it has real rules;
  defence-in-depth elsewhere); pin it with a forgery-only-Writer test rather
  than assuming pass-through.

Reference implementation: the default-deny proposal's harness contains a
worked `scanGenericRuns` + gate whose behavior produced the empirical tables
below — port it, don't reinvent (scratchpad `harness*` dirs; see also the
anchored proposal's `final-diff.patch` for test-file conventions).

## 2. Rule changes (`src/redact/rules/sshgate/rules.go`)

### 2a. REPLACE `sshgate-sensitive-assignment` regex (same ID, same SecretGroup 1 / MinLen 4 / MaxLen 0)

```
(?i)(?:^|[^A-Za-z0-9])(?:export\s+)?["']?(?:(?:[A-Z0-9]+[_-])?(?:API[_-]?KEY|ACCESS[_-]?KEY|SECRET[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|API[_-]?HASH|KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|SESSION|COOKIE)|(?:api|auth|oauth|bot|access|refresh|client|app|session|user|private|service|master|admin|db)(?:key|token|secret|hash|password|pass|pwd|cookie|session)|[A-Z0-9]+[_-](?:PWD|PASS))["']?[ \t]*[:=][ \t]*("[^"\n]{1,1000}"|'[^'\n]{1,1000}'|[^\s'"`;&|<>$(){}]{4,1000})
```

(backtick in the value class spliced as `+"`"+` in Go source, as today)

Keywords: `key, token, secret, password, pass, passwd, pwd, credential, hash,
session, cookie` (the last three are NEW — without them the new stems are
prefilter-dead; `auth` deliberately absent: `authToken`/`oauthsecret` already
contain `token`/`secret` substrings).

The five deltas, each empirically motivated:
1. `["']?` around the name → JSON `"botToken": "…"` and Python-dict
   `'botToken': '…'` (the closing quote before `:` was the single blocker for
   5 of 8 spec JSON cases).
2. camelCase branch: whitelisted-prefix × stem with no separator →
   `botToken:`, `authToken:`, `apiKey:`. A prefix WHITELIST, not `[a-z]+`, so
   `possession:` / `expression:` can never match.
3. New stems `API[_-]?HASH`, `SESSION`, `COOKIE`. Bare `HASH` is deliberately
   NOT a stem (`GIT_COMMIT_HASH=` build metadata would over-redact
   everywhere); only the `API_HASH` compound is secret-shaped.
4. `\s*` → `[ \t]*` around `[:=]` — **fixes a live over-redaction bug**: the
   current rule crosses newlines, so names-only output
   (`grep -oE '^[A-Za-z_]+=' .env` → `A_API_KEY=\nB_API_KEY=`) redacts the
   NEXT LINE'S NAME as a value today. Both proposals found this
   independently; the spec's names-only fixture is unmeetable without it.
   Trade: YAML block-scalar (`password:\n  value`) is no longer caught —
   documented miss, the bug fix outweighs.
5. `PWD`/`PASS` strict branch, `$`-exclusion in the unquoted value class, and
   MinLen 4 unchanged — preserves every pinned negative (PWD, OLDPWD, MONKEY,
   WHISKEY, COMPASS, BYPASS, KEYBOARD) and the `$VAR`-reference protection in
   approval displays.

Accepted, test-pinned over-redaction: `DESKTOP_SESSION=gnome` loses its value
(price of the SESSION stem). Verified survivors: `SESSION_MANAGER`,
`GDMSESSION`, `XDG_SESSION_*`, `SSH_AUTH_SOCK`, `SESSION_TIMEOUT=30`.

### 2b. Tighten `sshgate-pgpassword` the same way

`\s*[:=]\s*` → `[ \t]*[:=][ \t]*` (same newline-crossing bug).

### 2c. New named rules (append)

| ID | Regex | Keywords | SG | MinLen | MaxLen | Entropy |
|---|---|---|---|---|---|---|
| `sshgate-openai-broad` | `\b(sk-[A-Za-z0-9_-]{16,})\b` | `sk-` | 1 | 19 | 320 | **3.5** |
| `sshgate-github-fine-pat` | `\b(github_pat_[A-Za-z0-9_]{20,})\b` | `github_pat_` | 1 | 31 | 255 | 0 |
| `sshgate-zoho-token` | `\b(1000\.[0-9a-fA-F]{32}\.[0-9a-fA-F]{32})\b` | `1000.` | 1 | 70 | 70 | 0 |

- openai-broad's Entropy 3.5 is load-bearing: the gate's 3-class check kills
  `sk-ecdsa-sha2-nistp256@openssh.com` (FIDO2 key-type markers) and prose
  slugs (`sk-migration-notes-2026`) — all lowercase(+digit) — while real
  base62 keys pass. Existing `sshgate-openai-project-key` /
  `sshgate-anthropic-key` stay unchanged (ungated belt-and-braces; dedup
  collapses overlap).
- github-fine-pat needs its OWN keyword: `ghp_` is not a substring of
  `github_pat_` — widening the existing rule can never fire (verified
  prefilter blocker). Real tokens are 93 chars; `{20,}` per operator spec.
- zoho: exact structural shape; hex body must NOT be entropy-gated (hex is
  2-class and caps at 4.0 bits/byte).
- `sshgate-url-userinfo-password` covers the `user:pass@host` form of
  PAT-in-URL / `git remote -v` (verified, including `github_pat_` userinfo).
  The COLON-LESS form `https://<pat>@github.com/…` does NOT fire that rule —
  the token rules themselves (`sshgate-github-pat` / `-fine-pat`) catch it
  regardless of URL framing (verified). Fixture both forms; no rule change.

### 2d. Comment fixes (while touching the file)

- Stale "Value group is #2" comment on sensitive-assignment (SecretGroup is 1).
- Package policy header: the generic/telegram net is NOT a rule — point at
  `scanGenericRuns` and record the measured +66–73%/MB regex alternative.
- `src/redact/scanner_bench_test.go` corpus comment says ~1 secret/100 KB but
  `makeCorpus` inserts ~1/10 KB — fix the comment (one line, no code change).

## 3. Test plan

Conventions: all secret-shaped fixtures ASSEMBLED AT RUNTIME
(`"AA"+strings.Repeat(…)` style) — no contiguous token literal in source;
synthetic names only (`ALPHA_PASSWORD`, `EXAMPLE_SESSION` — never real fleet
names); per-file fixed salts per existing convention.

1. **`sensitive_assignment_test.go`** — extend the dual-polarity table.
   NOTE: every redact=true value must be ≥ 4 chars (MinLen-4 floor on the
   secret group — `authToken: v` would NOT redact and the row would fail).
   - redact=true: JSON `"botToken"`/`"apiKey"`/`"api_key"`/`"client_secret"`/
     `"token"`/`"refresh_token"`/nested `"auth": {"token": …}`/`"api_hash"`/
     `"session"`/`"cookie"` (values like `"abcd1234efgh"`); single-quoted
     `'botToken': 'abcd1234'`; camelCase YAML `botToken: abcd1234` /
     `authToken: abcd1234` / `apiKey: abcd1234`; `EXAMPLE_API_HASH=<32hex>`;
     `EXAMPLE_SESSION=abcd1234`; `Cookie: sessionid=abc123def456`;
     `DESKTOP_SESSION=gnome` (documented-bias row with comment).
   - redact=false (OVER-REDACTION rows): all 7 existing pins PLUS
     `SESSION_MANAGER=local/unix:…`, `GDMSESSION=gnome-xorg`,
     `XDG_SESSION_TYPE=wayland`, `SSH_AUTH_SOCK=/run/…`, `SESSION_TIMEOUT=30`,
     `possession: myhouse12345`, `expression: a+b*c1234`,
     `{"region": "ap-south-1"}`, `{"status": "ok"}`, and the multi-line
     names-only block `"A_API_KEY=\nB_API_KEY=\nDB_PASSWORD="` (pins the
     `[ \t]*` fix — this row FAILS against master, which is the bug evidence).
2. **`scanner_test.go` goldens** — positive + negative per new detector:
   - openai-broad: pos `"sk-"+mixed62(40)`; neg `sk-ecdsa-sha2-nistp256@openssh.com`,
     and the existing `sk_test_xxxxx` pin must keep passing.
   - github-fine-pat: pos `"github_pat_"+mixed(82)`; neg `github_pat (words)`.
   - zoho: pos `"1000."+hex32+"."+hex32`; neg `1000.50 price`.
   - telegram: pos `digits(10)+":AA"+b64url(33)` bare AND glued
     `…/bot<token>/sendMessage` (fires via the digit-SUFFIX peel — assert
     marker present + full `<id>:<body>` absent, do NOT assert RuleID);
     neg `epoch(10)+":"+hex(36)` (A-pin miss — deliberate; the operator
     spec's literal regex FPs here).
   - generic: pos `mixed-3class(40)` bare AND a long 3-class PATH segment
     `/tmp/AbcDef…40/data.txt` (documented-bias row — path segments that
     look like tokens DO redact, see §6); negs: full `git log --oneline`
     line, `nginx@sha256:`+hex64, dashed UUID, nix-store path, `ssh-rsa AAAA…`
     authorized_keys line (ssh veto), `_ZN4absl…` (Itanium veto),
     `strings.Repeat("Test123", 7)` (entropy veto), 9 KiB of `Z`.
   - engine pins: forgery-only-Writer with a qualifying run (generic pass
     active — intended); ringMax test with a >64 KiB benign prefix followed
     by a tail-reaching generic run (pins `MatchStart = Start`; a wrong
     MatchStart swallows the benign prefix into the marker).
3. **New `src/redact/spec_acceptance_test.go`** mirroring the operator spec's
   acceptance list: multi-line `.env` cat (named values + one unknown-named
   high-entropy value all redacted; comments, names, `DEBUG=true` survive);
   jq-style JSON doc with `botToken`/`api_key`/nested `auth.token`;
   `grep -oE '^[A-Za-z_]+='` names-only output byte-identical; `git remote -v`
   two-column output with runtime-assembled `ghp_` AND `github_pat_` userinfo;
   bare telegram / sk- / github_pat_ / zoho tokens.
4. **Streaming sweeps** (extend writer tests or acceptance file): telegram
   stitch and a ≥32-char generic run pushed through chunk sizes 8 B…64 KiB
   (the existing chunk-sweep helper pattern); assert exactly-one-marker.
5. **Pinned interactions that must NOT change**: `TestRedactStringMysqlFlagGapXFAIL`
   (`-psecretpassword` is 15 chars, sub-floor, stays unredacted — do NOT flip);
   PEM nil-rules + aborted-PEM (Z-padding is 1-class); writer benign
   byte-identical tests; `gitleaks-twitter-bearer`'s pre-existing redaction of
   AAAA-prefixed ed25519 pubkey bodies (pre-existing behavior — pin with a
   comment, do not fix here).
6. **Known suite fallout (exactly one, decided)**:
   `TestGateAuditBenignCommandUnchanged` (src/gate/cmd/sshgate-gate/
   audit_redact_test.go) goes red because its `t.TempDir()` path embeds the
   test-function name — a 45-char 3-class run the generic net now redacts.
   Decision: this is the ACCEPTED over-redaction posture, not a bug. Change
   the fixture to a short fixed path (e.g. `/tmp/x/data.txt`) so the test
   keeps meaning "a genuinely benign command is unchanged", and add the
   companion documented-bias golden (§2 generic pos path row) pinning that
   token-shaped path segments redact.
6. **Cross-sink check**: one telegram-shaped row in `livelog_redact_test.go`.
7. **Bench**: `BenchmarkScannerNoMatch` / `Throughput` / `Chunked` before vs
   after, recorded in the commit message. Acceptance: NoMatch ≤ +10%;
   keyword-dense/Throughput ≤ +35% (measured expectation: +2–8% and ≤ +33%,
   median ≈ +19%).

## 4. Doc edits

1. `docs/redaction-architecture.md`: modes §(:55-56) — standard now includes
   the bounded generic net (3-class + ssh-line veto + entropy ≥ 3.5, ≥ 32
   chars); strike ":108 no free-floating entropy" absolute; ":110" exclusions
   → unguarded gitleaks entropy rules stay excluded, the bounded net shipped
   2026-07 after a live missed-secret report; ":204" step 3 no longer
   "(thorough mode only)"; Rule struct comment ":89"; dated changelog entry.
2. `docs/FUTURE.md`: thorough-mode entry — promotion condition (:133a) FIRED
   2026-07-02; standard got the bounded net + live `Rule.Entropy`; thorough's
   remaining scope = decode depth 3 + looser gates (1/2-class candidates,
   lower floors). Limitation #8 softened (hex-shaped custom secrets remain
   invisible unless name-anchored).
3. `src/redact/rules/gitleaks/PROVENANCE.md`: exclusions stand; note the
   criterion is now "entropy without the three-guard gate"; cross-ref the
   native net.
4. `docs/ROADMAP.md`: mark the P1-B "default-deny output-value redaction" item
   SHIPPED with date + one-liner; leave a residual note (bare hex / <32-char
   tokens) and cross-ref the Aho-Corasick perf item.

## 5. Build order (verify gate after each phase: `go build ./... && go vet ./... && go test -race ./...`)

1. **Engine**: `passesSecretGate` + helpers + `Rule.Entropy` consult +
   `scanGenericRuns` + step-3 wiring, with unit tests (gate table, stitch
   table, generic table, dedup interplay, nil-rules contract) — TDD.
2. **Rules**: 2a/2b/2c/2d + goldens + dual-polarity extensions. Expect
   existing-fixture fallout (writer/scanner corpora may contain qualifying
   runs) — resolve each as either a legitimate new redaction (update
   expectation, justify in the diff) or a real FP (fix the gate/thresholds).
3. **Acceptance + sweeps + livelog row + bench before/after.**
4. **Docs.**
5. Whole-suite verify, `make preflight`, PII audit, push, local deploy
   (MCP + signer restart), then the live-host acceptance run per the operator
   spec (gate redeploy on the target box is an open operational step — see
   below).

## 6. Deliberate trades (operator-visible, test-pinned)

- **Bare lowercase-hex secrets stay unredacted** (git SHAs / digests /
  checksums are THE dominant benign ops class; the no-veto ablation row shows
  a 30-FP explosion). Hex IS caught when name-anchored or exactly shaped
  (zoho). Both proposals converged on this independently.
- Bare tokens < 32 chars with no name/prefix anchor are missed (floor).
- `$`-bearing unquoted assignment values remain excluded (protects `$VAR`
  refs in approval display); the net catches their ≥32 high-entropy tail.
- `DESKTOP_SESSION`-class over-redaction accepted (2 lines per env dump).
- Random base64 blobs ≥ 32 (certs, `base64 file` output) redact —
  redact-on-doubt by mandate; `reveal=true` is the operator escape hatch.
- **Token-shaped path segments redact** (≥32-char mixed-case+digit segments:
  Go `t.TempDir()` names, some generated container/cache names). In the
  approval display a human may see `rm -rf /tmp/[SSHGATE_REDACTED …]/x` and
  should use `reveal=true` (or a shorter path) if exact-path verification
  matters. The alternative — a `/`-neighbour veto — was REJECTED because it
  leaks real after-slash secrets (Discord webhook tokens are a 68-char
  3-class run immediately after `/`). Lowercase-hex and lowercase-alnum
  path hashes (go-build cache, k8s pod names, nix) do NOT redact (2-class).
- The ssh-line veto keeps the GENERIC net off pubkey lines; it does NOT make
  `cat authorized_keys` clean overall — the pre-existing
  `gitleaks-twitter-bearer` rule already redacts `AAAA…` ed25519/rsa bodies.
- Keyword-dense output pays ≈ +19% median scan cost (worst measured +33%);
  the keyword-free common case pays +2–10% (two independent measurements:
  +2–8% and +8–10% on a noisier box — hold the ≤ +10% gate). The
  Aho-Corasick roadmap item is the structural fix.
- Sink (a) lags on live servers until each remote gate binary is replaced
  (`SSHGATE_UPDATE` is an unimplemented stub; today's path is
  `revoke_server` → re-paste pubkey → `sshgate add`). The live acceptance
  test requires a gate redeploy on at least the migration target box —
  operator decision on the mechanism.
