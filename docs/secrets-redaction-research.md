# Secret-redaction research

Survey of the state-of-the-art for redacting secrets/keys from output streams
before they reach a downstream consumer (an agent, an LLM, a logger).

> **Dated research.** This survey was written in mid-2026, before SSHGate's
> redactor was built. Tool features, vendor offerings, issue states and
> benchmark numbers below are as reported then and may have changed since.
> Most of the document is a general landscape scan. Two parts apply it to
> SSHGate's own case: "Recommendation (industry-consensus reading)" and
> "Recommendations for an SSH-output redactor" at the end. The design that
> came out of it, and what is actually built, is in
> [`redaction-architecture.md`](redaction-architecture.md). Example tokens
> such as `[REDACTED:abc123de]` here are generic; SSHGate's real marker is
> `[SSHGATE_REDACTED key=<8hex>]`.

## Summary

**Top 6 detection tools surveyed in depth**
1. Gitleaks (Go, OSS) — regex + Shannon entropy, the de-facto OSS baseline.
2. TruffleHog (Go, OSS) — regex + entropy + live API verification ("verified" secrets).
3. detect-secrets (Python, OSS, Yelp) — pluggable per-secret-type detectors + baseline workflow.
4. GitHub secret scanning (managed) — 200+ partner-registered patterns, push protection.
5. GitGuardian / ggshield (commercial + OSS CLI) — 500+ secret types, post-validation rules.
6. AWS CodeGuru Secrets Detector — ML-based semantic analysis over code + config.

Honourable mentions: **Betterleaks** (BPE-token-efficiency replacement for entropy, by
Gitleaks's original author) and **Nosey Parker** (Praetorian, ML-augmented).

**Top 4 streaming-redaction / LLM-input scrubbing tools**
1. Microsoft Presidio (+ PII Shield proxy) — pluggable analyzer/anonymizer/deanonymizer.
2. LLM Guard (Protect AI) — 15 input + 20 output scanners; the `Secrets` scanner wraps detect-secrets.
3. LiteLLM `hide-secrets` guardrail — proxy-mode; wraps detect-secrets too.
4. Datadog Sensitive Data Scanner (Observability Pipelines) — stream-based, PCRE rules, 90+ OOTB patterns.

HashiCorp Vault audit-log HMAC-SHA256 hashing is the canonical reference for
"log the request but hide the secret while keeping correlation."

**Best-practice mechanisms found**
- **Hybrid detection**: regex for known formats + entropy (or BPE token-efficiency) for unknown high-randomness strings + keyword pre-filters + (optional) live verification.
- **Streaming with overlap window**: process input in chunks but keep a `maxMatchLen` sliding overlap so multi-chunk secrets aren't split. Gitleaks shipped `StreamDetectReader` (PR #1760) precisely for this; `replacestream`/`stream-snitch` use the same idiom.
- **HMAC-SHA256 with per-session salt** as the redaction map: the same plaintext → same token *within a session*, but **never reversible** and not correlatable across sessions. This is what Vault audit devices do by default.
- **Pseudonymisation with restorable mapping** when the consumer needs the real value back (Presidio, prompt-sentinel, LiteLLM): replace with `<SECRET_1>` placeholder, hold the mapping in a session-scoped store, restore on the way out.
- **Defence in depth**: redaction at the proxy plus content-policy at the model boundary. At the time of the survey, both an open Claude Code issue (#29434) and Microsoft (PII Shield) pointed to redacting *before* the LLM ever sees the bytes.

**Notable evasions / known failure modes**
- **Base64 / hex / URL-encoded secrets** bypass nearly all entropy-based scanners because the encoded form has different randomness signature. Betterleaks adds recursive decoding; almost nothing else does.
- **Whitespace and newline insertion inside long secrets** (e.g. PEM blocks reformatted) breaks single-line regexes.
- **Multi-line / chunk-boundary** secrets — naive streaming detectors miss tokens that straddle a buffer boundary.
- **Verification API throttling** in TruffleHog: when the provider rate-limits, "unverified" candidates get silently dropped (or marked unverified and ignored by default).
- **Generic high-entropy false positives**: UUIDs, hashes, minified JS, base64 payloads tokenize *efficiently* under BPE but trip Shannon-entropy thresholds. This is the dominant FP class for gitleaks and detect-secrets.

**Industry consensus (one sentence)**
Hybrid (regex + keyword + entropy/BPE) detection is the floor; HMAC-SHA256 with a
per-session salt is the consensus for redaction-with-correlation; for LLM
contexts specifically, a proxy/middleware that replaces secrets with placeholders
*before* the model sees them — and optionally restores them on the way out — is
the emerging standard (Presidio, LLM Guard, LiteLLM, PII Shield).

---

## Detection tools (top 6)

### Tool: Gitleaks

- **What it does**: CLI scanner for git repos, directories, and stdin. Default-rule
  base covers ~160+ secret types as of 2025–26.
- **Detection mechanism**: TOML-defined regex rules + Shannon entropy on a specific
  regex capture group + per-rule keyword pre-filter to reduce work.
- **Rule format**: TOML. Each rule has `id`, `description`, `regex` (Go RE2),
  optional `entropy` (float threshold, typically ~3.5) + `secretGroup` (which
  regex capture-group to entropy-check), `keywords` (list of cheap substring
  pre-filters), and `allowlists` (regex/path/stop-word exclusions). Custom rules
  are first-class; users routinely ship `.gitleaks.toml`.
- **FPR / FNR**: Independent benchmark (arxiv 2307.00714) found Gitleaks
  ~46% precision and ~88% recall on a 818-repo / 97k-secret dataset — the
  highest recall of the open-source tools but a notable FP rate driven by
  generic entropy rules. Betterleaks's own benchmark (CredData) puts entropy-only
  recall at 70.4%.
- **Streaming-capable**: Yes via `detect --pipe` or `gitleaks stdin`. Historically
  it buffered the whole stdin before reporting (issue #1759); PR #1760 added
  `StreamDetectReader` that chunks the io.Reader and emits findings via a
  results channel, with sliding-window overlap to catch boundary-spanning
  secrets.
- **Redaction output**: Gitleaks **finds**; it does not redact. Output is
  JSON/CSV/SARIF describing line, commit, fingerprint, and rule id. A
  downstream consumer must apply the redaction itself.
- **Custom rule authoring**: TOML files; new rule = 3-5 lines. Good developer ergonomics.
- **Known evasions**: base64-encoded secrets, secrets split by newlines, secrets
  that fall below entropy threshold (short JWT-like tokens), and any string
  that doesn't match a known pattern *and* doesn't trip generic entropy.
- **Source**: <https://github.com/gitleaks/gitleaks>,
  <https://gitleaks.org/how-gitleaks-works-deep-dive-into-secret-detection-scanning-engine-and-security-automation/>,
  <https://deepwiki.com/gitleaks/gitleaks/4-rule-system>,
  <https://github.com/gitleaks/gitleaks/pull/1760>.

### Tool: TruffleHog

- **What it does**: Detects, **verifies** (calls the real service API), and
  analyzes leaked credentials. 800+ supported secret types via per-service
  detectors compiled into the binary.
- **Detection mechanism**: Two-phase. Phase 1 — regex + entropy + keyword
  pre-filter to find candidates. Phase 2 — type-specific verifier calls the
  provider API (e.g. `s3.HeadBucket`, `slack.AuthTest`) and reports `verified=true`
  only on a 200/auth-success.
- **Rule format**: Built-in detectors are Go code (one package per service).
  Custom detectors are declared in `config.yaml` (`detectors:` list with
  `name`, `keywords[]`, `regex{}`, `verify[]`, plus validators like
  `contains_digit`, `contains_lowercase`, exclude_regexes_match).
- **FPR / FNR**: Verified mode → near-zero FPR (only live secrets surface).
  Recall from the arxiv study: ~52% (lower than Gitleaks because verification
  drops anything the API can't confirm — expired secrets, scoped tokens, etc.).
- **Streaming-capable**: Yes, has dedicated `stdin` and `syslog` subcommands.
  `--no-verification` flag speeds it up for real-time log scanning where
  network round-trips to provider APIs are too expensive.
- **Redaction output**: Like gitleaks, it **finds**, doesn't redact. JSON output.
- **Custom rule authoring**: YAML for "custom" detectors; native Go for full
  detectors with verifiers.
- **Known evasions**: Verification can be defeated by ephemeral / one-time
  secrets that were valid at leak time but no longer accept auth. Rate-limited
  APIs cause silent skips. Base64-encoded secrets evade the same way they do
  with Gitleaks.
- **Source**: <https://github.com/trufflesecurity/trufflehog>,
  <https://trufflesecurity.com/blog/how-trufflehog-verifies-secrets>,
  <https://docs.trufflesecurity.com/custom-detectors>.

### Tool: detect-secrets (Yelp)

- **What it does**: Python library + CLI focused on baseline-driven secret
  prevention. The model: scan once → write `.secrets.baseline` → on every
  re-scan only fail on *new* secrets.
- **Detection mechanism**: **Plugin per secret type**. 27 built-in detectors
  including `AWSKeyDetector`, `GitHubTokenDetector`, `PrivateKeyDetector`,
  `JwtTokenDetector`, `Base64HighEntropyString`, `HexHighEntropyString`,
  `KeywordDetector`, `BasicAuthDetector`, etc. Each detector returns `(line,
  secret)` tuples.
- **Rule format**: Python classes. New detectors inherit from
  `detect_secrets.plugins.base.BasePlugin` (full custom) or
  `detect_secrets.plugins.base.RegexBasedDetector` (just a regex). `basic_auth.py`
  is the canonical example. Custom plugins can be loaded with `-p PLUGIN`.
- **FPR / FNR**: Lowest FP profile among the OSS three when used with its
  baseline workflow (the user *audits* every initial finding once, marking
  false positives in the baseline). Recall similar to Gitleaks for the
  detectors it ships.
- **Streaming-capable**: Designed for file/dir scanning, not optimized for
  streaming. Used as the *engine* inside LLM Guard and LiteLLM, which feed
  it bounded strings.
- **Redaction output**: Doesn't redact; produces an audit JSON. The audit
  helper walks findings interactively (`detect-secrets audit`) for FP labeling.
- **Custom rule authoring**: Excellent — Pythonic, well-documented at
  <https://github.com/Yelp/detect-secrets/blob/master/docs/plugins.md>.
- **Known evasions**: Same entropy class (base64-wrapped secrets), plus any
  secret type with no matching plugin class will only catch via the generic
  entropy plugins.
- **Source**: <https://github.com/Yelp/detect-secrets>,
  <https://engineeringblog.yelp.com/2018/06/yelps-secret-detector.html>.

### Tool: GitHub secret scanning

- **What it does**: Server-side scanning of public/private repos for 200+
  partner-registered secret types. **Push protection** blocks pushes that
  contain matched, high-confidence patterns before they hit the repo.
- **Detection mechanism**: Curated regex patterns supplied by token-issuing
  partners (AWS, Google, Stripe, Cloudflare, Figma, GCP, Langchain, OpenVSX,
  PostHog, etc.). Many include validity checks (GitHub calls the partner's
  endpoint to confirm the token is live).
- **Rule format**: Not user-editable. The pattern list is published at
  <https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns>
  but you cannot add your own (Advanced Security tier allows *custom patterns*
  on a per-org basis — regex with `Secret format`, `Before secret`, `After secret`
  context anchors).
- **FPR / FNR**: arxiv 2307.00714 found 75% precision — best of the studied
  tools — at the cost of partial coverage (it only sees what partners have
  registered).
- **Streaming-capable**: N/A — server-side scan of git history and pushed refs.
  Push-protection runs at push time on the diff.
- **Redaction output**: Alerts + push refusal. No content rewriting.
- **Known evasions**: Anything not from a partner-registered service; legacy
  token versions (push protection deliberately covers only newest versions to
  minimize FPs).
- **Source**: <https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns>,
  <https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection>.

### Tool: GitGuardian / ggshield

- **What it does**: Commercial secret detection platform with an OSS CLI
  (`ggshield`). Claims 500+ secret types and 317 published "validity checks"
  (post-detection filters).
- **Detection mechanism**: Layered: regex pattern → entropy gate → contextual
  validation that examines surrounding code (variable name, file path, file
  type) → optional live validity check.
- **Rule format**: Server-side, not directly user-editable; users can add
  ignore rules via `.gitguardian.yml` and offer "custom detector" creation
  through the SaaS UI. Pre-commit integration is the canonical local entry
  point.
- **FPR / FNR**: Vendor-published numbers only; the multi-stage validation
  pipeline is the explicit FP-reduction strategy.
- **Streaming-capable**: ggshield CLI takes files, paths, or `--scan` input;
  not a streaming pipe.
- **Redaction output**: Reports SHA256 fingerprints of secrets in output so
  they can be added to ignore lists without storing the plaintext anywhere.
- **Known evasions**: Same general class; vendor opacity means evasion
  techniques are less publicly documented.
- **Source**: <https://github.com/gitguardian/ggshield>,
  <https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/quick_start>.

### Tool: AWS CodeGuru Secrets Detector

- **What it does**: Repo-attached managed service that flags hardcoded secrets
  in Java and Python source + common config files, with a click-through to
  rotate them into AWS Secrets Manager.
- **Detection mechanism**: Machine-learning + automated reasoning over AST
  context, not just regex. Marketed as semantic — the model considers what the
  variable is being used for, not just whether a string looks random.
- **Rule format**: Not user-editable.
- **FPR / FNR**: Not publicly benchmarked. AWS-internal numbers only.
- **Streaming-capable**: No — repo-bound, batch.
- **Redaction output**: Code-review comments + remediation guidance.
- **Known evasions**: Languages outside Java/Python; secrets in unsupported
  config formats.
- **Source**: <https://aws.amazon.com/blogs/aws/codeguru-reviewer-secrets-detector-identify-hardcoded-secrets/>.

### Honourable mention: Betterleaks (2026)

- Built by the original author of Gitleaks. Same TOML rule model, but replaces
  Shannon entropy with **BPE token-efficiency** scoring using the `cl100k_base`
  tokenizer.
- Logic: real secrets generated from CSPRNGs tokenize *inefficiently* (many
  short tokens), while UUIDs, hashes, base64 payloads — the entropy-FP class —
  tokenize efficiently because the trained BPE model has seen them.
- Reported benchmark on CredData: **98.6% recall** vs 70.4% (entropy-only),
  91.28% precision in best-config, F1 0.8922.
- Adds recursive base64/hex/URL decoding before scanning, closing one of the
  longest-standing Gitleaks evasions.
- Source: <https://blog.canadianwebhosting.com/betterleaks-gitleaks-secret-scanner-bpe/>,
  <https://www.aikido.dev/blog/token-efficiency-secrets-scan>,
  <https://github.com/betterleaks/betterleaks>.

### Honourable mention: Nosey Parker (Praetorian)

- Rust CLI; transformer LLM fine-tuned on ~10k labeled real secrets.
- Reported 92.4% precision regex-only, 98.5% precision with ML filtering.
- More accurate than truffleHog3 even with the latter's noisy entropy mode.
- Source: <https://github.com/praetorian-inc/noseyparker>.

---

## Streaming-redaction prior art

### HashiCorp Vault audit-log redaction

- Default behaviour: every audit-device log line passes through an
  **HMAC-SHA256** transformation keyed by a per-device salt. All string fields
  in the request/response (tokens, paths, secret values) are emitted as
  `hmac-sha256:<base64>` strings; integers and booleans are not hashed.
- Headers are *not* hashed by default — operators must add them to the
  hash-list explicitly.
- Recovery: an admin can call `POST /sys/audit-hash/:path` with the plaintext
  to reproduce the hash and confirm whether a given known value appears in
  the logs. There is **no inverse** without the plaintext.
- `log_raw` toggle disables hashing entirely; explicitly forbidden in
  production by the docs.
- Source: <https://developer.hashicorp.com/vault/docs/audit>,
  <https://support.hashicorp.com/hc/en-us/articles/8216361599763-Vault-Audit-Log-3-methods-to-un-Hash>,
  <https://developer.hashicorp.com/vault/docs/audit/best-practices>.

### Microsoft Presidio + PII Shield

- Two-component architecture: **Analyzer** (NER + regex + checksum + context
  recognisers, with optional spaCy/transformers backends) → **Anonymizer**
  (operator chain: `replace`, `mask`, `hash`, `redact`, `encrypt`).
- Deanonymizer node lets you reverse pseudonymisation when the placeholder
  encodes a reversible operator (e.g. AES with stored key).
- **PII Shield** (Microsoft community blog, 2026) wraps Presidio as an HTTP
  privacy proxy: app sends text → proxy returns redacted text + mapping →
  app forwards redacted text to LLM → on response, proxy restores
  placeholders before returning to user. The LLM never sees raw PII.
- Source: <https://github.com/microsoft/presidio>,
  <https://microsoft.github.io/presidio/anonymizer/>,
  <https://techcommunity.microsoft.com/blog/azuredevcommunityblog/introducing-pii-shield-a-privacy-proxy-for-every-llm-call/4514726>.

### LLM Guard (Protect AI)

- 15 input scanners + 20 output scanners. **The `Secrets` input scanner is a
  thin wrapper around Yelp `detect-secrets`**. The `Anonymize` scanner wraps
  Presidio.
- Deployable as a Python library or a standalone API server. Integrated with
  LangChain, LlamaIndex, LiteLLM, Azure OpenAI, Bedrock.
- Source: <https://protectai.com/llm-guard>,
  <https://github.com/protectai/llm-guard>,
  <https://github.com/protectai/llm-guard/blob/main/docs/input_scanners/secrets.md>.

### LiteLLM `hide-secrets` guardrail

- Proxy-mode-only feature in LiteLLM (an LLM API gateway). Set
  `guardrails: [hide-secrets]` and the proxy runs `detect-secrets` against
  every incoming prompt; matched substrings are replaced with `[REDACTED]`.
- Per-API-key toggle so different consumers get different policies.
- Source: <https://docs.litellm.ai/docs/proxy/guardrails/secret_detection>.

### Datadog Sensitive Data Scanner / Observability Pipelines

- **Stream-based**: runs inside the Observability Pipelines Worker on the
  user's infra. Scans events as they pass through, not as a batch.
- PCRE regex rules (no lookaround / backref support). 90+ OOTB rules cover
  PII + PCI; custom rules editable per-pipeline.
- Match-action options: **Redact** (replace with literal token), **Partially
  redact** (mask a slice — e.g. show last 4 of card), **Hash** (replace with
  non-reversible unique identifier — the building block for
  redact-with-correlation).
- Two configuration surfaces: Agent-level `log_processing_rules` (mask_sequences
  Go regex transforms) and platform-level Sensitive Data Scanner Processor.
- Source: <https://docs.datadoghq.com/observability_pipelines/processors/sensitive_data_scanner/>,
  <https://docs.datadoghq.com/agent/logs/advanced_log_collection/>.

### Splunk SEDCMD anonymisation

- `props.conf` SEDCMD entries run sed-style `s/regex/replacement/g` on each
  event at ingest. The classic example masks credit-card numbers to
  `XXXX-XXXX-XXXX-NNNN`.
- **Limitation**: no multi-line mode. Multi-line secrets need two SEDCMDs
  (one to flatten newlines, one to replace) — exemplary of the boundary-spanning
  problem.
- Source: <https://docs.splunk.com/Documentation/Splunk/latest/Data/Anonymizedata>.

### Vector / Fluent Bit / fluentd

- **Vector** (Datadog OSS observability pipeline) — `redact()` function in
  VRL takes filters (`us_social_security_number`, custom regex). Designed for
  in-stream redaction during transport.
- **Fluent Bit** — Nightfall filter is the canonical OSS option for streaming
  secret/PII redaction; also `modify`/`rewrite_tag` for regex-based field
  replacement.
- Source: <https://vector.dev/docs/reference/vrl/functions/>,
  <https://docs.fluentbit.io/manual/data-pipeline/filters/nightfall>.

### Cloudflare One DLP (R2-adjacent) — out-of-band scanner

- Serverless architecture: a customer-cloud-resident Controller pulls policy
  from Cloudflare, a Crawler enumerates objects, a Scanner streams object
  contents through the DLP engine. Sensitive Data Scanner over R2 is on the
  roadmap; currently AWS S3 / GCS first-party.
- Streams object contents through the DLP engine — confirms the streaming
  approach is the standard cloud-DLP pattern.
- Source: <https://blog.cloudflare.com/scan-cloud-dlp-with-casb/>,
  <https://developers.cloudflare.com/cloudflare-one/data-loss-prevention/dlp-settings/>.

### GCP Cloud DLP / Sensitive Data Protection

- 200+ built-in **infoTypes**. De-identification operators:
  - `cryptoReplaceFfxFpe` — **Format-Preserving Encryption** (NIST FF1)
    preserves alphabet + length.
  - `cryptoDeterministic` — **AES-SIV** with a tweak; same plaintext → same
    ciphertext (deterministic, reversible with key).
  - `cryptoHash` — HMAC-SHA256 non-reversible (the Vault model).
- Keys may be provided inline or wrapped via Cloud KMS for envelope encryption.
- Source: <https://cloud.google.com/dlp/docs/pseudonymization>.

### Kubernetes secret mount file modes

- `defaultMode: 0400` is the documented secure pattern for projected secret
  volumes. The pattern is *signaling sensitivity through file mode*. Default
  is 0644 (world-readable) which is widely considered too permissive.
- Source: <https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/>.

### SELinux / AppArmor file labelling

- **SELinux** assigns a label (user:role:type[:sensitivity]) to every file.
  The MLS policy explicitly carries sensitivity labels designed for classified
  data. There is no direct cross-tool API a redactor could query short of
  asking the kernel via `getxattr("security.selinux", ...)`.
- **AppArmor** uses path-based profiles, not labels — no per-file
  sensitivity signal.
- These are **access-control** policies, not content-classification ones.
  Useful only as a hint ("this file's SELinux type is `etc_t` with a
  sensitivity level — treat its content as sensitive by default") rather than
  as a redaction primitive.
- Source: <https://natnat1.medium.com/selinux-vs-apparmor-ee8178927bc6>,
  <https://www.computernetworkingnotes.com/linux-tutorials/selinux-and-apparmor-differences-and-terminology.html>.

### Streaming regex / buffer-boundary handling

The dominant pattern across `stream-buffer-replace`, `replacestream`, and
Gitleaks' new `StreamDetectReader`:

1. Read chunk N.
2. Concatenate `tail(maxMatchLen)` from chunk N-1 in front of it.
3. Run regex/match on the combined buffer.
4. Emit through everything up to `len(buffer) - maxMatchLen`.
5. Carry the tail forward as the overlap for N+1.

`maxMatchLen` is the longest plausible secret you can detect. PEM-encoded
private keys (~1600 chars for RSA 2048) are the practical worst case; in
practice 4KB overlap covers everything that isn't a multi-MB blob.

- Source: <https://github.com/neonadventures/stream-buffer-replace>,
  <https://github.com/eugeneware/replacestream>,
  <https://github.com/gitleaks/gitleaks/pull/1760>.

---

## Stable-identifier mapping techniques

| Technique | Reversible? | Cross-session correlation? | Within-session correlation? | Output shape | Who uses it |
|---|---|---|---|---|---|
| Static mask (`[REDACTED]`, `***`) | No | No | No (lossy) | Constant string | LiteLLM, basic loggers |
| Static-mask + index (`[SECRET_1]`, `[SECRET_2]`) | No (without map) | No | Yes — but only because the map is held in memory | Sequential placeholder | Presidio, prompt-sentinel, PII Shield |
| Truncated SHA256 / SHA256 fingerprint | No | **Yes** (collision-free in practice) | Yes | Short hex | ggshield (ignore lists), Gitleaks (finding fingerprint) |
| HMAC-SHA256 with secret salt | No | Only if salt persists | Yes if salt persists; **No if salt rotates per session** | Long base64 | **Vault audit logs**; consensus default |
| Format-preserving encryption (FPE, FF1/FF3) | Yes (with key) | Yes (deterministic) | Yes | Same alphabet+length as input | GCP DLP, Thales CipherTrust |
| Vaulted tokenisation | Yes (vault lookup) | Yes | Yes | Random surrogate | PCI environments |
| Vaultless tokenisation | Yes (algorithm + key) | Yes | Yes | Random-looking surrogate | Thales, Fortanix |
| Deterministic encryption (AES-SIV) | Yes | Yes (deterministic) | Yes | Base64 ciphertext | GCP DLP cryptoDeterministic |

### Detailed pros/cons

**HMAC-SHA256 with per-session salt**
- **How it works**: `token = HMAC-SHA256(session_salt, plaintext)[:n]`. The
  agent sees a stable, opaque blob. Same secret appearing twice in the same
  session → same token. New session → fresh salt → different token, so the
  agent can't accumulate long-term knowledge.
- **Pros**: non-reversible; per-session unlinkability; one of the most-studied
  primitives (Vault has run this in prod since ~2015); fast (single hash);
  no state outside the salt; works for arbitrary lengths.
- **Cons**: not reversible (the redactor itself can't recover plaintext for
  debugging); collision-free only at full length — heavy truncation can
  collide; needs care to rotate salt at session boundary and never log it.
- **Verdict**: consensus best-practice for "I want correlation without retention."

**Hash truncation (SHA256[0:8])**
- **Pros**: simplest possible; deterministic; no key management.
- **Cons**: short truncation is brute-forceable if the attacker can guess the
  plaintext space (8 hex = 32 bits → trivial for an attacker with a
  passwords-list). For high-entropy secrets it's fine, for low-entropy ones
  (e.g. short common passwords) it's a privacy leak.
- **Verdict**: acceptable for high-entropy secrets *only*. Inferior to HMAC for
  the general case because the attacker doesn't need a key. (SSHGate's marker
  is also truncated to 32 bits, but it is a keyed HMAC: guessing a plaintext
  needs the per-session salt, which never leaves the gate process.)

**Format-preserving encryption (FPE)**
- **Pros**: output looks like input — preserves downstream schema validation,
  string-length checks, regex flows. Reversible with the key.
- **Cons**: heavyweight; needs key management infra; subtle implementation
  bugs (FF1/FF3 had multiple disclosed weaknesses); reversibility is a
  liability if you don't want the agent (or anyone with the cipher output)
  to ever recover the plaintext.
- **Verdict**: overkill for an agent-output redactor. Designed for compliance
  workflows that *need* the original value back (payment processing).

**Vaulted tokenisation**
- **Pros**: bullet-proof — surrogate token has zero relationship to plaintext.
- **Cons**: needs a vault. Operational overhead. Latency. Stateful.
- **Verdict**: overkill.

**Placeholder + restoration map (Presidio/prompt-sentinel)**
- **How it works**: replace each occurrence with `<SECRET_K>` where K is a
  per-occurrence counter; hold the `{<SECRET_K>: plaintext}` map in a
  session-scoped store; restore on the way back out (i.e. when the LLM's
  output is forwarded to a downstream consumer who is allowed to see the
  plaintext, like the original user).
- **Pros**: full round-trip — the consumer who initiated the request still
  gets the real secret in the final response; intermediate LLM never sees it.
- **Cons**: requires bidirectional flow; if the agent is the *terminal*
  consumer (no upstream to restore to), this collapses to HMAC + map; you must
  protect the map.
- **Verdict**: best when the redactor sits *between* user and LLM and needs to
  restore. Less useful when the redactor sits *between LLM and tool output*
  (the LLM is the terminal consumer and shouldn't see plaintext anyway).

### Recommendation (industry-consensus reading)

For an "agent-output redactor" where the agent is the consumer and the user
is the operator who originally typed `ssh remote env`:

- The redactor sits between the remote process and the agent.
- The agent is the *terminal* consumer of the bytes; we do not want to restore
  plaintext for the agent.
- The operator may want to know "is the secret the agent just saw the same as
  the one it saw two commands ago?" — within-session correlation only.

The consensus primitive is **HMAC-SHA256 with a per-session salt, output as a
short stable token like `[REDACTED:abc123de]`** (SSHGate's form is
`[SSHGATE_REDACTED key=abc123de]`). This is essentially the
Vault audit-log model. It gives within-session correlation, no cross-session
linkability, no reversibility, and tiny overhead.

---

## File-mode-based heuristics — prior art

There is **little explicit prior art** for "use file mode 0400/0600 as a
sensitivity signal in a redactor." The closest analogues:

1. **Kubernetes secret mounts** — 0400 is the *recommended* permission, but it
   is a *convention*, not a signal that any tool consumes.
2. **SELinux MLS** — sensitivity labels on files are explicit and queryable
   via `getxattr("security.selinux", ...)`. The MLS policy is the canonical
   "this file is classified" mechanism in Linux, but is almost never deployed
   outside government/military contexts.
3. **Linux `LSM` hooks and `auditd`** — `auditd` can fire rules on access to
   specific paths or labels, useful for detection but not for content
   redaction.
4. **Container security scanners** (Datadog, Falco) — flag world-readable
   sensitive files; not used for content classification.
5. **POSIX mode bits semantics** — historically used by sysadmins as a
   *signal* ("this file is sensitive if the owner restricted reads") but not
   formalised in any redaction tool surveyed.

**Conclusion**: file-mode as sensitivity heuristic is a folk practice — common
in security operations as a manual triage signal, but not codified in any of
the surveyed redaction tools. SELinux MLS is the only formal mechanism, and
it's deployed too narrowly to call industry consensus. There is an opportunity
for novel work here: "treat content of files with `mode & 077 == 0` as
candidate-sensitive by default" is sensible and has no published precedent in
the redaction-tool space.

---

## LLM/agent-context-window redaction

As of the survey (mid-2026):

- **Anthropic** (Claude Code): no first-party redaction feature at the time. Open
  issue #29434 explicitly asks for "Mechanism to redact secrets/PII from the
  context window." Public docs recommend client-side scrubbing (Nightfall,
  Presidio) before content enters context. Enterprise plans offer Zero Data
  Retention but ZDR is about *server-side retention*, not in-context exposure.
  Source: <https://github.com/anthropics/claude-code/issues/29434>,
  <https://code.claude.com/docs/en/security>.
- **OpenAI**: no documented in-platform secret redaction; ecosystem solutions
  via LiteLLM / LLM Guard / Pangea.
- **Cloudflare AI Gateway**: Cloudflare One DLP profiles applied to AI Gateway
  traffic. PCI/PII/custom regex profiles can be set to "Block" or "Redact".
  Source: <https://developers.cloudflare.com/ai-gateway/features/dlp/>.
- **LiteLLM** `hide-secrets` guardrail — see streaming-redaction section.
- **LLM Guard** — see streaming-redaction section.
- **PII Shield** (Microsoft) — see streaming-redaction section.
- **LangChain / LlamaIndex** — no first-party scrubber; LLM Guard is the
  documented integration (LlamaIndex has a blog post co-authored with Protect
  AI). Source: <https://www.llamaindex.ai/blog/secure-rag-with-llamaindex-and-llm-guard-by-protect-ai>.
- **prompt-sentinel** (PyPI, OSS) — Python package; placeholder + restoration
  with LangChain message-type support. The closest match to "drop-in LLM
  redactor library."
- **WangYihang/llm-redactor** (GitHub) — transparent egress gateway
  specifically for LLM coding agents; redacts before egress. Architectural
  cousin of an SSH-output redactor.
  Source: <https://github.com/WangYihang/llm-redactor>.

**Synthesis**: every major vendor has either landed or is mid-flight on
"redact-before-LLM" as a first-class proxy concern, but Anthropic and OpenAI
do not provide it natively — they punt to middleware. The industry-standard
deployment is a **proxy in front of the LLM** (LiteLLM-style) running a
secret scanner over every inbound prompt and every tool result.

---

## Open questions

- Published numerical FPR comparisons specifically for *streaming* (vs batch)
  scanners on log-shaped data are scarce. Most benchmarks use repo / source
  corpora (CredData, the 818-repo arxiv set).
- No publicly available benchmark of secret scanners against **command output**
  specifically (env dumps, journalctl, docker inspect). All existing benchmarks
  use source repositories. This is a gap.
- The combination "BPE token-efficiency + recursive base64 decode + verified
  detection" (i.e. Betterleaks ideas + TruffleHog verification) has not been
  published as a single tool.
- Effectiveness of HMAC-redaction at preserving agent reasoning quality
  ("does the agent still produce useful responses when secrets are HMAC'd?")
  has no published evaluation that I could find.
- Whether `getxattr` of SELinux sensitivity labels as a redaction signal has
  been deployed anywhere — no public references found.

---

## Recommendations for an SSH-output redactor

Based on the survey, an SSH-output redactor *should* do the following. These
recommendations fed SSHGate's design; see
[`redaction-architecture.md`](redaction-architecture.md) for what was decided
and what is built.

1. **Layer detection**: regex over a curated rule set (gitleaks's TOML rule
   base or detect-secrets's plugin set is the obvious starting library) +
   keyword pre-filter + entropy *or* (preferably) BPE token-efficiency for the
   unknown-secret tail. Live verification (TruffleHog-style) is impractical
   in the latency budget of an interactive shell.
2. **Stream with a sliding overlap** sized to the longest plausible secret
   (~4KB covers PEM blocks; pad to taste). Don't buffer the whole command
   output. Gitleaks's `StreamDetectReader` is the reference implementation.
3. **Redact via HMAC-SHA256 with a per-session salt**, output as a short
   stable token (e.g. `[REDACTED:abc123de]`; SSHGate uses
   `[SSHGATE_REDACTED key=abc123de]`). This is the Vault model. It
   preserves within-session correlation without leaking across sessions and
   is non-reversible.
4. **Never** ship a "log raw" mode that disables redaction (Vault's docs are
   emphatic; it's a footgun). (SSHGate has no such mode. Its one bypass is a
   per-command secret reveal that a human approves each time.)
5. **Stay opinionated about what you do NOT do**: don't try format-preserving
   encryption (overkill, reversible-by-design), don't try ML semantic analysis
   in the hot path (latency), don't try restoration mapping (the agent is the
   terminal consumer — there's nothing to restore to).
6. **Allow custom rules** in the same format as your base library, because
   no published rule set covers every shop's internal secret formats.
7. **Treat file-mode 0400/0600 hits as a categorical signal** to redact the
   file's entire contents, not just regex matches — this is novel but
   conservatively safe and has reasonable folk-precedent.
8. **Avoid the "verified secret" trap**: for an interactive shell, false
   negatives are worse than false positives. Bias the threshold toward
   over-redaction; the human (or a logged unredacted side-channel for the
   operator only) can recover what was lost.

---

## Source links (consolidated)

- Gitleaks: <https://github.com/gitleaks/gitleaks>, <https://gitleaks.org/how-gitleaks-works-deep-dive-into-secret-detection-scanning-engine-and-security-automation/>, <https://deepwiki.com/gitleaks/gitleaks/4-rule-system>, <https://github.com/gitleaks/gitleaks/issues/1759>, <https://github.com/gitleaks/gitleaks/pull/1760>
- TruffleHog: <https://github.com/trufflesecurity/trufflehog>, <https://trufflesecurity.com/blog/how-trufflehog-verifies-secrets>, <https://docs.trufflesecurity.com/custom-detectors>, <https://docs.trufflesecurity.com/running-the-scanner>
- detect-secrets: <https://github.com/Yelp/detect-secrets>, <https://github.com/Yelp/detect-secrets/blob/master/docs/plugins.md>, <https://engineeringblog.yelp.com/2018/06/yelps-secret-detector.html>
- GitHub secret scanning: <https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns>, <https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection>
- GitGuardian / ggshield: <https://github.com/gitguardian/ggshield>, <https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/quick_start>
- AWS CodeGuru: <https://aws.amazon.com/blogs/aws/codeguru-reviewer-secrets-detector-identify-hardcoded-secrets/>
- Betterleaks: <https://blog.canadianwebhosting.com/betterleaks-gitleaks-secret-scanner-bpe/>, <https://lookingatcomputer.substack.com/p/regex-is-almost-all-you-need>, <https://www.aikido.dev/blog/token-efficiency-secrets-scan>, <https://github.com/betterleaks/betterleaks>
- Nosey Parker: <https://github.com/praetorian-inc/noseyparker>, <https://www.praetorian.com/blog/nosey-parker-ai-secrets-scanner-release/>
- Vault audit log: <https://developer.hashicorp.com/vault/docs/audit>, <https://support.hashicorp.com/hc/en-us/articles/8216361599763-Vault-Audit-Log-3-methods-to-un-Hash>, <https://developer.hashicorp.com/vault/docs/audit/best-practices>
- Presidio: <https://github.com/microsoft/presidio>, <https://microsoft.github.io/presidio/anonymizer/>
- PII Shield: <https://techcommunity.microsoft.com/blog/azuredevcommunityblog/introducing-pii-shield-a-privacy-proxy-for-every-llm-call/4514726>
- LLM Guard: <https://protectai.com/llm-guard>, <https://github.com/protectai/llm-guard>, <https://github.com/protectai/llm-guard/blob/main/docs/input_scanners/secrets.md>
- LiteLLM guardrail: <https://docs.litellm.ai/docs/proxy/guardrails/secret_detection>
- prompt-sentinel: <https://pypi.org/project/prompt-sentinel/>
- llm-redactor: <https://github.com/WangYihang/llm-redactor>
- Datadog Sensitive Data Scanner: <https://docs.datadoghq.com/observability_pipelines/processors/sensitive_data_scanner/>, <https://docs.datadoghq.com/agent/logs/advanced_log_collection/>, <https://docs.datadoghq.com/tracing/configure_data_security/>
- Splunk SEDCMD: <https://docs.splunk.com/Documentation/Splunk/latest/Data/Anonymizedata>
- Vector VRL: <https://vector.dev/docs/reference/vrl/functions/>
- Fluent Bit Nightfall: <https://docs.fluentbit.io/manual/data-pipeline/filters/nightfall>
- Cloudflare DLP/CASB: <https://blog.cloudflare.com/scan-cloud-dlp-with-casb/>, <https://developers.cloudflare.com/cloudflare-one/data-loss-prevention/dlp-settings/>, <https://developers.cloudflare.com/ai-gateway/features/dlp/>
- GCP Cloud DLP pseudonymisation: <https://cloud.google.com/dlp/docs/pseudonymization>
- Kubernetes secret mode: <https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/>
- SELinux / AppArmor comparison: <https://natnat1.medium.com/selinux-vs-apparmor-ee8178927bc6>
- Streaming regex (boundary-aware): <https://github.com/neonadventures/stream-buffer-replace>, <https://github.com/eugeneware/replacestream>, <https://github.com/dmotz/stream-snitch>
- HMAC-redaction for logs: <https://www.devsecopsnow.com/hmac/>, <https://andrewlock.net/redacting-sensitive-data-with-microsoft-extensions-compliance/>, <https://dev.to/aragossa/stop-leaking-api-keys-in-your-ai-agent-logs-a-go-sidecar-approach-d3>
- Anthropic Claude redaction discussion: <https://github.com/anthropics/claude-code/issues/29434>, <https://code.claude.com/docs/en/security>
- Comparative benchmark: <https://arxiv.org/abs/2307.00714>
- detect-secrets vs Gitleaks vs TruffleHog vs GitGuardian comparison: <https://devsecops.ae/secrets-scanners-comparison-2026/>, <https://rafter.so/blog/secrets/secret-scanning-tools-comparison>, <https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools>
