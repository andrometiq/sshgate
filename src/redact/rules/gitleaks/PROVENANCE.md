# Gitleaks vendored rules — provenance

## Source

- Upstream: <https://github.com/gitleaks/gitleaks>
- Reference SHA at vendor time: `c2bb20a` (2024-12 era; pulled 2026-05-19)
- Source path: `config/gitleaks.toml` and `config/rules/*.toml`

## What's vendored here

A curated subset of named-format gitleaks rules has been transcribed
into `rules.go` as Go `redact.Rule` literals. We pulled the rules
whose detection logic is purely a structurally-anchored regex —
provider-issued tokens with a fixed prefix, structural certificate
markers, and a small set of well-known SaaS API formats.

## What we explicitly did NOT vendor

The rules below were intentionally excluded from R1 because they are
either entropy-based (deferred to v1.2.1 "thorough" mode), generic
catch-alls that drive unacceptable false-positive rates on streaming
command output, or duplicates of what SSHGate-native rules already
cover:

- `generic-api-key` — entropy + keyword heuristic; ~46% precision on
  broad corpora (research §"FPR/FNR benchmarks").
- `hashicorp-tf-api-token` (legacy entropy form).
- Any rule with `entropy >= N` and no structural prefix.
- Any rule that matches every base64 blob over a length threshold.

The exclusions stand, but the exclusion criterion is now sharper: what
is excluded is entropy detection **without the three-guard gate**
(3-class content + ssh-line veto + Shannon ≥ 3.5). SSHGate ships its own
*gated* unanchored net natively as of 2026-07 — the O(n) linear
`scanGenericRuns` pass in `src/redact/scanner_generic.go` (NOT a vendored
gitleaks rule) — precisely because these upstream rules are ungated and
would explode false positives on lowercase-hex ops output. The *unguarded*
gitleaks rules above still reappear only in v1.2.1 thorough mode behind an
explicit operator toggle. See `docs/redaction-architecture.md` and
`docs/FUTURE.md`.

## How to re-pull from upstream

1. Diff `config/rules/*.toml` between this PROVENANCE SHA and current upstream HEAD.
2. For each new/changed rule, decide whether it is structurally
   anchored (vendor it) or entropy-driven (defer).
3. Transcribe the regex into Go in `rules.go`, with the rule ID
   prefixed `gitleaks-` to keep the namespace distinct from
   sshgate-native.
4. Add a positive + negative golden fixture under
   `testdata/redact/rules/` and a per-rule test.
5. Update this PROVENANCE.md with the new SHA and date.

## License

Gitleaks is MIT-licensed. We mention this only because the *patterns*
are being copied; the Go source here is our own transcription. The
SSHGate repository's license applies to the transcribed code.

## Curation notes

- We canonicalised every rule to use a leading `\b` word boundary
  rather than the upstream pattern's mixed positional anchors. This
  is to avoid the streaming-window edge case where a partial token at
  the end of the window matches a non-anchored prefix.
- Length filters (`MinLen`/`MaxLen`) were added wherever the upstream
  TOML's "secretGroup" had implicit length expectations. The
  upstream rules trust the regex; SSHGate's hot path benefits from
  pre-filtering matches too long to be the secret type.
