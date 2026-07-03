// Package sshgate is the SSHGate-native floor of named-format
// redaction rules. These are SSHGate's own contributions to Layer 1:
// patterns we observed leaking in real workloads that gitleaks does
// not cover (or covers with broader regex than we want for streaming
// log output).
//
// Add a rule here when you find a new format leaking. Each rule MUST:
//
//   - have a stable, descriptive ID (gets logged, signed via redact.why)
//   - have at least one keyword the pre-filter can use (a regex run on
//     every chunk with no pre-filter is a hot-path bug)
//   - match a structurally-anchored token, or opt into the shared entropy
//     gate via WithEntropy for a broad prefix (sk-<base62>)
//
// UNANCHORED free-floating high-entropy detection is deliberately NOT a
// rule here: it lives in the engine as the O(n) linear pass
// scanGenericRuns (src/redact/scanner_generic.go). A regex net was
// measured and rejected — the two zero-keyword regex formulations cost
// +66% and +73% per MB on BenchmarkScannerNoMatch (Go's regexp is
// NFA-only: no DFA, no literal-prefix skip), while the linear pass does
// the same work in ~+2%; a keyword-scoped regex net was rejected too
// because it silently deactivates on keyword-free buffers, leaking an
// unknown-named secret.
//
// The combined ruleset is built by src/redact/rules/gen.go; this
// file's Rules() result is one input.
package sshgate

import "github.com/karthikeyan5/sshgate/src/redact"

// Rules returns the SSHGate-native rule set. Called once at package
// initialisation by the combined generator.
func Rules() []redact.Rule {
	return []redact.Rule{
		// AWS access key — same structural prefix as gitleaks's rule,
		// but we keep our own copy so SSHGate's floor is stable even
		// when we re-vendor gitleaks.
		redact.CompileRule(
			"sshgate-aws-access-key",
			"AWS access key (AKIA/ASIA/AGPA/AROA prefix)",
			`\b((?:AKIA|ASIA|AGPA|AROA)[0-9A-Z]{16})\b`,
			[]string{"AKIA", "ASIA", "AGPA", "AROA"},
			1, 20, 20,
		),

		// GitHub personal-access tokens (classic + fine-grained + OAuth + server).
		redact.CompileRule(
			"sshgate-github-pat",
			"GitHub PAT/OAuth/server token (ghp_, gho_, ghu_, ghs_, ghr_)",
			`\b(gh[psour]_[A-Za-z0-9]{36,251})\b`,
			[]string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
			1, 40, 255,
		),

		// GitLab tokens.
		redact.CompileRule(
			"sshgate-gitlab-pat",
			"GitLab personal/project/group token (glpat-, glptt-)",
			`\b(glp(?:at|tt)-[A-Za-z0-9_\-]{20,50})\b`,
			[]string{"glpat-", "glptt-"},
			1, 26, 56,
		),

		// JWT — header.payload.sig, all three base64url. We anchor on
		// the structurally-identifiable header prefix `eyJ`. High-
		// confidence: a JWT is unmistakable, so an over-4096-char token
		// is still redacted (MaxLen is advisory here, not a drop —
		// MINOR 7).
		redact.CompileRule(
			"sshgate-jwt",
			"JSON Web Token (eyJ-prefixed three-part base64url)",
			`\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b`,
			[]string{"eyJ"},
			1, 30, 4096,
		).WithHighConfidence(),

		// HTTP Authorization: Bearer header. Token value only.
		// Upper bound is 999 (RE2 max repeat is 1000); MaxLen filter
		// extends to 1024 if a longer token slips through.
		redact.CompileRule(
			"sshgate-auth-bearer",
			"Authorization: Bearer <token>",
			`(?i)authorization:\s*bearer\s+([A-Za-z0-9_\-\.=+/]{8,999})`,
			[]string{"authorization", "bearer"},
			1, 8, 1024,
		),

		// password=foo / *_pwd=foo / passwd=foo (URL-/env-style). The
		// rule fires on the value only; common log noise like
		// "password = ****" passes through because the value-character
		// class excludes spaces and the like.
		//
		// `password`/`passwd` match bare (a `\b` before them) since they
		// are unambiguous secret keys. `pwd` is the cwd-env-var landmine:
		// bare `PWD=/home/...` and `OLDPWD=/home/...` appear in EVERY
		// `env`/`printenv` dump and must NOT have their value scrubbed, or
		// the operator goes blind to its own working directory. So `pwd`
		// only matches as a `_`/`-`-separated suffix (`DB_PWD=`,
		// `MYSQL_PWD=`); `OLDPWD` (no separator before `pwd`) and bare
		// `PWD` are deliberately excluded.
		redact.CompileRule(
			"sshgate-password-kv",
			"password=/*_pwd=/passwd= key-value (URL or env form)",
			`(?i)(?:\b(?:password|passwd)|[a-z0-9]+[_-]pwd)\s*[=:]\s*['"]?([^\s'";&,<>]{4,256})['"]?`,
			[]string{"password", "passwd", "pwd"},
			1, 4, 256,
		),

		// Slack tokens (xoxb-, xoxp-, xoxa-, xoxr-, xoxs-).
		redact.CompileRule(
			"sshgate-slack-token",
			"Slack token (xox[bparso]-...)",
			`\b(xox[bparso]-[A-Za-z0-9\-]{10,255})\b`,
			[]string{"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxo-"},
			1, 15, 255,
		),

		// Stripe live keys.
		redact.CompileRule(
			"sshgate-stripe-live",
			"Stripe live API key (sk_live_/pk_live_/rk_live_)",
			`\b([srp]k_live_[A-Za-z0-9]{24,99})\b`,
			[]string{"sk_live_", "pk_live_", "rk_live_"},
			1, 30, 110,
		),

		// Google OAuth access token (ya29.<base64>).
		redact.CompileRule(
			"sshgate-google-oauth",
			"Google OAuth access token (ya29.<payload>)",
			`\b(ya29\.[A-Za-z0-9_\-]{20,255})\b`,
			[]string{"ya29."},
			1, 25, 255,
		),

		// Azure storage AccountKey embedded in a connection string.
		redact.CompileRule(
			"sshgate-azure-account-key",
			"Azure storage AccountKey (in connection string)",
			`AccountKey=([A-Za-z0-9+/=]{40,200})`,
			[]string{"AccountKey="},
			1, 40, 200,
		),

		// --- BLOCKER 3(a): secret VALUES behind common assignment
		// shapes. The existing sshgate-password-kv rule only covers
		// password/passwd/pwd; an env dump / .env / `printenv` leaks a
		// far wider surface — *_KEY, *_TOKEN, *_SECRET, *_PASSWORD,
		// *_PASS, PGPASSWORD, etc. These rules redact the VALUE only and
		// bias toward over-redacting: some assignment values that aren't
		// truly secret will be scrubbed, which is the safe failure mode
		// for a single-tap unsigned read path.

		// Assignment of a secret-looking value to a sensitively-NAMED key.
		// Widened 2026-07 (same rule ID) to cover the shapes a production
		// multi-server run showed leaking raw: JSON-quoted keys
		// (`"botToken": "…"`), Python-dict single-quoted keys, camelCase
		// keys with no separator (`authToken:`, `apiKey:`), and the new
		// stems API_HASH / SESSION / COOKIE — plus a newline-crossing bug
		// fix. SecretGroup is #1 (the value); MinLen 4 / MaxLen 0 unchanged.
		//
		// The value class: unquoted values exclude whitespace/quotes/shell
		// metacharacters (redact one token, not the rest of the line);
		// quoted values capture through the closing quote INCLUDING the
		// quotes (so `PASSWORD="my secret"` is redacted in full while the
		// NAME and `=`/`:` survive). The `$`-exclusion in the unquoted
		// class protects `$VAR` references in the approval display.
		//
		// Name shapes (three alternation branches):
		//  1. `(?:[A-Z0-9]+[_-])?STEM` — an underscore/dash-suffix stem
		//     (KEY/TOKEN/SECRET/PASSWORD/PASSWD/CREDENTIAL(S)/SESSION/COOKIE,
		//     the API[_-]?KEY/HASH etc. compounds) with an OPTIONAL
		//     `NAME_`/`NAME-` prefix — so `MY_DB_PASSWORD=`, `API_HASH=`,
		//     `SESSION=` all match. Bare `HASH` is deliberately NOT a stem
		//     (`GIT_COMMIT_HASH=` build metadata would over-redact); only
		//     the `API_HASH` compound is secret-shaped.
		//  2. camelCase — a WHITELISTED lowercase prefix (api/auth/oauth/
		//     bot/access/refresh/client/app/session/user/private/service/
		//     master/admin/db) glued directly to a suffix (key/token/secret/
		//     hash/password/pass/pwd/cookie/session). A whitelist, not
		//     `[a-z]+`, so `possession:` / `expression:` can NEVER match.
		//  3. `[A-Z0-9]+[_-](?:PWD|PASS)` — PWD/PASS are short, extremely
		//     common English fragments (PWD, OLDPWD, COMPASS, BYPASS,
		//     WHISKEY/MONKEY for the KEY case), so they REQUIRE a `_`/`-`
		//     separator: `DB_PWD=` redacts, but the bare cwd env var `PWD=…`
		//     / `OLDPWD=…` (in every `env` dump) survive.
		//
		// Boundary discipline: the name must begin at `(?:^|[^A-Za-z0-9])`
		// so a stem can never match inside a longer alphanumeric run
		// (`KEYBOARD=`, `TOKENIZER=`). The `["']?` around the name lets a
		// JSON/dict closing quote sit between the key and the `:`.
		//
		// Newline fix: the separator is `[ \t]*[:=][ \t]*` (NOT `\s*…\s*`).
		// The old `\s*` crossed newlines, so names-only output
		// (`grep -oE '^[A-Za-z_]+=' .env` → `A_API_KEY=\nB_API_KEY=`)
		// redacted the NEXT LINE'S NAME as a value. Trade: a YAML
		// block-scalar (`password:\n  value`) is no longer caught — a
		// documented miss the bug fix outweighs.
		//
		// Accepted, test-pinned over-redaction: `DESKTOP_SESSION=gnome`
		// loses its value (price of the SESSION stem). Verified survivors:
		// SESSION_MANAGER, GDMSESSION, XDG_SESSION_*, SSH_AUTH_SOCK,
		// SESSION_TIMEOUT=30.
		redact.CompileRule(
			"sshgate-sensitive-assignment",
			"Secret value assigned to a *KEY/*TOKEN/*SECRET/*PASSWORD/*PASS/*HASH/*SESSION/*COOKIE-named variable",
			`(?i)(?:^|[^A-Za-z0-9])(?:export\s+)?["']?(?:(?:[A-Z0-9]+[_-])?(?:API[_-]?KEY|ACCESS[_-]?KEY|SECRET[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|API[_-]?HASH|KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|SESSION|COOKIE)|(?:api|auth|oauth|bot|access|refresh|client|app|session|user|private|service|master|admin|db)(?:key|token|secret|hash|password|pass|pwd|cookie|session)|[A-Z0-9]+[_-](?:PWD|PASS))["']?[ \t]*[:=][ \t]*("[^"\n]{1,1000}"|'[^'\n]{1,1000}'|[^\s'"`+"`"+`;&|<>$(){}]{4,1000})`,
			[]string{"key", "token", "secret", "password", "pass", "passwd", "pwd", "credential", "hash", "session", "cookie"},
			1, 4, 0,
		),

		// PGPASSWORD is special-cased: the libpq env var name has no
		// `_PASS` boundary the rule above keys on cleanly, and it is an
		// extremely common leak in `env` / `ps -e` dumps. Separator is
		// `[ \t]*[:=][ \t]*` (2026-07 newline-crossing fix, same as the
		// rule above).
		redact.CompileRule(
			"sshgate-pgpassword",
			"PGPASSWORD libpq environment variable",
			`(?i)\bPGPASSWORD[ \t]*[:=][ \t]*("[^"\n]{1,1000}"|'[^'\n]{1,1000}'|[^\s'"`+"`"+`;&|<>$(){}]{1,1000})`,
			[]string{"pgpassword"},
			1, 1, 0,
		),

		// --- BLOCKER 3(b): URL-embedded credentials
		// scheme://user:PASSWORD@host. Redacts the password component of
		// a userinfo-bearing URL for the common DB / cache / web schemes.
		// SecretGroup 1 is the password between the first ':' after the
		// scheme and the '@'.
		redact.CompileRule(
			"sshgate-url-userinfo-password",
			"Password embedded in a scheme://user:pass@host URL",
			`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?|https?|ftp|ssh)://[^\s:/@]*:([^\s:/@]+)@`,
			[]string{"://"},
			1, 1, 4096,
		),

		// --- BLOCKER 3(c): modern provider prefixes the vendored
		// gitleaks snapshot predates. Anchored on a structural prefix so
		// the pre-filter keyword carries its weight.

		// OpenAI project keys (sk-proj-...) and legacy (sk-...). We anchor
		// on `sk-proj-` and `sk-ant-api03-` separately so the bare `sk-`
		// stays out (too noisy). Order in the alternation matters: the
		// longer, more specific prefixes are tried first.
		redact.CompileRule(
			"sshgate-openai-project-key",
			"OpenAI project/secret key (sk-proj-, sk-svcacct-)",
			`\b(sk-(?:proj|svcacct|None|admin)-[A-Za-z0-9_\-]{20,300})\b`,
			[]string{"sk-proj-", "sk-svcacct-", "sk-none-", "sk-admin-"},
			1, 24, 320,
		),

		// Anthropic API keys (sk-ant-api03-...).
		redact.CompileRule(
			"sshgate-anthropic-key",
			"Anthropic API key (sk-ant-...)",
			`\b(sk-ant-[A-Za-z0-9_\-]{20,300})\b`,
			[]string{"sk-ant-"},
			1, 24, 320,
		),

		// DigitalOcean PATs (dop_v1_<64 hex>) and OAuth (doo_v1_, dor_v1_).
		redact.CompileRule(
			"sshgate-digitalocean-token",
			"DigitalOcean token (dop_v1_/doo_v1_/dor_v1_)",
			`\b(do[opr]_v1_[a-f0-9]{64})\b`,
			[]string{"dop_v1_", "doo_v1_", "dor_v1_"},
			1, 71, 71,
		),

		// xAI (Grok) API keys (xai-...).
		redact.CompileRule(
			"sshgate-xai-key",
			"xAI / Grok API key (xai-...)",
			`\b(xai-[A-Za-z0-9_\-]{20,200})\b`,
			[]string{"xai-"},
			1, 24, 220,
		),

		// Groq API keys (gsk_...).
		redact.CompileRule(
			"sshgate-groq-key",
			"Groq API key (gsk_...)",
			`\b(gsk_[A-Za-z0-9]{40,200})\b`,
			[]string{"gsk_"},
			1, 44, 220,
		),

		// Google API keys (AIza...) — Maps/Firebase/etc.
		redact.CompileRule(
			"sshgate-google-api-key",
			"Google API key (AIza...)",
			`\b(AIza[A-Za-z0-9_\-]{35})\b`,
			[]string{"AIza"},
			1, 39, 39,
		),

		// Hugging Face access tokens (hf_...).
		redact.CompileRule(
			"sshgate-huggingface-token",
			"Hugging Face access token (hf_...)",
			`\b(hf_[A-Za-z0-9]{30,200})\b`,
			[]string{"hf_"},
			1, 33, 220,
		),

		// npm automation/access tokens (npm_...).
		redact.CompileRule(
			"sshgate-npm-token",
			"npm access token (npm_...)",
			`\b(npm_[A-Za-z0-9]{36})\b`,
			[]string{"npm_"},
			1, 40, 40,
		),

		// --- 2026-07 default-deny widening: broad/new provider shapes.

		// OpenAI-style secret key, BROAD `sk-<base62>` prefix. Entropy 3.5
		// is load-bearing: the shared gate's 3-class check kills the
		// lowercase FIDO2 key-type marker `sk-ecdsa-sha2-nistp256@openssh.com`
		// and prose slugs (`sk-migration-notes-2026`) — all lowercase(+digit)
		// — while a real base62 key (upper+lower+digit, ~5-6 bits/byte)
		// passes. The narrow `sshgate-openai-project-key` /
		// `sshgate-anthropic-key` rules stay ungated (belt-and-braces; dedup
		// collapses the overlap). MinLen 19 = `sk-` + 16.
		redact.CompileRule(
			"sshgate-openai-broad",
			"OpenAI-style secret key (sk-<base62>), entropy-gated",
			`\b(sk-[A-Za-z0-9_-]{16,})\b`,
			[]string{"sk-"},
			1, 19, 320,
		).WithEntropy(3.5),

		// GitHub fine-grained PAT (github_pat_...). It needs its OWN keyword:
		// `ghp_` (the existing sshgate-github-pat keyword) is NOT a substring
		// of `github_pat_`, so widening that rule could never fire on this
		// shape (verified prefilter blocker). Real tokens are 93 chars;
		// `{20,}` per the operator spec. Not entropy-gated — the
		// `github_pat_` prefix is already unambiguous.
		redact.CompileRule(
			"sshgate-github-fine-pat",
			"GitHub fine-grained PAT (github_pat_...)",
			`\b(github_pat_[A-Za-z0-9_]{20,})\b`,
			[]string{"github_pat_"},
			1, 31, 255,
		),

		// Zoho OAuth token: exact structural shape `1000.<32hex>.<32hex>`.
		// The hex body must NOT be entropy-gated — hex is 2-class and caps
		// at 4.0 bits/byte, and the fixed shape is confident on its own.
		redact.CompileRule(
			"sshgate-zoho-token",
			"Zoho OAuth token (1000.<32hex>.<32hex>)",
			`\b(1000\.[0-9a-fA-F]{32}\.[0-9a-fA-F]{32})\b`,
			[]string{"1000."},
			1, 70, 70,
		),
	}
}
