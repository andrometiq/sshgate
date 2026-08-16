package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
)

func TestStringListFlag(t *testing.T) {
	var got stringListFlag
	if err := got.Set("https://one.example, https://two.example"); err != nil {
		t.Fatal(err)
	}
	if err := got.Set("  https://three.example  ,,"); err != nil {
		t.Fatal(err)
	}
	want := stringListFlag{"https://one.example", "https://two.example", "https://three.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("origins = %#v; want %#v", got, want)
	}
}

type markerHandler struct{ body string }

func (h *markerHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte(h.body))
}

func TestHostedHTTPHandlerMachineOnlyIsIdentity(t *testing.T) {
	api := &markerHandler{body: "api"}
	ui := &markerHandler{body: "ui"}
	if got := hostedHTTPHandler(false, api, ui); got != api {
		t.Fatalf("UI-off handler = %T %p; want exact API handler %p", got, got, api)
	}
}

func TestHostedHTTPHandlerUIRoutes(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api:" + r.URL.Path))
	})
	ui := &markerHandler{body: "ui"}
	h := hostedHTTPHandler(true, api, ui)

	for _, tc := range []struct {
		path string
		want string
	}{
		{"/v1/sign", "api:/v1/sign"},
		{"/v2/policy/base-manifests", "api:/v2/policy/base-manifests"},
		{"/auth/login", "api:/auth/login"},
		{"/ui/pending", "api:/ui/pending"},
		{"/healthz", "api:/healthz"},
		{"/", "ui"},
		{"/app.js", "ui"},
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rr.Body.String() != tc.want {
			t.Errorf("GET %s body = %q; want %q", tc.path, rr.Body.String(), tc.want)
		}
	}
}

func TestResolvePolicyServingOptionsFlagMatrix(t *testing.T) {
	complete := policyServingFlags{
		AuthorityID: "pauth_11111111111111111111111111111111", ArchiveDirectory: "/policy/archive",
		ArchiveID: "parch_22222222222222222222222222222222", AuditFile: "/policy/audit.log",
	}
	for mask := 0; mask < 32; mask++ {
		flags := policyServingFlags{}
		if mask&1 != 0 {
			flags.AuthorityID = complete.AuthorityID
		}
		if mask&2 != 0 {
			flags.ArchiveDirectory = complete.ArchiveDirectory
		}
		if mask&4 != 0 {
			flags.ArchiveID = complete.ArchiveID
		}
		if mask&8 != 0 {
			flags.AuditFile = complete.AuditFile
		}
		ui := mask&16 != 0
		options, err := resolvePolicyServingOptions(flags, ui)
		switch mask {
		case 0, 16:
			if err != nil || options.Requested {
				t.Fatalf("empty policy flags = %#v, %v", options, err)
			}
		case 31:
			if err != nil || !options.Requested || options.MaxRejectionBytes != policystore.DefaultRejectionReservedBytes {
				t.Fatalf("complete policy flags = %#v, %v", options, err)
			}
		default:
			if err == nil {
				t.Fatalf("incomplete policy flag mask %05b was accepted: %#v", mask, options)
			}
		}
	}

	complete.MaxRejectionBytes = "1"
	options, err := resolvePolicyServingOptions(complete, true)
	if err != nil || options.MaxRejectionBytes != 1 {
		t.Fatalf("minimum cap = %#v, %v", options, err)
	}
	complete.MaxRejectionBytes = "8388608"
	options, err = resolvePolicyServingOptions(complete, true)
	if err != nil || options.MaxRejectionBytes != policystore.MaxRejectionReservedBytes {
		t.Fatalf("maximum cap = %#v, %v", options, err)
	}
	for _, invalid := range []string{"0", "8388609", "+1", " 1", "1 "} {
		complete.MaxRejectionBytes = invalid
		if _, err := resolvePolicyServingOptions(complete, true); err == nil {
			t.Errorf("invalid cap %q was accepted", invalid)
		}
	}
	if _, err := resolvePolicyServingOptions(policyServingFlags{MaxRejectionBytes: "1"}, false); err == nil || !strings.Contains(err.Error(), "--policy-authority-id") {
		t.Fatalf("cap-only request error = %v", err)
	}
	for _, test := range []struct {
		name  string
		flags policyServingFlags
		want  string
	}{
		{name: "authority spelling", flags: func() policyServingFlags {
			value := complete
			value.MaxRejectionBytes = ""
			value.AuthorityID += " "
			return value
		}(), want: "--policy-authority-id"},
		{name: "relative archive", flags: func() policyServingFlags {
			value := complete
			value.MaxRejectionBytes = ""
			value.ArchiveDirectory = "relative"
			return value
		}(), want: "--policy-archive-dir"},
		{name: "archive spelling", flags: func() policyServingFlags {
			value := complete
			value.MaxRejectionBytes = ""
			value.ArchiveID = "parch_BAD"
			return value
		}(), want: "--policy-archive-id"},
		{name: "relative audit", flags: func() policyServingFlags {
			value := complete
			value.MaxRejectionBytes = ""
			value.AuditFile = "relative"
			return value
		}(), want: "--policy-audit-file"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := resolvePolicyServingOptions(test.flags, true); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("configuration error = %v; want named %s", err, test.want)
			}
		})
	}
}

func TestPolicyAuthorityBindingMatchesProductionReviewAndVoteConfiguration(t *testing.T) {
	options, err := resolvePolicyServingOptions(policyServingFlags{
		AuthorityID: "pauth_11111111111111111111111111111111", ArchiveDirectory: "/policy/archive",
		ArchiveID: "parch_22222222222222222222222222222222", AuditFile: "/policy/audit.log",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := policyAuthorityBinding(options, "operator", 2, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Config.VoterEligibilityVersion != "sshgate-policy-voter-eligibility-v1" || string(binding.Config.VoteAuthMethodsJSON) != `["totp"]` ||
		binding.Config.ReviewRendererVersion != "sshgate-policy-review-v2" || len(binding.Config.ReviewRulesDigest) != 64 || binding.ConfigDigest == "" {
		t.Fatalf("production binding = %#v", binding)
	}
}

func TestRunUIRequiresRPConfiguration(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root refusal occurs before UI validation")
	}
	if code := run([]string{"--ui"}); code != 1 {
		t.Fatalf("run(--ui) = %d; want 1 for missing --rp-id", code)
	}
	if code := run([]string{"--ui", "--rp-id", "localhost"}); code != 1 {
		t.Fatalf("run(--ui --rp-id) = %d; want 1 for missing --rp-origin", code)
	}
	if code := run([]string{"--ui", "--rp-id", "localhost", "--rp-origin", "http://localhost:8443", "--session-ttl", "0s"}); code != 1 {
		t.Fatalf("run(--ui --session-ttl=0) = %d; want 1", code)
	}
}

func TestValidateUIConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		rpID    string
		origins []string
		ttl     time.Duration
		wantErr string
	}{
		{name: "UI off", enabled: false},
		{name: "missing RP ID", enabled: true, origins: []string{"https://signer.example"}, ttl: time.Hour, wantErr: "--rp-id is required with --ui"},
		{name: "missing origin", enabled: true, rpID: "signer.example", ttl: time.Hour, wantErr: "at least one --rp-origin is required with --ui"},
		{name: "invalid TTL", enabled: true, rpID: "signer.example", origins: []string{"https://signer.example"}, wantErr: "--session-ttl must be greater than zero with --ui"},
		{name: "valid", enabled: true, rpID: "signer.example", origins: []string{"https://signer.example"}, ttl: time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUIConfig(tc.enabled, tc.rpID, tc.origins, tc.ttl)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateUIConfig: %v", err)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("validateUIConfig error = %v; want %q", err, tc.wantErr)
			}
		})
	}
}

func TestRunMachineDefaultDoesNotRequireRPConfiguration(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root refusal occurs before required API-key validation")
	}
	// With UI disabled the first missing requirement remains the historical
	// machine-plane API key, proving RP settings are not consulted.
	if code := run(nil); code != 1 {
		t.Fatalf("run(defaults) = %d; want 1", code)
	}
}

func TestLoadAPIKeyRefusesGroupOrWorldAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-key")
	if err := os.WriteFile(path, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAPIKey(path); err == nil || !strings.Contains(err.Error(), "group/world bits must be off") {
		t.Fatalf("loadAPIKey(0644) err=%v; want insecure-mode refusal", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadAPIKey(path)
	if err != nil || got != "secret" {
		t.Fatalf("loadAPIKey(0600)=(%q,%v); want secret,nil", got, err)
	}
}

func TestBootstrapOperatorCreatesSecureRecoverableArtifactIdempotently(t *testing.T) {
	dir := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := hosted.AuthConfig{
		RPID: "signer.example.com", RPOrigins: []string{"https://signer.example.com"}, SessionTTL: time.Hour,
	}
	artifactPath := filepath.Join(dir, "bootstrap-alice.txt")
	if err := bootstrapOperator(context.Background(), db, cfg, "alice", artifactPath); err != nil {
		t.Fatal(err)
	}
	user, err := db.GetUserByName(context.Background(), "alice")
	if err != nil || user.ID != "alice" || user.Role != "operator" {
		t.Fatalf("operator = %+v, err=%v", user, err)
	}
	secret, err := db.GetTOTP(context.Background(), user.ID)
	raw, readErr := os.ReadFile(artifactPath)
	if err != nil || readErr != nil || secret == "" || !strings.Contains(string(raw), "totp_secret="+secret+"\n") {
		t.Fatalf("factor not persisted in secure artifact: secret=%q factorErr=%v readErr=%v", secret, err, readErr)
	}
	info, err := os.Stat(artifactPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact mode = %v err=%v; want 0600", info.Mode().Perm(), err)
	}
	if err := bootstrapOperator(context.Background(), db, cfg, "alice", artifactPath); err != nil {
		t.Fatalf("idempotent bootstrap with artifact: %v", err)
	}
	if err := os.Remove(artifactPath); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapOperator(context.Background(), db, cfg, "alice", artifactPath); err != nil {
		t.Fatalf("idempotent bootstrap after artifact consumption: %v", err)
	}
	if _, err := os.Stat(artifactPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("already-enrolled bootstrap recreated secret artifact: %v", err)
	}
}

func TestBootstrapOperatorRejectsUnsafeNameBeforeMutation(t *testing.T) {
	db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := hosted.AuthConfig{
		RPID: "signer.example.com", RPOrigins: []string{"https://signer.example.com"}, SessionTTL: time.Hour,
	}
	if err := bootstrapOperator(context.Background(), db, cfg, "bad name", filepath.Join(t.TempDir(), "artifact")); err == nil {
		t.Fatal("unsafe operator name accepted")
	}
	if _, err := db.GetUserByName(context.Background(), "bad name"); err == nil {
		t.Fatal("rejected operator was persisted")
	}
}

func TestLoadAPIKeyRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "api-key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAPIKey(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("loadAPIKey(symlink) err=%v; want refusal", err)
	}
}

func TestValidateApprovalRosterPreventsUnreachableFreshPolicy(t *testing.T) {
	db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := hosted.AuthConfig{RPID: "signer.example.com", RPOrigins: []string{"https://signer.example.com"}, SessionTTL: time.Hour}
	for _, name := range []string{"alice", "bob"} {
		if err := bootstrapOperator(context.Background(), db, cfg, name, filepath.Join(t.TempDir(), "bootstrap-"+name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateApprovalRoster(context.Background(), db, "alice", 1, false); err != nil {
		t.Fatalf("one non-self approver should be reachable: %v", err)
	}
	if err := validateApprovalRoster(context.Background(), db, "alice", 2, false); err == nil {
		t.Fatal("unreachable two-of-one-non-self policy accepted")
	}
	if err := validateApprovalRoster(context.Background(), db, "ghost", 1, false); err == nil {
		t.Fatal("unbootstrapped requester identity accepted")
	}
}

func TestPolicyMaintenanceRefusesAbsentAndUnboundDatabaseBeforeArchiveWrite(t *testing.T) {
	directory := t.TempDir()
	archiveRoot := filepath.Join(directory, "archive")
	if err := os.Mkdir(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(archiveRoot, "owner-marker")
	if err := os.WriteFile(marker, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Unix(10, 0).UTC().Format(time.RFC3339)
	absent := filepath.Join(directory, "absent.db")
	if err := runPolicyMaintenance(context.Background(), absent, archiveRoot, cutoff, ""); err == nil {
		t.Fatal("maintenance accepted an absent database")
	}
	if _, err := os.Stat(absent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("maintenance created absent database: %v", err)
	}

	unbound := filepath.Join(directory, "unbound.db")
	database, err := sqlitestore.Open(unbound)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runPolicyMaintenance(context.Background(), unbound, archiveRoot, cutoff, ""); err == nil {
		t.Fatal("maintenance accepted an unbound database")
	}
	contents, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "unchanged" {
		t.Fatalf("maintenance changed archive marker to %q", contents)
	}
	entries, err := os.ReadDir(archiveRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "owner-marker" {
		t.Fatalf("maintenance wrote archive before DB preflight: %v", entries)
	}
}

func TestDeployScriptSyntaxAndRequiredUnitWiring(t *testing.T) {
	installDir := filepath.Join("..", "..", "install")
	deployPath := filepath.Join(installDir, "deploy.sh")
	if out, err := exec.Command("bash", "-n", deployPath).CombinedOutput(); err != nil {
		t.Fatalf("bash -n deploy.sh: %v\n%s", err, out)
	}
	unit, err := os.ReadFile(filepath.Join(installDir, "sshgate-signer-server.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"--signing-key-file __SIGNING_KEY_FILE__",
		"--ui",
		"--rp-id __RP_ID__",
		"--rp-origin __RP_ORIGIN__",
		"--machine-client-id __MACHINE_CLIENT_ID__",
		"--required-approvals __REQUIRED_APPROVALS__",
		"--trust-proxy-headers=__TRUST_PROXY_HEADERS__",
		"--require-step-up=__REQUIRE_STEP_UP__",
		"UMask=0077",
		"CapabilityBoundingSet=",
	} {
		if !strings.Contains(string(unit), required) {
			t.Errorf("systemd unit missing %q", required)
		}
	}
	deploy, err := os.ReadFile(deployPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"--bootstrap-output-file",
		"refuse_symlink \"${API_KEY_FILE}\"",
		"refuse_symlink \"${SIGNING_KEY_FILE}\"",
		"runuser -u \"${SERVICE_USER}\" -- chmod 0600 -- \"${DB_PATH}\"",
		"SIGNER_SERVER_BOOTSTRAP_OPERATORS",
		"SIGNER_SERVER_MACHINE_CLIENT_ID",
		"SIGNER_SERVER_REQUIRED_APPROVALS",
	} {
		if !strings.Contains(string(deploy), required) {
			t.Errorf("deploy script missing %q", required)
		}
	}
}
