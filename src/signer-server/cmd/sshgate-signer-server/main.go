// Command signer-server is the hosted v2 signing service. It serves
// the HTTPS API described in docs/design.md §"Signed-write wire format"
// and docs/approval-architecture.md: SSHGate plugins on any machine submit
// a sign request, a human approves it through the WebAuthn/TOTP UI,
// and the server returns signed payloads compatible with gate.
//
// Flags:
//
//	--config <path>          TOML config (default: /etc/signer-server/config.toml
//	                          or $SSHGATE_SIGNER_SERVER_CONFIG)
//	--api-key-file <path>    Single machine bearer-token file (0600).
//	--signing-key-file <path> 64-byte raw Ed25519 master signing key (0600).
//	                          The server mints gate-valid SSHGATE_SIG
//	                          envelopes with this; missing/insecure = fatal.
//	--addr <host:port>       Listen address (default: :8443). TLS is
//	                          terminated upstream (Caddy/nginx) in v2.0.
//	--db <path>              SQLite database path (default:
//	                          /var/lib/signer-server/state.db)
//	--compact-policy-before <RFC3339>
//	                          Offline archive/compact older policy terminals.
//	--clear-policy-recovery-lease <review_id>
//	                          Offline owner clear for one recovery lease.
//	--policy-archive-dir <absolute path>
//	                          Existing bound archive for policy maintenance.
//	--policy-authority-id <pauth_...>
//	--policy-archive-id <parch_...>
//	--policy-audit-file <absolute path>
//	                          Required together with archive-dir and --ui to
//	                          serve the permanent-policy plane.
//	--ui                     Serve the embedded human approval UI (default off).
//	--rp-id <domain>         WebAuthn relying-party ID (required with --ui).
//	--rp-origin <origin>     Allowed WebAuthn origin; repeatable/comma-separated.
//	--version                Print version and exit
//
// On startup:
//
//  1. Refuse to run as root (same reflex as signer — a daemon that
//     holds signing capability should never be the kernel).
//  2. Load the API key from --api-key-file (single-token bearer auth
//     for v2.0). Empty file = fatal.
//  3. Load the Ed25519 master signing key from --signing-key-file
//     (64-byte raw, 0600). Missing/insecure/wrong-size = fatal.
//  4. Open the SQLite request, operator, factor, session, and vote store.
//  5. Build the http.Server and listen.
//  6. Shut down cleanly on SIGTERM/SIGINT (5s drain window).
//
// v2.0 does NOT terminate TLS itself: that's the reverse proxy's job
// (Caddy or nginx in the deploy script). The server binds plain HTTP
// on a private interface; the proxy handles the public 443.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted/refapp"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policyarchive"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	"github.com/karthikeyan5/sshgate/src/policyauthority"
	"github.com/karthikeyan5/sshgate/src/policyreview"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
)

// version is stamped from the single VERSION file at link time via
// -ldflags "-X main.version=<VERSION>" (Makefile SIGNER_SERVER_VERSION_FLAGS).
// Unstamped builds keep "dev"; `make verify-versions` proves the stamp
// landed. The hosted signer-server is still a v2 scaffold, but its
// reported version tracks the repo VERSION like every other binary.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("signer-server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	apiKeyFile := fs.String("api-key-file", "", "Path to a 0600 file containing the bearer API key")
	signingKeyFile := fs.String("signing-key-file", "", "Path to a 0600 file containing the 64-byte raw Ed25519 master signing key")
	signingPublicKeyFile := fs.String("signing-public-key-file", "", "Path for the 32-byte public key written by --init-signing-key")
	initSigningKey := fs.Bool("init-signing-key", false, "Generate a new signing keypair and exit; refuses to overwrite either file")
	bootstrapOperatorName := fs.String("bootstrap-operator", "", "Create the first UI operator with a TOTP factor and exit")
	bootstrapOutputFile := fs.String("bootstrap-output-file", "", "0600 artifact for bootstrap TOTP material (required with --bootstrap-operator)")
	machineClientID := fs.String("machine-client-id", "", "Stable operator ID bound to the machine bearer credential")
	requiredApprovals := fs.Int("required-approvals", 1, "Number of distinct eligible approvals required per request")
	addr := fs.String("addr", ":8443", "Listen address (host:port). Default :8443; TLS terminated upstream.")
	dbPath := fs.String("db", "/var/lib/signer-server/state.db", "SQLite database path")
	compactPolicyBefore := fs.String("compact-policy-before", "", "Offline compact policy terminals resolved before RFC3339 time")
	clearPolicyRecoveryLease := fs.String("clear-policy-recovery-lease", "", "Offline clear of the recovery lease for one policy review ID")
	policyAuthorityID := fs.String("policy-authority-id", "", "Canonical pauth_ policy authority ID")
	policyArchiveDir := fs.String("policy-archive-dir", "", "Absolute owner-only policy archive directory for offline maintenance")
	policyArchiveID := fs.String("policy-archive-id", "", "Canonical parch_ policy archive namespace ID")
	policyAuditFile := fs.String("policy-audit-file", "", "Absolute owner-only durable policy audit file")
	policyMaxRejectionBytes := fs.String("policy-max-rejection-bytes-per-principal", "", "Retained rejection-byte cap per principal (1 through 8388608)")
	uiEnabled := fs.Bool("ui", false, "Serve the embedded human approval UI")
	rpID := fs.String("rp-id", "", "WebAuthn relying-party ID (required with --ui)")
	var rpOrigins stringListFlag
	fs.Var(&rpOrigins, "rp-origin", "Allowed WebAuthn origin (required with --ui; repeatable or comma-separated)")
	rpDisplayName := fs.String("rp-display-name", "SSHGate Signer", "WebAuthn relying-party display name")
	sessionTTL := fs.Duration("session-ttl", time.Hour, "Human session lifetime")
	totpIssuer := fs.String("totp-issuer", "", "TOTP issuer label (defaults to RP display name)")
	requireStepUp := fs.Bool("require-step-up", false, "Require a fresh TOTP code for every approve or deny")
	secureCookie := fs.Bool("secure-cookie", true, "Mark the human session cookie Secure (disable only for local plain-HTTP development)")
	denyVeto := fs.Bool("deny-veto", true, "Let one deny vote veto a request")
	allowSelfApprove := fs.Bool("allow-self-approve", false, "Allow a requester's own approval vote to count")
	trustProxyHeaders := fs.Bool("trust-proxy-headers", false, "Trust X-Forwarded-For only from a loopback reverse proxy")
	_ = fs.String("config", defaultConfigPath(), "TOML config file (reserved for a future release)")
	showVersion := fs.Bool("version", false, "Print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(os.Stdout, "signer-server %s\n", version)
		return 0
	}

	if *initSigningKey && strings.TrimSpace(*bootstrapOperatorName) != "" {
		logf("--init-signing-key and --bootstrap-operator are mutually exclusive")
		return 1
	}
	if *initSigningKey {
		if strings.TrimSpace(*signingKeyFile) == "" || strings.TrimSpace(*signingPublicKeyFile) == "" {
			logf("--signing-key-file and --signing-public-key-file are required with --init-signing-key")
			return 1
		}
		if err := signerkit.GenerateKeyPair(*signingKeyFile, *signingPublicKeyFile); err != nil {
			logf("initialize signing key: %v", err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "signing key initialized\nprivate_key=%s\npublic_key=%s\n", *signingKeyFile, *signingPublicKeyFile)
		return 0
	}
	if err := assertNonRoot(); err != nil {
		logf("%v", err)
		return 1
	}
	if *compactPolicyBefore != "" || *clearPolicyRecoveryLease != "" {
		if *compactPolicyBefore != "" && *clearPolicyRecoveryLease != "" {
			logf("--compact-policy-before and --clear-policy-recovery-lease are mutually exclusive")
			return 1
		}
		if err := runPolicyMaintenance(context.Background(), *dbPath, *policyArchiveDir, *compactPolicyBefore, *clearPolicyRecoveryLease); err != nil {
			logf("policy maintenance: %v", err)
			return 1
		}
		return 0
	}
	if name := strings.TrimSpace(*bootstrapOperatorName); name != "" {
		if err := validateUIConfig(true, *rpID, rpOrigins, *sessionTTL); err != nil {
			logf("bootstrap operator: %v", err)
			return 1
		}
		db, err := sqlitestore.Open(*dbPath)
		if err != nil {
			logf("bootstrap operator: open store: %v", err)
			return 1
		}
		defer func() { _ = db.Close() }()
		err = bootstrapOperator(context.Background(), db, hosted.AuthConfig{
			RPID:          strings.TrimSpace(*rpID),
			RPDisplayName: strings.TrimSpace(*rpDisplayName),
			RPOrigins:     slices.Clone(rpOrigins),
			SessionTTL:    *sessionTTL,
			TOTPIssuer:    strings.TrimSpace(*totpIssuer),
		}, name, strings.TrimSpace(*bootstrapOutputFile))
		if err != nil {
			logf("bootstrap operator: %v", err)
			return 1
		}
		return 0
	}
	policyOptions, err := resolvePolicyServingOptions(policyServingFlags{
		AuthorityID: *policyAuthorityID, ArchiveDirectory: *policyArchiveDir,
		ArchiveID: *policyArchiveID, AuditFile: *policyAuditFile,
		MaxRejectionBytes: *policyMaxRejectionBytes,
	}, *uiEnabled)
	if err != nil {
		logf("policy configuration: %v", err)
		return 1
	}
	if err := validateUIConfig(*uiEnabled, *rpID, rpOrigins, *sessionTTL); err != nil {
		logf("%v", err)
		return 1
	}
	if *uiEnabled {
		if strings.TrimSpace(*machineClientID) == "" {
			logf("--machine-client-id is required with --ui")
			return 1
		}
		if *requiredApprovals <= 0 {
			logf("--required-approvals must be greater than zero with --ui")
			return 1
		}
	}

	if *apiKeyFile == "" {
		logf("--api-key-file is required (see --help)")
		return 1
	}
	apiKey, err := loadAPIKey(*apiKeyFile)
	if err != nil {
		logf("load api key: %v", err)
		return 1
	}

	// Load the Ed25519 master signing key. A server that cannot sign is
	// useless, and one that starts with a missing/insecure key would be
	// a silent security hole, so we fail closed here — the same reflex
	// as the empty-API-key panic in NewServer and the v1 signer's 0600
	// key-load. Where the prod key lives is a separate ops decision; we
	// only accept a path.
	if *signingKeyFile == "" {
		logf("--signing-key-file is required (see --help)")
		return 1
	}
	// Load the master key and construct the SHARED signerkit core (the same
	// core the local Telegram signer uses — one codebase, phase 5). LoadKey
	// enforces the 0600/size/exists reflexes; New requires a non-nil Signer +
	// Audit sink. The hosted plane fails CLOSED without an audit trail, so we
	// anchor it to an append-only JSON-Lines sink on stderr.
	signingKey, err := signerkit.LoadKey(*signingKeyFile)
	if err != nil {
		logf("load signing key: %v", err)
		return 1
	}
	core, err := signerkit.New(signerkit.Config{
		Signer: signingKey,
		Audit:  signerkit.NewAppendOnlySink(os.Stderr),
	})
	if err != nil {
		logf("construct signing core: %v", err)
		return 1
	}

	logger := log.New(os.Stderr, "signer-server: ", log.LstdFlags|log.Lmicroseconds)
	policyLifetime := context.Background()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var httpSrv *http.Server
	buildServer := func(database *sqlitestore.DB) (*hosted.Server, error) {
		if *uiEnabled {
			if err := validateApprovalRoster(policyLifetime, database, strings.TrimSpace(*machineClientID), *requiredApprovals, *allowSelfApprove, *requireStepUp); err != nil {
				return nil, fmt.Errorf("approval policy: %w", err)
			}
		}
		config := hosted.Config{
			Core: core, Store: database, APIKey: apiKey,
			MachineClientID:   strings.TrimSpace(*machineClientID),
			RequiredApprovals: *requiredApprovals, Logger: logger,
		}
		if *uiEnabled {
			config.Auth = hosted.AuthConfig{
				RPID: strings.TrimSpace(*rpID), RPDisplayName: strings.TrimSpace(*rpDisplayName),
				RPOrigins: slices.Clone(rpOrigins), SessionTTL: *sessionTTL,
				TOTPIssuer: strings.TrimSpace(*totpIssuer),
			}
			config.Human = hosted.HumanAPIConfig{
				ApprovalPolicy: hosted.ApprovalPolicy{DenyVeto: *denyVeto, AllowSelfApprove: *allowSelfApprove},
				RequireStepUp:  *requireStepUp, SecureCookie: *secureCookie, TrustProxyHeaders: *trustProxyHeaders,
			}
		}
		return hosted.New(config)
	}

	var srv *hosted.Server
	var policyRuntime *hosted.PolicyRuntime
	if policyOptions.Requested {
		if !filepath.IsAbs(*dbPath) {
			logf("policy configuration: --db must be absolute when the policy plane is requested")
			return 1
		}
		binding, bindErr := policyAuthorityBinding(policyOptions, strings.TrimSpace(*machineClientID), *requiredApprovals, *denyVeto, *allowSelfApprove, *requireStepUp)
		if bindErr != nil {
			logf("policy configuration: %v", bindErr)
			return 1
		}
		policyRuntime, err = hosted.StartPolicy(policyLifetime, hosted.PolicyStartupConfig{
			DatabasePath: *dbPath, ArchiveRoot: policyOptions.ArchiveDirectory,
			Binding: binding, WorkerID: "signer-server-policy-worker", Core: core,
			OpenDatabase: func() (hosted.PolicyDatabase, error) { return sqlitestore.Open(*dbPath) },
			OpenAudit: func() (signerkit.DurableAuditSink, error) {
				return signerkit.NewDurableFileAuditSink(policyOptions.AuditFile)
			},
			BuildServer: func(database hosted.PolicyDatabase) (*hosted.Server, error) {
				sqlite, ok := database.(*sqlitestore.DB)
				if !ok {
					return nil, errors.New("policy database is not the production SQLite store")
				}
				return buildServer(sqlite)
			},
			BuildHandler: func(engine *hosted.PolicyEngine, archive *policyarchive.Archive) (http.Handler, error) {
				return hosted.NewPolicyMachineHandler(engine, archive)
			},
			StopIntake: func() error {
				if httpSrv == nil {
					return nil
				}
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return httpSrv.Shutdown(shutdownCtx)
			},
			ReviewRules: redactrules.Combined(), RedactString: redact.RedactString,
			ReviewRendererVersion: policyreview.RendererVersion, ReviewRulesDigest: policyreview.RulesDigest(),
		})
		if err != nil {
			logf("start policy authority: %v", err)
			return 1
		}
		defer func() { _ = policyRuntime.Close() }()
		srv = policyRuntime.Server
	} else {
		database, openErr := sqlitestore.Open(*dbPath)
		if openErr != nil {
			logf("open store: %v", openErr)
			return 1
		}
		defer func() { _ = database.Close() }()
		srv, err = buildServer(database)
		if err != nil {
			logf("build hosted server: %v", err)
			return 1
		}
	}

	httpSrv = &http.Server{
		Addr:              *addr,
		Handler:           hostedHTTPHandler(*uiEnabled, srv, refapp.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
		// Long-poll handlers can hold the connection up to ~60s;
		// budget a comfortable WriteTimeout above that. A future release can
		// move to per-route timeouts.
		ReadTimeout:  90 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	listener, err := net.Listen("tcp", httpSrv.Addr)
	if err != nil {
		logf("listen: %v", err)
		return 1
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Printf("listening on %s (version=%s)", listener.Addr(), version)
		if err := httpSrv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	if policyRuntime != nil {
		if err := policyRuntime.CompleteStartup(policyLifetime); err != nil {
			logf("policy authority unavailable: %v", err)
		}
	}

	select {
	case <-ctx.Done():
		logger.Printf("signal received, shutting down")
	case err := <-errCh:
		if err != nil {
			logf("listen: %v", err)
			return 1
		}
		return 0
	}

	if policyRuntime != nil {
		if err := policyRuntime.Close(); err != nil {
			logf("shutdown policy authority: %v", err)
			return 1
		}
	} else {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			logf("shutdown: %v", err)
			return 1
		}
	}
	logger.Printf("stopped")
	return 0
}

func runPolicyMaintenance(ctx context.Context, databasePath, archiveDirectory, compactBefore, clearReviewID string) (returnError error) {
	if !filepath.IsAbs(databasePath) {
		return errors.New("--db must be absolute for policy maintenance")
	}
	if !filepath.IsAbs(archiveDirectory) {
		return errors.New("--policy-archive-dir must be absolute for policy maintenance")
	}
	var before time.Time
	var err error
	if compactBefore != "" {
		before, err = time.Parse(time.RFC3339, compactBefore)
		if err != nil {
			return fmt.Errorf("parse --compact-policy-before: %w", err)
		}
	}
	lease, err := policyarchive.AcquireMaintenanceLease(databasePath, policyarchive.LeaseExclusive)
	if err != nil {
		return err
	}
	defer func() { returnError = errors.Join(returnError, lease.Close()) }()
	database, err := sqlitestore.OpenExisting(databasePath)
	if err != nil {
		return err
	}
	defer func() { returnError = errors.Join(returnError, database.Close()) }()
	binding, err := database.PolicyStore().VerifyAuthorityBinding(ctx)
	if err != nil {
		return err
	}
	archive, err := policyarchive.OpenExisting(archiveDirectory, lease)
	if err != nil {
		return err
	}
	defer func() { returnError = errors.Join(returnError, archive.Close()) }()
	if err := archive.VerifyBinding(binding.ArchiveID, binding.AuthorityID); err != nil {
		return err
	}
	if clearReviewID != "" {
		return database.ClearPolicyRecoveryLease(ctx, clearReviewID)
	}
	if _, err := archive.CleanupTemporaryObjects(lease, func(path string) { logf("removed orphan policy archive temporary object %s", path) }); err != nil {
		return err
	}
	store := database.PolicyStore()
	var cursor *policystore.TerminalCursor
	for {
		page, err := store.ListTerminalCompactionCandidates(ctx, before, cursor, 64)
		if err != nil {
			return err
		}
		for _, request := range page.Requests {
			record, err := store.SnapshotTerminalArchive(ctx, request.Key(), request.StateVersion)
			if err != nil {
				return err
			}
			reference, encoded, err := record.ObjectRef()
			if err != nil {
				return err
			}
			object, err := archive.PublishObject(lease, encoded)
			if err != nil {
				return err
			}
			if object.SHA256 != reference.ObjectSHA256 || object.Bytes != reference.RecordBytes {
				return errors.New("policy archive publication reference mismatch")
			}
			if _, err := store.CommitTerminalArchive(ctx, request.Key(), request.StateVersion, reference); err != nil {
				return err
			}
		}
		if page.Next == nil {
			return nil
		}
		cursor = page.Next
	}
}

// stringListFlag accepts a repeatable flag and comma-separated values while
// discarding surrounding whitespace and empty entries.
type stringListFlag []string

func (s *stringListFlag) String() string { return strings.Join(*s, ",") }

func (s *stringListFlag) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			*s = append(*s, item)
		}
	}
	return nil
}

type policyServingFlags struct {
	AuthorityID       string
	ArchiveDirectory  string
	ArchiveID         string
	AuditFile         string
	MaxRejectionBytes string
}

type policyServingOptions struct {
	Requested         bool
	AuthorityID       string
	ArchiveDirectory  string
	ArchiveID         string
	AuditFile         string
	MaxRejectionBytes uint64
}

var policyDecimalPattern = regexp.MustCompile(`^[0-9]+$`)

func resolvePolicyServingOptions(flags policyServingFlags, uiEnabled bool) (policyServingOptions, error) {
	requested := flags.AuthorityID != "" || flags.ArchiveDirectory != "" || flags.ArchiveID != "" || flags.AuditFile != "" || flags.MaxRejectionBytes != ""
	options := policyServingOptions{Requested: requested, AuthorityID: flags.AuthorityID, ArchiveDirectory: flags.ArchiveDirectory, ArchiveID: flags.ArchiveID, AuditFile: flags.AuditFile, MaxRejectionBytes: policystore.DefaultRejectionReservedBytes}
	if !requested {
		return options, nil
	}
	if flags.AuthorityID == "" {
		return policyServingOptions{}, errors.New("--policy-authority-id is required when the policy plane is requested")
	}
	if !policyauthority.ValidAuthorityID(flags.AuthorityID) {
		return policyServingOptions{}, errors.New("--policy-authority-id must be pauth_ followed by 32 lowercase hexadecimal characters")
	}
	if flags.ArchiveDirectory == "" {
		return policyServingOptions{}, errors.New("--policy-archive-dir is required when the policy plane is requested")
	}
	if !filepath.IsAbs(flags.ArchiveDirectory) {
		return policyServingOptions{}, errors.New("--policy-archive-dir must be absolute when the policy plane is requested")
	}
	if flags.ArchiveID == "" {
		return policyServingOptions{}, errors.New("--policy-archive-id is required when the policy plane is requested")
	}
	if !policystore.ValidArchiveID(flags.ArchiveID) {
		return policyServingOptions{}, errors.New("--policy-archive-id must be parch_ followed by 32 lowercase hexadecimal characters")
	}
	if flags.AuditFile == "" {
		return policyServingOptions{}, errors.New("--policy-audit-file is required when the policy plane is requested")
	}
	if !filepath.IsAbs(flags.AuditFile) {
		return policyServingOptions{}, errors.New("--policy-audit-file must be absolute when the policy plane is requested")
	}
	if !uiEnabled {
		return policyServingOptions{}, errors.New("--ui is required when the policy plane is requested")
	}
	if flags.MaxRejectionBytes != "" {
		if !policyDecimalPattern.MatchString(flags.MaxRejectionBytes) {
			return policyServingOptions{}, errors.New("--policy-max-rejection-bytes-per-principal must be a decimal integer")
		}
		value, err := strconv.ParseUint(flags.MaxRejectionBytes, 10, 64)
		if err != nil || value == 0 || value > policystore.MaxRejectionReservedBytes {
			return policyServingOptions{}, fmt.Errorf("--policy-max-rejection-bytes-per-principal must be between 1 and %d", policystore.MaxRejectionReservedBytes)
		}
		options.MaxRejectionBytes = value
	}
	return options, nil
}

func policyAuthorityBinding(options policyServingOptions, requester string, requiredApprovals int, denyVeto, allowSelfApprove, requireStepUp bool) (policystore.AuthorityBinding, error) {
	config := policystore.DefaultConfigDigestInput()
	config.RequesterOperatorID = requester
	config.RequiredApprovals = uint64(requiredApprovals)
	config.DenyVeto = denyVeto
	config.AllowSelfApprove = allowSelfApprove
	config.PolicyVoterRole = "operator"
	config.VoterEligibilityVersion = "sshgate-policy-voter-eligibility-v1"
	config.VoteStepUpRequired = requireStepUp
	config.VoteAuthMethodsJSON = []byte(`["session"]`)
	if requireStepUp {
		config.VoteAuthMethodsJSON = []byte(`["totp"]`)
	}
	config.MaxRejectionReservedBytesPerPrincipal = options.MaxRejectionBytes
	config.ArchiveID = options.ArchiveID
	config.ReviewRendererVersion = policyreview.RendererVersion
	config.ReviewRulesDigest = policyreview.RulesDigest()
	if err := config.Validate(); err != nil {
		return policystore.AuthorityBinding{}, err
	}
	digest, err := policystore.ConfigDigest(config)
	if err != nil {
		return policystore.AuthorityBinding{}, err
	}
	return policystore.AuthorityBinding{
		AuthorityID: options.AuthorityID, ArchiveID: options.ArchiveID,
		AccountingVersion: policystore.AccountingVersion, ConfigDigest: digest,
		MaxRejectionReservedBytesPerPrincipal: options.MaxRejectionBytes,
		Config:                                config,
	}, nil
}

// hostedHTTPHandler keeps the default machine surface literally unchanged:
// when UI is disabled it returns api itself. UI mode routes only the existing
// hosted prefixes to api and reserves the catch-all for embedded static files.
func hostedHTTPHandler(uiEnabled bool, api, ui http.Handler) http.Handler {
	if !uiEnabled {
		return api
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/", api)
	mux.Handle("/v2/", api)
	mux.Handle("/auth/", api)
	mux.Handle("/ui/", api)
	mux.Handle("/healthz", api)
	mux.Handle("/", ui)
	return mux
}

func validateUIConfig(enabled bool, rpID string, rpOrigins []string, sessionTTL time.Duration) error {
	if !enabled {
		return nil
	}
	if strings.TrimSpace(rpID) == "" {
		return errors.New("--rp-id is required with --ui")
	}
	if len(rpOrigins) == 0 {
		return errors.New("at least one --rp-origin is required with --ui")
	}
	if sessionTTL <= 0 {
		return errors.New("--session-ttl must be greater than zero with --ui")
	}
	return nil
}

var operatorNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)

func bootstrapOperator(ctx context.Context, db *sqlitestore.DB, authCfg hosted.AuthConfig, username, outputPath string) error {
	username = strings.TrimSpace(username)
	if !operatorNamePattern.MatchString(username) {
		return errors.New("operator must be 1-128 characters: letters, digits, dot, underscore, @, or hyphen")
	}
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		return errors.New("--bootstrap-output-file is required with --bootstrap-operator")
	}
	// Validate RP/TOTP configuration through the same constructor used by the
	// live human plane, without enrolling or persisting anything yet.
	_, err := hosted.NewAuthManager(db, authCfg)
	if err != nil {
		return err
	}
	user, err := db.GetUserByName(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		user = &store.User{ID: username, Username: username, Role: "operator"}
		if err := db.CreateUser(ctx, user); err != nil {
			return fmt.Errorf("create operator: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("look up operator: %w", err)
	}

	existingSecret, factorErr := db.GetTOTP(ctx, user.ID)
	if factorErr != nil && !errors.Is(factorErr, store.ErrNotFound) {
		return fmt.Errorf("check existing factor: %w", factorErr)
	}
	artifact, artifactErr := readBootstrapArtifact(outputPath)
	if artifactErr == nil {
		if artifact.Operator != username {
			return fmt.Errorf("bootstrap artifact %s belongs to operator %q", outputPath, artifact.Operator)
		}
		if factorErr == nil {
			if artifact.Secret != existingSecret {
				return fmt.Errorf("bootstrap artifact %s does not match the stored factor", outputPath)
			}
			return nil
		}
		if err := db.SetTOTP(ctx, user.ID, artifact.Secret); err != nil {
			return fmt.Errorf("resume stored bootstrap factor: %w", err)
		}
		return nil
	}
	if !errors.Is(artifactErr, os.ErrNotExist) {
		return artifactErr
	}
	if factorErr == nil {
		// Idempotent deploy after the one-time artifact was deliberately removed.
		return nil
	}
	issuer := strings.TrimSpace(authCfg.TOTPIssuer)
	if issuer == "" {
		issuer = strings.TrimSpace(authCfg.RPDisplayName)
	}
	if issuer == "" {
		issuer = strings.TrimSpace(authCfg.RPID)
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: user.Username})
	if err != nil {
		return fmt.Errorf("generate TOTP enrollment: %w", err)
	}
	artifact = bootstrapArtifact{Operator: user.Username, Secret: key.Secret(), URI: key.URL()}
	if err := writeBootstrapArtifact(outputPath, artifact); err != nil {
		return err
	}
	// Artifact-before-store ordering is intentional: a DB failure leaves a
	// recoverable 0600 secret that the next invocation resumes, never an
	// enrolled factor whose only copy vanished into stdout or a failed pipe.
	if err := db.SetTOTP(ctx, user.ID, artifact.Secret); err != nil {
		return fmt.Errorf("store bootstrap factor (artifact retained at %s): %w", outputPath, err)
	}
	return nil
}

type bootstrapArtifact struct {
	Operator string
	Secret   string
	URI      string
}

func readBootstrapArtifact(path string) (bootstrapArtifact, error) {
	raw, err := readOwnerFile(path, "bootstrap artifact")
	if err != nil {
		return bootstrapArtifact{}, err
	}
	var out bootstrapArtifact
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "operator":
			out.Operator = value
		case "totp_secret":
			out.Secret = value
		case "totp_uri":
			out.URI = value
		}
	}
	if out.Operator == "" || out.Secret == "" || out.URI == "" {
		return bootstrapArtifact{}, fmt.Errorf("bootstrap artifact %s is incomplete", path)
	}
	return out, nil
}

func writeBootstrapArtifact(path string, artifact bootstrapArtifact) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create bootstrap artifact %s: %w", path, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(path)
		}
	}()
	content := []byte(fmt.Sprintf("operator=%s\ntotp_secret=%s\ntotp_uri=%s\n", artifact.Operator, artifact.Secret, artifact.URI))
	if n, err := f.Write(content); err != nil {
		_ = f.Close()
		return fmt.Errorf("write bootstrap artifact %s: %w", path, err)
	} else if n != len(content) {
		_ = f.Close()
		return fmt.Errorf("write bootstrap artifact %s: %w", path, io.ErrShortWrite)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync bootstrap artifact %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close bootstrap artifact %s: %w", path, err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open bootstrap artifact directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync bootstrap artifact directory: %w", err)
	}
	committed = true
	return nil
}

// loadAPIKey reads path, trims surrounding whitespace, and returns the
// key. An empty file is treated as a fatal misconfiguration: the
// daemon refuses to start with an empty bearer token rather than
// accept all-token-mismatches as a feature.
func loadAPIKey(path string) (string, error) {
	raw, err := readOwnerFile(path, "api key file")
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(bytes.TrimSpace(raw)))
	if key == "" {
		return "", fmt.Errorf("api key file %s is empty", path)
	}
	return key, nil
}

func readOwnerFile(path, kind string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s %s: %w", kind, path, err)
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s %s is a symbolic link", kind, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s %s: %w", kind, path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s %s: %w", kind, path, err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("reinspect %s %s: %w", kind, path, err)
	}
	if after.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, after) {
		return nil, fmt.Errorf("%s %s changed or became a symbolic link during open", kind, path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s %s is not a regular file", kind, path)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("%s %s has insecure mode %#o (group/world bits must be off)", kind, path, mode)
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read %s %s: %w", kind, path, err)
	}
	return raw, nil
}

func validateApprovalRoster(ctx context.Context, db *sqlitestore.DB, requesterID string, required int, allowSelf, stepUp bool) error {
	if err := policystore.ValidateIdentity(requesterID); err != nil {
		return fmt.Errorf("machine client ID: %w", err)
	}
	requester, err := db.GetUser(ctx, requesterID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("machine client ID %q is not a bootstrapped operator", requesterID)
		}
		return fmt.Errorf("load machine client operator: %w", err)
	}
	if requester.Role != store.Role("operator") {
		return fmt.Errorf("machine client ID %q is not a bootstrapped operator", requesterID)
	}
	eligible, err := db.CountEligiblePolicyVoters(ctx, "operator", requesterID, allowSelf, stepUp)
	if err != nil {
		return err
	}
	if eligible < required {
		return fmt.Errorf("required approvals %d exceed %d eligible policy voters (allow-self-approve=%v require-step-up=%v)", required, eligible, allowSelf, stepUp)
	}
	return nil
}

// defaultConfigPath returns the env-overridden default config path.
// The current server doesn't parse a config file (all options are flags);
// the path is reserved for a future release when [auth], [tls], and [store]
// blocks land.
func defaultConfigPath() string {
	if p := os.Getenv("SSHGATE_SIGNER_SERVER_CONFIG"); p != "" {
		return p
	}
	return "/etc/signer-server/config.toml"
}

// assertNonRoot mirrors signer's check. A daemon that owns
// signing capability should never run as UID 0.
func assertNonRoot() error {
	if os.Geteuid() == 0 {
		return errors.New("signer-server refuses to run as root; create a dedicated user (see install/deploy.sh)")
	}
	return nil
}

// logf writes one line to stderr with the daemon prefix. Mirrors the
// pattern used by the v1 signer main.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "signer-server: "+format+"\n", args...)
}
