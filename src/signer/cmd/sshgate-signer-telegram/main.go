// Command sshgate-signer-telegram is the local approval daemon for
// SSHGate. It runs as a dedicated OS user (`sshgatesigner`) on the
// operator's laptop, owns the master Ed25519 signing key, and signs
// commands only after the configured Backend returns Approved.
//
// Flags:
//
//	--config <path>   TOML config (default:
//	                  /var/lib/sshgatesigner/config/config.toml or
//	                  $SSHGATE_SIGNER_CONFIG)
//	--init            Generate keypair + skeleton config + state dirs, exit
//	--dev             Only meaningful with --init: anchor generated paths
//	                  under $XDG_RUNTIME_DIR. No-op at runtime.
//	--version         Print version and exit
//
// On startup the daemon:
//
//  1. Fails fast if running as root (writing-to-a-master-key-file as
//     root is exactly the install-time mistake we want to catch).
//  2. Acquires an flock on <sock_dir>/sock.lock (daemon.md §3.1). A
//     second start refuses immediately.
//  3. Loads the private key via signerkit.LoadKey (mode 0o077 check).
//  4. Opens the audit log in append mode.
//  5. Builds the configured backend (currently only "stub"; "telegram"
//     is recognised as a config value but returns "not yet implemented
//     in v0.1.4").
//  6. Runs the Unix-socket server until SIGTERM/SIGINT.
//
// SIGHUP is logged as "not supported in v1; restart to apply changes"
// per daemon.md §8.2; partial reloads are explicitly disallowed.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// version is stamped from the single VERSION file at link time via
// -ldflags "-X main.version=<VERSION>" (Makefile SIGNER_VERSION_FLAGS).
// Unstamped builds keep "dev"; `make verify-versions` proves the stamp
// landed (a wrong -X path is silently ignored by the linker). This keeps
// the daemon's --version in lockstep with VERSION instead of drifting
// (it read a hardcoded 0.2.0 while VERSION said 0.1.4).
var version = "dev"

type tomlConfig struct {
	Paths struct {
		Key           string `toml:"key"`
		PubKey        string `toml:"pubkey"`
		AuditLog      string `toml:"audit_log"`
		Socket        string `toml:"socket"`
		PolicyJournal string `toml:"policy_journal"`
	} `toml:"paths"`
	Backend struct {
		Type     string         `toml:"type"`
		Telegram telegramConfig `toml:"telegram"`
		Hosted   hostedConfig   `toml:"hosted"`
	} `toml:"backend"`
}

// hostedConfig is the [backend.hosted] block, consulted only when
// backend.type = "hosted". The v2 swap-point: setting this in
// /var/lib/sshgatesigner/config/config.toml redirects approval traffic from the
// local Telegram bot to the centralized signer-server.
type hostedConfig struct {
	// BaseURL is the signer-server origin (no trailing slash),
	// e.g. https://signer-server.example.com.
	BaseURL string `toml:"base_url"`
	// APIKeyFile is the path to a 0600 file containing the
	// bearer token. Mirrors backend.telegram.token_path's "file,
	// not inline" rule (daemon.md §6).
	APIKeyFile string `toml:"api_key_file"`
	// ClientID identifies this laptop in the server's audit log.
	ClientID string `toml:"client_id"`
	// PollWaitSec bounds each /v1/poll long-poll. Default 30.
	PollWaitSec int `toml:"poll_wait_sec"`
	// TimeoutSec bounds the total per-Request budget. Default 60.
	TimeoutSec int `toml:"timeout_sec"`
}

// telegramConfig is the [backend.telegram] block. Only consulted when
// backend.type = "telegram"; an empty block is fine for stub.
type telegramConfig struct {
	// TokenPath points at a 0600 file whose entire content is the
	// @BotFather-issued bot token (no quotes, no surrounding whitespace).
	TokenPath string `toml:"token_path"`
	// AllowedUserID is the only Telegram user_id whose callbacks the
	// daemon will honour (spec §"signer-bot").
	AllowedUserID int64 `toml:"allowed_user_id"`
	// ChatStorePath is the JSON file capturing the DM chat_id learned
	// from the allowed user's first /start.
	ChatStorePath string `toml:"chatstore_path"`
	// APIBaseURL optionally routes the approval bot through a
	// maintainer-owned Bot-API reverse proxy (e.g.
	// "https://tg-proxy.example.com") instead of api.telegram.org — the
	// fix when api.telegram.org is IP-blocked. Empty => api.telegram.org
	// (default). The env var SSHGATE_TELEGRAM_API_URL overrides this.
	// Must be https:// (http:// only for a localhost proxy); the proxy
	// must preserve Telegram's "/bot<token>/<method>" path shape.
	APIBaseURL string `toml:"api_base_url"`
	// Explainer is the optional LLM-explainer block. When Enabled is
	// false (or this block is absent in the TOML), no explainer is
	// wired up and v1 rendering applies.
	Explainer explainerConfig `toml:"explainer"`
}

// explainerConfig is the [backend.telegram.explainer] block. v1.1 Task D.
type explainerConfig struct {
	Enabled    bool   `toml:"enabled"`
	Endpoint   string `toml:"endpoint"`
	Model      string `toml:"model"`
	APIKeyPath string `toml:"api_key_path"`
	TimeoutSec int    `toml:"timeout_sec"`
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("signer", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath(), "TOML config file")
	doInit := fs.Bool("init", false, "Generate keypair + skeleton config + state dirs, then exit")
	dev := fs.Bool("dev", false, "Dev mode: only meaningful with --init (anchors generated paths under $XDG_RUNTIME_DIR); ignored at runtime")
	showVersion := fs.Bool("version", false, "Print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintf(os.Stdout, "signer %s\n", version)
		return 0
	}

	if *doInit {
		if err := doInitFlow(*configPath, *dev); err != nil {
			logf("init: %v", err)
			return 1
		}
		return 0
	}

	if err := assertNonRoot(); err != nil {
		logf("%v", err)
		return 1
	}
	// Note: assertion that we're running as the `sshgatesigner` user
	// (production) vs any user (--dev) is omitted from v0.1.4. The
	// install script creates the sshgatesigner user and the systemd unit
	// runs under `User=sshgatesigner`; that's the load-bearing layer. If
	// the operator runs the binary as some other non-root user, the
	// 0o077 mask check on the key file will catch them.
	//
	// --dev is therefore a no-op on the runtime path; it only affects
	// --init (path anchoring under $XDG_RUNTIME_DIR). The flag is kept
	// declared at the top so `signer --dev --init` parses cleanly;
	// the help string for --dev says so explicitly.
	_ = dev

	cfg, err := loadConfig(*configPath)
	if err != nil {
		logf("load config: %v", err)
		return 1
	}

	// Singleton: flock <sock_dir>/sock.lock. The lockfile lives next
	// to the socket because that's the directory the operator can
	// inspect to "see what's holding the daemon."
	lockPath := cfg.Paths.Socket + ".lock"
	release, err := flockOrFail(lockPath)
	if err != nil {
		logf("%v", err)
		return 1
	}
	defer release()

	priv, err := signerkit.LoadKey(cfg.Paths.Key)
	if err != nil {
		logf("load key: %v", err)
		return 1
	}

	audit, err := signerkit.OpenAuditLog(cfg.Paths.AuditLog)
	if err != nil {
		logf("open audit log: %v", err)
		return 1
	}
	defer audit.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// F5 — per-process state for COMMAND-STRING redaction. The salt is a fresh
	// random 32 bytes; the ruleset is the same rules.Combined() the gate scrubs
	// OUTPUT with. Both are computed ONCE here at startup — the signer is a
	// long-running daemon, so we must NOT compile the ~1 MB ruleset per request.
	// A crypto/rand failure is fatal: we will not serve with a predictable salt
	// for HMAC marker keys. The SAME salt + already-compiled slice are reused by
	// the Daemon (signer audit log) AND the Telegram backend (the approval/grant
	// MESSAGE text, the 4th F5 sink) — one salt, one ruleset, for the process.
	var redactSalt [32]byte
	if _, err := rand.Read(redactSalt[:]); err != nil {
		logf("redact salt: %v", err)
		return 1
	}
	redactRules := redactrules.Combined()

	bk, err := buildBackend(ctx, cfg.Backend, redactSalt, redactRules)
	if err != nil {
		logf("build backend: %v", err)
		return 1
	}

	// Box→box transfer registry (the per-server pubkey trust anchor). It lives
	// beside the master key as <keydir>/xfer-registry.json — the RUNTIME path,
	// derived from cfg.Paths.Key (initPaths is --init-only and never runs here).
	// A missing file is an empty registry, so a daemon whose operator has not
	// registered any transfer peer still starts and simply refuses every
	// transfer at the lookup step. A present file must be 0600 (LoadXferRegistry
	// enforces the group/other-bit rejection — it is a trust anchor).
	xferRegPath := filepath.Join(filepath.Dir(cfg.Paths.Key), "xfer-registry.json")
	xferReg, err := signerkit.LoadXferRegistry(xferRegPath)
	if err != nil {
		logf("load xfer registry: %v", err)
		return 1
	}
	policyJournalRoot, usedPolicyDefault := resolvePolicyJournalRoot(cfg)
	if usedPolicyDefault {
		logf("config paths.policy_journal omitted; using safe default %s", policyJournalRoot)
	}

	// One codebase (signerkit phase 4): the local signer constructs its core
	// through signerkit.New instead of a signerkit.Daemon struct literal, so this
	// front-end and the embeddable/hosted front-end share ONE signing core.
	// The wiring is byte-for-byte the same as the old literal: the file key
	// loaded above is passed as the crypto.Signer identity (an
	// ed25519.PrivateKey satisfies crypto.Signer, and signBytes pins
	// crypto.Hash(0) so a minted envelope is identical to the pre-seam
	// ed25519.Sign — proven by the phase-0 envelope golden); the same audit
	// log, xfer registry, and single-sourced redaction salt+rules go in, and
	// NowFunc stays nil (⇒ time.Now), exactly as the literal left it. New's ONLY
	// error returns are a nil Signer or nil Audit, both unreachable here because
	// LoadKey and OpenAuditLog above already returned non-nil-or-failed (C9;
	// proven in new_unreachable_test.go). The error is still checked so no
	// future wiring change can construct a broken Service silently.
	svc, err := signerkit.New(signerkit.Config{
		Signer:            priv,
		Backend:           bk,
		Audit:             audit,
		XferRegistry:      xferReg,
		PolicyJournalRoot: policyJournalRoot,
		RedactSalt:        redactSalt,
		RedactRules:       redactRules,
	})
	if err != nil {
		logf("construct signer: %v", err)
		return 1
	}
	defer func() {
		if err := svc.Close(); err != nil {
			logf("close policy journal: %v", err)
		}
	}()
	if err := svc.PolicyRecoveryError(); err != nil {
		logf("policy authority temporarily unavailable after startup recovery: %v (ordinary signing remains available)", err)
	}
	// HandlerTimeout bounds the WHOLE connection (request read + approval
	// wait + response write) under serveOne's single absolute deadline.
	// It is pinned to sigwire.SignerHandlerTimeout, which is defined as
	// ApprovalWindow + slack, so it can never fall at/below the window and
	// strand an approved-but-undelivered signature. See sigwire/timeouts.go.
	srv := &signerkit.Server{Path: cfg.Paths.Socket, Handler: svc, HandlerTimeout: sigwire.SignerHandlerTimeout}

	// SIGHUP: log "restart to apply changes" and continue.
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	hupDone := make(chan struct{})
	go func() {
		defer close(hupDone)
		for {
			select {
			case <-hupCh:
				logf("SIGHUP received; config reload not supported in v1 — restart to apply changes")
			case <-ctx.Done():
				signal.Stop(hupCh)
				return
			}
		}
	}()

	logf("ready (socket=%s backend=%s)", cfg.Paths.Socket, cfg.Backend.Type)
	listenErr := srv.Listen(ctx)
	logf("shutting down")
	stop()
	<-hupDone
	if listenErr != nil {
		logf("listen returned: %v", listenErr)
	}
	logf("stopped")
	return 0
}

// loadConfig reads the TOML file at path and returns its parsed shape.
// Empty paths in the config are tolerated only when produced by --init;
// the production daemon refuses to start with empty path fields.
func loadConfig(path string) (tomlConfig, error) {
	var cfg tomlConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("decode %s: %w", path, err)
	}
	if cfg.Paths.Key == "" {
		return cfg, errors.New("config missing paths.key")
	}
	if cfg.Paths.AuditLog == "" {
		return cfg, errors.New("config missing paths.audit_log")
	}
	if cfg.Paths.Socket == "" {
		return cfg, errors.New("config missing paths.socket")
	}
	if cfg.Backend.Type == "" {
		return cfg, errors.New("config missing backend.type")
	}
	return cfg, nil
}

func resolvePolicyJournalRoot(cfg tomlConfig) (string, bool) {
	if cfg.Paths.PolicyJournal != "" {
		return cfg.Paths.PolicyJournal, false
	}
	return filepath.Join(filepath.Dir(cfg.Paths.Key), "policy-requests"), true
}

// buildBackend returns the Backend implementation for the configured
// type. "telegram" loads the bot token from the configured token file,
// validates it via getMe, then starts the polling loop. ctx scopes the
// polling goroutine — when ctx is cancelled (SIGTERM), polling exits.
func buildBackend(ctx context.Context, bcfg struct {
	Type     string         `toml:"type"`
	Telegram telegramConfig `toml:"telegram"`
	Hosted   hostedConfig   `toml:"hosted"`
}, redactSalt [32]byte, redactRules []redact.Rule) (signerkit.Backend, error) {
	switch bcfg.Type {
	case "stub":
		return signerkit.StubBackend{}, nil
	case "telegram":
		return buildTelegramBackend(ctx, bcfg.Telegram, redactSalt, redactRules)
	case "hosted":
		return buildHostedBackend(bcfg.Hosted)
	default:
		return nil, fmt.Errorf("unknown backend type %q", bcfg.Type)
	}
}

// buildHostedBackend reads the bearer token file and constructs the
// HostedServerBackend. It does NOT probe the server with a /healthz
// call: a misconfigured base_url surfaces on the first sign request
// rather than blocking daemon startup (the daemon still serves
// "error" responses to the MCP, which surfaces the operator's
// misconfiguration without preventing other v1 backends from
// continuing to work after a swap-back).
func buildHostedBackend(c hostedConfig) (signerkit.Backend, error) {
	if c.BaseURL == "" {
		return nil, errors.New(`config missing backend.hosted.base_url`)
	}
	if c.APIKeyFile == "" {
		return nil, errors.New(`config missing backend.hosted.api_key_file`)
	}
	if c.ClientID == "" {
		return nil, errors.New(`config missing backend.hosted.client_id`)
	}
	keyRaw, err := readOwnerSecretFile(c.APIKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read hosted api key %s: %w", c.APIKeyFile, err)
	}
	key := string(bytes.TrimSpace(keyRaw))
	if key == "" {
		return nil, fmt.Errorf("hosted api key file %s is empty", c.APIKeyFile)
	}
	pollWait := time.Duration(c.PollWaitSec) * time.Second
	if pollWait == 0 {
		pollWait = 30 * time.Second
	}
	timeout := time.Duration(c.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	logf("hosted backend ready (base_url=%s client_id=%s poll_wait=%s timeout=%s)",
		c.BaseURL, c.ClientID, pollWait, timeout)
	return &signerkit.HostedServerBackend{
		BaseURL:    c.BaseURL,
		APIKey:     key,
		ClientID:   c.ClientID,
		HTTPClient: &http.Client{Timeout: timeout + 10*time.Second},
		PollWait:   pollWait,
		Timeout:    timeout,
	}, nil
}

// buildTelegramBackend reads the bot token, constructs the backend
// (which calls getMe internally — daemon.md §11 "fail fast at the
// boundary"), and starts the polling goroutine before returning.
func buildTelegramBackend(ctx context.Context, c telegramConfig, redactSalt [32]byte, redactRules []redact.Rule) (signerkit.Backend, error) {
	if c.TokenPath == "" {
		return nil, errors.New(`config missing backend.telegram.token_path`)
	}
	if c.AllowedUserID == 0 {
		return nil, errors.New(`config missing backend.telegram.allowed_user_id`)
	}
	if c.ChatStorePath == "" {
		return nil, errors.New(`config missing backend.telegram.chatstore_path`)
	}

	tokenRaw, err := readOwnerSecretFile(c.TokenPath)
	if err != nil {
		return nil, fmt.Errorf("read token: %w", err)
	}
	token := string(bytes.TrimSpace(tokenRaw))
	if token == "" {
		return nil, fmt.Errorf("token file %s is empty", c.TokenPath)
	}

	// Optional custom Bot-API endpoint: route the approval bot through a
	// maintainer-owned reverse proxy when api.telegram.org is IP-blocked.
	// Env SSHGATE_TELEGRAM_API_URL wins over backend.telegram.api_base_url
	// (mirrors the token-on-disk precedents). Empty => default
	// api.telegram.org. Validated so a typo can't leak the token.
	apiBase := strings.TrimSpace(c.APIBaseURL)
	if env := strings.TrimSpace(os.Getenv("SSHGATE_TELEGRAM_API_URL")); env != "" {
		apiBase = env
	}
	apiEndpoint, err := backend.APIEndpointForBase(apiBase)
	if err != nil {
		return nil, err
	}

	tb, err := backend.NewTelegramBackend(backend.TelegramOptions{
		BotToken:      token,
		AllowedUserID: c.AllowedUserID,
		ChatStore:     &backend.FileChatStore{Path: c.ChatStorePath},
		APIEndpoint:   apiEndpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("new telegram backend: %w", err)
	}
	// F5 (4th sink): wire the SAME per-process salt + already-compiled ruleset
	// the Daemon uses so the approval/grant MESSAGE text redacts the secret
	// (secret-only — the command shape stays visible). Display-only: the signed/
	// executed command is the raw request command, never this display copy.
	tb.RedactSalt = redactSalt
	tb.RedactRules = redactRules
	if apiEndpoint != "" {
		// apiBase carries no token — safe to log; helps the operator
		// confirm the bypass endpoint is active.
		logf("telegram: routing Bot-API via custom endpoint %s (api.telegram.org bypass)", apiBase)
	}

	// Optional: wire up the LLM command explainer (v1.1 Task D). The
	// daemon refuses to start if [backend.telegram.explainer] enabled =
	// true but the configured key file is missing — silent fallback is
	// worse than fail-fast for a misconfigured operator.
	if c.Explainer.Enabled {
		ex, err := buildExplainer(c.Explainer)
		if err != nil {
			return nil, fmt.Errorf("build explainer: %w", err)
		}
		tb.Explainer = ex
		if c.Explainer.TimeoutSec > 0 {
			tb.ExplainerTimeout = time.Duration(c.Explainer.TimeoutSec) * time.Second
		}
		logf("telegram explainer enabled (model=%s endpoint=%s timeout=%s)",
			c.Explainer.Model, c.Explainer.Endpoint, tb.ExplainerTimeout)
	}

	if err := tb.Run(ctx); err != nil {
		return nil, fmt.Errorf("start telegram polling: %w", err)
	}
	logf("telegram backend ready (allowed_user_id=%d chatstore=%s)", c.AllowedUserID, c.ChatStorePath)
	return tb, nil
}

// buildExplainer validates the explainer config block and returns a
// configured OpenAICompatibleExplainer. Errors are wrapped with
// per-field context so a misconfiguration message points the operator
// at the exact TOML key.
func buildExplainer(c explainerConfig) (backend.Explainer, error) {
	if c.Endpoint == "" {
		return nil, errors.New("config missing backend.telegram.explainer.endpoint")
	}
	if c.Model == "" {
		return nil, errors.New("config missing backend.telegram.explainer.model")
	}
	if c.APIKeyPath == "" {
		return nil, errors.New("config missing backend.telegram.explainer.api_key_path")
	}
	keyRaw, err := readOwnerSecretFile(c.APIKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read explainer api key %s: %w", c.APIKeyPath, err)
	}
	key := string(bytes.TrimSpace(keyRaw))
	if key == "" {
		return nil, fmt.Errorf("explainer api key file %s is empty", c.APIKeyPath)
	}
	timeout := 5 * time.Second
	if c.TimeoutSec > 0 {
		timeout = time.Duration(c.TimeoutSec) * time.Second
	}
	return &backend.OpenAICompatibleExplainer{
		Endpoint:   c.Endpoint,
		Model:      c.Model,
		APIKey:     key,
		HTTPClient: &http.Client{Timeout: timeout},
		Timeout:    timeout,
	}, nil
}

func readOwnerSecretFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("secret file is a symbolic link")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if after.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, after) {
		return nil, fmt.Errorf("secret file changed or became a symbolic link during open")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("secret file is not a regular file")
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("secret file has insecure mode %#o (group/world bits must be off)", mode)
	}
	return io.ReadAll(f)
}

// defaultConfigPath returns the value of $SSHGATE_SIGNER_CONFIG if set,
// otherwise the canonical /var/lib/sshgatesigner/config/config.toml.
// The systemd unit always passes --config explicitly; this default is
// only used for hand-runs.
func defaultConfigPath() string {
	if p := os.Getenv("SSHGATE_SIGNER_CONFIG"); p != "" {
		return p
	}
	return "/var/lib/sshgatesigner/config/config.toml"
}

// assertNonRoot returns an error if the process is running as UID 0.
// Daemons that hold a master signing key should NEVER run as root — a
// compromised daemon then has the kernel.
func assertNonRoot() error {
	if os.Geteuid() == 0 {
		return errors.New("signer refuses to run as root; create a dedicated user (run scripts/install.sh)")
	}
	return nil
}

// flockOrFail acquires an exclusive non-blocking flock on lockPath and
// returns a function that releases it. If the lock is held by another
// live process, flockOrFail returns an error rather than blocking.
func flockOrFail(lockPath string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir lock dir: %w", err)
	}
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o660)
	if err != nil {
		return nil, fmt.Errorf("open lockfile: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another signer instance is running (lock held on %s)", lockPath)
		}
		return nil, fmt.Errorf("flock %s: %w", lockPath, err)
	}
	// Stamp the PID so an operator running `cat sock.lock` sees what
	// holds the lock.
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		// We don't remove the lockfile: a stale empty file is fine,
		// and removal races with the next start trying to open it.
	}, nil
}

// initPaths holds the resolved on-disk locations for `--init`.
type initPaths struct {
	Root, KeyPath, PubPath, AuditPath, SockPath, PolicyJournalPath, ConfigPath string
}

// resolveInitPaths computes the init layout from the --config path. It
// performs NO I/O (so it is unit-testable unprivileged); doInitFlow does
// the MkdirAll/keygen/config-write using the result.
//
// Production (non-dev): root is the config file's GRANDPARENT
// (<root>/config/config.toml -> <root>), keys/pub/audit live under
// <root>/keys + <root>/log, and the socket is the fixed runtime path
// /run/sshgatesigner/sock provisioned by the systemd unit
// (RuntimeDirectory=sshgatesigner). A non-absolute configPath is rejected
// — the path-relative derivation would otherwise silently mis-root the
// state dir (audit B4/B5/B6).
//
// Dev (--init --dev): everything is anchored FLAT under the config file's
// own directory (or $XDG_RUNTIME_DIR/signer-<pid> when no absolute
// --config is given) so tests and local runs need no privileged /run or
// /var/lib access. This preserves the existing dev layout exactly.
func resolveInitPaths(configPath string, dev bool) (initPaths, error) {
	if dev {
		var root string
		if configPath != "" && filepath.IsAbs(configPath) {
			root = filepath.Dir(configPath)
		} else {
			runtime := os.Getenv("XDG_RUNTIME_DIR")
			if runtime == "" {
				runtime = filepath.Join(os.TempDir(), "signer-dev")
			}
			root = filepath.Join(runtime, "signer-"+strconv.Itoa(os.Getpid()))
		}
		return initPaths{
			Root:              root,
			KeyPath:           filepath.Join(root, "gate.key"),
			PubPath:           filepath.Join(root, "gate.pub"),
			AuditPath:         filepath.Join(root, "approvals.log"),
			SockPath:          filepath.Join(root, "sock"),
			PolicyJournalPath: filepath.Join(root, "policy-requests"),
			ConfigPath:        configPath,
		}, nil
	}

	// Production: derive the state root from the --config grandparent so
	// the operator controls the layout. install.sh passes
	// --config /var/lib/sshgatesigner/config/config.toml ->
	// root = /var/lib/sshgatesigner (audit B4 — previously hardcoded
	// /var/lib/signer, which the unprivileged sshgatesigner user could
	// not create).
	if configPath == "" || !filepath.IsAbs(configPath) {
		return initPaths{}, fmt.Errorf("non-dev --init requires an absolute --config path (e.g. /var/lib/sshgatesigner/config/config.toml); got %q", configPath)
	}
	root := filepath.Dir(filepath.Dir(configPath))
	return initPaths{
		Root:              root,
		KeyPath:           filepath.Join(root, "keys", "gate.key"),
		PubPath:           filepath.Join(root, "keys", "gate.pub"),
		AuditPath:         filepath.Join(root, "log", "approvals.log"),
		PolicyJournalPath: filepath.Join(root, "keys", "policy-requests"),
		// Socket is a fixed runtime path provisioned by the systemd unit
		// (RuntimeDirectory=sshgatesigner) — audit B5.
		SockPath:   "/run/sshgatesigner/sock",
		ConfigPath: configPath,
	}, nil
}

// doInitFlow generates a fresh keypair, creates the state directories,
// and writes a skeleton TOML config at configPath. The flow is
// idempotent only in the sense of "second run fails clearly" — it
// refuses to overwrite existing keys (so an accidental --init does not
// silently rotate the master key).
//
// In --dev mode, paths are rooted under $XDG_RUNTIME_DIR/signer-<pid>
// so the operator can run the daemon entirely in userspace; --config is
// resolved relative to that root if it does not look absolute.
func doInitFlow(configPath string, dev bool) error {
	p, err := resolveInitPaths(configPath, dev)
	if err != nil {
		return err
	}
	keyPath, pubPath, auditPath, sockPath, policyJournalPath := p.KeyPath, p.PubPath, p.AuditPath, p.SockPath, p.PolicyJournalPath

	// Make the directories the daemon will need.
	dirs := []string{
		filepath.Dir(keyPath),
		filepath.Dir(auditPath),
		filepath.Dir(sockPath),
		filepath.Dir(policyJournalPath),
		filepath.Dir(configPath),
	}
	for _, d := range dirs {
		if d == "" || d == "." {
			continue
		}
		if err := os.MkdirAll(d, 0o750); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	if err := signerkit.GenerateKeyPair(keyPath, pubPath); err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	// Write a skeleton config. Refuse to overwrite — the operator
	// might have hand-customised an existing config.
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing config %s", configPath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat config: %w", err)
	}

	body := fmt.Sprintf(`# signer v0.1.4 configuration

[paths]
key       = %q
pubkey    = %q
audit_log = %q
socket    = %q
policy_journal = %q

[backend]
# "stub" denies every request; used by the phase-1 e2e test that proves
# the cryptographic loop without a human in the loop. Switch to
# "telegram" once task 2.1 lands.
type = "stub"
`, keyPath, pubPath, auditPath, sockPath, policyJournalPath)

	// 0600: the daemon runs as sshgatesigner and reads this as the file owner
	// (systemd User=sshgatesigner; --init runs under `sudo -u sshgatesigner`), so
	// group-read is never needed. Group traversal on the signer home is for the
	// audit log / peer.json, not this config; keep the config owner-only.
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	logf("init: keys at %s, %s", keyPath, pubPath)
	logf("init: audit log at %s", auditPath)
	logf("init: socket at %s", sockPath)
	logf("init: config at %s", configPath)
	return nil
}

// logf writes one line to stderr with the "signer: " prefix. Errors
// from the write are intentionally ignored — there is no recovery for
// "could not write to stderr."
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "signer: "+format+"\n", args...)
}
