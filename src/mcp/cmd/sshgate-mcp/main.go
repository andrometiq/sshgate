// Command sshgate-mcp is the SSHGate Claude Code MCP server. It is
// the binary that Claude Code spawns per session for SSH execution
// against registered servers.
//
// Configuration (all paths in $XDG_CONFIG_HOME/sshgate/, default
// ~/.config/sshgate/):
//
//	servers.json          — alias → host/port/user registry
//	ssh/sshgate_ed25519   — SSH client private key (mode 0o600)
//	known_hosts           — TOFU host-key store (mode 0o600)
//
// Environment overrides:
//
//	$XDG_CONFIG_HOME         — config root (default ~/.config)
//	$SSHGATE_SIGNER_SOCK  — signer socket (default /run/sshgatesigner/sock)
//
// Stdio: stdout is the JSON-RPC channel (do not log there). stderr
// is the operator log. stdin EOF is a clean shutdown signal.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp"
	"github.com/karthikeyan5/sshgate/src/mcp/livelog"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

const (
	defaultSignerSock = "/run/sshgatesigner/sock"
	// signTimeout is the MCP sign client's total per-request budget
	// (dial + write + read). It MUST outlast the signer's whole
	// connection handler — and therefore the full human approval window —
	// so a verdict that resolves late is DELIVERED, not stranded as
	// "verdict undelivered". Sourced from sigwire's single source of
	// truth, which guarantees ClientSignTimeout > SignerHandlerTimeout >
	// ApprovalWindow by construction. Do NOT replace this with a
	// hand-rolled literal: a hardcoded 75s against the 5-minute approval
	// window (the client abandoning the socket ~4 min early) was the
	// 2026-07-01 verdict-undelivered root cause. See
	// TestSignTimeoutOutlastsSignerHandler.
	signTimeout = sigwire.ClientSignTimeout
	// sshTimeout bounds a single SSH dial+exec.
	sshTimeout = 30 * time.Second
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("sshgate-mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	showVersion := fs.Bool("version", false, "Print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(os.Stdout, "sshgate-mcp %s\n", mcp.Version)
		return 0
	}

	logger := log.New(os.Stderr, "sshgate-mcp: ", log.LstdFlags)

	cfgRoot, err := configRoot()
	if err != nil {
		logger.Printf("config root: %v", err)
		return 1
	}

	socketPath := os.Getenv("SSHGATE_SIGNER_SOCK")
	if socketPath == "" {
		socketPath = defaultSignerSock
	}

	server, err := buildServer(cfgRoot, socketPath, logger)
	if err != nil {
		logger.Printf("startup: %v", err)
		return 1
	}

	keyPath := filepath.Join(cfgRoot, "ssh", "sshgate_ed25519")
	regPath := filepath.Join(cfgRoot, "servers.json")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Printf("ready (registry=%s key=%s signer=%s)", regPath, keyPath, socketPath)
	if err := server.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		logger.Printf("serve: %v", err)
		return 1
	}
	logger.Printf("shutdown")
	return 0
}

// buildServer constructs the MCP server (runner + SSH client + registry)
// for the given cfgRoot and signer socket, without calling Serve. This
// is the testable seam: tests can call buildServer and inspect the
// returned *mcp.Server (or error) without blocking on Serve.
//
// Security invariant: if the SSH key file EXISTS with insecure
// permissions (looser than 0600), buildServer returns a non-nil error
// and startup is aborted. If the key is simply absent, buildServer logs
// a warning and continues — the SSH client loads the key lazily at dial
// time, so a later /sshgate:setup will make the key available without a
// server restart.
func buildServer(cfgRoot, socketPath string, logger *log.Logger) (*mcp.Server, error) {
	regPath := filepath.Join(cfgRoot, "servers.json")
	keyPath := filepath.Join(cfgRoot, "ssh", "sshgate_ed25519")
	khPath := filepath.Join(cfgRoot, "known_hosts")

	servers, err := registry.New(regPath)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}

	// If the SSH key exists but has insecure permissions, abort: an
	// existing world-readable key is a security violation regardless of
	// whether we're in a fresh-install state.
	if err := requireFileIfExists(keyPath, 0o600); err != nil {
		return nil, fmt.Errorf("ssh key: %w", err)
	}
	// Warn (stderr only) when the key is simply absent — Tier-1 users
	// land here at /reload-plugins time, before /sshgate:setup runs.
	if _, statErr := os.Stat(keyPath); errors.Is(statErr, fs.ErrNotExist) {
		logger.Printf("no SSH key at %s yet — starting in unconfigured mode; server tools need it (run /sshgate:setup). status/list work without it.", keyPath)
	}

	// known_hosts is created on first contact; only enforce 0600 when
	// the file already exists.
	if err := requireFileIfExists(khPath, 0o600); err != nil {
		return nil, fmt.Errorf("known_hosts: %w", err)
	}

	signer := &signpkg.Client{SocketPath: socketPath, Timeout: signTimeout}
	sshClient := &sshpkg.Client{KeyPath: keyPath, KnownHostsPath: khPath, Timeout: sshTimeout}
	runner := &tools.Runner{
		Servers:               servers,
		Sign:                  signer,
		SSH:                   sshClient,
		SSHStdin:              sshClient,
		Xfer:                  signer,
		StagedGatePath:        stagedGatePath(cfgRoot),
		KeyPath:               keyPath,
		SignerSockPath:        socketPath,
		DefaultMaxOutputBytes: tools.DefaultOutputCapBytes,
	}

	// Tier 6b — MCP-side rolling live log (convenience surface). On by
	// default with a sane cap; configurable via cfgRoot/audit-live-cap
	// (bytes; 0 disables). A nil log is a no-op, so a disabled config or a
	// resolution error simply means "no live log."
	liveLog := buildLiveLog(cfgRoot, logger)

	// F5 — per-process state for COMMAND-STRING redaction in the live log.
	// The salt is a fresh random 32 bytes; the ruleset is the same
	// rules.Combined() the gate scrubs OUTPUT with. Both are computed ONCE
	// here at startup — the MCP is a long-running daemon, so we must NOT
	// compile the ~1 MB ruleset per command. A crypto/rand failure is fatal:
	// we will not serve with a predictable salt for HMAC marker keys.
	var redactSalt [32]byte
	if _, err := rand.Read(redactSalt[:]); err != nil {
		return nil, fmt.Errorf("redact salt: %w", err)
	}
	redactRules := redactrules.Combined()

	return &mcp.Server{
		Runner:      runner,
		Logger:      logger,
		LiveLog:     liveLog,
		RedactSalt:  redactSalt,
		RedactRules: redactRules,
	}, nil
}

// defaultLiveLogCapBytes is the default size cap of the Tier-6b rolling
// live log: 5 MiB of terminal-scrollback-style history, plenty for a
// `tail -f` operator view while staying bounded and transient.
const defaultLiveLogCapBytes int64 = 5 * 1024 * 1024

// buildLiveLog resolves the Tier-6b live-log path + cap and returns a
// *livelog.Log (or nil when disabled). The cap is read from
// cfgRoot/audit-live-cap (an integer byte count; 0 disables); a missing
// or unparseable file falls to defaultLiveLogCapBytes. The log lives at
// cfgRoot/audit-live.log.
func buildLiveLog(cfgRoot string, logger *log.Logger) *livelog.Log {
	capBytes := defaultLiveLogCapBytes
	if b, err := os.ReadFile(filepath.Join(cfgRoot, "audit-live-cap")); err == nil {
		if n, perr := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); perr == nil {
			capBytes = n
		} else {
			logger.Printf("audit-live-cap unparseable (%v); using default %d bytes", perr, defaultLiveLogCapBytes)
		}
	}
	if capBytes <= 0 {
		logger.Printf("Tier-6b live log disabled (audit-live-cap=%d)", capBytes)
		return nil
	}
	return livelog.New(filepath.Join(cfgRoot, "audit-live.log"), capBytes)
}

// stagedGatePath resolves the absolute path to the operator's locally-staged
// gate binary that update_gate hashes and pushes. $SSHGATE_GATE_BIN overrides
// it; otherwise it is cfgRoot/bin/sshgate-gate-linux-amd64 — the exact path
// `make install-local` stages to. This is NEVER an agent parameter (R5).
func stagedGatePath(cfgRoot string) string {
	if p := os.Getenv("SSHGATE_GATE_BIN"); p != "" {
		return p
	}
	return filepath.Join(cfgRoot, "bin", "sshgate-gate-linux-amd64")
}

// configRoot returns the sshgate config root, honouring
// $XDG_CONFIG_HOME (default ~/.config). Returns an error if $HOME is
// unset and $XDG_CONFIG_HOME is empty.
func configRoot() (string, error) {
	if root := os.Getenv("XDG_CONFIG_HOME"); root != "" {
		return filepath.Join(root, "sshgate"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "sshgate"), nil
}

// requireFile fails if path does not exist or its permission bits are
// looser than maxPerm (i.e. it carries any bit set in ~maxPerm &
// 0o777).
func requireFile(path string, maxPerm os.FileMode) error {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("required file %s does not exist", path)
	}
	if err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm&^maxPerm != 0 {
		return fmt.Errorf("file %s has insecure mode %#o (must be at most %#o)", path, perm, maxPerm)
	}
	return nil
}

// requireFileIfExists is requireFile but tolerates a missing file.
func requireFileIfExists(path string, maxPerm os.FileMode) error {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return requireFile(path, maxPerm)
}
