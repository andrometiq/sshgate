package main

import (
	"path/filepath"
	"testing"
)

// TestResolveInitPaths_NonDev asserts the PRODUCTION layout: root is the
// config file's grandparent, keys/pub/audit live under <root>, and the
// socket is the fixed runtime path. No filesystem, no root needed — this
// is a pure function. Audit B4/B5/B6.
func TestResolveInitPaths_NonDev(t *testing.T) {
	got, err := resolveInitPaths("/var/lib/sshgatesigner/config/config.toml", false /* dev */)
	if err != nil {
		t.Fatalf("resolveInitPaths: %v", err)
	}
	want := initPaths{
		Root:              "/var/lib/sshgatesigner",
		KeyPath:           "/var/lib/sshgatesigner/keys/gate.key",
		PubPath:           "/var/lib/sshgatesigner/keys/gate.pub",
		AuditPath:         "/var/lib/sshgatesigner/log/approvals.log",
		SockPath:          "/run/sshgatesigner/sock",
		PolicyJournalPath: "/var/lib/sshgatesigner/keys/policy-requests",
		ConfigPath:        "/var/lib/sshgatesigner/config/config.toml",
	}
	if got != want {
		t.Errorf("resolveInitPaths(non-dev) =\n  %+v\nwant\n  %+v", got, want)
	}
}

// TestResolveInitPaths_Dev asserts everything anchors under the config
// file's own directory when --dev is set with an absolute --config, so
// tests and local runs need no privileged /run or /var/lib access. The
// dev layout is FLAT (gate.key/gate.pub/approvals.log/sock under root),
// matching the existing dev branch — do not change that behavior.
func TestResolveInitPaths_Dev(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.toml")
	got, err := resolveInitPaths(configPath, true /* dev */)
	if err != nil {
		t.Fatalf("resolveInitPaths: %v", err)
	}
	want := initPaths{
		Root:              tmp,
		KeyPath:           filepath.Join(tmp, "gate.key"),
		PubPath:           filepath.Join(tmp, "gate.pub"),
		AuditPath:         filepath.Join(tmp, "approvals.log"),
		SockPath:          filepath.Join(tmp, "sock"),
		PolicyJournalPath: filepath.Join(tmp, "policy-requests"),
		ConfigPath:        configPath,
	}
	if got != want {
		t.Errorf("resolveInitPaths(dev) =\n  %+v\nwant\n  %+v", got, want)
	}
}

// TestResolveInitPaths_NonAbsoluteErrors asserts a non-absolute config
// path is rejected (production safety — the derivation is path-relative
// and a relative path would silently mis-root the state dir).
func TestResolveInitPaths_NonAbsoluteErrors(t *testing.T) {
	if _, err := resolveInitPaths("config/config.toml", false /* dev */); err == nil {
		t.Error("resolveInitPaths(relative path) = nil error; want non-nil")
	}
}

func TestResolvePolicyJournalRootConfiguredAndSafeDefault(t *testing.T) {
	var cfg tomlConfig
	cfg.Paths.Key = "/var/lib/sshgatesigner/keys/gate.key"
	got, usedDefault := resolvePolicyJournalRoot(cfg)
	if got != "/var/lib/sshgatesigner/keys/policy-requests" || !usedDefault {
		t.Fatalf("default policy journal = %q, default=%t", got, usedDefault)
	}
	cfg.Paths.PolicyJournal = "/srv/sshgate/policy-journal"
	got, usedDefault = resolvePolicyJournalRoot(cfg)
	if got != cfg.Paths.PolicyJournal || usedDefault {
		t.Fatalf("configured policy journal = %q, default=%t", got, usedDefault)
	}
}
