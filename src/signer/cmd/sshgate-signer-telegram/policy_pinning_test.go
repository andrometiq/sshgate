package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

func writePolicyPublicKeyFile(t *testing.T, content []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.pub")
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("write policy public key: %v", err)
	}
	return path
}

func TestReadPinnedPolicyPublicKeyAcceptsExactGrammar(t *testing.T) {
	want := bytes.Repeat([]byte{0xab}, ed25519.PublicKeySize)
	encoded := []byte(hex.EncodeToString(want))
	for _, suffix := range []string{"", "\n"} {
		t.Run(map[string]string{"": "without-newline", "\n": "one-newline"}[suffix], func(t *testing.T) {
			path := writePolicyPublicKeyFile(t, append(append([]byte(nil), encoded...), suffix...), 0o600)
			got, err := readPinnedPolicyPublicKey(path)
			if err != nil {
				t.Fatalf("readPinnedPolicyPublicKey: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("public key = %x; want %x", got, want)
			}
			got[0] ^= 0xff
			again, err := readPinnedPolicyPublicKey(path)
			if err != nil || !bytes.Equal(again, want) {
				t.Fatalf("second read = %x, %v; source must not alias prior result", again, err)
			}
		})
	}
}

func TestReadPinnedPolicyPublicKeyRejectsUnsafeFilePredicates(t *testing.T) {
	valid := strings.Repeat("a", 64)
	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, []byte(valid), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(directory, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readPinnedPolicyPublicKey(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("symlink error = %v", err)
		}
	})
	t.Run("not-regular", func(t *testing.T) {
		if _, err := readPinnedPolicyPublicKey(t.TempDir()); err == nil || !strings.Contains(err.Error(), "regular") {
			t.Fatalf("directory error = %v", err)
		}
	})
	t.Run("group-readable", func(t *testing.T) {
		path := writePolicyPublicKeyFile(t, []byte(valid), 0o640)
		if _, err := readPinnedPolicyPublicKey(path); err == nil || !strings.Contains(err.Error(), "insecure mode") {
			t.Fatalf("mode error = %v", err)
		}
	})
	t.Run("wrong-owner", func(t *testing.T) {
		path := writePolicyPublicKeyFile(t, []byte(valid), 0o600)
		if _, err := readPinnedPolicyPublicKeyForUID(path, ^uint32(0)); err == nil || !strings.Contains(err.Error(), "effective uid") {
			t.Fatalf("owner error = %v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		path := writePolicyPublicKeyFile(t, bytes.Repeat([]byte{'a'}, 4097), 0o600)
		if _, err := readPinnedPolicyPublicKey(path); err == nil || !strings.Contains(err.Error(), "4096") {
			t.Fatalf("oversize error = %v", err)
		}
	})
}

func TestReadPinnedPolicyPublicKeyRejectsPostOpenPathSubstitution(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "policy.pub")
	replacement := filepath.Join(directory, "replacement.pub")
	displaced := filepath.Join(directory, "displaced.pub")
	for name, content := range map[string]string{
		path:        strings.Repeat("a", 64),
		replacement: strings.Repeat("b", 64),
	} {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", filepath.Base(name), err)
		}
	}

	lstatCalls := 0
	lstat := func(name string) (os.FileInfo, error) {
		lstatCalls++
		if lstatCalls == 2 {
			if err := os.Rename(path, displaced); err != nil {
				t.Fatalf("displace opened key: %v", err)
			}
			if err := os.Rename(replacement, path); err != nil {
				t.Fatalf("substitute key path: %v", err)
			}
		}
		return os.Lstat(name)
	}

	if _, err := readPinnedPolicyPublicKeyForUIDWithLstat(path, uint32(os.Geteuid()), lstat); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("post-open substitution error = %v; want changed-file rejection", err)
	}
	if lstatCalls != 2 {
		t.Fatalf("Lstat calls = %d; want initial and post-open checks", lstatCalls)
	}
}

func TestReadPinnedPolicyPublicKeyRejectsBadContentGrammar(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"short", strings.Repeat("a", 63)},
		{"long", strings.Repeat("a", 65)},
		{"uppercase", strings.Repeat("A", 64)},
		{"space", strings.Repeat("a", 63) + " "},
		{"leading-newline", "\n" + strings.Repeat("a", 64)},
		{"two-newlines", strings.Repeat("a", 64) + "\n\n"},
		{"carriage-return", strings.Repeat("a", 64) + "\r\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writePolicyPublicKeyFile(t, []byte(test.content), 0o600)
			if _, err := readPinnedPolicyPublicKey(path); err == nil {
				t.Fatal("bad key content accepted")
			}
		})
	}
}

func TestBuildHostedPolicyAnchorIsInseparableAndValidatedBeforeNetwork(t *testing.T) {
	apiKey := writePolicyPublicKeyFile(t, []byte("api-token"), 0o600)
	policyKey := writePolicyPublicKeyFile(t, []byte(strings.Repeat("1", 64)), 0o600)
	base := hostedConfig{BaseURL: "https://hosted.example", APIKeyFile: apiKey, ClientID: "operator"}

	for _, test := range []struct {
		name string
		edit func(*hostedConfig)
		want string
	}{
		{"key-only", func(c *hostedConfig) { c.PolicyPubKeyFile = policyKey }, "configured together"},
		{"authority-only", func(c *hostedConfig) { c.PolicyAuthorityID = "pauth_" + strings.Repeat("2", 32) }, "configured together"},
		{"bad-authority", func(c *hostedConfig) {
			c.PolicyPubKeyFile = policyKey
			c.PolicyAuthorityID = "pauth_" + strings.Repeat("A", 32)
		}, "32 lowercase"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.edit(&config)
			if _, err := buildHostedBackend(config); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("buildHostedBackend error = %v; want %q", err, test.want)
			}
		})
	}

	base.PolicyPubKeyFile = policyKey
	base.PolicyAuthorityID = "pauth_" + strings.Repeat("2", 32)
	backend, err := buildHostedBackend(base)
	if err != nil {
		t.Fatalf("buildHostedBackend: %v", err)
	}
	hosted, ok := backend.(*signerkit.HostedServerBackend)
	if !ok {
		t.Fatalf("backend type = %T", backend)
	}
	publicKey, err := hosted.BaseManifestAuthorityPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(publicKey); got != strings.Repeat("1", 64) {
		t.Fatalf("pinned key = %q", got)
	}
	authorityID, err := hosted.BaseManifestAuthorityID()
	if err != nil {
		t.Fatal(err)
	}
	if authorityID != base.PolicyAuthorityID {
		t.Fatalf("authority = %q; want %q", authorityID, base.PolicyAuthorityID)
	}
}
