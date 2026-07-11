package tools

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// newTestKey returns a fresh OpenSSH-format ssh.PublicKey suitable for
// authorized_keys-line assertions.
func newTestKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return sshPub
}

// authLine returns the OpenSSH authorized_keys-style single line for
// pub (no options, no comment, no trailing newline). Convenience for
// table tests.
func authLine(pub ssh.PublicKey) string {
	return strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n")
}

func TestRewriteAuthorizedKeys_EmptyFile(t *testing.T) {
	pub := newTestKey(t)
	cmd := "~/.sshgate-gate/gate"

	out, err := rewriteAuthorizedKeys(nil, pub, cmd)
	if err != nil {
		t.Fatalf("rewriteAuthorizedKeys: %v", err)
	}
	want := `restrict,command="` + cmd + `",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding ` + authLine(pub) + "\n"
	if string(out) != want {
		t.Errorf("output mismatch:\ngot:  %q\nwant: %q", string(out), want)
	}
}

// TestRewriteAuthorizedKeys_ForcedOptionsGoldenPin locks the EXACT forced-command
// option list the rewrite emits — including restrict (the deny-all catch-all that
// also closes no-user-rc and future-proofs) and no-pty, both load-bearing: without
// no-pty a third-party client holding the SSHGate key could allocate a TTY and turn
// a classified-read pager interactive to escape the gate (docs/security-readonly-bypass.md
// B9); without restrict/no-user-rc a landed write to ~/.ssh/rc yields a shell outside
// the gate on the next connection. Pinning the whole string once means any change to
// the option list (dropping restrict or no-pty, reordering, adding an option) fails
// here loudly rather than silently weakening every provisioned key.
func TestRewriteAuthorizedKeys_ForcedOptionsGoldenPin(t *testing.T) {
	pub := newTestKey(t)
	cmd := "~/.sshgate-gate/gate"

	out, err := rewriteAuthorizedKeys(nil, pub, cmd)
	if err != nil {
		t.Fatalf("rewriteAuthorizedKeys: %v", err)
	}
	const wantOpts = `no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding`
	want := `restrict,command="` + cmd + `",` + wantOpts + ` ` + authLine(pub) + "\n"
	if string(out) != want {
		t.Errorf("forced-command line drifted:\ngot:  %q\nwant: %q", string(out), want)
	}
	if !strings.Contains(string(out), "no-pty") {
		t.Errorf("emitted line is missing no-pty (PTY escape reopened): %q", string(out))
	}
	if !strings.HasPrefix(string(out), "restrict,") {
		t.Errorf("emitted line is missing the restrict catch-all (no-user-rc reopened): %q", string(out))
	}
}

func TestRewriteAuthorizedKeys_RestrictedReAddIdempotent(t *testing.T) {
	pub := newTestKey(t)
	cmd := "~/.sshgate-gate/gate"
	first, err := rewriteAuthorizedKeys(nil, pub, cmd)
	if err != nil {
		t.Fatalf("first rewrite: %v", err)
	}
	// Re-run against the already-rewritten file. Output must be
	// identical (no duplicated lines).
	second, err := rewriteAuthorizedKeys(first, pub, cmd)
	if err != nil {
		t.Fatalf("second rewrite: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("re-add was not idempotent:\nfirst:  %q\nsecond: %q", string(first), string(second))
	}
}

func TestRewriteAuthorizedKeys_UnrestrictedSameKeyReplaced(t *testing.T) {
	pub := newTestKey(t)
	cmd := "~/.sshgate-gate/gate"

	// Pre-existing unrestricted entry for the same key — this is the
	// "plain authorized_keys" case (e.g. linuxserver/openssh-server
	// drops the key in verbatim).
	existing := []byte(authLine(pub) + "\n")
	out, err := rewriteAuthorizedKeys(existing, pub, cmd)
	if err != nil {
		t.Fatalf("rewriteAuthorizedKeys: %v", err)
	}
	// The output must NOT contain a line that is just the bare key
	// (the unrestricted form). The plain key should have been
	// replaced by the restricted entry.
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == authLine(pub) {
			t.Errorf("unrestricted entry survived rewrite: %q", line)
		}
	}
	if !strings.Contains(string(out), `command="`+cmd+`"`) {
		t.Errorf("output missing command= forcing: %q", string(out))
	}
}

func TestRewriteAuthorizedKeys_UnrelatedKeysPreserved(t *testing.T) {
	pub := newTestKey(t)
	other := newTestKey(t)
	cmd := "~/.sshgate-gate/gate"

	existing := []byte(
		authLine(other) + " other-user@host\n" +
			authLine(pub) + "\n",
	)
	out, err := rewriteAuthorizedKeys(existing, pub, cmd)
	if err != nil {
		t.Fatalf("rewriteAuthorizedKeys: %v", err)
	}
	// "other" must still be present, verbatim.
	if !strings.Contains(string(out), authLine(other)) {
		t.Errorf("unrelated key was dropped:\nout: %q", string(out))
	}
	// "pub" must be present exactly once, with the forcing prefix.
	occurrences := strings.Count(string(out), authLine(pub))
	if occurrences != 1 {
		t.Errorf("pubkey appears %d times; want 1", occurrences)
	}
	if !strings.Contains(string(out), `restrict,command="`+cmd+`"`+",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding "+authLine(pub)) {
		t.Errorf("restricted form missing for pub:\nout: %q", string(out))
	}
}

func TestRewriteAuthorizedKeys_CommentsPreserved(t *testing.T) {
	pub := newTestKey(t)
	other := newTestKey(t)
	cmd := "~/.sshgate-gate/gate"

	existing := []byte(
		"# managed by sshgate\n" +
			"\n" +
			authLine(other) + " backup-key\n" +
			"# old sshgate line follows\n" +
			authLine(pub) + " sshgate@laptop\n",
	)
	out, err := rewriteAuthorizedKeys(existing, pub, cmd)
	if err != nil {
		t.Fatalf("rewriteAuthorizedKeys: %v", err)
	}
	for _, c := range []string{
		"# managed by sshgate",
		"# old sshgate line follows",
		authLine(other),
	} {
		if !strings.Contains(string(out), c) {
			t.Errorf("output dropped %q:\n%s", c, out)
		}
	}
}

func TestRewriteAuthorizedKeys_ExistingRestrictedEntryReplaced(t *testing.T) {
	pub := newTestKey(t)
	cmd := "~/.sshgate-gate/gate"

	// Existing restricted entry with EXTRA options we don't reproduce
	// (e.g. an old "from=" clause). Must still be detected as a
	// matching key and replaced with our canonical form.
	existing := []byte(
		`command="/old/path",from="10.0.0.0/8" ` + authLine(pub) + "\n",
	)
	out, err := rewriteAuthorizedKeys(existing, pub, cmd)
	if err != nil {
		t.Fatalf("rewriteAuthorizedKeys: %v", err)
	}
	// Old line must be gone.
	if strings.Contains(string(out), `command="/old/path"`) {
		t.Errorf("old restricted entry survived:\n%s", out)
	}
	if !strings.Contains(string(out), `command="`+cmd+`"`) {
		t.Errorf("new restricted entry missing:\n%s", out)
	}
}

func TestRewriteAuthorizedKeys_RejectsForbiddenCmdChars(t *testing.T) {
	pub := newTestKey(t)
	cases := []string{
		`~/.sshgate-gate/gate"; rm -rf /`,
		"~/.sshgate-gate/gate\nfoo",
	}
	for _, bad := range cases {
		if _, err := rewriteAuthorizedKeys(nil, pub, bad); err == nil {
			t.Errorf("expected error for commandPath %q; got nil", bad)
		}
	}
}

func TestHasRestrictedEntryForKey(t *testing.T) {
	pub := newTestKey(t)
	other := newTestKey(t)
	cmd := "~/.sshgate-gate/gate"

	rewritten, err := rewriteAuthorizedKeys(nil, pub, cmd)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	t.Run("PresentAfterRewrite", func(t *testing.T) {
		if !hasRestrictedEntryForKey(rewritten, pub, cmd) {
			t.Errorf("hasRestrictedEntryForKey returned false after rewrite")
		}
	})

	t.Run("AbsentWhenKeyIsBare", func(t *testing.T) {
		existing := []byte(authLine(pub) + "\n")
		if hasRestrictedEntryForKey(existing, pub, cmd) {
			t.Errorf("hasRestrictedEntryForKey returned true on bare key")
		}
	})

	t.Run("AbsentForDifferentKey", func(t *testing.T) {
		if hasRestrictedEntryForKey(rewritten, other, cmd) {
			t.Errorf("hasRestrictedEntryForKey returned true for unrelated key")
		}
	})

	t.Run("AbsentForDifferentCmd", func(t *testing.T) {
		if hasRestrictedEntryForKey(rewritten, pub, "/different/path") {
			t.Errorf("hasRestrictedEntryForKey returned true for different cmd path")
		}
	})
}
