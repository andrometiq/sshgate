package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/karthikeyan5/sshgate/src/xfer"
)

// This file implements the gate's HUMAN-ONLY on-host transfer-key generation
// subcommand (`gate genkeys`). It is reachable ONLY as an ARGV subcommand —
// dispatched in main() BEFORE run() ever reads SSH_ORIGINAL_COMMAND — so the
// FORCED-COMMAND path can never reach it: OpenSSH's forced command is
// `command="~/.sshgate-gate/gate"` with NO arguments, so a gated invocation
// always has len(os.Args)==1 and the client's requested command lands in the
// env var, never in os.Args. The argv branch is thus reachable only when the
// gate binary is exec'd directly with arguments — a PLAIN shell (the
// fresh-provisioning window between paste and lock, or the box operator's own
// out-of-band admin shell). An agent CAN place the string
// `~/.sshgate-gate/gate genkeys` in SSH_ORIGINAL_COMMAND via sshgate.run, but
// that classifies as a WRITE (unknown binary), so it executes only as a child
// process after a human approves that exact, visible command — never
// agent-autonomously — and registering the resulting public keys still
// requires the separate human-only CLI + signer tap. This is the human-only
// proof for genkeys (P4 spec §6.2).
//
// SECURITY — the load-bearing invariants this file enforces:
//   - PRIVATE KEYS NEVER LEAVE THE HOST. genkeys writes private bytes ONLY via
//     key.Save (atomic 0600) on the host; it prints ONLY the two PUBLIC lines
//     (PublicText). No private key material ever reaches stdout/stderr/logs.
//   - genkeys is OUTSIDE the audited command path: it runs no /bin/sh child and
//     is not an SSH_ORIGINAL_COMMAND verb, so it touches no audit logger, no
//     redactor, and no sessionSalt (like the empty-cmd probe).
//   - FAIL CLOSED: any generate/save/load error → a GENERIC logf (never any key
//     bytes) + the right sysexit, and NO BEGIN/END block is printed, so the CLI
//     readback parser treats a partial run as a hard failure.

// Fixed markers bracketing the two PUBLIC key lines on stdout. They are a wire
// contract with the CLI readback parser (parseGenKeysReadback in src/mcp/tools);
// keep them byte-for-byte in lockstep with that parser.
const (
	xferPubkeysBeginMarker = "SSHGATE_XFER_PUBKEYS_BEGIN"
	xferPubkeysEndMarker   = "SSHGATE_XFER_PUBKEYS_END"
)

// runLocalSubcommand dispatches a gate ARGV subcommand (NOT an
// SSH_ORIGINAL_COMMAND verb). It is called from main() only when the binary was
// exec'd with arguments — i.e. over a plain shell, never through the
// forced-command path. An unknown subcommand fails closed with exitDataErr.
func runLocalSubcommand(args []string) int {
	if len(args) == 0 {
		logf("no subcommand")
		return exitDataErr
	}
	switch args[0] {
	case "genkeys":
		return runGenKeys(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	default:
		logf("unknown subcommand")
		return exitDataErr
	}
}

// runGenKeys generates (or reads back) this gate's box→box transfer keypair and
// prints the two PUBLIC lines between the fixed markers. Flags: --rotate
// overwrites existing keys. Any other argument is a usage error (exitDataErr).
//
// Idempotency: without --rotate, an existing key file is READ BACK (loaded,
// which enforces 0600) and its public half re-printed — a re-run never clobbers.
// With --rotate, or when a key is absent, a fresh key is generated and saved
// (atomic 0600). The two key files land at exactly the paths the RECV/SEND
// handlers load from (xferBoxKeyPath / xferIDKeyPath), via the same gateDirFn
// resolution — NEVER an env var.
func runGenKeys(args []string) int {
	rotate := false
	for _, a := range args {
		switch a {
		case "--rotate":
			rotate = true
		default:
			logf("genkeys: unexpected argument")
			return exitDataErr
		}
	}

	boxPath, err := xferBoxKeyPath()
	if err != nil {
		logf("genkeys: locate gate dir")
		return exitSoftware
	}
	idPath, err := xferIDKeyPath()
	if err != nil {
		logf("genkeys: locate gate dir")
		return exitSoftware
	}

	boxLine, rc := ensureBoxPublicText(boxPath, rotate)
	if rc != exitOK {
		return rc
	}
	idLine, rc := ensureIDPublicText(idPath, rotate)
	if rc != exitOK {
		return rc
	}

	// Print ONLY the two PUBLIC lines between the fixed markers, nothing else.
	// The private halves reached disk (key.Save 0600) and NEVER stdout. The
	// lines are exactly BoxKey/IDKey.PublicText, so they round-trip through
	// ParseBoxPublicText / ParseIDPublicText byte-for-byte.
	fmt.Println(xferPubkeysBeginMarker)
	fmt.Println(boxLine)
	fmt.Println(idLine)
	fmt.Println(xferPubkeysEndMarker)
	return exitOK
}

// ensureBoxPublicText returns the canonical PublicText for the box key at path,
// reading it back (idempotent) unless rotate is set or the file is absent, in
// which case it generates + atomically saves a fresh key at 0600. On any error
// it returns a generic exit code (never key bytes in the log) and "".
func ensureBoxPublicText(path string, rotate bool) (string, int) {
	if !rotate {
		if _, statErr := os.Stat(path); statErr == nil {
			k, err := xfer.LoadBoxKey(path) // enforces 0600
			if err != nil {
				logf("genkeys: existing box key unusable")
				return "", exitSoftware
			}
			return k.PublicText(), exitOK
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			logf("genkeys: stat box key")
			return "", exitSoftware
		}
	}
	k, err := xfer.GenerateBoxKey()
	if err != nil {
		logf("genkeys: generate box key")
		return "", exitSoftware
	}
	if err := k.Save(path); err != nil { // atomic 0600; writes only the private scalar
		logf("genkeys: write key")
		return "", exitSoftware
	}
	return k.PublicText(), exitOK
}

// ensureIDPublicText is the id-key sibling of ensureBoxPublicText.
func ensureIDPublicText(path string, rotate bool) (string, int) {
	if !rotate {
		if _, statErr := os.Stat(path); statErr == nil {
			k, err := xfer.LoadIDKey(path) // enforces 0600
			if err != nil {
				logf("genkeys: existing id key unusable")
				return "", exitSoftware
			}
			return k.PublicText(), exitOK
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			logf("genkeys: stat id key")
			return "", exitSoftware
		}
	}
	k, err := xfer.GenerateIDKey()
	if err != nil {
		logf("genkeys: generate id key")
		return "", exitSoftware
	}
	if err := k.Save(path); err != nil { // atomic 0600; writes only the private key
		logf("genkeys: write key")
		return "", exitSoftware
	}
	return k.PublicText(), exitOK
}
