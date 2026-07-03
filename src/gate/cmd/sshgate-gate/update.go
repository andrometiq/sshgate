package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/karthikeyan5/sshgate/src/gate"
)

// maxGateBinaryBytes bounds the SSHGATE_UPDATE stdin read. A gate binary is
// single-digit MB; 64 MiB is generous headroom while capping a hostile or
// runaway stream so io.ReadAll can never exhaust memory. It is a var (not a
// const) only so a test can shrink it to exercise the over-cap refusal without
// a 64 MiB fixture; production never reassigns it.
var maxGateBinaryBytes int64 = 64 << 20

// minGateBinaryBytes rejects an absurdly small "binary". A hash match already
// pins the exact bytes, but a mistaken tiny staged file should never land over
// the gate; a real stripped gate binary is comfortably above this floor.
const minGateBinaryBytes = 256 << 10

// updateHexLen is the hex length of a SHA-256 digest (32 bytes).
const updateHexLen = 64

// updateVerbPrefix is the signed admin verb that carries the committed hash.
const updateVerbPrefix = "SSHGATE_UPDATE "

// archMachine maps the running gate's GOARCH to the ELF machine a replacement
// binary MUST declare. A binary built for a different arch passes the ELF-magic
// check but bricks the gate on its next exec ("exec format error"), so an exact
// match is required for the arch we are replacing.
var archMachine = map[string]elf.Machine{
	"amd64":   elf.EM_X86_64,
	"arm64":   elf.EM_AARCH64,
	"386":     elf.EM_386,
	"arm":     elf.EM_ARM,
	"ppc64le": elf.EM_PPC64,
	"riscv64": elf.EM_RISCV,
	"s390x":   elf.EM_S390,
}

// handleUpdate implements the signed SSHGATE_UPDATE verb: replace THIS gate's
// own binary in place with operator-approved bytes. It is reached only on the
// signed path after VerifySigned succeeded (authentic, unexpired, host-bound)
// and only on a Tier-2 gate (pubkey != nil) — a Tier-1 gate denies the signed
// line upstream at exit 77, so this code never runs there.
//
// SECURITY. The human's approval commits to the SHA-256 of the exact new binary
// (carried inside the signed Cmd, so tampering the hash breaks the signature).
// This handler reads the new bytes from the gate's OWN os.Stdin (the SSH
// channel), hashes them, and writes NOTHING unless the hash matches — so an
// approved update authorises exactly one binary and can never be swapped for
// other code, on the wire or by a compromised agent. The bytes are consumed
// HERE as data and are NEVER handed to a shell child (the executor's
// /dev/null-stdin hardening is on a different path and stays untouched), so
// this does not reopen the stdin-exec vector.
//
// It ALWAYS returns an exit code and never falls through to classify/exec:
//
//	65 (EX_DATAERR)  — malformed hash, empty/oversized/undersized stdin,
//	                   hash mismatch, non-ELF, or wrong-arch ELF. Writes nothing.
//	70 (EX_SOFTWARE) — could not locate or replace the binary. Old gate intact.
//	0                — replaced; prints "SSHGATE_UPDATED sha256=… size=… rev=…".
func handleUpdate(audit *gate.AuditLogger, innerCmd string) int {
	// 1. Anchored parse: innerCmd MUST equal "SSHGATE_UPDATE <64 lowercase hex>"
	//    exactly. Reject any trailing content (belt-and-braces with the
	//    never-exec guarantee above). The caller guaranteed the prefix.
	hexHash := innerCmd[len(updateVerbPrefix):]
	if len(hexHash) != updateHexLen || !isLowerHex(hexHash) {
		logf("update: malformed hash argument (want exactly %d lowercase hex chars)", updateHexLen)
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}
	want, err := hex.DecodeString(hexHash)
	if err != nil {
		logf("update: hash decode: %v", err)
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}

	// 2. Bounded read of the gate's OWN stdin — LimitReader, never bare
	//    io.ReadAll, so a hostile stream cannot exhaust memory. The +1 lets us
	//    detect an over-cap stream.
	body, err := io.ReadAll(io.LimitReader(os.Stdin, maxGateBinaryBytes+1))
	if err != nil {
		logf("update: read stdin: %v", err)
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}
	switch {
	case len(body) == 0:
		logf("update: no binary on stdin")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	case int64(len(body)) > maxGateBinaryBytes:
		logf("update: binary exceeds %d-byte cap", maxGateBinaryBytes)
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	case len(body) < minGateBinaryBytes:
		logf("update: binary too small (%d bytes)", len(body))
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}

	// 3. Hash gate: install ONLY the exact approved bytes. The hash is public
	//    (it is in the signed command the peer sent), so a plain compare is
	//    correct — there is no secret to leak by timing.
	got := sha256.Sum256(body)
	if !bytes.Equal(got[:], want) {
		logf("update: binary hash mismatch — refusing (approved %s, got %x)", hexHash, got)
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}

	// 4. Sanity BEFORE any write: a valid ELF for THIS gate's arch (else the
	//    next exec bricks the gate). Best-effort build revision for the marker.
	if err := checkGateELF(body); err != nil {
		logf("update: %v", err)
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}
	rev := binaryRevision(body)

	// 5. Locate THIS gate's own path (os.Executable via gateDirFn — not an env
	//    var, so it cannot be redirected).
	_, binPath, err := gateDirFn()
	if err != nil {
		logf("update: locate gate: %v", err)
		auditNoExec(audit, innerCmd, "write", "signed", exitSoftware)
		return exitSoftware
	}

	// 6. Best-effort backup of the current binary to gate.bak. This is an
	//    OUT-OF-BAND recovery aid only — the forced command pins the gate path,
	//    so a bricked gate cannot self-heal via the gated key; restoring
	//    gate.bak needs separate shell/console access. A backup failure does
	//    NOT abort the update.
	if cur, rerr := os.ReadFile(binPath); rerr == nil {
		if berr := gate.AtomicReplace(binPath+".bak", cur, 0o755); berr != nil {
			logf("update: backup to %s.bak failed (proceeding): %v", binPath, berr)
		}
	} else {
		logf("update: could not read current binary for backup (proceeding): %v", rerr)
	}

	// 7. Atomic in-place replace. gate.pub and the dir layout are untouched
	//    (only the gate binary inode changes).
	if err := gate.AtomicReplace(binPath, body, 0o755); err != nil {
		logf("update: replace failed: %v", err)
		auditNoExec(audit, innerCmd, "write", "signed", exitSoftware)
		return exitSoftware
	}

	// 8. Audit the completed update, then 9. print the success marker (the MCP
	//    reads "SSHGATE_UPDATED" as confirmation and checks the echoed hash).
	auditNoExec(audit, innerCmd, "write", "signed", exitOK)
	fmt.Printf("SSHGATE_UPDATED sha256=%s size=%d rev=%s\n", hexHash, len(body), rev)
	return exitOK
}

// isLowerHex reports whether s is non-empty and every byte is a lowercase hex
// digit. We pin lowercase because the MCP emits hex.EncodeToString (lowercase)
// and the anchored form must be exact.
func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return len(s) > 0
}

// checkGateELF verifies body is a valid ELF whose machine matches the running
// gate's GOARCH. A wrong-arch (or non-)ELF that somehow matched the approved
// hash would still brick the gate on the next exec, so this is a fail-closed
// pre-write guard.
func checkGateELF(body []byte) error {
	f, err := elf.NewFile(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("not a valid ELF binary: %w", err)
	}
	defer f.Close()
	want, ok := archMachine[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("cannot validate ELF arch for GOARCH=%s — refusing", runtime.GOARCH)
	}
	if f.Machine != want {
		return fmt.Errorf("binary arch mismatch: ELF machine %v, gate needs %v (GOARCH=%s) — refusing to brick the gate", f.Machine, want, runtime.GOARCH)
	}
	return nil
}

// binaryRevision extracts the vcs.revision (short) from body's Go buildinfo, or
// "unknown" if body carries none / cannot be parsed. Best-effort: the
// buildinfo section survives -trimpath -ldflags='-s -w'.
func binaryRevision(body []byte) string {
	bi, err := buildinfo.Read(bytes.NewReader(body))
	if err != nil {
		return "unknown"
	}
	return shortRevision(bi.Settings)
}

// runningGateVersion reports THIS running gate's build revision for the
// unsigned SSHGATE_VERSION probe.
func runningGateVersion() string {
	rev := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		rev = shortRevision(bi.Settings)
	}
	return "SSHGATE_VERSION rev=" + rev
}

// shortRevision returns the vcs.revision setting truncated to 12 chars, or
// "unknown" when absent.
func shortRevision(settings []debug.BuildSetting) string {
	for _, s := range settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			if len(s.Value) > 12 {
				return s.Value[:12]
			}
			return s.Value
		}
	}
	return "unknown"
}
