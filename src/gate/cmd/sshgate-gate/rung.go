package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// jailFloorFile is the optional operator-written rung floor in the gate dir.
// It holds one rung name ("full" | "unconfined"). Like gate.pub it
// is static config: the command path only ever reads it.
const jailFloorFile = "jail-floor"

// detectFn probes the host's jail rung. A var only so tests can inject a probe
// error or a weaker rung; production always uses confine.Detect.
var detectFn = confine.Detect

// readPinnedFloor returns the rung floor pinned in gateDir. No file means no
// floor (Rung3Unconfined: nothing is below it). A floor that exists but cannot
// be trusted — unreadable, group/world-writable, or not a rung name — is an
// error, and the caller denies: an operator who pinned a floor must never get
// an unconfined read because the pin was damaged.
func readPinnedFloor(gateDir string) (confine.Rung, error) {
	path := filepath.Join(gateDir, jailFloorFile)
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return confine.Rung3Unconfined, nil
	}
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", jailFloorFile, err)
	}
	if mode := info.Mode().Perm(); mode&0o022 != 0 {
		return 0, fmt.Errorf("%s has insecure mode %#o (group/world write must be off)", jailFloorFile, mode)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", jailFloorFile, err)
	}
	name := strings.TrimSpace(string(b))
	for _, r := range []confine.Rung{confine.Rung1Full, confine.Rung3Unconfined} {
		if name == r.String() {
			return r, nil
		}
	}
	return 0, fmt.Errorf("%s holds %q, want full or unconfined", jailFloorFile, name)
}

// confineSpecFor turns the host probe and the pinned floor into the read jail.
// It returns ro-v1 for a full probe, nil for an unconfined probe,
// or a non-empty deny reason. It never downgrades: a probe that failed for an
// unexplained reason, or a live rung below the pinned floor, denies.
func confineSpecFor(rep confine.Report, floor confine.Rung) (*confine.Spec, string) {
	if rep.ProbeErr != nil {
		return nil, fmt.Sprintf("jail probe failed (%v); refusing to run the read unconfined", rep.ProbeErr)
	}
	if rep.Rung < floor {
		return nil, fmt.Sprintf("jail rung %s is below the pinned floor %s; refusing to run the read", rep.Rung, floor)
	}
	switch rep.Rung {
	case confine.Rung1Full:
		// Reads keep network access: the jail stops writes to the host, not
		// outbound connections (a per-server network pin is planned work).
		return &confine.Spec{Profile: confine.ProfileROv1, Net: true}, ""
	case confine.Rung3Unconfined:
		return nil, ""
	default:
		return nil, fmt.Sprintf("unknown jail rung %d; refusing to run the read", rep.Rung)
	}
}

// resolveReadConfine resolves the read jail for this process from the live
// probe and the floor pinned in the gate dir.
func resolveReadConfine() (*confine.Spec, string) {
	gateDir, _, err := gateDirFn()
	if err != nil {
		return nil, fmt.Sprintf("locate gate dir for the jail floor: %v", err)
	}
	floor, err := readPinnedFloor(gateDir)
	if err != nil {
		return nil, fmt.Sprintf("jail floor: %v; refusing to run the read", err)
	}
	return confineSpecFor(detectFn(), floor)
}

// rungLabel is the audit "rung" value for a read run under spec.
func rungLabel(spec *confine.Spec) string {
	if spec == nil {
		return confine.Rung3Unconfined.String()
	}
	return confine.Rung1Full.String()
}
