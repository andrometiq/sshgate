//go:build linux && jail_e2e

package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// TestJailMatrixPhase3 holds the gate's daemon-read legs, run through run() at
// the native Landlock ABI and at forced ABI 1. They run in-process: the
// fixture legs need the package-var seams.
func TestJailMatrixPhase3(t *testing.T) {
	spec := readSpec(pinState{}, false, false)
	res, err := gate.ExecWithRedaction(context.Background(), ":", gate.ExecOpts{Confine: &spec})
	var setup *confine.SetupError
	if res.ExitCode != 0 && errors.As(err, &setup) && attemptClass(setup, res) == confine.Absent {
		t.Skipf("SKIP jail: %s", confine.DenyReason(confine.Absent, setup.Stage, setup.Errno))
	}
	for _, abi := range []string{"native", "abi1"} {
		t.Run(abi, func(t *testing.T) {
			t.Run("G-L2-GRAMMAR", func(t *testing.T) { legLane2Unadmitted(t, abi, "G-L2-GRAMMAR", "--sg-unlisted", "grammar-flag") })
			t.Run("G-L2-REDIRECT", func(t *testing.T) { legLane2Unadmitted(t, abi, "G-L2-REDIRECT", "--user", "redirect-flag") })
		})
	}
}

// legLane2Unadmitted: a daemon-read line carrying flag, which the grammar (and,
// for a redirect flag, the refusal list) does not admit, is no daemon read. It
// takes the normal read path, where the jailed real systemctl runs, so the
// fixture client never sees the flag.
func legLane2Unadmitted(t *testing.T, abi, name, flag, effect string) {
	p := newProof(t, name)
	dir := buildLane2Fixtures(t)
	gateDir := t.TempDir()
	withGateDir(t, gateDir)
	withReadSpec(t, abi, nil)
	mode := lane2Mode(t, "report")
	direct, err := exec.Command(filepath.Join(dir, "systemctl"), "status", mode, flag).Output()
	p.Control("argv", err == nil && lane2Reported(direct, mode, flag))

	code, out, _ := runWith(t, "systemctl status "+mode+" "+flag)
	passed := lane2Reported([]byte(out), mode, flag)
	p.Effect(effect, passed)
	recs := auditRecords(t, gateDir)
	daemonRead := len(recs) == 1 && recs[0]["enforcement"] == "daemon-read"
	jailed := len(recs) == 1 && recs[0]["enforcement"] == "kernel" && recs[0]["profile"] == "ro-v1"
	p.Jailed("lane2", passed && code == exitOK && daemonRead || !passed && jailed)
	p.Observed("output", passed || !strings.Contains(out, mode))
	p.Finish()
}
