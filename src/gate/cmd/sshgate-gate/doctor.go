package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// doctorReport is `gate doctor` output: the host's jail probe, the pinned floor,
// and what the read path would do with them right now.
type doctorReport struct {
	Rung                string   `json:"rung"`
	LandlockABI         int      `json:"landlock_abi"`
	Userns              bool     `json:"userns"`
	Seccomp             bool     `json:"seccomp"`
	LSM                 []string `json:"lsm"`
	AppArmorUsernsClamp bool     `json:"apparmor_userns_clamp"`
	ProbeErr            string   `json:"probe_err,omitempty"`
	Notes               []string `json:"notes,omitempty"`
	// Floor is the pinned jail-floor ("" when none); FloorErr is set when a
	// floor file exists but cannot be trusted.
	Floor    string `json:"floor,omitempty"`
	FloorErr string `json:"floor_err,omitempty"`
	// Reads is the read-path verdict: "jailed:<rung>", "unconfined" or
	// "denied: <reason>".
	Reads string `json:"reads"`
}

// runDoctor is the `gate doctor [--json] [--pin]` ARGV subcommand: an operator
// tool (a plain shell, never the forced-command path — see runLocalSubcommand)
// that reports the host's read-jail rung. --pin writes the live rung as the
// jail-floor the read path enforces; it never lowers an existing floor. It runs
// no command and touches no audit log.
func runDoctor(args []string) int {
	asJSON, pin := false, false
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "--pin":
			pin = true
		default:
			logf("doctor: unexpected argument")
			return exitDataErr
		}
	}
	gateDir, _, err := gateDirFn()
	if err != nil {
		logf("doctor: locate gate dir: %v", err)
		return exitSoftware
	}

	rep := detectFn()
	floor, floorErr := readPinnedFloor(gateDir)
	_, statErr := os.Lstat(filepath.Join(gateDir, jailFloorFile))
	floorPresent := !errors.Is(statErr, os.ErrNotExist)
	d := doctorReport{
		Rung:                rep.Rung.String(),
		LandlockABI:         rep.LandlockABI,
		Userns:              rep.Userns,
		Seccomp:             rep.Seccomp,
		LSM:                 rep.LSMs,
		AppArmorUsernsClamp: rep.AppArmorUsernsClamp,
		Notes:               rep.Notes,
	}
	if rep.ProbeErr != nil {
		d.ProbeErr = rep.ProbeErr.Error()
	}
	switch {
	case floorErr != nil:
		d.FloorErr = floorErr.Error()
		d.Reads = "denied: jail floor: " + floorErr.Error()
	default:
		if floorPresent {
			d.Floor = floor.String()
		}
		spec, deny := confineSpecFor(rep, floor)
		switch {
		case deny != "":
			d.Reads = "denied: " + deny
		case spec == nil:
			d.Reads = confine.Rung3Unconfined.String()
		default:
			d.Reads = "jailed:" + rungLabel(spec)
		}
	}

	if pin {
		if rc := pinFloor(gateDir, rep, floor, floorErr); rc != exitOK {
			return rc
		}
		d.Floor = rep.Rung.String()
	}
	if asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(d); err != nil {
			logf("doctor: encode: %v", err)
			return exitSoftware
		}
		return exitOK
	}
	printDoctor(d)
	return exitOK
}

// pinFloor writes rep's rung as the jail-floor. It refuses (writing nothing) on
// a probe error, on rung 3 (no jail to pin), on a floor file it cannot trust,
// and when the live rung is below the existing floor: a pin only ever keeps or
// raises the floor; lowering one is a manual operator edit.
func pinFloor(gateDir string, rep confine.Report, floor confine.Rung, floorErr error) int {
	switch {
	case rep.ProbeErr != nil:
		logf("doctor: probe failed (%v); not pinning", rep.ProbeErr)
		return exitSoftware
	case rep.Rung != confine.Rung1Full:
		logf("doctor: rung %s has no jail to pin", rep.Rung)
		return exitSoftware
	case floorErr != nil:
		logf("doctor: existing %s: %v; not pinning", jailFloorFile, floorErr)
		return exitSoftware
	case rep.Rung < floor:
		logf("doctor: rung %s is below the pinned floor %s; not lowering it", rep.Rung, floor)
		return exitSoftware
	}
	if err := gate.AtomicReplace(filepath.Join(gateDir, jailFloorFile), []byte(rep.Rung.String()+"\n"), 0o644); err != nil {
		logf("doctor: write %s: %v", jailFloorFile, err)
		return exitSoftware
	}
	return exitOK
}

func printDoctor(d doctorReport) {
	orNone := func(s string) string {
		if s == "" {
			return "none"
		}
		return s
	}
	yesNo := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	clamp := "no"
	if d.AppArmorUsernsClamp {
		clamp = "yes (needs an AppArmor userns profile for rung full)"
	}
	floor := orNone(d.Floor)
	if d.FloorErr != "" {
		floor = "damaged: " + d.FloorErr
	}
	fmt.Printf("rung:                  %s\n", d.Rung)
	fmt.Printf("landlock_abi:          %d\n", d.LandlockABI)
	fmt.Printf("userns:                %s\n", yesNo(d.Userns))
	fmt.Printf("seccomp:               %s\n", yesNo(d.Seccomp))
	fmt.Printf("lsm:                   %s\n", orNone(strings.Join(d.LSM, ",")))
	fmt.Printf("apparmor_userns_clamp: %s\n", clamp)
	fmt.Printf("probe_err:             %s\n", orNone(d.ProbeErr))
	fmt.Printf("floor:                 %s\n", floor)
	fmt.Printf("reads:                 %s\n", d.Reads)
	fmt.Printf("notes:                 %s\n", orNone(strings.Join(d.Notes, "; ")))
}
