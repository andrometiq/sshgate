package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// doctorReport is `gate doctor` output: the jail pin, the host facts, one jail
// attempt, and what an unsigned read would do with them right now.
type doctorReport struct {
	Pin                 string   `json:"pin"` // absent | valid | damaged
	PinError            string   `json:"pin_error,omitempty"`
	PinNet              string   `json:"pin_net,omitempty"`
	AcceptFS            []string `json:"accept_fs,omitempty"`
	Attempt             string   `json:"attempt"` // kernel, or the attempt's deny reason
	LandlockABI         int      `json:"landlock_abi"`
	MaxUserNS           int      `json:"max_user_namespaces"`
	AppArmorUsernsClamp bool     `json:"apparmor_userns_clamp"`
	SeccompFilter       bool     `json:"seccomp_filter"`
	DevShm              bool     `json:"dev_shm"`
	LSM                 []string `json:"lsm"`
	Reads               string   `json:"reads"`
	Label               string   `json:"label"`
	Notes               []string `json:"notes,omitempty"`
}

// runDoctor is the `gate doctor [--json]` ARGV subcommand: an operator tool (a
// plain shell, never the forced-command path — see runLocalSubcommand) that
// reports the read jail. It makes one jail attempt with `:` and changes
// nothing: no pin is written and no audit record. Pinning (--pin) arrives with
// the doctor rehearsal; until then it is refused.
func runDoctor(args []string) int {
	asJSON := false
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "--pin":
			logf("doctor: --pin is not available in this build; nothing was written")
			return exitDataErr
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
	d := doctor(gateDir)
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

// doctor reports what the read router would do: it reads the pin with the
// router's reader and takes the host capability the SSHGATE_JAIL verb reports
// (one unsealed `:` attempt routed like a read; none for a damaged pin).
func doctor(gateDir string) doctorReport {
	facts := hostFactsFn()
	d := doctorReport{
		LandlockABI: facts.LandlockABI, MaxUserNS: facts.MaxUserNS, AppArmorUsernsClamp: facts.AppArmorUsernsClamp,
		SeccompFilter: facts.SeccompFilter, DevShm: facts.DevShmDir, LSM: facts.LSMs,
	}
	pin := jailPinFn()
	_, floorErr := os.Lstat(filepath.Join(gateDir, jailFloorFile))
	switch {
	case pin.legacyFloor:
		d.Pin, d.PinError = "damaged", pin.damaged
		d.Notes = append(d.Notes, "a jail-floor file from an earlier release is present and there is no jail pin, so reads are denied. Re-pin with 'gate doctor --pin' (available from the next release step), or remove jail-floor to run reads classifier-only where the host has no usable jail.")
	case pin.damaged != "":
		d.Pin, d.PinError = "damaged", pin.damaged
	case pin.valid:
		d.Pin, d.PinNet, d.AcceptFS = "valid", "deny", pin.pin.AcceptFS
		if pin.pin.Net {
			d.PinNet = "allow"
		}
	default:
		d.Pin = "absent"
	}
	if pin.valid && !errors.Is(floorErr, os.ErrNotExist) {
		d.Notes = append(d.Notes, "jail-floor is no longer used and is ignored: the jail pin decides.")
	}

	c := hostCapability(context.Background(), pin, jailProbeCommand, nil, nil)
	route := c.route
	d.Attempt, d.Label = route.reason, c.label()
	if route.kernel {
		d.Attempt = "kernel"
	}
	if route.reason == "jail:absent:clone:EACCES" && facts.AppArmorUsernsClamp {
		d.Notes = append(d.Notes, "the AppArmor userns restriction refuses the jail: each read makes one attempt, which logs one AppArmor userns_create denial; install an AppArmor profile for the gate, or accept classifier-only reads (and the log line), or pin the host to refuse reads")
	}

	switch {
	case pin.damaged != "":
		reason, _ := pin.denial()
		d.Reads = "denied (" + reason + ")"
	case route.kernel && c.spec.Net:
		d.Reads = "kernel-jailed, network open"
	case route.kernel:
		d.Reads = "kernel-jailed, no network"
	case route.fallback:
		d.Reads = "classifier-only (no usable jail)"
	default:
		d.Reads = "denied (" + route.reason + ")"
	}
	return d
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
	pin := d.Pin
	switch {
	case d.PinError != "":
		pin += ": " + d.PinError
	case d.Pin == "valid":
		pin += ": net=" + d.PinNet
		if len(d.AcceptFS) > 0 {
			pin += " accept_fs=" + strings.Join(d.AcceptFS, ",")
		}
	}
	fmt.Printf("pin:                   %s\n", pin)
	fmt.Printf("attempt:               %s\n", d.Attempt)
	fmt.Printf("reads:                 %s\n", d.Reads)
	fmt.Printf("label:                 %s\n", d.Label)
	fmt.Printf("landlock_abi:          %d\n", d.LandlockABI)
	fmt.Printf("max_user_namespaces:   %d\n", d.MaxUserNS)
	fmt.Printf("apparmor_userns_clamp: %s\n", yesNo(d.AppArmorUsernsClamp))
	fmt.Printf("seccomp_filter:        %s\n", yesNo(d.SeccompFilter))
	fmt.Printf("dev_shm:               %s\n", yesNo(d.DevShm))
	fmt.Printf("lsm:                   %s\n", orNone(strings.Join(d.LSM, ",")))
	for _, note := range d.Notes {
		fmt.Printf("note: %s\n", note)
	}
}
