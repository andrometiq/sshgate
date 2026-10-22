//go:build linux && jail_e2e

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

func TestJailMatrixPhase4(t *testing.T) {
	spec := readSpec(pinState{}, false, false)
	result, err := gate.ExecWithRedaction(context.Background(), ":", gate.ExecOpts{Confine: &spec})
	var setup *confine.SetupError
	if result.ExitCode != 0 && errors.As(err, &setup) && attemptClass(setup, result) == confine.Absent {
		t.Skipf("SKIP jail: %v", err)
	}
	for _, abi := range []string{"native", "abi1"} {
		t.Run(abi, func(t *testing.T) {
			t.Run("G-ENVELOPE-GRAMMAR", func(t *testing.T) {
				p := newProof(t, "G-ENVELOPE-GRAMMAR")
				dir := t.TempDir()
				withGateDir(t, dir)
				target := seedTarget(t, dir)
				out, err := exec.Command("cat", target).Output()
				p.Control("effect", err == nil && string(out) == "orig\n")
				withReadSpec(t, abi, nil)
				code, out2, stderr := runWith(t, "SSHGATE_READ1 confined\tcat "+target)
				ran := out2 == "orig\n"
				p.Effect("agent-bytes", ran)
				p.Jailed("attempt", ran && code == 0 || code == 77 && strings.Contains(stderr, "gate: bad envelope"))
				p.Observed("effect", ran || out2 == "")
				p.Finish()
			})
			t.Run("G-ENVELOPE-NO-NET-UNPINNED", func(t *testing.T) { legEnvelopeNetwork(t, abi, "G-ENVELOPE-NO-NET-UNPINNED") })
			t.Run("G-ENVELOPE-NO-NET-DENY", func(t *testing.T) { legEnvelopeNetwork(t, abi, "G-ENVELOPE-NO-NET-DENY") })
			t.Run("G-ENVELOPE-NET-ALLOW", func(t *testing.T) { legEnvelopeNetwork(t, abi, "G-ENVELOPE-NET-ALLOW") })
			t.Run("G-ENVELOPE-PIN-SNAPSHOT", func(t *testing.T) { legEnvelopeNetwork(t, abi, "G-ENVELOPE-PIN-SNAPSHOT") })
			t.Run("G-ENVELOPE-ABSENT", func(t *testing.T) { legEnvelopeAbsent(t, abi, "G-ENVELOPE-ABSENT") })
			t.Run("G-ENVELOPE-ABSENT-TWIN", func(t *testing.T) { legEnvelopeAbsent(t, abi, "G-ENVELOPE-ABSENT-TWIN") })
			t.Run("G-ENVELOPE-UNMET", func(t *testing.T) { legUnmetFuse(t, abi, "G-ENVELOPE-UNMET", "", false) })
			t.Run("G-NET-LANE2-AVAILABLE", func(t *testing.T) { legEnvelopeDaemon(t, abi) })
			t.Run("G-NET-LANE2-ABSENT", func(t *testing.T) { legNetDaemonAbsent(t, abi, false) })
			t.Run("G-NET-LANE2-ABSENT-TWIN", func(t *testing.T) { legNetDaemonAbsent(t, abi, true) })
			t.Run("G-NET-NO-FALLBACK-TWIN", func(t *testing.T) { legEnvelopeAbsent(t, abi, "G-NET-NO-FALLBACK-TWIN") })
			t.Run("G-NET-GRANT-CONNECT", func(t *testing.T) { legInet(t, abi, "G-NET-GRANT-CONNECT") })
			t.Run("G-ENVELOPE-NEW-GATE", func(t *testing.T) {
				p := newProof(t, "G-ENVELOPE-NEW-GATE")
				dir := t.TempDir()
				withGateDir(t, dir)
				target := seedTarget(t, dir)
				withReadSpec(t, abi, nil)
				code, out, _ := runWith(t, "SSHGATE_READ1 confined cat "+target)
				recs := auditRecords(t, dir)
				p.Jailed("attempt", code == 0 && out == "orig\n")
				p.Observed("effect", len(recs) == 1 && recs[0]["requires_confinement"] == true && recs[0]["envelope"] == true && recs[0]["net"] == false)
				p.Finish()
			})
			t.Run("G-ENVELOPE-OLD-GATE", func(t *testing.T) {
				p := newProof(t, "G-ENVELOPE-OLD-GATE")
				valid := true
				for _, signed := range []bool{false, true} {
					dir := t.TempDir()
					withGateDir(t, dir)
					target := seedTarget(t, dir)
					if signed {
						pub, _ := genKey(t)
						seedPub(t, dir, pub, 0600)
					}
					binary, err := os.ReadFile("../../../../dist/gate/sshgate-gate-linux-amd64")
					if err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(dir, "gate")
					if err := os.WriteFile(path, binary, 0700); err != nil {
						t.Fatal(err)
					}
					command := exec.Command(path)
					command.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND=SSHGATE_READ1 confined,net cat "+target)
					out, err := command.CombinedOutput()
					var exit *exec.ExitError
					valid = valid && errors.As(err, &exit) && exit.ExitCode() == 77 && !strings.Contains(string(out), "orig\n")
				}
				p.Jailed("attempt", valid)
				p.Observed("effect", valid)
				p.Finish()
			})
		})
	}
}

func legEnvelopeAbsent(t *testing.T, abi, name string) {
	p := newProof(t, name)
	readNamedWriter(t)
	dir := t.TempDir()
	withGateDir(t, dir)
	target := seedTarget(t, dir)
	twin := strings.HasSuffix(name, "-TWIN")
	if !twin {
		control := filepath.Join(dir, "control")
		if err := os.WriteFile(control, []byte("orig\n"), 0600); err != nil {
			t.Fatal(err)
		}
		err := exec.Command("stat", control, "edited").Run()
		p.Control("effect", err == nil && readFile(control) == "edited\n")
	}
	withReadSpec(t, abi, func(spec *confine.Spec) { spec.ForceABI = confine.ForceNoLandlock })
	cmd := "stat " + target + " edited"
	if !twin {
		cmd = "SSHGATE_READ1 confined " + cmd
	}
	code, _, stderr := runWith(t, cmd)
	ran := readFile(target) == "edited\n"
	recs := auditRecords(t, dir)
	if twin {
		p.Jailed("attempt", code == 0 && ran)
		p.Observed("effect", len(recs) == 1 && recs[0]["enforcement"] == "classifier")
	} else {
		p.Effect("ran-unconfined", ran)
		p.Jailed("attempt", code == 0 && ran || code == 77 && strings.Contains(stderr, "this read must run confined") && len(recs) == 1 && recs[0]["deny_reason"] == "jail:absent:landlock:ENOSYS")
		p.Observed("effect", ran || readFile(target) == "orig\n")
	}
	p.Finish()
}

func legEnvelopeNetwork(t *testing.T, abi, name string) {
	p := newProof(t, name)
	t.Cleanup(func() { envelopeParsedHook = nil; readAdmittedHook = nil })
	probes := buildInetProbe(t)
	withEnv(t, "PATH", probes+string(os.PathListSeparator)+os.Getenv("PATH"))
	withReadSpec(t, abi, nil)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	command := "cat dial-inet " + port
	allow := name == "G-ENVELOPE-NET-ALLOW"
	snapshot := name == "G-ENVELOPE-PIN-SNAPSHOT"
	if !allow {
		out, err := exec.Command(filepath.Join(probes, "cat"), "dial-inet", port).Output()
		p.Control("effect", err == nil && strings.Contains(string(out), "connect=ok") && accepted(t, listener))
	}
	cases := []string{""}
	if snapshot {
		cases = []string{"removed-before", "deny-before", "removed-after", "deny-after"}
	}
	valid := true
	for _, change := range cases {
		dir := t.TempDir()
		withGateDir(t, dir)
		flags := "confined"
		if allow || snapshot {
			plantPin(t, dir, pinAllow, 0644)
			flags += ",net"
		} else if name == "G-ENVELOPE-NO-NET-DENY" {
			plantPin(t, dir, pinDeny, 0644)
		}
		envelopeParsedHook = nil
		readAdmittedHook = nil
		if change == "removed-before" {
			envelopeParsedHook = func() {
				if err := os.Remove(filepath.Join(dir, confine.PinFile)); err != nil {
					t.Fatal(err)
				}
			}
		}
		if change == "deny-before" {
			envelopeParsedHook = func() { plantPin(t, dir, pinDeny, 0644) }
		}
		if change == "removed-after" {
			readAdmittedHook = func(pinState) {
				if err := os.Remove(filepath.Join(dir, confine.PinFile)); err != nil {
					t.Fatal(err)
				}
			}
		}
		if change == "deny-after" {
			readAdmittedHook = func(pinState) { plantPin(t, dir, pinDeny, 0644) }
		}
		code, out, stderr := runWith(t, "SSHGATE_READ1 "+flags+" "+command)
		connected := accepted(t, listener)
		recs := auditRecords(t, dir)
		envelopeParsedHook = nil
		readAdmittedHook = nil
		switch {
		case allow || change == "removed-after" || change == "deny-after":
			valid = valid && code == 0 && connected && len(recs) == 1 && recs[0]["net"] == true
		case snapshot:
			ran := strings.Contains(out, "socket=1")
			p.Effect("ran-without-network", ran)
			valid = valid && !connected && (code == 77 && strings.Contains(stderr, "network not permitted") || ran && code == 1)
		default:
			p.Effect("connected", connected)
			valid = valid && (connected && code == 0 || !connected && code == 1 && out == "socket=1\n")
		}
	}
	p.Jailed("attempt", valid)
	p.Observed("effect", valid)
	p.Finish()
}

func legEnvelopeDaemon(t *testing.T, abi string) {
	p := newProof(t, "G-NET-LANE2-AVAILABLE")
	bin := buildLane2Fixtures(t)
	mode := lane2Mode(t, "report")
	valid, controls := true, true
	for _, command := range []string{"systemctl status " + mode, "docker ps"} {
		fields := strings.Fields(command)
		out, err := exec.Command(filepath.Join(bin, fields[0]), fields[1:]...).Output()
		controls = controls && (err == nil || fields[0] == "docker") && len(out) > 0
		for _, signed := range []bool{false, true} {
			dir := t.TempDir()
			withGateDir(t, dir)
			plantPin(t, dir, pinAllow, 0644)
			withReadSpec(t, abi, nil)
			raw := "SSHGATE_READ1 confined,net " + command
			if signed {
				raw = signedNetRead(t, dir, command)
			}
			code, out2, stderr := runWith(t, raw)
			ran := lane2Reported([]byte(out2), mode)
			if fields[0] == "docker" {
				ran = out2 == "SG-FIXTURE no mode\n"
			}
			p.Effect("lane2-ran", ran)
			valid = valid && (code == 77 && stderr == "gate: "+sigwire.GateDenyNetDaemonRead+"\n" && !ran || (code == 0 || code == 2) && ran)
		}
	}
	p.Control("effect", controls)
	p.Jailed("attempt", valid)
	p.Observed("effect", valid)
	p.Finish()
}

func legNetDaemonAbsent(t *testing.T, abi string, twin bool) {
	name := "G-NET-LANE2-ABSENT"
	if twin {
		name += "-TWIN"
	}
	p := newProof(t, name)
	bin := buildLane2Fixtures(t)
	socket := filepath.Join(lane2SocketDir(t), "docker")
	listener := lane2UnixListen(t, socket)
	previous := lane2SystemEndpoints
	lane2SystemEndpoints.docker = socket
	t.Cleanup(func() { lane2SystemEndpoints = previous })
	dir := t.TempDir()
	withGateDir(t, dir)
	withReadSpec(t, abi, func(spec *confine.Spec) { spec.ForceABI = confine.ForceNoLandlock })
	if !twin {
		nonce := lane2Nonce(lane2Mode(t, "ps"))
		lane2FixtureFile(t, bin, "ps-connect", nonce)
		code, out, _ := runWith(t, "docker ps")
		received, healthy := lane2Received(listener, time.Second)
		records := auditRecords(t, dir)
		p.Control("effect", code == 0 && strings.HasPrefix(out, "CONTAINER ID") && healthy && received == "SG-PS "+nonce && len(records) == 1 && records[0]["enforcement"] == "daemon-read" && records[0]["jail_absent"] == "landlock:ENOSYS")
	}
	nonce := lane2Nonce(lane2Mode(t, "ps"))
	lane2FixtureFile(t, bin, "ps-connect", nonce)
	command := "docker ps"
	if !twin {
		command = signedNetRead(t, dir, command)
	}
	code, out, stderr := runWith(t, command)
	received, healthy := lane2Received(listener, time.Second)
	ran := received == "SG-PS "+nonce
	records := auditRecords(t, dir)
	valid := false
	if twin {
		valid = code == 0 && ran && len(records) == 1 && records[0]["enforcement"] == "daemon-read" && records[0]["jail_absent"] == "landlock:ENOSYS"
	} else {
		p.Effect("lane2-ran", ran)
		if len(records) == 2 {
			record := records[1]
			valid = code == 77 && out == "" && (record["deny_reason"] == "net:daemon-read" && stderr == "gate: "+sigwire.GateDenyNetDaemonRead+"\n" || record["deny_reason"] == "jail:absent:landlock:ENOSYS") || code == 0 && ran
		}
	}
	p.Jailed("attempt", valid)
	p.Observed("effect", healthy && (received == "" || ran))
	p.Finish()
}
