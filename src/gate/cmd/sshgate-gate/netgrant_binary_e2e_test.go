//go:build linux && jail_e2e

package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/classify"
	"github.com/karthikeyan5/sshgate/src/hostkey"
)

// TestGateBinaryNetGrant uses the production binary and host-key loader.
// An unavailable jail is a failure, including a classifier-only fallback.
func TestGateBinaryNetGrant(t *testing.T) {
	readNamedWriter(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "gate")
	build := exec.Command("go", "build", "-trimpath", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gate: %v\n%s", err, out)
	}
	probe := filepath.Join(dir, "cat")
	build = exec.Command("go", "build", "-trimpath", "-o", probe, "../../confine/testdata/probe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build network probe: %v\n%s", err, out)
	}
	withEnv(t, "PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	runGate := func(t *testing.T, command string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin)
		cmd.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND="+command)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("gate: %v (stdout=%q stderr=%q)", err, stdout.String(), stderr.String())
		}
		return stdout.String()
	}
	report := decodeVerbLine(t, runGate(t, "SSHGATE_JAIL"))
	if !report.NetGrants || report.Enforcement != "kernel" || report.Pinned || report.Net {
		t.Fatalf("capability: %+v; want unpinned kernel jail with network grants", report)
	}
	fingerprints, err := hostkey.LoadHostFingerprints()
	if err != nil || len(fingerprints) == 0 {
		t.Fatalf("load production host fingerprints: %v (count %d)", err, len(fingerprints))
	}
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	for _, source := range []string{"grant", "envelope"} {
		t.Run(source, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accept := func(wantConnection bool) {
				t.Helper()
				if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				connection, err := listener.Accept()
				if err == nil {
					connection.Close()
					if !wantConnection {
						t.Fatal("envelope connected without network permission")
					}
				} else if timeout, ok := err.(net.Error); wantConnection || !ok || !timeout.Timeout() {
					t.Fatalf("accept (want connection %t): %v", wantConnection, err)
				}
			}
			target := filepath.Join(dir, source+"-target")
			resetTarget := func() {
				t.Helper()
				if err := os.WriteFile(target, []byte("orig\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			checkTarget := func(want string) {
				t.Helper()
				got, err := os.ReadFile(target)
				if err != nil || string(got) != want {
					t.Fatalf("target = %q, %v; want %q", got, err, want)
				}
			}
			command := "stat " + target + " changed; cat dial-inet " + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port) + "; echo done"
			if kind := classify.Classify(command); kind != classify.KindRead {
				t.Fatalf("command classified %v, want read", kind)
			}
			resetTarget()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			control, err := exec.CommandContext(ctx, "/bin/sh", "-c", command).CombinedOutput()
			if err != nil || string(control) != "socket=ok\nconnect=ok\ndone\n" {
				t.Fatalf("unjailed control: %v, output %q", err, control)
			}
			checkTarget("changed\n")
			accept(true)
			resetTarget()
			line := "SSHGATE_READ1 confined " + command
			if source == "grant" {
				payload := freshPayload(command)
				payload.Host, payload.Net = fingerprints[0], true
				line = signedLine(t, priv, payload)
			}
			out := runGate(t, line)
			want := "socket=1\ndone\n"
			if source == "grant" {
				want = "socket=ok\nconnect=ok\ndone\n"
			}
			if out != want {
				t.Errorf("jailed read output: %q; want %q", out, want)
			}
			checkTarget("orig\n")
			accept(source == "grant")
		})
	}
	records := auditRecords(t, dir)
	if len(records) != 2 {
		t.Fatalf("audit: %v; want two reads", records)
	}
	for i, record := range records {
		isGrant := i == 0
		approval := "unsigned"
		if isGrant {
			approval = "signed"
		}
		if record["classification"] != "read" || record["enforcement"] != "kernel" || record["requires_confinement"] != true || record["net"] != isGrant || record["approval_status"] != approval || (record["net_grant"] == true) != isGrant || (record["envelope"] == true) == isGrant {
			t.Errorf("audit read %d: %v", i, record)
		}
	}
}
