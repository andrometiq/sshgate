package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

func TestNetGrantDeniedBeforeAdminDispatch(t *testing.T) {
	for _, command := range []string{"SSHGATE_REVOKE", "SSHGATE_UPDATE " + strings.Repeat("a", 64), "SSHGATE_XFER_SEND ignored", "SSHGATE_XFER_RECV ignored", "SSHGATE_VERSION", "SSHGATE_JAIL", "touch /must-not-exist", "   ", "unrecognised-command"} {
		t.Run(command, func(t *testing.T) {
			dir, home := t.TempDir(), t.TempDir()
			withGateDir(t, dir)
			withHomeDir(t, home)
			if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
				t.Fatal(err)
			}
			authorized := filepath.Join(home, ".ssh", "authorized_keys")
			keys := []byte("untouched-authorized-keys\n")
			if err := os.WriteFile(authorized, keys, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "gate"), []byte("untouched-gate"), 0700); err != nil {
				t.Fatal(err)
			}
			line := signedNetRead(t, dir, command)
			snapshot := func() map[string]string {
				result := map[string]string{}
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if entry.Name() == "audit.log" {
						continue
					}
					data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					info, err := entry.Info()
					if err != nil {
						t.Fatal(err)
					}
					result[entry.Name()] = string(data) + info.Mode().String()
				}
				return result
			}
			before := snapshot()
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			payload := []byte("stdin-must-remain-unread")
			if _, err := writer.Write(payload); err != nil {
				t.Fatal(err)
			}
			writer.Close()
			oldStdin := os.Stdin
			os.Stdin = reader
			defer func() { os.Stdin = oldStdin }()
			fake := withFakeAttempt(t, gate.ExecResult{}, nil)
			code, out, stderr := runWith(t, line)
			if code != 77 || out != "" || stderr != "gate: "+sigwire.GateDenyNetReadsOnly+"\n" || fake.confined != 0 || fake.fallback != 0 {
				t.Fatalf("code=%d out=%q stderr=%q calls=%+v", code, out, stderr, fake)
			}
			remaining, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(remaining, payload) {
				t.Fatalf("stdin=%q err=%v", remaining, err)
			}
			if !reflect.DeepEqual(before, snapshot()) {
				t.Fatal("gate directory changed")
			}
			after, err := os.ReadFile(authorized)
			if err != nil || !bytes.Equal(after, keys) {
				t.Fatalf("authorized keys changed: %q %v", after, err)
			}
			rows := auditRecords(t, dir)
			if len(rows) != 1 || rows[0]["deny_reason"] != "net:not-a-read" || rows[0]["net_grant"] != true || rows[0]["classification"] != "write" {
				t.Fatalf("audit=%v", rows)
			}
		})
	}
}

func TestSignedInnerEnvelopeDenied(t *testing.T) {
	for _, network := range []bool{false, true} {
		for _, command := range []string{"SSHGATE_READ1 confined cat /dev/null", "SSHGATE_READ2 confined cat /dev/null", "SSHGATE_READ"} {
			t.Run(command+"/"+map[bool]string{false: "plain", true: "net"}[network], func(t *testing.T) {
				dir := t.TempDir()
				withGateDir(t, dir)
				pub, priv := genKey(t)
				seedPub(t, dir, pub, 0644)
				payload := freshPayload(command)
				payload.Net = network
				fake := withFakeAttempt(t, gate.ExecResult{}, nil)
				code, out, stderr := runWith(t, signedLine(t, priv, payload))
				if code != 77 || out != "" || stderr != "gate: "+sigwire.GateDenySignedEnvelope+"\n" || fake.confined != 0 || fake.fallback != 0 {
					t.Fatalf("code=%d out=%q stderr=%q calls=%+v", code, out, stderr, fake)
				}
				rows := auditRecords(t, dir)
				if len(rows) != 1 || rows[0]["deny_reason"] != "envelope:signed" || (rows[0]["net_grant"] == true) != network {
					t.Fatalf("audit=%v", rows)
				}
			})
		}
	}
}

func TestVerifyAdmissionWindow(t *testing.T) {
	for _, seconds := range []int64{31, 30} {
		t.Run((time.Duration(seconds) * time.Second).String(), func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			pub, priv := genKey(t)
			seedPub(t, dir, pub, 0644)
			fake := withFakeAttempt(t, gate.ExecResult{}, nil)
			payload := freshPayload("cat /dev/null")
			payload.Net = true
			var code int
			var stderr string
			for attempt := 0; ; attempt++ {
				if attempt == 10 {
					t.Fatal("could not observe the admission boundary within one clock second")
				}
				now := time.Now().Unix()
				payload.TS, payload.Exp = now+seconds, now+seconds+60
				fake.confined, fake.fallback = 0, 0
				code, _, stderr = runWith(t, signedLine(t, priv, payload))
				// A crossed second changes +31 into an admissible +30.
				if time.Now().Unix() == now {
					break
				}
			}
			if seconds == 31 {
				if code != 65 || fake.confined != 0 || fake.fallback != 0 {
					t.Fatalf("code=%d stderr=%q calls=%+v", code, stderr, fake)
				}
			} else if code != 0 || fake.confined != 1 || fake.fallback != 0 {
				t.Fatalf("code=%d stderr=%q calls=%+v", code, stderr, fake)
			}
		})
	}
}
