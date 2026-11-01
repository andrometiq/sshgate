//go:build linux

package faultpoint_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func TestFileStoreFaultProbe(t *testing.T) {
	draft := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("true", 60))
	record, answer := ap.Apply(nil, st.SubmitOf(draft, st.PrincipalA, st.T0, time.Hour),
		ap.Now{Wall: st.T0}, ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings})
	if answer.Code != "" {
		t.Fatal(answer)
	}
	data, err := ap.EncodeR1(record)
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(fixture, data, 0600); err != nil {
		t.Fatal(err)
	}
	key := ap.RecordKey(record.Header.Principal, record.Header.RequestID)
	for _, tag := range []string{"", "sshgate_faults"} {
		name := "release"
		if tag != "" {
			name = "tagged"
		}
		t.Run(name, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "probe")
			build := exec.Command("go", "build", "-tags="+tag, "-ldflags=", "-buildvcs=false", "-o", binary, "./testdata/filestoreprobe")
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build: %v: %s", err, out)
			}
			symbols, err := exec.Command("go", "tool", "nm", binary).CombinedOutput()
			if err != nil {
				t.Fatalf("nm: %v: %s", err, symbols)
			}
			for _, symbol := range []string{"/pkg/signerkit/lifecycle.AcquireFileStore", "/pkg/signerkit/lifecycle.(*FileStore).Commit"} {
				if !strings.Contains(string(symbols), symbol) {
					t.Fatalf("probe does not link %s", symbol)
				}
			}
			if tag == "" && strings.Contains(string(symbols), "/internal/faultpoint.") {
				t.Fatal("release probe contains faultpoint symbols")
			}
			for _, point := range []string{"", "unmatched", "filestore.flock", "filestore.before-update", "filestore.after-update"} {
				t.Run("fault="+point, func(t *testing.T) {
					directory := filepath.Join(t.TempDir(), "approvals")
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, binary, directory, fixture)
					cmd.Env = append(os.Environ(), "SSHGATE_TEST_FAULT="+point)
					out, err := cmd.CombinedOutput()
					wantExit, wantRecord := 0, true
					if tag != "" {
						switch point {
						case "filestore.flock":
							wantExit, wantRecord = 87, false
						case "filestore.before-update":
							wantExit, wantRecord = 86, false
						case "filestore.after-update":
							wantExit = 86
						}
					}
					if wantExit == 0 {
						if err != nil || string(out) != "committed\n" {
							t.Fatalf("commit: %v: %s", err, out)
						}
					} else {
						var exit *exec.ExitError
						if !errors.As(err, &exit) || exit.ExitCode() != wantExit {
							t.Fatalf("want exit %d: %v: %s", wantExit, err, out)
						}
					}
					stored, err := os.ReadFile(filepath.Join(directory, key))
					if wantRecord {
						if err != nil || !bytes.Equal(stored, data) {
							t.Fatalf("durable record differs: %v", err)
						}
					} else if !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("uncommitted record present: %v", err)
					}
				})
			}
		})
	}
}
