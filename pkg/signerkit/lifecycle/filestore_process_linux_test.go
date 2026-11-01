//go:build linux && sshgate_faults

package lifecycle_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	"golang.org/x/sys/unix"
)

func TestFileStoreProcessFaults(t *testing.T) {
	if path := os.Getenv("SSHGATE_FAULT_STORE"); path != "" {
		s, err := lc.OpenFileStore(path, uint32(os.Getuid()))
		if os.Getenv("SSHGATE_TEST_FAULT") == "filestore.flock" {
			if s != nil {
				s.Close()
				t.Fatal("flock fault acquired ownership")
			}
			if !errors.Is(err, lc.ErrStoreFatal) || !errors.Is(err, unix.EBADF) || !strings.Contains(err.Error(), "requires a local filesystem with working flock") {
				t.Fatalf("flock error: %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		key, rec := record(t, 1)
		if err := s.Commit(key, rec); err != nil {
			t.Fatal(err)
		}
		t.Fatal("crash cut did not exit")
	}
	for _, point := range []string{"filestore.flock", "filestore.before-update", "filestore.after-update"} {
		t.Run(point, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "approvals")
			cmd := exec.Command(os.Args[0], "-test.run=^TestFileStoreProcessFaults$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "SSHGATE_FAULT_STORE="+path, "SSHGATE_TEST_FAULT="+point)
			out, err := cmd.CombinedOutput()
			if point == "filestore.flock" {
				if err != nil {
					t.Fatalf("%v: %s", err, out)
				}
			} else {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 86 {
					t.Fatalf("crash: %v: %s", err, out)
				}
			}
			s, err := lc.OpenFileStore(path, uint32(os.Getuid()))
			if err != nil {
				t.Fatalf("ownership after child: %v", err)
			}
			defer s.Close()
			key, _ := record(t, 1)
			_, err = s.Load(key)
			if point == "filestore.after-update" {
				if err != nil {
					t.Fatalf("committed record missing: %v", err)
				}
			} else if !errors.Is(err, lc.ErrNotFound) {
				t.Fatalf("uncommitted record present: %v", err)
			}
		})
	}
}
