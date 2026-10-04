//go:build linux && jail_e2e

package confine

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestJailMatrixCredentials(t *testing.T) {
	for _, configuration := range []struct {
		name string
		abi  int
	}{{"native", 0}, {"abi1", 1}} {
		t.Run(configuration.name, func(t *testing.T) {
			spec := Spec{Profile: ProfileROv1, ForceABI: configuration.abi, Net: true}
			t.Run("L-NNP-LANDLOCK", func(t *testing.T) {
				inherited, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
				mutationSetup(t, err)
				if inherited != 0 {
					t.Fatal("SETUP: inherited NoNewPrivs=1 makes removal of the NNP wall unobservable")
				}
				result := runP12(t, spec, "printf COMMAND_RAN", nil)
				if result.setupErr != nil {
					var setup *SetupError
					if errors.As(result.setupErr, &setup) && setup.Stage == "landlock" && setup.Errno == unix.EPERM && result.stdout == "" && result.exit == ExitSetupFailed {
						mutationAbort(t, "L-NNP-LANDLOCK", "landlock", true)
						return
					}
					t.Fatalf("SETUP: unexpected abort: %+v", result)
				}
				if result.exit != 0 || result.stdout != "COMMAND_RAN" {
					t.Fatalf("intact NNP did not reach exec: %+v", result)
				}
			})
			t.Run("L-SELFCHECK-CREDS", func(t *testing.T) {
				result := runP12(t, spec, "cat /proc/self/status", nil)
				if result.setupErr != nil {
					var setup *SetupError
					if errors.As(result.setupErr, &setup) && setup.Stage == "selfcheck" && result.stdout == "" {
						mutationAbort(t, "L-SELFCHECK-CREDS", "selfcheck", true)
						return
					}
					t.Fatalf("SETUP: unexpected abort: %+v", result)
				}
				if result.exit != 0 {
					t.Fatalf("SETUP: %+v", result)
				}
				mutationEffect(t, "L-SELFCHECK-CREDS", "credentials", selfcheckCredentials(result.stdout, os.Getuid() == 0) != nil)
			})
			t.Run("L-SELFCHECK-LL", func(t *testing.T) {
				without := spec
				without.ForceABI = ForceNoLandlock
				result := runP12(t, without, "printf COMMAND_RAN", nil)
				if result.stdout == "COMMAND_RAN" {
					mutationEffect(t, "L-SELFCHECK-LL", "reached-exec", true)
					return
				}
				var setup *SetupError
				if !errors.As(result.setupErr, &setup) || (setup.Stage != "landlock" && setup.Stage != "selfcheck") || result.stdout != "" {
					t.Fatalf("SETUP: %+v", result)
				}
			})
			t.Run("L-SETUID", func(t *testing.T) {
				control, err := os.ReadFile("/proc/self/mountinfo")
				mutationSetup(t, err)
				entries, err := parseMountInfo(strings.NewReader(string(control)))
				mutationSetup(t, err)
				if len(entries) == 0 {
					t.Fatal("SETUP: empty control mountinfo")
				}
				t.Logf("control mount flags: %v", entries[0].opts)
				result := runP12(t, spec, "cat /proc/self/status; printf '\\nMOUNTS\\n'; cat /proc/self/mountinfo", nil)
				if result.setupErr != nil || result.exit != 0 {
					t.Fatalf("SETUP: %+v", result)
				}
				parts := strings.SplitN(result.stdout, "\nMOUNTS\n", 2)
				if len(parts) != 2 {
					t.Fatal("missing mount report")
				}
				if !strings.Contains(parts[0], "NoNewPrivs:\t1\n") {
					t.Fatal("NoNewPrivs is not 1")
				}
				entries, err = parseMountInfo(strings.NewReader(parts[1]))
				mutationSetup(t, err)
				if len(entries) == 0 {
					t.Fatal("empty jailed mountinfo")
				}
				missing := false
				for _, entry := range entries {
					missing = missing || !slices.Contains(entry.opts, "nosuid")
				}
				mutationEffect(t, "L-SETUID", "nosuid-state", missing)
			})
		})
	}
}
