//go:build linux

package confine

import (
	"os"
	"os/exec"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCoreLimitInheritedHard(t *testing.T) {
	if value := os.Getenv("SSHGATE_TEST_CORE_HARD"); value != "" {
		hard, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: hard, Max: hard}); err != nil {
			t.Fatal(err)
		}
		if err := setRlimits(); err != nil {
			t.Fatal(err)
		}
		var got unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &got); err != nil {
			t.Fatal(err)
		}
		want := min(uint64(1), hard)
		if got.Cur != want || got.Max != want {
			t.Fatalf("core=%+v, want %d:%d", got, want, want)
		}
		return
	}
	var inherited unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &inherited); err != nil {
		t.Fatal(err)
	}
	for _, hard := range []uint64{0, 1, 2} {
		t.Run(strconv.FormatUint(hard, 10), func(t *testing.T) {
			if hard > inherited.Max {
				t.Skip("inherited hard limit cannot be raised")
			}
			child := exec.Command(os.Args[0], "-test.run=^TestCoreLimitInheritedHard$")
			child.Env = append(os.Environ(), "SSHGATE_TEST_CORE_HARD="+strconv.FormatUint(hard, 10))
			if output, err := child.CombinedOutput(); err != nil {
				t.Fatalf("child: %v\n%s", err, output)
			}
		})
	}
}
