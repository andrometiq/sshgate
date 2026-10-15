package fixture

import (
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/srcmut"
)

// The declared mutation changes dependency.Guard, which this test never calls.
func TestAmbientOverlay(t *testing.T) {
	if Guard() {
		srcmut.Effect(t, "red")
	}
}

func TestOrdinaryTimeout(t *testing.T) {
	path := os.Getenv("DESCENDANT_PIDS")
	if path == "" {
		return
	}
	child := exec.Command("sleep", "300")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"+strconv.Itoa(child.Process.Pid)), 0600); err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Second)
	}
}
