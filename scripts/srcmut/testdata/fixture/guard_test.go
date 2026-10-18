package fixture

import (
	"github.com/karthikeyan5/sshgate/internal/srcmut"
	"github.com/karthikeyan5/sshgate/scripts/srcmut/testdata/dependency"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if path := os.Getenv("HANG_PID"); path != "" {
		if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			panic(err)
		}
		for {
			time.Sleep(time.Second)
		}
	}
	code := m.Run()
	if !Guard() {
		switch os.Getenv("CLEANUP") {
		case "panic":
			panic("cleanup")
		case "exit2":
			os.Exit(2)
		}
	}
	os.Exit(code)
}
func TestRed(t *testing.T) {
	if Guard() {
		return
	}
	switch os.Getenv("MODE") {
	case "pass":
		return
	case "missing":
		t.Fail()
		return
	case "extra":
		srcmut.Effect(t, "extra")
	case "panic":
		t.Log("MUTATION-EFFECT red")
		panic("red")
	case "hang":
		for {
			time.Sleep(time.Second)
		}
	case "kill":
		t.Log("MUTATION-EFFECT red")
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	case "exit2":
		os.Exit(2)
	}
	srcmut.Effect(t, "red")
}
func TestGreen(t *testing.T) {
	if !Guard() && os.Getenv("GREEN_FAIL") == "1" {
		t.Fatal("control failed")
	}
}
func TestEnv(t *testing.T) {
	if !Guard() && os.Getenv("EFFECT") == "yes" {
		srcmut.Effect(t, "red")
	}
}
func TestDependency(t *testing.T) {
	if !dependency.Guard() {
		srcmut.Effect(t, "red")
	}
}
func TestP(t *testing.T) {
	t.Run("a", func(t *testing.T) {
		if !Guard() {
			srcmut.Effect(t, "ma")
		}
	})
	t.Run("b", func(t *testing.T) {
		if !Guard() {
			srcmut.Effect(t, "mb")
		}
	})
	t.Run("green", func(t *testing.T) {})
	if !Guard() && os.Getenv("PARENT_FAIL") == "1" {
		t.Error("parent error")
	}
}
func TestG(t *testing.T) {
	t.Run("control", func(t *testing.T) {
		if os.Getenv("SKIP_CONTROL") == "always" || (!Guard() && os.Getenv("SKIP_CONTROL") == "mutated") {
			t.SkipNow()
		}
	})
}
