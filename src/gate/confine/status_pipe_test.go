package confine

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func startStatusFixture(t *testing.T) (*Jailed, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	commandReader, commandWriter, err := os.Pipe()
	if err != nil {
		reader.Close()
		writer.Close()
		t.Fatal(err)
	}
	j := &Jailed{statusR: reader, cmdW: commandWriter, spec: Spec{Profile: ProfileROv1}}
	t.Cleanup(func() { j.Abort(); writer.Close(); commandReader.Close() })
	if err := j.Started(); err != nil {
		t.Fatal(err)
	}
	return j, writer
}

func TestStatusPipeLargeReport(t *testing.T) {
	jailed, writer := startStatusFixture(t)
	facts := Facts{Profile: ProfileROv1, ABI: 1, Unmet: []string{strings.Repeat("x", 256<<10)}}
	finished := make(chan error, 1)
	go func() { err := writeExecReport(writer, facts); writer.Close(); finished <- err }()
	// A worker must finish writing before Wait can finish and Status is called.
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("status writer blocked before Status")
	}
	got, err := jailed.Status()
	if err != nil || len(got.Unmet) != 1 || got.Unmet[0] != facts.Unmet[0] {
		t.Fatalf("large report: unmet count=%d error=%v", len(got.Unmet), err)
	}
}

func TestStatusPipeOverflow(t *testing.T) {
	jailed, writer := startStatusFixture(t)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, _ = writer.WriteString(strings.Repeat("x", maxStatusBytes*2))
		writer.Close()
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("overflow left writer blocked")
	}
	_, err := jailed.Status()
	var setup *SetupError
	if !errors.As(err, &setup) || setup.Stage != "report" {
		t.Fatalf("overflow: %v", err)
	}
	var out bytes.Buffer
	if err := writeExecReport(&out, Facts{Profile: ProfileROv1, ABI: 1, Unmet: []string{strings.Repeat("x", maxStatusBytes)}}); !errors.Is(err, syscall.E2BIG) || out.Len() != 0 {
		t.Fatalf("oversized worker report wrote %d bytes: %v", out.Len(), err)
	}
}

func TestStatusPipeAbort(t *testing.T) {
	jailed, _ := startStatusFixture(t)
	finished := make(chan struct{})
	go func() { jailed.Abort(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("Abort did not join status reader")
	}
	select {
	case <-jailed.statusDone:
	default:
		t.Fatal("status reader survived Abort")
	}
}

func TestStatusPipeSurvivingDescendant(t *testing.T) {
	const info = `I{"profile":"ro-v1","abi":1,"net":false,"lane2":false}` + "\n"
	for _, test := range []struct {
		name, report string
		valid        bool
	}{
		{"empty", "", false},
		{"incomplete", info, false},
		{"executed", info + "X", true},
		{"cleanup", info + "X\nCdeadline exceeded\n", true},
		{"invalid", strings.Replace(info, "ro-v1", "wrong", 1) + "X", false},
		{"exec-failed", info + "XFexec:2\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			jailed, writer := startStatusFixture(t)
			// Stand in for a descendant surviving the cleanup deadline with fd 4 open.
			descendant := exec.Command("sleep", "30")
			descendant.ExtraFiles = []*os.File{writer, writer}
			if err := descendant.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = descendant.Process.Kill(); _ = descendant.Wait() }()
			if _, err := writer.WriteString(test.report); err != nil {
				t.Fatal(err)
			}
			writer.Close()
			start := time.Now()
			finished := make(chan error, 1)
			go func() { _, err := jailed.Status(); finished <- err }()
			select {
			case err := <-finished:
				if (err == nil) != test.valid {
					t.Fatalf("status: %v", err)
				}
				if test.valid && (jailed.Facts.Profile != ProfileROv1 || !strings.Contains(jailed.CleanupError, "status pipe")) {
					t.Fatalf("lost execution or cleanup evidence: %+v", jailed)
				}
				if test.name == "cleanup" && !strings.Contains(jailed.CleanupError, "deadline exceeded") {
					t.Fatal("lost shim cleanup diagnostic")
				}
			case <-time.After(statusWait + 2*time.Second):
				t.Fatal("status collection exceeded bound")
			}
			if time.Since(start) < statusWait {
				t.Fatal("descendant did not retain status writer")
			}
			select {
			case <-jailed.statusDone:
			default:
				t.Fatal("status reader was not joined")
			}
		})
	}
}
