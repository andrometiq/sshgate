package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestWrapperHelper(t *testing.T) {
	if os.Getenv("SRCMUT_WRAPPER_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			os.Exit(run())
		}
	}
	os.Exit(124)
}
func helper(t *testing.T, path, script string) *exec.Cmd {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestWrapperHelper$", "--", "sh", "-c", script)
	command.Env = append(os.Environ(), "SRCMUT_WRAPPER_HELPER=1", "SRCMUT_STATUS_FILE="+path)
	return command
}
func TestWaitStatus(t *testing.T) {
	for _, code := range []int{0, 1, 2} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "status")
			command := helper(t, path, "exit "+strconv.Itoa(code))
			_ = command.Run()
			if command.ProcessState.ExitCode() != code {
				t.Fatal(command.ProcessState)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var record struct {
				Exited   bool
				Code     int
				Signaled bool
				Signal   int
			}
			if err = json.Unmarshal(data, &record); err != nil || !record.Exited || record.Code != code || record.Signaled || record.Signal != 0 {
				t.Fatalf("%s %v", data, err)
			}
			duplicate := helper(t, path, "exit 0")
			_ = duplicate.Run()
			if duplicate.ProcessState.ExitCode() != 125 {
				t.Fatal("overwrote status")
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(data) {
				t.Fatal("changed existing status")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "status")
	command := helper(t, path, "kill -TERM $$")
	_ = command.Run()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Exited   bool
		Code     int
		Signaled bool
		Signal   int
	}
	if json.Unmarshal(data, &record) != nil || record.Exited || !record.Signaled || record.Signal != int(syscall.SIGTERM) || command.ProcessState.ExitCode() != 143 {
		t.Fatalf("%s %v", data, command.ProcessState)
	}
}
func TestForwardSignal(t *testing.T) {
	for _, signal := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "status")
			ready := filepath.Join(dir, "ready")
			command := helper(t, path, `trap 'exit 7' INT TERM; touch "$READY"; while :; do sleep 0.01; done`)
			command.Env = append(command.Env, "READY="+ready)
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }()
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := os.Stat(ready); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("child not ready")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := command.Process.Signal(signal); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("signal not forwarded")
			}
			if command.ProcessState.ExitCode() != 7 {
				t.Fatal(command.ProcessState)
			}
		})
	}
}
