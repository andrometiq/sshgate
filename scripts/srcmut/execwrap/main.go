// execwrap preserves the test binary's wait status independently of go test.
package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() { os.Exit(run()) }

func run() int {
	path := os.Getenv("SRCMUT_STATUS_FILE")
	if !filepath.IsAbs(path) || len(os.Args) < 2 {
		return 125
	}
	command := exec.Command(os.Args[1], os.Args[2:]...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	if command.Start() != nil {
		return 125
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-signals:
				_ = command.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	_ = command.Wait()
	close(done)
	status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return 125
	}
	record := struct {
		Exited   bool `json:"exited"`
		Code     int  `json:"code"`
		Signaled bool `json:"signaled"`
		Signal   int  `json:"signal"`
	}{status.Exited(), status.ExitStatus(), status.Signaled(), 0}
	code := status.ExitStatus()
	if status.Signaled() {
		record.Signal = int(status.Signal())
		code = 128 + record.Signal
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 125
	}
	err = json.NewEncoder(file).Encode(record)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return 125
	}
	return code
}
