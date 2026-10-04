package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

type record struct {
	PID    int    `json:"pid"`
	Signal int    `json:"signal"`
	Bytes  int64  `json:"bytes"`
	Error  string `json:"error,omitempty"`
}

func collect(directory string, pid, signal int, input io.Reader) (result error) {
	defer func() {
		if result == nil {
			return
		}
		latch, err := os.OpenFile(filepath.Join(directory, "failed"), os.O_WRONLY, 0600)
		if err == nil {
			_, err = latch.WriteAt([]byte{1}, 0)
			if err == nil {
				err = latch.Sync()
			}
			closeErr := latch.Close()
			if err == nil {
				err = closeErr
			}
		}
		if err != nil {
			result = fmt.Errorf("%v; failure latch: %w", result, err)
		}
	}()

	inflight := filepath.Join(directory, "inflight-"+strconv.Itoa(pid))
	pending, err := os.OpenFile(inflight, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = pending.Close(); err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(directory, "records"), os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if file != nil {
			if err := file.Close(); err != nil {
				result = fmt.Errorf("%v; close record: %w", result, err)
			}
		}
	}()
	item := record{PID: pid, Signal: signal}
	item.Bytes, err = io.Copy(io.Discard, input)
	if err != nil {
		item.Error = err.Error()
	} else if item.Bytes == 0 {
		item.Error = "empty core"
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	if _, err = file.Write(append(data, '\n')); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if item.Error != "" {
		return fmt.Errorf("%s", item.Error)
	}
	if err = file.Close(); err != nil {
		file = nil
		return err
	}
	file = nil
	return os.Remove(inflight)
}

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil || pid <= 0 {
		os.Exit(2)
	}
	signal, err := strconv.Atoi(os.Args[2])
	if err != nil || signal <= 0 {
		os.Exit(2)
	}
	executable, err := os.Executable()
	if err != nil {
		os.Exit(2)
	}
	if err = collect(filepath.Dir(executable), pid, signal, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
