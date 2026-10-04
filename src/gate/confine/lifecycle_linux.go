//go:build linux

package confine

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

// EnableSubreaper makes orphaned command descendants our children.
func EnableSubreaper() error {
	if jailmut.On("P-SUBREAPER") {
		return nil
	}
	return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
}

func establishSession() error {
	if jailmut.On("P-SESSION") {
		return nil
	}
	if _, err := unix.Setsid(); err != nil {
		return err
	}
	sid, err := unix.Getsid(0)
	if err != nil {
		return err
	}
	if sid != unix.Getpid() || unix.Getpgrp() != unix.Getpid() {
		return unix.EPERM
	}
	return nil
}

func childPIDs() (map[int]bool, error) { return childPIDsFrom("/proc", os.Getpid()) }

func childPIDsFrom(proc string, self int) (map[int]bool, error) {
	tasks, err := os.ReadDir(filepath.Join(proc, "self/task"))
	if os.IsNotExist(err) {
		return childPIDsFromStat(proc, self)
	}
	if err != nil {
		return nil, err
	}
	children := make(map[int]bool)
	present := false
	for _, task := range tasks {
		data, err := os.ReadFile(filepath.Join(proc, "self/task", task.Name(), "children"))
		if os.IsNotExist(err) {
			continue
		} // A runtime thread can exit during enumeration.
		if err != nil {
			return nil, err
		}
		present = true
		for _, field := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(field)
			if err != nil || pid <= 0 {
				return nil, unix.EINVAL
			}
			children[pid] = true
		}
	}
	if !present {
		return childPIDsFromStat(proc, self)
	}
	return children, nil
}

// comm is parenthesized and may itself contain spaces and parentheses.
func statParentPID(data string) (int, error) {
	end := strings.LastIndexByte(data, ')')
	if end < 0 || !strings.Contains(data[:end], "(") {
		return 0, unix.EINVAL
	}
	fields := strings.Fields(data[end+1:])
	if len(fields) < 2 || len(fields[0]) != 1 {
		return 0, unix.EINVAL
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil || parent < 0 {
		return 0, unix.EINVAL
	}
	return parent, nil
}

func childPIDsFromStat(proc string, self int) (map[int]bool, error) {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, err
	}
	children := make(map[int]bool)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		data, err := os.ReadFile(filepath.Join(proc, entry.Name(), "stat"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		parent, err := statParentPID(string(data))
		if err != nil {
			return nil, fmt.Errorf("proc stat %d: %w", pid, err)
		}
		if parent == self {
			children[pid] = true
		}
	}
	return children, nil
}

// CleanupDescendants kills and reaps our remaining children, including detached
// descendants adopted as they exit. Call only after all exec.Cmd waits complete.
func CleanupDescendants() error {
	if jailmut.On("P-SUBREAPER") {
		return nil
	}
	var enabled int32
	if err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&enabled)), 0, 0, 0); err != nil {
		return err
	}
	if enabled == 0 {
		return nil
	}
	return cleanupDescendants(childPIDs, 5*time.Second)
}

func cleanupDescendants(enumerate func() (map[int]bool, error), timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		children, err := enumerate()
		if err != nil {
			if time.Now().After(deadline) {
				return fmt.Errorf("enumerate descendants: %w", err)
			}
			time.Sleep(time.Millisecond)
			continue
		}
		if len(children) == 0 {
			var info unix.Siginfo
			err := unix.Waitid(unix.P_ALL, 0, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil)
			if err == unix.ECHILD {
				return nil
			}
			if err != nil && err != unix.EINTR {
				return err
			}
		}
		for pid := range children {
			if time.Now().After(deadline) {
				return fmt.Errorf("descendant cleanup exceeded deadline")
			}
			fd, err := unix.PidfdOpen(pid, 0)
			if err == unix.ESRCH {
				continue
			}
			if err != nil {
				return fmt.Errorf("pidfd_open child: %w", err)
			}
			var info unix.Siginfo
			err = unix.Waitid(unix.P_PIDFD, fd, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil)
			if err == unix.ECHILD || err == unix.EINTR {
				_ = unix.Close(fd)
				continue
			}
			if err == nil {
				err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			}
			_ = unix.Close(fd)
			if err != nil && err != unix.ESRCH {
				return fmt.Errorf("kill child: %w", err)
			}
			var status unix.WaitStatus
			_, err = unix.Wait4(pid, &status, unix.WNOHANG|unix.WALL, nil)
			if err != nil && err != unix.ECHILD && err != unix.EINTR {
				return err
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("descendant cleanup exceeded deadline")
		}
		time.Sleep(time.Millisecond)
	}
}

func reap(workerPID int, terminated <-chan os.Signal, report io.Writer) int {
	return reapWithCleanup(workerPID, terminated, report, CleanupDescendants)
}

func reapWithCleanup(workerPID int, terminated <-chan os.Signal, report io.Writer, cleanup func() error) int {
	unavailable := ""
	defer func() {
		cleanupErr := cleanup()
		canReport := true
		if unavailable != "" && cleanupErr != nil {
			// A worker still in setup owns fd 4 until it exits. Never interleave
			// shim records with its I/X or failure report.
			var status unix.WaitStatus
			pid, err := unix.Wait4(workerPID, &status, unix.WNOHANG|unix.WALL, nil)
			canReport = pid == workerPID || err == unix.ECHILD
		}
		if report != nil && canReport && unavailable != "" {
			fmt.Fprintf(report, "\nW{\"unavailable\":%q}\n", unavailable)
		}
		if cleanupErr != nil {
			reason := strings.Join(strings.Fields(cleanupErr.Error()), " ")
			if report != nil && canReport {
				fmt.Fprintf(report, "\nC%s\n", reason)
			}
			fmt.Fprintln(os.Stderr, "gate-jail: cleanup:", reason)
		}
	}()
	for {
		select {
		case <-terminated:
			unavailable = "cancelled before worker reap"
			return 128 + int(unix.SIGTERM)
		default:
		}
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WNOHANG|unix.WALL, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			unavailable = "wait: " + err.Error()
			return ExitSetupFailed
		}
		if pid == workerPID {
			if status.Signaled() {
				if report != nil {
					fmt.Fprintf(report, "\nW{\"signal\":%d,\"core\":%t}\n", status.Signal(), status.CoreDump())
				}
				return 128 + int(status.Signal())
			}
			if report != nil {
				fmt.Fprintf(report, "\nW{\"exit\":%d}\n", status.ExitStatus())
			}
			return status.ExitStatus()
		}
		if pid == 0 {
			time.Sleep(time.Millisecond)
		}
	}
}
