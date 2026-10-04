package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) < 3 {
		return
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "fuse-ioctl":
		if len(args) != 3 {
			os.Exit(2)
		}
		command, err := strconv.ParseUint(args[1], 0, 32)
		if err != nil {
			os.Exit(2)
		}
		value, err := strconv.ParseUint(args[2], 0, 64)
		if err != nil {
			os.Exit(2)
		}
		fd, err := unix.Open(args[0], unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if report("open", err) {
			report("ioctl", ioctlPtr(fd, uintptr(command), unsafe.Pointer(&value)))
			unix.Close(fd)
		}
	case "mntid":
		var state unix.Statx_t
		if report("statx", unix.Statx(unix.AT_FDCWD, args[0], unix.AT_STATX_DONT_SYNC, unix.STATX_MNT_ID, &state)) {
			fmt.Printf("mntid=%d\n", state.Mnt_id)
		}
	case "read":
		coverRead(args[0])
	case "jail-proc":
		if len(args) < 2 || len(args) > 3 || (args[0] != "shim" && args[0] != "gate") {
			os.Exit(2)
		}
		pid, err := shimAncestor()
		if err != nil {
			report("ancestor", err)
			break
		}
		if len(args) == 3 {
			if args[2] != "wait-nocaps" {
				os.Exit(2)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				status, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
				if readErr != nil {
					fmt.Fprintln(os.Stderr, "SETUP: shim status:", readErr)
					os.Exit(2)
				}
				ready, parseErr := shimCapabilitiesZero(string(status))
				if parseErr != nil {
					fmt.Fprintln(os.Stderr, "SETUP: shim status:", parseErr)
					os.Exit(2)
				}
				if ready {
					break
				}
				if time.Now().After(deadline) {
					fmt.Fprintln(os.Stderr, "SETUP: shim capabilities did not clear within 2s")
					os.Exit(2)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
		if args[0] == "gate" {
			pid, err = processParent(pid)
			if err != nil {
				report("ancestor", err)
				break
			}
		}
		path := fmt.Sprintf("/proc/%d/%s", pid, args[1])
		fmt.Printf("target=%d\n", pid)
		if strings.Contains(args[1], "/") || args[1] == "maps" {
			coverRead(path)
		} else {
			_, err = os.Readlink(path)
			if pe, ok := err.(*os.PathError); ok {
				err = pe.Err
			}
			report("readlink", err)
		}
	default:
		return
	}
	if failed != 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func coverRead(path string) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if report("open", err) {
		var data [1]byte
		n, err := unix.Read(fd, data[:])
		if report("read", err) {
			fmt.Printf("bytes=%d\n", n)
		}
		unix.Close(fd)
	}
}
func processParent(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			return strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
		}
	}
	return 0, fmt.Errorf("missing PPid")
}
func shimAncestor() (int, error) {
	pid := os.Getppid()
	for depth := 0; pid > 1 && depth < 64; depth++ {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return 0, err
		}
		for _, arg := range strings.Split(string(data), "\x00") {
			if arg == "__jail" {
				return pid, nil
			}
		}
		pid, err = processParent(pid)
		if err != nil {
			return 0, err
		}
	}
	return 0, fmt.Errorf("shim ancestor not found")
}

func shimCapabilitiesZero(status string) (bool, error) {
	seen := make(map[string]bool)
	zero := true
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "CapPrm:", "CapEff:", "CapAmb:":
			if len(fields) != 2 || seen[fields[0]] {
				return false, fmt.Errorf("malformed capability field %q", line)
			}
			value, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil {
				return false, err
			}
			seen[fields[0]] = true
			zero = zero && value == 0
		}
	}
	if len(seen) != 3 {
		return false, fmt.Errorf("missing shim capability field")
	}
	return zero, nil
}
