package main

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

func hostPIDProbe(op string, args []string) bool {
	number := func(s string) uintptr {
		n, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			panic(err)
		}
		return uintptr(n)
	}
	switch op {
	case "signal-one":
		nr, pid := number(args[0]), number(args[1])
		var info [128]byte
		binary.LittleEndian.PutUint32(info[0:], 10)
		binary.LittleEndian.PutUint32(info[8:], 0xffffffff)
		binary.LittleEndian.PutUint32(info[16:], uint32(os.Getpid()))
		binary.LittleEndian.PutUint32(info[20:], uint32(os.Getuid()))
		values := [6]uintptr{pid, 10}
		switch nr {
		case 234:
			values = [6]uintptr{pid, pid, 10}
		case 129:
			values = [6]uintptr{pid, 10, uintptr(unsafe.Pointer(&info))}
		case 297:
			values = [6]uintptr{pid, pid, 10, uintptr(unsafe.Pointer(&info))}
		case 424:
			fd, err := unix.PidfdOpen(int(pid), 0)
			if err != nil {
				panic(err)
			}
			defer unix.Close(fd)
			values = [6]uintptr{uintptr(fd), 10, 0, 0}
		}
		_, _, err := unix.Syscall6(nr, values[0], values[1], values[2], values[3], values[4], values[5])
		report("signal", errnoOrNil(err))
	case "mrelease":
		fd, err := unix.PidfdOpen(int(number(args[0])), 0)
		if err != nil {
			panic(err)
		}
		defer unix.Close(fd)
		_, _, e := unix.Syscall(448, uintptr(fd), 0, 0)
		report("mrelease", errnoOrNil(e))
	case "async-victim":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGIO)
		fmt.Println("READY")
		select {
		case <-signals:
			fmt.Println("SIGIO")
		case <-time.After(10 * time.Second):
		}
	case "async-owner":
		pid := number(args[0])
		var fds [2]int
		if err := unix.Pipe2(fds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
			panic(err)
		}
		defer unix.Close(fds[0])
		defer unix.Close(fds[1])
		_, err := unix.FcntlInt(uintptr(fds[0]), unix.F_SETFL, unix.O_ASYNC|unix.O_NONBLOCK)
		if err != nil {
			panic(err)
		}
		_, _, e := unix.Syscall(unix.SYS_FCNTL, uintptr(fds[0]), 8, pid)
		report("owner", errnoOrNil(e))
		if _, err := unix.Write(fds[1], []byte("x")); err != nil {
			panic(err)
		}
	case "async-errno":
		pid := number(args[0])
		var fds [2]int
		if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
			panic(err)
		}
		defer unix.Close(fds[0])
		defer unix.Close(fds[1])
		for _, value := range []uintptr{pid, uintptr(uint32(-int32(pid))), 0x80000000, 0xffffffff80000000, pid | 1<<32} {
			_, _, e := unix.Syscall(unix.SYS_FCNTL, uintptr(fds[0]), 8, value)
			report("setown", errnoOrNil(e))
		}
		owner := struct{ kind, pid int32 }{1, int32(pid)}
		_, _, e := unix.Syscall(unix.SYS_FCNTL, uintptr(fds[0]), 15, uintptr(unsafe.Pointer(&owner)))
		report("setown_ex", errnoOrNil(e))
		_, _, e = unix.Syscall(unix.SYS_FCNTL, uintptr(fds[0]), 8, 0)
		report("clear", errnoOrNil(e))
		_, _, e = unix.Syscall(unix.SYS_FCNTL, uintptr(fds[0]), 10, 0)
		report("setsig", errnoOrNil(e))
		for _, request := range []uintptr{0x8901, 0x8902, 0x5410} {
			_, _, e = unix.Syscall(unix.SYS_IOCTL, uintptr(fds[0]), request, uintptr(unsafe.Pointer(&owner.pid)))
			report("ioctl", errnoOrNil(e))
		}
	case "retune-errno":
		pid := number(args[0])
		var limit unix.Rlimit
		report("query", unix.Prlimit(int(pid), unix.RLIMIT_NOFILE, nil, &limit))
		for _, target := range []uintptr{pid, 0xffffffff, 0xffffffffffffffff, 0x80000000, 0xffffffff80000000, pid | 1<<32} {
			for _, nr := range []uintptr{142, 144, 203, 314, 256, 279} {
				_, _, e := unix.Syscall6(nr, target, 0, 0, 0, 0, 0)
				report("retune", errnoOrNil(e))
			}
			_, _, e := unix.Syscall(unix.SYS_SETPRIORITY, 0, target, 19)
			report("retune", errnoOrNil(e))
			_, _, e = unix.Syscall(unix.SYS_IOPRIO_SET, 1, target, 3<<13)
			report("retune", errnoOrNil(e))
			_, _, e = unix.Syscall6(unix.SYS_PRLIMIT64, target, unix.RLIMIT_NOFILE, uintptr(unsafe.Pointer(&limit)), 0, 0, 0)
			report("retune", errnoOrNil(e))
		}
	case "lifecycle-nested", "lifecycle-forking":
		if op == "lifecycle-nested" {
			if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
				panic(err)
			}
		}
		fmt.Printf("CHILD=%d\n", os.Getpid())
		ready := os.NewFile(3, "ready")
		child := exec.Command("sh", "-c", "sleep 8 & echo CHILD=$!; echo ready >&3")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		child.ExtraFiles = []*os.File{ready}
		if err := child.Run(); err != nil {
			panic(err)
		}
		if op == "lifecycle-forking" {
			// Finite, nonrecursive creation continues after the worker exits.
			for i := 0; i < 32; i++ {
				child := exec.Command("sleep", "8")
				child.Stdout, child.Stderr = os.Stdout, os.Stderr
				if err := child.Start(); err != nil {
					panic(err)
				}
				fmt.Printf("SPAWN=%d\n", child.Process.Pid)
				if i == 2 {
					fmt.Fprintln(ready, "ready")
				}
				time.Sleep(20 * time.Millisecond)
			}
		} else {
			fmt.Fprintln(ready, "ready")
		}
		time.Sleep(8 * time.Second)
	case "session":
		sid, err := unix.Getsid(0)
		if err != nil {
			panic(err)
		}
		fmt.Printf("session=%d:%d:%d\n", os.Getpid(), sid, unix.Getpgrp())
	default:
		return false
	}
	return true
}
