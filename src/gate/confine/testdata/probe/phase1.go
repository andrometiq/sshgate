package main

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
)

func phase1Probe(op string, args []string) bool {
	switch op {
	case "phase1-exec":
		report("exec", unix.Exec(args[0], []string{args[0]}, os.Environ()))
	case "phase1-fd":
		fd, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		_, err = unix.Write(fd, []byte("leak"))
		report("write", err)
	case "phase1-tty":
		fd, err := unix.Open(args[0], unix.O_RDONLY|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if !report("open", err) {
			return true
		}
		defer unix.Close(fd)
		report("exclusive", unix.IoctlSetInt(fd, unix.TIOCEXCL, 0))
		termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if !report("get-termios", err) {
			return true
		}
		termios.Lflag ^= unix.ECHO
		report("termios", unix.IoctlSetTermios(fd, unix.TCSETS, termios))
		winsize, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
		if !report("get-winsize", err) {
			return true
		}
		winsize.Row++
		report("winsize", unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, winsize))
	case "phase1-open":
		fd, err := unix.Open(args[0], unix.O_RDONLY|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		report("open", err)
		if err == nil {
			unix.Close(fd)
		}
	case "phase1-fill":
		file, err := os.Create(args[0])
		if !report("open", err) {
			return true
		}
		defer file.Close()
		block := make([]byte, 1<<20)
		for i := 0; i < 65; i++ {
			if _, err = file.Write(block); err != nil {
				break
			}
		}
		report("fill", phase1Errno(err))
	case "phase1-fsize":
		signal.Ignore(syscall.SIGXFSZ)
		file, err := os.Create(args[0])
		if !report("open", err) {
			return true
		}
		defer file.Close()
		_, err = file.Seek(1<<30, 0)
		if !report("seek", err) {
			return true
		}
		_, err = file.Write([]byte{1})
		report("write", phase1Errno(err))
	case "phase1-forks":
		reader, writer, err := os.Pipe()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer reader.Close()
		children := []*exec.Cmd{}
		defer func() {
			_ = writer.Close()
			for _, child := range children {
				_ = child.Wait()
			}
		}()
		for i := 0; i < 257; i++ {
			child := exec.Command("/bin/cat")
			child.Stdin = reader
			err = child.Start()
			if err != nil {
				break
			}
			children = append(children, child)
		}
		if errors.Is(err, unix.EAGAIN) {
			err = unix.EAGAIN
		}
		fmt.Printf("children=%d\n", len(children))
		report("fork", err)
	default:
		return false
	}
	return true
}

func phase1Errno(err error) error {
	var errno unix.Errno
	if errors.As(err, &errno) {
		return errno
	}
	return err
}
