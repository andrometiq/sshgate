package main

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Each argument is deliberately invalid. The caller selects only reviewed
// non-allow rows; no success-capable mount, signal, or credential arguments run.
func syscallSweep(arguments []string) {
	for _, argument := range arguments {
		name, raw, valid := strings.Cut(argument, ":")
		number, err := strconv.ParseUint(raw, 10, 32)
		if !valid || err != nil {
			panic("invalid sweep row")
		}
		bad := ^uintptr(0)
		_, _, errno := unix.Syscall6(uintptr(number), bad, bad, bad, bad, bad, bad)
		fmt.Printf("%s=%d\n", name, errno)
	}
}
