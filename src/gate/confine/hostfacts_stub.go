//go:build !linux

package confine

import "syscall"

// ReadHostFacts off linux reports the facts under which no fact-dependent row
// is Absent. There is no jail here, so no attempt reaches a classified stage.
func ReadHostFacts() HostFacts {
	return HostFacts{MaxUserNS: -1, DevShmDir: true, SeccompFilter: true, LandlockABI: -1}
}

func errnoSymbol(syscall.Errno) string { return "" }
