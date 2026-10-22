//go:build !linux

package confine

func SealProcess() error     { return errUnsupported }
func Dumpable() (int, error) { return 0, errUnsupported }
