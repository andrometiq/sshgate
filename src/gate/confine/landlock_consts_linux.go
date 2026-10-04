//go:build linux

package confine

// Linux UAPI linux/landlock.h:418, introduced in ABI 9; absent from x/sys v0.45.0.
const landlockAccessFSResolveUnix = 1 << 16
