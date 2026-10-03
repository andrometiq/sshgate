//go:build linux

package confine

// This file is reserved for Landlock ABI constants that ship in a newer kernel
// before golang.org/x/sys carries them. x/sys v0.45.0 already defines every LANDLOCK_* constant the
// current rungs use, so there is nothing to declare here today.
