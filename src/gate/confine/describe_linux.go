//go:build linux

package confine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// DescribeMounts reports every mount of this process's mount namespace, as
// the read jail would treat it with acceptFS.
func DescribeMounts(acceptFS []string) ([]MountReport, error) {
	entries, err := readMountInfo()
	if err != nil {
		return nil, err
	}
	inspector := backingInspector{sys: "/sys"}
	reports := make([]MountReport, 0, len(entries))
	for _, entry := range entries {
		reports = append(reports, inspector.describe(entry, acceptFS))
	}
	return reports, nil
}

// MountOf reports the mount that holds path.
func MountOf(path string, acceptFS []string) (MountReport, error) {
	id, err := pathMountID(path)
	if err != nil {
		return MountReport{}, err
	}
	entries, err := readMountInfo()
	if err != nil {
		return MountReport{}, err
	}
	for _, entry := range entries {
		if entry.id == id {
			return backingInspector{sys: "/sys"}.describe(entry, acceptFS), nil
		}
	}
	return MountReport{}, fmt.Errorf("mount %d of %s is not in mountinfo", id, path)
}

// describe is one mount's report. It never decides: Accepted is
// mountAccepted's answer.
func (inspector backingInspector) describe(entry mountEntry, acceptFS []string) MountReport {
	report := MountReport{Point: entry.point, FSType: entry.fstype, Source: entry.source, Accepted: mountAccepted(entry, acceptFS, inspector)}
	switch {
	case slices.Contains(networkFstypes, entry.fstype):
		report.Class = "network"
	case entry.fstype == "autofs":
		report.Class = "autofs"
	case entry.fstype == "btrfs" || slices.Contains(blockFstypes, entry.fstype):
		report.Class = "block"
		report.Backing = [...]string{backingDirect: "direct", backingNetwork: "network", backingCovered: "covered"}[inspector.mount(entry)]
		report.DevicePath, report.Slaves = inspector.deviceChain(entry.dev)
	case slices.Contains(readSafeFstypes, entry.fstype):
		report.Class = "virtual"
	default:
		report.Class = "unsupported"
	}
	return report
}

// deviceChain is the block device dev under /sys (relative to it) and the
// devices beneath it, depth first. A partition's chain is its disk's.
func (inspector backingInspector) deviceChain(dev string) (string, []string) {
	path, err := filepath.EvalSymlinks(filepath.Join(inspector.sys, "dev/block", dev))
	if err != nil || !pathWithin(path, inspector.sys) {
		return "", nil
	}
	relative, _ := filepath.Rel(inspector.sys, path)
	var slaves []string
	var walk func(string, int)
	walk = func(device string, depth int) {
		if _, err := os.Lstat(filepath.Join(device, "partition")); err == nil {
			device = filepath.Dir(device)
		}
		children, err := os.ReadDir(filepath.Join(device, "slaves"))
		if depth > 8 || err != nil && !errors.Is(err, os.ErrNotExist) {
			return
		}
		for _, child := range children {
			slaves = append(slaves, child.Name())
			if next, err := filepath.EvalSymlinks(filepath.Join(device, "slaves", child.Name())); err == nil && pathWithin(next, inspector.sys) {
				walk(next, depth+1)
			}
		}
	}
	walk(path, 0)
	return relative, slaves
}
