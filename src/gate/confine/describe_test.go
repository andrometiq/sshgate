//go:build linux

package confine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestDescribeMountAgreesWithAccepted: on a fake sysfs, each report's class,
// backing and device chain are right, and Accepted is mountAccepted's verdict
// for every accept_fs.
func TestDescribeMountAgreesWithAccepted(t *testing.T) {
	sys, proc := t.TempDir(), t.TempDir()
	disk := func(name, dev, driver string) string {
		path := filepath.Join(sys, "devices", name)
		mkdir(t, path)
		if driver != "" {
			driverPath := filepath.Join(sys, "drivers", driver)
			mkdir(t, driverPath)
			link(t, driverPath, filepath.Join(path, "driver"))
		}
		link(t, path, filepath.Join(sys, "dev/block", dev))
		mkdir(t, filepath.Join(proc, "fs/jbd2", filepath.Base(path)+"-8"))
		return path
	}
	nvme := disk("pci/nvme0/nvme0n1", "259:0", "nvme")
	write(t, filepath.Join(filepath.Dir(nvme), "transport"), "pcie")
	tcp := disk("virtual/nvme1/nvme1n1", "259:2", "nvme-tcp")
	write(t, filepath.Join(filepath.Dir(tcp), "transport"), "tcp")
	loop := disk("virtual/loop0", "7:0", "")
	dm := disk("virtual/dm-0", "253:0", "")
	link(t, loop, filepath.Join(dm, "slaves/loop0"))
	inspector := backingInspector{sys: sys, proc: proc}

	for _, tc := range []struct {
		entry                  mountEntry
		class, backing, device string
		slaves                 []string
	}{
		{mountEntry{point: "/", fstype: "ext4", dev: "259:0"}, "block", "direct", "devices/pci/nvme0/nvme0n1", nil},
		{mountEntry{point: "/remote-disk", fstype: "xfs", dev: "259:2"}, "block", "network", "devices/virtual/nvme1/nvme1n1", nil},
		{mountEntry{point: "/image", fstype: "ext4", dev: "253:0"}, "block", "covered", "devices/virtual/dm-0", []string{"loop0"}},
		{mountEntry{point: "/srv", fstype: "nfs4", dev: "0:50"}, "network", "", "", nil},
		{mountEntry{point: "/net", fstype: "autofs", dev: "0:51"}, "autofs", "", "", nil},
		{mountEntry{point: "/tmp", fstype: "tmpfs", dev: "0:52"}, "virtual", "", "", nil},
		{mountEntry{point: "/run/user/1000/doc", fstype: "fuse.portal", dev: "0:53"}, "unsupported", "", "", nil},
		{mountEntry{point: "/tank", fstype: "zfs", dev: "0:54"}, "unsupported", "", "", nil},
	} {
		for _, accept := range [][]string{nil, {"network"}, {"network", "autofs"}} {
			got := inspector.describe(tc.entry, accept)
			want := MountReport{Point: tc.entry.point, FSType: tc.entry.fstype, Class: tc.class, Backing: tc.backing,
				DevicePath: tc.device, Slaves: tc.slaves, Accepted: mountAccepted(tc.entry, accept, inspector)}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s accept=%v:\n got %+v\nwant %+v", tc.entry.point, accept, got, want)
			}
		}
	}
	if !inspector.describe(mountEntry{fstype: "ext4", dev: "259:0"}, nil).Accepted || inspector.describe(mountEntry{fstype: "ext4", dev: "253:0"}, []string{"network"}).Accepted {
		t.Fatal("a direct disk must be accepted and a loop-backed one covered")
	}
}

// TestDescribeMountsHost: on this host every mount is reported, as
// mountAccepted would treat it, and MountOf finds the mount of a path.
func TestDescribeMountsHost(t *testing.T) {
	entries, err := readMountInfo()
	if err != nil {
		t.Fatal(err)
	}
	reports, err := DescribeMounts([]string{"network"})
	if err != nil || len(reports) != len(entries) {
		t.Fatalf("%d reports for %d mounts: %v", len(reports), len(entries), err)
	}
	inspector := backingInspector{sys: "/sys"}
	for i, entry := range entries {
		if reports[i].Point != entry.point || reports[i].Accepted != mountAccepted(entry, []string{"network"}, inspector) {
			t.Errorf("%s: %+v", entry.point, reports[i])
		}
	}
	proc, err := MountOf("/proc/self", nil)
	if err != nil || proc.Point != "/proc" || proc.FSType != "proc" || proc.Class != "virtual" || !proc.Accepted {
		t.Fatalf("MountOf(/proc/self) = %+v, %v", proc, err)
	}
	dir := t.TempDir()
	report, err := MountOf(dir, nil)
	if err != nil || !strings.HasPrefix(dir, report.Point) {
		t.Fatalf("MountOf(%s) = %+v, %v", dir, report, err)
	}
	if _, err := MountOf(filepath.Join(dir, "missing"), nil); err == nil {
		t.Fatal("MountOf of a missing path")
	}
}

// TestDescribeIsReportOnly: the report functions are reached from nowhere
// in the jail itself, so the device walker can never feed a jail decision.
func TestDescribeIsReportOnly(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	reportOnly := []string{"describe", "deviceChain", "DescribeMounts", "MountOf"}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") || strings.HasPrefix(path, "describe") || strings.HasSuffix(path, "_stub.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok && slices.Contains(reportOnly, selector.Sel.Name) {
				t.Errorf("%s uses %s", path, selector.Sel.Name)
			}
			if ident, ok := node.(*ast.Ident); ok && slices.Contains(reportOnly[2:], ident.Name) {
				t.Errorf("%s uses %s", path, ident.Name)
			}
			return true
		})
	}
}
