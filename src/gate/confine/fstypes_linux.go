//go:build linux

package confine

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// BUILD-22-P2 §3.2a, r8: qualified read safety, including its R10/R17 residuals.
var readSafeFstypes = strings.Fields("ext2 ext3 ext4 xfs btrfs vfat msdos exfat iso9660 squashfs tmpfs ramfs devtmpfs devpts proc sysfs cgroup cgroup2 pstore binfmt_misc fusectl nsfs selinuxfs")
var networkFstypes = strings.Fields("nfs nfs4 cifs smb3 smbfs ceph 9p afs")
var blockFstypes = strings.Fields("ext2 ext3 ext4 xfs vfat msdos exfat iso9660 squashfs")

// BUILD-22-P2 §3.2a: local-bus chains only; unlisted drivers fail closed.
// NVMe/block/SCSI names checked in kernel v6.1/6.8/6.12/6.17;
// PCI/ATA/MMC ancestor names seed the specification criterion (matrix pending).
var directDrivers = strings.Fields("pcieport nvme ahci ata_piix virtio-pci virtio_pci virtio-mmio virtio_mmio virtio_blk virtio_scsi sd xen-blkfront xen_blkfront vbd hv_storvsc storvsc mmcblk mmc_block sdhci-pci sdhci-pci-data sdhci-acpi mpt3sas mpt2sas megaraid_sas smartpqi aacraid hpsa vmw_pvscsi")

// BUILD-22-P2 §3.2a: SCSI host templates, independently of PCI position.
// Kernel drivers/scsi/* host_template.proc_name; storvsc uses storvsc_host.
var directSCSIHosts = strings.Fields("ahci ata_piix virtio_scsi storvsc_host vmw_pvscsi mpt3sas mpt2sas megaraid_sas smartpqi aacraid hpsa")

type backingClass uint8

const (
	backingDirect backingClass = iota
	backingNetwork
	backingCovered
)

func combineBacking(a, b backingClass) backingClass {
	if b > a {
		return b
	}
	return a
}

type backingInspector struct {
	sys             string
	auxiliaryDevice func(string) (string, error)
}

// sysfsPresent distinguishes absent optional metadata from broken links and
// unreadable paths. A present entry must resolve before its value is trusted.
func sysfsPresent(path string) (bool, error) {
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	_, err := os.Stat(path)
	return err == nil, err
}
func (inspector backingInspector) read(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

var nvmeNamespaceName = regexp.MustCompile(`^nvme[0-9]+(c[0-9]+)?n[0-9]+$`)
var nvmeControllerName = regexp.MustCompile(`^nvme[0-9]+$`)

func (inspector backingInspector) device(dev string) backingClass {
	major, minor, ok := strings.Cut(dev, ":")
	if _, err := strconv.ParseUint(major, 10, 32); err != nil {
		return backingCovered
	}
	if _, err := strconv.ParseUint(minor, 10, 32); err != nil {
		return backingCovered
	}
	if !ok || major == "0" {
		return backingCovered
	}
	path, err := filepath.EvalSymlinks(filepath.Join(inspector.sys, "dev/block", dev))
	if err != nil {
		return backingCovered
	}
	return inspector.chain(path, 0, map[string]bool{})
}
func (inspector backingInspector) chain(path string, depth int, seen map[string]bool) backingClass {
	if depth > 8 || seen[path] || !pathWithin(path, inspector.sys) {
		return backingCovered
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return backingCovered
	}
	seen[path] = true
	defer delete(seen, path)
	hasPartition, err := sysfsPresent(filepath.Join(path, "partition"))
	if err != nil {
		return backingCovered
	}
	if hasPartition {
		return inspector.chain(filepath.Dir(path), depth+1, seen)
	}
	for _, directory := range []string{"slaves", "multipath"} {
		childDirectory := filepath.Join(path, directory)
		present, err := sysfsPresent(childDirectory)
		if err != nil {
			return backingCovered
		}
		if !present {
			continue
		}
		children, err := os.ReadDir(childDirectory)
		if err != nil {
			return backingCovered
		}
		if len(children) == 0 {
			if directory == "multipath" {
				return backingCovered
			}
			continue
		}
		class := backingDirect
		for _, child := range children {
			next, err := filepath.EvalSymlinks(filepath.Join(childDirectory, child.Name()))
			if err != nil {
				return backingCovered
			}
			class = combineBacking(class, inspector.chain(next, depth+1, seen))
		}
		return class
	}
	name := filepath.Base(path)
	if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "nbd") || strings.HasPrefix(name, "ublk") || strings.HasPrefix(name, "drbd") {
		return backingCovered
	}
	isNetwork := strings.HasPrefix(name, "rbd")
	isDirect := false
	driversOK := true
	for current := path; pathWithin(current, inspector.sys) && current != inspector.sys; current = filepath.Dir(current) {
		base := filepath.Base(current)
		if strings.HasPrefix(base, "vhci_hcd") || strings.HasPrefix(base, "session") {
			isNetwork = true
		}
		if strings.HasPrefix(base, "host") {
			for _, class := range []string{"iscsi_host", "fc_host", "srp_host"} {
				present, err := sysfsPresent(filepath.Join(inspector.sys, "class", class, base))
				if err != nil {
					return backingCovered
				}
				isNetwork = isNetwork || present
			}

			host := inspector.read(filepath.Join(inspector.sys, "class/scsi_host", base, "proc_name"))
			if strings.HasPrefix(name, "sd") && slices.Contains(directSCSIHosts, host) {
				isDirect = true
			}
		}
		if nvmeControllerName.MatchString(base) {
			data, err := os.ReadFile(filepath.Join(current, "transport"))
			if err != nil {
				return backingCovered
			}
			transport := strings.TrimSpace(string(data))
			switch transport {
			case "pcie":
				isDirect = nvmeNamespaceName.MatchString(name)
			case "tcp", "rdma", "fc":
				isNetwork = true
			default:
				return backingCovered
			}
		}
		driverPath := filepath.Join(current, "driver")
		present, err := sysfsPresent(driverPath)
		if err != nil {
			return backingCovered
		}
		if present {
			driver, err := filepath.EvalSymlinks(driverPath)
			if err != nil {
				return backingCovered
			}
			driver = filepath.Base(driver)
			if !slices.Contains(directDrivers, driver) {
				driversOK = false
			}
			switch driver {
			case "virtio_blk", "xen-blkfront", "xen_blkfront", "vbd", "mmcblk", "mmc_block":
				isDirect = true
			}
			if driver == "vhci_hcd" {
				isNetwork = true
			}
		}

	}
	if isNetwork {
		return backingNetwork
	}
	if strings.HasPrefix(name, "ram") {
		_, err := strconv.ParseUint(strings.TrimPrefix(name, "ram"), 10, 32)
		isDirect = err == nil
	}
	if strings.HasPrefix(name, "zram") {
		isDirect = inspector.read(filepath.Join(path, "backing_dev")) == "none"
	}
	if isDirect && driversOK {
		return backingDirect
	}
	return backingCovered
}
func (inspector backingInspector) mount(entry mountEntry) backingClass {
	if entry.fstype == "btrfs" {
		filesystems, err := os.ReadDir(filepath.Join(inspector.sys, "fs/btrfs"))
		if err != nil {
			return backingCovered
		}
		class := backingDirect
		devicesSeen := 0
		for _, filesystem := range filesystems {
			if filesystem.Name() == "features" {
				continue
			} // global feature attributes, not a mounted fsid
			directory := filepath.Join(inspector.sys, "fs/btrfs", filesystem.Name(), "devices")
			devices, err := os.ReadDir(directory)
			if err != nil || len(devices) == 0 {
				return backingCovered
			}
			for _, device := range devices {
				dev := inspector.read(filepath.Join(directory, device.Name(), "dev"))
				class = combineBacking(class, inspector.device(dev))
				devicesSeen++
			}
		}
		if devicesSeen == 0 {
			return backingCovered
		}

		return class
	}
	class := inspector.device(entry.dev)
	if entry.fstype == "xfs" {
		for _, option := range entry.superOpts {
			name, value, ok := strings.Cut(option, "=")
			if !ok || (name != "logdev" && name != "rtdev") {
				continue
			}
			value, err := unescapeMountField(value)
			if err != nil {
				return backingCovered
			}
			resolve := inspector.auxiliaryDevice
			if resolve == nil {
				resolve = inspector.resolveAuxiliaryDevice
			}
			dev, err := resolve(value)
			if err != nil {
				return backingCovered
			}

			class = combineBacking(class, inspector.device(dev))
		}
	}
	return class
}
func mountAccepted(entry mountEntry, accept []string, inspector backingInspector) bool {
	if slices.Contains(networkFstypes, entry.fstype) {
		return slices.Contains(accept, "network")
	}
	if entry.fstype == "autofs" {
		return slices.Contains(accept, "autofs")
	}
	if !slices.Contains(readSafeFstypes, entry.fstype) {
		return false
	}
	if entry.fstype == "btrfs" || slices.Contains(blockFstypes, entry.fstype) {
		class := inspector.mount(entry)
		return class == backingDirect || class == backingNetwork && slices.Contains(accept, "network")
	}
	return true
}

// resolveAuxiliaryDevice never resolves through an unconfirmed mount. In
// particular, root XFS with auxiliary devices is circular and remains unmet.
func (inspector backingInspector) resolveAuxiliaryDevice(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", unix.EINVAL
	}
	entries, err := readMountInfo()
	if err != nil {
		return "", err
	}
	root, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	rootID, err := mountID(root)
	unix.Close(root)
	if err != nil {
		return "", err
	}
	view := reachableMounts(entries, rootID)
	if len(view.unmet) > 0 {
		return "", unix.ESTALE
	}
	accepted := map[int]bool{}
	for _, entry := range view.entries {
		hasAuxiliary := false
		if entry.fstype == "xfs" {
			for _, option := range entry.superOpts {
				if strings.HasPrefix(option, "logdev=") || strings.HasPrefix(option, "rtdev=") {
					hasAuxiliary = true
				}
			}
		}
		if !hasAuxiliary {
			accepted[entry.id] = mountAccepted(entry, nil, inspector)
		}
	}
	result := walkTo(path, view, accepted, nil)
	defer result.close()
	if result.err != nil {
		return "", result.err
	}
	id, err := mountID(result.fd)
	if err != nil || !accepted[id] {
		return "", unix.ESTALE
	}
	var stat unix.Stat_t
	if err := unix.Fstat(result.fd, &stat); err != nil {
		return "", err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFBLK {
		return "", unix.ENOTBLK
	}
	return fmt.Sprintf("%d:%d", unix.Major(stat.Rdev), unix.Minor(stat.Rdev)), nil
}
