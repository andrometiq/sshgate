package confine

// MountReport describes one mount for gate doctor. It is a report only:
// Accepted is the jail's own verdict (mountAccepted), and DevicePath and
// Slaves feed no decision.
type MountReport struct {
	Point  string `json:"point"`
	FSType string `json:"fstype"`
	Source string `json:"source"`
	// Class is network, autofs, block (a block-device file system), virtual
	// (another read-safe type) or unsupported.
	Class string `json:"class"`
	// Backing is the block device chain's class: direct, network or covered.
	// Empty for other classes.
	Backing string `json:"backing,omitempty"`
	// DevicePath is the block device under /sys; Slaves are the devices
	// beneath it (a device-mapper, md or loop chain), outermost first.
	DevicePath string   `json:"device_path,omitempty"`
	Slaves     []string `json:"slaves,omitempty"`
	// Accepted reports whether the read jail shows this mount, with the
	// given accept_fs, rather than covering it.
	Accepted bool `json:"accepted"`
}
