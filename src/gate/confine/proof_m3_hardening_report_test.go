package confine

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func validateHardeningReport(leg, stdout, stderr string, exit, wantExit int) error {
	if wantExit >= 0 && exit != wantExit {
		return fmt.Errorf("probe exit %d, want %d", exit, wantExit)
	}
	if leg != "L-ROOT-PROC" && stderr != "" {
		return fmt.Errorf("probe stderr %q", stderr)
	}
	if leg == "L-ROOT-PROC" && !((exit == 2 && stderr == "/bin/sh: 1: cannot create /proc/sys/kernel/printk: Read-only file system\n") || (exit == 1 && stderr == "/bin/sh: line 1: /proc/sys/kernel/printk: Read-only file system\n")) {
		return fmt.Errorf("printk write exit=%d stderr=%q", exit, stderr)
	}
	switch leg {
	case "L-ROOT-STATE":
		if validateHardeningControl("root-state", stdout) != nil || !strings.HasSuffix(stdout, "open_by_handle_at=1\n") {
			return fmt.Errorf("incomplete root state report %q", stdout)
		}
	case "L-ROOT-NPROC":
		if stdout != "getrlimit=ok\nnproc=256:256\nsetrlimit=ok\nfork-root=ok\n" {
			return fmt.Errorf("incomplete root nproc report %q", stdout)
		}
	case "L-ROOT-PROC":
		if stdout != "" {
			return fmt.Errorf("unexpected printk stdout %q", stdout)
		}
	case "L-SCRATCH-META":
		_, _, body, err := parseHardeningMetadata(stdout)
		if err != nil {
			return err
		}
		if !regexp.MustCompile(`^chmod=(ok|1)
chown=(ok|1)
setxattr=(ok|1|95)
utimensat=(ok|1)
mode=(600|644)
mtime=[0-9]+
(xattr=test
)?$`).MatchString(body) || (exit != 0 && exit != 1 && exit != 3) {
			return fmt.Errorf("incomplete metadata report %q exit %d", stdout, exit)
		}
	case "L-FILEATTR-ERRNO":
		if !regexp.MustCompile(`^open=ok
setflags=(ok|[0-9]+)
setflags32=(ok|[0-9]+)
fssetxattr=(ok|[0-9]+)
$`).MatchString(stdout) {
			return fmt.Errorf("incomplete fileattr report %q", stdout)
		}
	}
	return nil
}
func TestM3HardeningReports(t *testing.T) {
	for _, test := range []struct {
		name, leg, out, err string
		exit, want          int
		valid               bool
	}{
		{"printk-denied", "L-ROOT-PROC", "", "/bin/sh: 1: cannot create /proc/sys/kernel/printk: Read-only file system\n", 2, -1, true},
		{"printk-noisy", "L-ROOT-PROC", "", "other failure read-only", 2, -1, false},
		{"nproc", "L-ROOT-NPROC", "getrlimit=ok\nnproc=256:256\nsetrlimit=ok\nfork-root=ok\n", "", 0, 0, true},
		{"nproc-truncated", "L-ROOT-NPROC", "getrlimit=ok\nnproc=256:256\nsetrlimit=ok\n", "", 0, 0, false},
		{"nproc-stderr", "L-ROOT-NPROC", "getrlimit=ok\nnproc=256:256\nsetrlimit=ok\nfork-root=ok\n", "error", 0, 0, false},
		{"metadata-denied", "L-SCRATCH-META", "chmod=1\nchown=1\nsetxattr=1\nutimensat=1\nmode=600\nmtime=123\n", "", 1, -1, true},
		{"metadata-truncated", "L-SCRATCH-META", "chmod=1\nchown=1\n", "", 1, -1, false},
		{"metadata-xattr-unsupported", "L-SCRATCH-META", "chmod=ok\nchown=ok\nsetxattr=95\nutimensat=ok\nmode=644\nmtime=1000\n", "", 3, -1, true},
		{"fileattr-denied", "L-FILEATTR-ERRNO", "open=ok\nsetflags=1\nsetflags32=1\nfssetxattr=1\n", "", 3, -1, true},
		{"fileattr-extra", "L-FILEATTR-ERRNO", "open=ok\nsetflags=1\nsetflags32=1\nfssetxattr=1\nextra\n", "", 3, -1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			out := test.out
			if test.leg == "L-SCRATCH-META" {
				after := "after-mode=600\nafter-mtime=123:0\nafter-xattr=absent\n"
				if test.name == "metadata-xattr-unsupported" {
					after = "after-mode=644\nafter-mtime=1000:0\nafter-xattr=unsupported\n"
				}
				out = "before-mode=600\nbefore-mtime=123:0\nbefore-xattr=absent\n" + out + after
			}
			err := validateHardeningReport(test.leg, out, test.err, test.exit, test.want)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v error=%v", test.valid, err)
			}
		})
	}
}

func validateHardeningControl(op, report string) error {
	if op == "root-nproc" {
		if !regexp.MustCompile(`^getrlimit=ok
nproc=[0-9]+:[0-9]+
setrlimit=ok
fork-root=ok
$`).MatchString(report) {
			return fmt.Errorf("invalid root nproc control %q", report)
		}
		return nil
	}
	if !regexp.MustCompile(`^uid_map=ok
uid_map:
[ 	]*[0-9]+[ 	]+[0-9]+[ 	]+[0-9]+
gid_map=ok
gid_map:
[ 	]*[0-9]+[ 	]+[0-9]+[ 	]+[0-9]+
status=ok
status:
([A-Za-z_][A-Za-z_0-9]*:[^
]*
)+open_by_handle_at=[0-9]+
$`).MatchString(report) {
		return fmt.Errorf("invalid root state control %q", report)
	}
	for _, name := range []string{"CapPrm", "CapEff", "CapBnd", "CapInh", "CapAmb"} {
		if strings.Count(report, name+":") != 1 {
			return fmt.Errorf("missing or duplicate %s", name)
		}
	}
	return nil
}

func TestM3HardeningControlReports(t *testing.T) {
	state := "uid_map=ok\nuid_map:\n         0          0 4294967295\ngid_map=ok\ngid_map:\n         0          0 4294967295\nstatus=ok\nstatus:\nName:\tprobe\nCapPrm:\t0000000000000004\nCapEff:\t0000000000000004\nCapBnd:\t0000000000000004\nCapInh:\t0000000000000000\nCapAmb:\t0000000000000000\nopen_by_handle_at=1\n"
	for _, test := range []struct {
		name, op, report string
		valid            bool
	}{
		{"state", "root-state", state, true},
		{"state-truncated", "root-state", strings.TrimSuffix(state, "open_by_handle_at=1\n"), false},
		{"state-noisy", "root-state", state + "unexpected\n", false},
		{"state-missing-cap", "root-state", strings.ReplaceAll(state, "CapAmb:\t0000000000000000\n", ""), false},
		{"nproc", "root-nproc", "getrlimit=ok\nnproc=123:456\nsetrlimit=ok\nfork-root=ok\n", true},
		{"nproc-truncated", "root-nproc", "getrlimit=ok\nnproc=123:456\nsetrlimit=ok\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateHardeningControl(test.op, test.report)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v error=%v", test.valid, err)
			}
		})
	}
}

func validateHardeningEffectControl(op, stdout, stderr string, exit int) error {
	if stderr != "" {
		return fmt.Errorf("control stderr %q", stderr)
	}
	if op == "metadata" {
		if exit != 0 || stdout != "chmod=ok\nchown=ok\nsetxattr=ok\nutimensat=ok\nmode=644\nmtime=1000\nxattr=test\n" {
			return fmt.Errorf("incomplete metadata control %q exit %d", stdout, exit)
		}
		return nil
	}
	if op != "fileattr" {
		return fmt.Errorf("unknown control %q", op)
	}
	if err := validateHardeningReport("L-FILEATTR-ERRNO", stdout, stderr, exit, -1); err != nil {
		return err
	}
	succeeded := strings.Count(stdout, "=ok\n")
	wantExit := 3
	if succeeded == 4 {
		wantExit = 0
	}
	if exit != wantExit {
		return fmt.Errorf("fileattr control exit %d, want %d", exit, wantExit)
	}
	return nil
}

func TestM3HardeningEffectControls(t *testing.T) {
	metadata := "chmod=ok\nchown=ok\nsetxattr=ok\nutimensat=ok\nmode=644\nmtime=1000\nxattr=test\n"
	fileattr := "open=ok\nsetflags=95\nsetflags32=95\nfssetxattr=25\n"
	for _, test := range []struct {
		op, stdout, stderr string
		exit               int
		valid              bool
	}{
		{"metadata", metadata, "", 0, true},
		{"metadata", metadata, "diagnostic", 0, false},
		{"metadata", strings.TrimSuffix(metadata, "xattr=test\n"), "", 0, false},
		{"metadata", strings.Replace(metadata, "mode=644", "mode=600", 1), "", 0, false},
		{"fileattr", fileattr, "", 3, true},
		{"fileattr", fileattr, "diagnostic", 3, false},
		{"fileattr", fileattr, "", 1, false},
		{"fileattr", fileattr + "extra\n", "", 3, false},
		{"fileattr", strings.TrimSuffix(fileattr, "fssetxattr=25\n"), "", 3, false},
	} {
		if err := validateHardeningEffectControl(test.op, test.stdout, test.stderr, test.exit); (err == nil) != test.valid {
			t.Fatalf("op=%s stdout=%q stderr=%q exit=%d valid=%t: %v", test.op, test.stdout, test.stderr, test.exit, test.valid, err)
		}
	}
}

type hardeningMetadataState struct {
	mode, seconds, nanoseconds, xattr string
}

func parseHardeningMetadata(report string) (before, after hardeningMetadataState, body string, err error) {
	pattern := regexp.MustCompile(`^before-mode=(600)
before-mtime=([0-9]+):([0-9]+)
before-xattr=(absent|unsupported)
([\s\S]*)after-mode=(600|644)
after-mtime=([0-9]+):([0-9]+)
after-xattr=(absent|unsupported|test)
$`)
	fields := pattern.FindStringSubmatch(report)
	if len(fields) != 10 {
		return before, after, "", fmt.Errorf("incomplete metadata snapshots %q", report)
	}
	before = hardeningMetadataState{fields[1], fields[2], fields[3], fields[4]}
	after = hardeningMetadataState{fields[6], fields[7], fields[8], fields[9]}
	body = fields[5]
	if !strings.Contains(body, "mode="+after.mode+"\nmtime="+after.seconds+"\n") {
		return before, after, body, fmt.Errorf("metadata report disagrees with after snapshot")
	}
	if strings.HasSuffix(body, "xattr=test\n") != (after.xattr == "test") {
		return before, after, body, fmt.Errorf("metadata xattr report disagrees with after snapshot")
	}
	if strings.HasPrefix(body, "chmod=1\nchown=1\nsetxattr=1\nutimensat=1\n") && before != after {
		return before, after, body, fmt.Errorf("denied metadata changed state: before=%+v after=%+v", before, after)
	}
	return before, after, body, nil
}

func TestM3MetadataSnapshotAbsence(t *testing.T) {
	prefix := "before-mode=600\nbefore-mtime=123:456\nbefore-xattr=absent\n"
	body := "chmod=1\nchown=1\nsetxattr=1\nutimensat=1\nmode=600\nmtime=123\n"
	suffix := "after-mode=600\nafter-mtime=123:456\nafter-xattr=absent\n"
	valid := prefix + body + suffix
	if err := validateHardeningReport("L-SCRATCH-META", valid, "", 1, -1); err != nil {
		t.Fatal(err)
	}
	for _, report := range []string{
		prefix + body + strings.Replace(suffix, "123:456", "123:457", 1),
		prefix + strings.Replace(body, "mode=600", "mode=644", 1) + strings.Replace(suffix, "mode=600", "mode=644", 1),
		prefix + body + strings.Replace(suffix, "xattr=absent", "xattr=test", 1),
		prefix + body,
		body + suffix,
	} {
		if err := validateHardeningReport("L-SCRATCH-META", report, "", 1, -1); err == nil {
			t.Fatalf("accepted unproved absence: %q", report)
		}
	}
}
