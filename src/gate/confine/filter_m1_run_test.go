//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/unix"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Every call is one framed operation; the leaf owns the aggregate evidence.
func runM1Filter(t *testing.T, p *proof, runs *[]JailedResult, spec Spec, command string, configure func(*Jailed)) jailResult {
	t.Helper()
	result := runJailed(t, p, spec, RunPlan{Mode: Execute, Configure: configure, Ops: []ProofOp{{Name: "probe", Command: command, Validate: func(stdout, stderr string, exit int) error {
		return validateM1Filter(command, jailResult{stdout: stdout, stderr: stderr, exit: exit})
	}}}})
	*runs = append(*runs, result)
	return result.jailResult
}

func validateM1Filter(command string, result jailResult) error {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return fmt.Errorf("empty filter operation")
	}
	expected := map[string][]string{
		"pipesz": {"pipesz", "size"}, "rwhint": {"open", "rwhint"},
		"rlimit-lock": {"getrlimit", "before", "setrlimit", "prlimit64", "getrlimit-after", "after"},
		"raw":         {"raw"}, "syncfs": {"open", "syncfs"}, "listen": {"socket", "listen"},
		"socket-tuple": {"socket"}, "socketpair-tuple": {"socketpair"},
		"clone-ns": {"clone", "clone>wait"}, "setns": {"open", "setns"},
		"dgram-send": {"socketpair", "socketpair>sendto"}, "signal": {"kill"},
		"shm-rmid": {"shmctl"}, "scheduler": {"prlimit", "nice", "ioprio", "policy", "affinity", "schedattr", "state"},
		"scheduler-state": {"state"}, "keyring-add": {"keyring"}, "keyring-clear": {"keyring"}, "keyring-request": {"keyring"},
		"dial-inet": {"socket", "socket>connect"}, "dial-inet6": {"socket", "socket>connect"},
		"unix-connect": {"socket", "socket>connect"}, "ioctl-scratch": {"open", "ioctl"}, "tiocsti": {"tiocsti"},
		"metadata-errno": {"open", "fchmod", "chmod", "chown", "setxattr", "utimensat"},
	}
	for _, operation := range fields {
		if operation == "uring" {
			return validateM1Uring(result)
		}
		if operation == "listen" && result.stdout != "socket=ok\nlisten=1\n" && result.stdout != "socket=ok\nlisten=ok\n" {
			return fmt.Errorf("listen operation not reached or invalid errno")
		}
		if reports, ok := expected[operation]; ok {
			return validateM1Reports(result, reports)
		}
		if operation == "socket-sweep" {
			var attempts, denied int
			if result.stderr != "" || result.exit != 0 || !regexp.MustCompile(`^attempts=[0-9]+ denied=[0-9]+\n$`).MatchString(result.stdout) {
				return fmt.Errorf("incomplete socket sweep")
			}
			if _, err := fmt.Sscanf(result.stdout, "attempts=%d denied=%d", &attempts, &denied); err != nil || attempts < 20000 || denied < 0 || denied > attempts {
				return fmt.Errorf("invalid socket sweep counts")
			}
			return nil
		}
	}
	if strings.HasPrefix(command, "ss ") {
		if result.exit != 0 || result.stdout == "" || !strings.HasSuffix(result.stdout, "\n") {
			return fmt.Errorf("ss did not complete")
		}
		if result.stderr != "" {
			for _, line := range strings.Split(strings.TrimSuffix(result.stderr, "\n"), "\n") {
				if line != "Cannot open netlink socket: Operation not permitted" {
					return fmt.Errorf("unexpected ss diagnostic %q", line)
				}
			}
		}
		port := strings.TrimPrefix(strings.TrimSuffix(fields[len(fields)-1], "'"), ":")
		for _, line := range strings.Split(strings.TrimSuffix(result.stdout, "\n"), "\n") {
			row := strings.Fields(line)
			if len(row) != 5 || row[0] != "LISTEN" || !strings.HasSuffix(row[3], ":"+port) || !strings.HasSuffix(row[4], ":*") {
				return fmt.Errorf("invalid ss listener row %q", line)
			}
			for _, count := range row[1:3] {
				n, err := strconv.Atoi(count)
				if err != nil || n < 0 {
					return fmt.Errorf("invalid ss queue count")
				}
			}
		}
		return nil
	}
	if fields[0] == "ulimit" || fields[0] == "prlimit" || fields[0] == "unshare" || fields[0] == "renice" || fields[0] == "ionice" || fields[0] == "chrt" || fields[0] == "taskset" {
		if result.exit == 0 {
			if result.stderr != "" {
				return fmt.Errorf("successful utility has diagnostics")
			}
			if fields[0] != "renice" && fields[0] != "taskset" && result.stdout != "" {
				return fmt.Errorf("unexpected utility output")
			}
			if fields[0] == "renice" && !regexp.MustCompile(`^[0-9]+ \(process ID\) old priority [-0-9]+, new priority 19\n$`).MatchString(result.stdout) {
				return fmt.Errorf("invalid renice completion")
			}
			if fields[0] == "taskset" && !regexp.MustCompile(`^pid [0-9]+'s current affinity list: [0-9,-]+\npid [0-9]+'s new affinity list: [0-9,-]+\n$`).MatchString(result.stdout) {
				return fmt.Errorf("invalid taskset completion")
			}
			return nil
		}
		if result.exit != 1 && result.exit != 2 {
			return fmt.Errorf("abnormal utility exit %d", result.exit)
		}
		diagnostic := strings.ToLower(result.stderr)
		if !strings.HasSuffix(diagnostic, "operation not permitted\n") && !strings.HasSuffix(diagnostic, "operation not permitted)\n") && !strings.HasSuffix(diagnostic, "no such process\n") {
			return fmt.Errorf("unexpected utility denial %q", result.stderr)
		}
		if strings.Count(diagnostic, "\n") != 1 || (result.stdout != "" && fields[0] != "taskset") {
			return fmt.Errorf("extra utility report")
		}
		return nil
	}
	return fmt.Errorf("undeclared filter command %q", command)
}

func validateM1Uring(result jailResult) error { return validateM1UringResult(result, false) }

func validateM1UringResult(result jailResult, control bool) error {
	lines := strings.Split(strings.TrimSuffix(result.stdout, "\n"), "\n")
	fields := map[string]string{}
	for _, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if !ok || fields[key] != "" {
			return fmt.Errorf("malformed or duplicate uring report")
		}
		fields[key] = value
	}
	expected := []string{"io_uring_setup"}
	if fields["io_uring_setup"] == "ok" {
		expected = append(expected, "eventfd", "io_uring_register")
		if fields["eventfd"] != "ok" {
			return fmt.Errorf("eventfd setup failed")
		}
		if fields["io_uring_register"] == "ok" {
			expected = append(expected, "sq-map", "cq-map", "sqes-map", "uring-socket-enter")
			for _, field := range []string{"sq-map", "cq-map", "sqes-map"} {
				if fields[field] != "ok" {
					return fmt.Errorf("ring mapping incomplete: %s", field)
				}
			}
			if fields["uring-socket-enter"] == "ok" {
				expected = append(expected, "uring-socket")
				if fields["uring-socket"] != "ok" {
					return fmt.Errorf("socket CQE failed: %s", fields["uring-socket"])
				}
				expected = append(expected, "uring-connect-enter", "uring-connect", "uring-setxattr-enter", "uring-setxattr")
				if fields["uring-connect-enter"] != "ok" || fields["uring-connect"] != "ok" || fields["uring-setxattr-enter"] != "ok" {
					return fmt.Errorf("missing operation-specific completion")
				}
				errno, err := strconv.Atoi(fields["uring-setxattr"])
				if !(control && fields["uring-setxattr"] == "ok") && (err != nil || errno != 13 && errno != 30) {
					return fmt.Errorf("xattr CQE must be EACCES or EROFS: %q", fields["uring-setxattr"])
				}
			} else if fields["uring-socket-enter"] != "1" {
				return fmt.Errorf("unexpected enter stop")
			}
		} else if fields["io_uring_register"] != "1" {
			return fmt.Errorf("unexpected register stop")
		}
	} else if fields["io_uring_setup"] != "1" {
		return fmt.Errorf("unexpected setup stop")
	}
	if len(fields) != len(expected) {
		return fmt.Errorf("unexpected uring reports: %v", fields)
	}
	return validateM1Reports(result, expected)
}

func validateM1Reports(result jailResult, expected []string) error {
	if err := validateProbeOutput(result, expected, probeExitMixed); err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, field := range expected {
		if _, next, ok := strings.Cut(field, ">"); ok {
			field = next
		}
		allowed[field] = true
	}
	for _, line := range strings.Split(strings.TrimSuffix(result.stdout, "\n"), "\n") {
		field, value, _ := strings.Cut(line, "=")
		if !allowed[field] {
			return fmt.Errorf("undeclared report %q", field)
		}
		switch field {
		case "size":
			if _, err := strconv.Atoi(value); err != nil {
				return fmt.Errorf("invalid pipe size")
			}
		case "before", "after":
			if !regexp.MustCompile(`^[0-9]+:[0-9]+$`).MatchString(value) {
				return fmt.Errorf("invalid limit state")
			}
		case "state":
			if !regexp.MustCompile(`^-?[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+$`).MatchString(value) {
				return fmt.Errorf("invalid scheduler state")
			}
		}
	}
	return nil
}

func validateM1Accept(err error, reportedConnected bool) error {
	if err != nil {
		timeout, ok := err.(interface{ Timeout() bool })
		if !ok || !timeout.Timeout() {
			return fmt.Errorf("listener observation failed: %w", err)
		}
	}
	if reportedConnected != (err == nil) {
		return fmt.Errorf("inconclusive listener observation: reported connection=%t, accept=%v", reportedConnected, err)
	}
	return nil
}

func m1ControlOutput(t *testing.T, command *exec.Cmd) ([]byte, error) {
	t.Helper()
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	output, err := command.Output()
	result := jailResult{stdout: string(output), stderr: diagnostic.String(), exit: proofExit(err)}
	if result.stderr != "" {
		t.Fatalf("SETUP: unjailed control diagnostic: %s", result.stderr)
	}
	if err != nil {
		return output, err
	}
	contract := strings.Join(command.Args, " ")
	if len(command.Args) > 2 && command.Args[1] == "-c" {
		contract = command.Args[2]
	}
	var validation error
	if len(command.Args) > 1 && command.Args[1] == "uring" {
		validation = validateM1UringResult(result, true)
	} else {
		validation = validateM1Filter(contract, result)
	}
	mutationSetup(t, validation)
	return output, nil
}

func m1ShmExists(t *testing.T, id int) bool {
	t.Helper()
	var state unix.SysvShmDesc
	_, err := unix.SysvShmCtl(id, unix.IPC_STAT, &state)
	exists, observationErr := m1ShmPresence(err)
	mutationSetup(t, observationErr)
	return exists
}
func m1ShmPresence(err error) (bool, error) {
	if err == nil {
		return true, nil
	}
	if err == unix.EINVAL || err == unix.EIDRM {
		return false, nil
	}
	return false, fmt.Errorf("shared-memory observation: %w", err)
}

func m1ShmCreate(t *testing.T) int {
	t.Helper()
	id, err := unix.SysvShmGet(unix.IPC_PRIVATE, 4096, unix.IPC_CREAT|unix.IPC_EXCL|0600)
	mutationSetup(t, err)
	t.Cleanup(func() { m1ShmRemove(t, id) })
	return id
}
func m1ShmRemove(t *testing.T, id int) {
	t.Helper()
	_, err := unix.SysvShmCtl(id, unix.IPC_RMID, nil)
	if err != nil && err != unix.EINVAL && err != unix.EIDRM {
		t.Fatalf("SETUP: remove SysV fixture: %v", err)
	}
}
