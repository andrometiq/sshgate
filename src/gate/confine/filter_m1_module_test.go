//go:build linux && jail_e2e

package confine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

func readM1Modules() ([]string, error) {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, err
	}
	return parseM1Modules(data)
}

func unloadM1Diag() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "modprobe", "-r", "raw_diag").CombinedOutput()
	if ctx.Err() != nil {
		return false, fmt.Errorf("unload raw_diag: %w", ctx.Err())
	}
	names, readErr := readM1Modules()
	if readErr != nil {
		return false, readErr
	}
	if err != nil {
		if _, exited := err.(*exec.ExitError); exited && (slices.Contains(names, "raw_diag") || strings.Contains(strings.ToLower(string(output)), "builtin") || strings.Contains(strings.ToLower(string(output)), "built-in")) {
			return false, nil
		}
		return false, fmt.Errorf("unload raw_diag: %v: %s", err, output)
	}
	if slices.Contains(names, "raw_diag") {
		return false, fmt.Errorf("raw_diag remains after successful unload")
	}
	if _, err := os.Stat("/sys/module/raw_diag"); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	return true, nil
}

func legSockdiagModule(t *testing.T, spec Spec) {
	p := newProof(t, "L-SOCKDIAG-AUTOLOAD")
	if os.Getuid() != 0 {
		p.Omit("root-only")
		return
	}
	if os.Getenv("SSHGATE_JAIL_CI") != "1" {
		p.Omit("ci-only")
		return
	}
	cold, err := unloadM1Diag()
	mutationSetup(t, err)
	if !cold {
		p.Omit("module-builtin")
		return
	}
	restore := func() error {
		cold, err := unloadM1Diag()
		if err != nil {
			return err
		}
		if !cold {
			return fmt.Errorf("raw_diag cannot be restored to cold state")
		}
		return nil
	}
	observer := &m1ModuleObserver{read: readM1Modules, restore: restore}
	p.ObserveWith("modules", observer)
	mark := observer.Mark()
	result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "ss", Command: "LC_ALL=C ss -tuxwa", Validate: validateM1DiagSS}}})
	p.Jailed("probe", result)
	// Socket/netlink request_module work completes before the requesting syscall returns.
	mutationSetup(t, observer.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}))
	records := observer.Since(mark)
	p.Observed("modules", Observation{Conclusive: records.Conclusive, Sealed: records.Sealed, Valid: records.Err == nil, Detail: strings.Join(records.Records, ",")})
	for _, record := range records.Records {
		if !slices.Contains([]string{"+raw_diag", "+inet_diag", "+tcp_diag", "+udp_diag", "+unix_diag"}, record) || !slices.Contains(records.Records, "+raw_diag") {
			t.Fatalf("SETUP: unrelated module change during sockdiag window: %s", record)
		}
	}
	mutationEffect(t, "L-SOCKDIAG-AUTOLOAD", "module-loaded", slices.Contains(records.Records, "+raw_diag"))
	// Reset even under a mutation: the control must demonstrate a fresh autoload.
	mutationSetup(t, restore())
	probe := buildProbe(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, probe, "sockdiag-request", "unused").CombinedOutput()
	mutationSetup(t, err)
	if string(output) != "socket=ok\nsockdiag=ok\n" {
		t.Fatalf("SETUP: sockdiag autoload control report %q", output)
	}
	names, err := readM1Modules()
	mutationSetup(t, err)
	p.Control("autoload", ControlResult{Valid: slices.Contains(names, "raw_diag"), Detail: "unjailed AF_INET6/IPPROTO_RAW request loads raw_diag from cold state"})
	p.Finish()
}

func validateM1DiagSS(stdout, stderr string, exit int) error {
	if exit != 0 || !strings.HasSuffix(stdout, "\n") {
		return fmt.Errorf("ss incomplete: exit %d stdout %q", exit, stdout)
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "Netid") || !strings.Contains(lines[0], "State") || !strings.Contains(lines[0], "Peer Address:Port") {
		return fmt.Errorf("ss missing table header: %q", stdout)
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 6 || !slices.Contains([]string{"tcp", "udp", "u_str", "u_dgr", "u_seq", "raw"}, fields[0]) {
			return fmt.Errorf("unexpected ss record %q", line)
		}
	}
	if stderr != "" {
		for _, line := range strings.Split(strings.TrimSuffix(stderr, "\n"), "\n") {
			if line != "Cannot open netlink socket: Operation not permitted" {
				return fmt.Errorf("unexpected ss diagnostic %q", line)
			}
		}
	}
	return nil
}
