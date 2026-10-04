package confine

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func catalogueName(t *testing.T, names []string) string {
	for _, name := range names {
		if strings.HasSuffix(t.Name(), "/"+name) {
			return name
		}
	}
	t.Fatalf("SETUP: unknown catalogue proof %s", t.Name())
	return ""
}

func catalogueControl(t *testing.T, command string) OpOutcome {
	t.Helper()
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	control := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	control.Stdout, control.Stderr = &stdout, &stderr
	err := control.Run()
	result := OpOutcome{Stdout: stdout.String(), Stderr: stderr.String(), Exit: proofExit(err)}
	if result.Exit != 0 {
		t.Fatalf("SETUP: catalogue control status %d: %s", result.Exit, result.Stderr)
	}
	return result
}

func catalogueRun(t *testing.T, p *proof, spec Spec, command string, control OpOutcome) JailedResult {
	t.Helper()
	return runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "exec", Command: catalogueCommand(command), Validate: func(stdout, stderr string, exit int) error {
		return validateCatalogueStatus(p.caseDef.Name, control, stdout, stderr, exit)
	}}}})
}

// The shared frame reserves status >=126; git also uses 128 for ordinary fatal errors.
func catalogueCommand(command string) string {
	return "( " + command + "\n ); catalogue_status=$?; printf '\\nCATALOGUE-STATUS %s\\n' \"$catalogue_status\"; if [ \"$catalogue_status\" -eq 128 ]; then exit 125; fi; exit \"$catalogue_status\""
}

func validateCatalogueStatus(name string, control OpOutcome, stdout, stderr string, exit int) error {
	const marker = "\nCATALOGUE-STATUS "
	if strings.Count(stdout, marker) != 1 {
		return fmt.Errorf("missing or duplicate catalogue status")
	}
	report, raw, _ := strings.Cut(stdout, marker)
	if !strings.HasSuffix(raw, "\n") {
		return fmt.Errorf("unterminated catalogue status")
	}
	raw = strings.TrimSuffix(raw, "\n")
	status, err := strconv.Atoi(raw)
	if err != nil || strconv.Itoa(status) != raw {
		return fmt.Errorf("invalid catalogue status %q", raw)
	}
	framedStatus := status
	if status == 128 {
		framedStatus = 125
	}
	if exit != framedStatus {
		return fmt.Errorf("catalogue status %d disagrees with frame %d", status, exit)
	}
	return validateCatalogueCompletion(name, control, report, stderr, status)
}

func validateCatalogueCompletion(name string, control OpOutcome, stdout, stderr string, exit int) error {
	if exit < 0 || exit > 125 && !(exit == 128 && strings.Contains(name, "/git_")) {
		return fmt.Errorf("abnormal utility exit %d", exit)
	}
	if exit == 0 {
		if stdout != control.Stdout || stderr != control.Stderr {
			return fmt.Errorf("successful utility report differs from control: stdout %q stderr %q", stdout, stderr)
		}
		return nil
	}
	// curl reports transport and sink failures as specific documented exit codes.
	if strings.Contains(name, "/curl_") {
		if exit != 7 && exit != 23 && exit != 26 {
			return fmt.Errorf("unexpected curl exit %d: %q", exit, stderr)
		}
		if stdout != "" && stdout != control.Stdout {
			return fmt.Errorf("unexpected curl stdout %q", stdout)
		}
		if stderr != "" {
			lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
			if len(lines) != 1 || !strings.HasPrefix(lines[0], fmt.Sprintf("curl: (%d) ", exit)) {
				return fmt.Errorf("unexpected curl stderr %q", stderr)
			}
		}
		return nil
	}
	if exit != 1 && exit != 2 && exit != 4 && exit != 32 && exit != 128 {
		return fmt.Errorf("unexpected utility exit %d", exit)
	}
	if stdout != "" && stdout != control.Stdout {
		// sysctl --system announces configuration files before attempting writes.
		if !strings.Contains(name, "/sysctl_") {
			return fmt.Errorf("unexpected utility stdout %q", stdout)
		}
		remaining := control.Stdout
		for _, line := range strings.Split(strings.TrimSuffix(stdout, "\n"), "\n") {
			_, tail, found := strings.Cut(remaining, line+"\n")
			if !found || !strings.HasPrefix(line, "* Applying ") {
				return fmt.Errorf("unexpected sysctl stdout %q", line)
			}
			remaining = tail
		}
	}
	if stderr == "" {
		return fmt.Errorf("failed utility lacks denial diagnostic")
	}
	for _, line := range strings.Split(strings.TrimSuffix(stderr, "\n"), "\n") {
		if !strings.Contains(line, "Permission denied") && !strings.Contains(line, "permission denied") && !strings.Contains(line, "Operation not permitted") && !strings.Contains(line, "Read-only file system") && !strings.Contains(line, "read-only file system") && !strings.Contains(line, "dmesg(1) may have more information") {
			return fmt.Errorf("unexpected utility diagnostic %q", line)
		}
	}
	return nil
}

func TestCatalogueM1Completion(t *testing.T) {
	control := OpOutcome{Stdout: "payload\n"}
	for _, item := range []struct {
		name, stdout, stderr string
		exit                 int
		valid                bool
	}{
		{"file", "payload\n", "", 0, true},
		{"file", "", "file: Permission denied\n", 1, true},
		{"file", "", "", 1, false},
		{"file", "", "file: Permission denied\nobserver crashed\n", 1, false},
		{"file", "", "", 139, false},
		{"L-CATALOGUE/curl_json_post/deny", "", "curl: (7) Failed to connect\n", 7, true},
		{"L-CATALOGUE/curl_json_post/deny", "", "", 28, false},
	} {
		if err := validateCatalogueCompletion(item.name, control, item.stdout, item.stderr, item.exit); (err == nil) != item.valid {
			t.Errorf("%+v: %v", item, err)
		}
	}
}

func TestCatalogueM1Status(t *testing.T) {
	for _, item := range []struct {
		status, frame int
		stderr        string
		valid         bool
	}{
		{128, 125, "fatal: cannot create file: Permission denied\n", true},
		{137, 137, "fatal: cannot create file: Permission denied\n", false},
		{128, 0, "fatal: cannot create file: Permission denied\n", false},
		{126, 126, "Permission denied\n", false},
		{127, 127, "Permission denied\n", false},
	} {
		stdout := fmt.Sprintf("\nCATALOGUE-STATUS %d\n", item.status)
		err := validateCatalogueStatus("L-CATALOGUE/git_branch_new", OpOutcome{}, stdout, item.stderr, item.frame)
		if (err == nil) != item.valid {
			t.Errorf("%+v: %v", item, err)
		}
	}
	for _, status := range []int{0, 1, 128, 137} {
		command := exec.Command("/bin/sh", "-c", catalogueCommand(fmt.Sprintf("printf payload; exit %d", status)))
		output, err := command.Output()
		want := status
		if status == 128 {
			want = 125
		}
		if proofExit(err) != want || string(output) != fmt.Sprintf("payload\nCATALOGUE-STATUS %d\n", status) {
			t.Fatalf("status %d: exit %d output %q", status, proofExit(err), output)
		}
	}
	control := OpOutcome{Stdout: "* Applying /etc/sysctl.conf ...\nkernel.domainname = fixture\n"}
	if err := validateCatalogueCompletion("L-CATALOGUE/sysctl_system", control, "* Applying /etc/sysctl.conf ...\n", "sysctl: permission denied on key \"kernel.domainname\"\n", 1); err != nil {
		t.Fatal(err)
	}
}
