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

// sink is the outside path the command writes (or mounts on); utility diagnostics
// that name it instead of an errno are matched against it exactly.
// isHeaderOpenCrash is the verdict of curlCrashesOnHeaderOpen's unjailed probe.
func catalogueRun(t *testing.T, p *proof, spec Spec, command, sink string, control OpOutcome, isHeaderOpenCrash bool) JailedResult {
	t.Helper()
	return runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "exec", Command: catalogueCommand(command), Validate: func(stdout, stderr string, exit int) error {
		return validateCatalogueStatus(p.caseDef.Name, sink, control, isHeaderOpenCrash, stdout, stderr, exit)
	}}}})
}

// The shared frame reserves status >=126; git uses 128 for fatal errors and
// 255 (error() returned from cmd_config) for a failed `git config` write, and
// 139 is the shell's SIGSEGV status for curl's -D crash (isCurlHeaderOpenCrash).
func catalogueCommand(command string) string {
	return "( " + command + "\n ); catalogue_status=$?; printf '\\nCATALOGUE-STATUS %s\\n' \"$catalogue_status\"; if [ \"$catalogue_status\" -eq 128 ] || [ \"$catalogue_status\" -eq 139 ] || [ \"$catalogue_status\" -eq 255 ]; then exit 125; fi; exit \"$catalogue_status\""
}

func validateCatalogueStatus(name, sink string, control OpOutcome, isHeaderOpenCrash bool, stdout, stderr string, exit int) error {
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
	if status == 128 || status == 139 || status == 255 {
		framedStatus = 125
	}
	if exit != framedStatus {
		return fmt.Errorf("catalogue status %d disagrees with frame %d", status, exit)
	}
	return validateCatalogueCompletion(name, sink, control, isHeaderOpenCrash, report, stderr, status)
}

func validateCatalogueCompletion(name, sink string, control OpOutcome, isHeaderOpenCrash bool, stdout, stderr string, exit int) error {
	isGitFatal := exit == 128 && strings.Contains(name, "/git_")
	isGitConfigError := exit == 255 && strings.HasSuffix(name, "/git_config_set")
	if isCurlHeaderOpenCrash(name, isHeaderOpenCrash, stdout, stderr, exit) {
		return nil
	}
	if exit < 0 || exit > 125 && !isGitFatal && !isGitConfigError {
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
			last := len(lines) - 1
			if !strings.HasPrefix(lines[last], fmt.Sprintf("curl: (%d) ", exit)) || last > 0 && !isCurlHeaderOpenWarning(name, sink, exit, lines[:last]) {
				return fmt.Errorf("unexpected curl stderr %q", stderr)
			}
		}
		return nil
	}
	if exit != 1 && exit != 2 && exit != 4 && exit != 32 && exit != 128 && exit != 255 {
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
	hasDenial := false
	for _, line := range strings.Split(strings.TrimSuffix(stderr, "\n"), "\n") {
		switch {
		case isErrnoDenial(line) || isCatalogueOwnDenial(name, sink, line):
			hasDenial = true
		case isCatalogueConsequence(name, line) || strings.Contains(line, "dmesg(1) may have more information"):
		default:
			return fmt.Errorf("unexpected utility diagnostic %q", line)
		}
	}
	if !hasDenial {
		return fmt.Errorf("utility diagnostic lacks the denial itself: %q", stderr)
	}
	return nil
}

func isErrnoDenial(line string) bool {
	for _, text := range []string{"Permission denied", "permission denied", "Operation not permitted", "Read-only file system", "read-only file system"} {
		if strings.Contains(line, text) {
			return true
		}
	}
	return false
}

// isCatalogueOwnDenial matches a utility's own errno-free wording for the refused
// sink: tree reports any failed -o open as an invalid filename, and libmount
// renders EPERM for a non-root caller as "must be superuser".
func isCatalogueOwnDenial(name, sink, line string) bool {
	switch {
	case sink == "":
		return false
	case strings.HasSuffix(name, "/tree_bundled_output"):
		return line == "tree: invalid filename '"+sink+"'"
	case strings.Contains(name, "/mount_"):
		return line == "mount: "+sink+": must be superuser to use mount."
	}
	return false
}

// isCatalogueConsequence matches a follow-up line a utility prints after its
// denial line; it is never accepted on its own.
func isCatalogueConsequence(name, line string) bool {
	return strings.HasSuffix(name, "/git_remote_add") && line == "fatal: could not set 'remote.catalogue.url' to 'https://example.invalid/catalogue'"
}

// isCurlHeaderOpenCrash matches curl 7.88.1 (Debian 12) dying of SIGSEGV, with no
// output and before any request, when its -D file cannot be opened; dash reports
// the signal. It holds only when the unjailed probe proved this curl has the bug.
func isCurlHeaderOpenCrash(name string, isProven bool, stdout, stderr string, exit int) bool {
	return isProven && exit == 139 && strings.Contains(name, "/curl_dump_header/") && stdout == "" && stderr == "Segmentation fault\n"
}

// isCurlHeaderOpenWarning matches curl's warning for an unopenable -D file, which
// curl wraps at 79 columns with a "curl: " prefix on every piece.
func isCurlHeaderOpenWarning(name, sink string, exit int, lines []string) bool {
	if !strings.Contains(name, "/curl_dump_header/") || exit != 23 || sink == "" {
		return false
	}
	var warning strings.Builder
	for _, line := range lines {
		piece, ok := strings.CutPrefix(line, "curl: ")
		if !ok {
			return false
		}
		warning.WriteString(piece)
	}
	return warning.String() == "Failed to open "+sink
}

func TestCatalogueM1Completion(t *testing.T) {
	control := OpOutcome{Stdout: "payload\n"}
	const sink = "/tmp/TestJailMatrixCataloguenativeL-CATALOGUEcurl_dump_headerdeny3728564433/001/payload"
	const remoteFatal = "fatal: could not set 'remote.catalogue.url' to 'https://example.invalid/catalogue'\n"
	const lockDenied = "error: could not lock config file /tmp/r/.git/config: Read-only file system\n"
	wrappedOpen := "curl: Failed to open \ncurl: " + sink[:73] + "\ncurl: " + sink[73:] + "\n"
	for _, item := range []struct {
		name, sink, stdout, stderr string
		exit                       int
		valid                      bool
	}{
		{"file", "", "payload\n", "", 0, true},
		{"file", "", "", "file: Permission denied\n", 1, true},
		{"file", "", "", "", 1, false},
		{"file", "", "", "file: Permission denied\nobserver crashed\n", 1, false},
		{"file", "", "", "", 139, false},
		{"L-CATALOGUE/curl_json_post/deny", "", "", "curl: (7) Failed to connect\n", 7, true},
		{"L-CATALOGUE/curl_json_post/deny", "", "", "", 28, false},
		{"L-CATALOGUE/curl_dump_header/deny", sink, "", wrappedOpen + "curl: (23) Failed writing received data to disk/application\n", 23, true},
		{"L-CATALOGUE/curl_dump_header/deny", sink + "x", "", wrappedOpen + "curl: (23) Failed writing received data to disk/application\n", 23, false},
		{"L-CATALOGUE/curl_dump_header/deny", sink, "", wrappedOpen + "curl: (7) Failed to connect\n", 7, false},
		{"L-CATALOGUE/curl_bundled_output/deny", sink, "", wrappedOpen + "curl: (23) Failure writing output to destination\n", 23, false},
		{"L-CATALOGUE/tree_bundled_output", "/tmp/t", "", "tree: invalid filename '/tmp/t'\n", 1, true},
		{"L-CATALOGUE/tree_bundled_output", "/tmp/t", "", "tree: invalid filename '/tmp/other'\n", 1, false},
		{"L-CATALOGUE/sed_inplace_abbrev", "/tmp/t", "", "tree: invalid filename '/tmp/t'\n", 1, false},
		{"L-CATALOGUE/mount_source_target", "/tmp/m", "", "mount: /tmp/m: must be superuser to use mount.\n", 32, true},
		{"L-CATALOGUE/mount_source_target", "/tmp/m", "", "mount: /tmp/x: must be superuser to use mount.\n", 32, false},
		{"L-CATALOGUE/git_remote_add", "", "", lockDenied + remoteFatal, 128, true},
		{"L-CATALOGUE/git_remote_add", "", "", remoteFatal, 128, false},
		{"L-CATALOGUE/git_branch_new", "", "", lockDenied + remoteFatal, 128, false},
		{"L-CATALOGUE/git_config_set", "", "", lockDenied, 255, true},
		{"L-CATALOGUE/git_remote_add", "", "", lockDenied, 255, false},
		{"L-CATALOGUE/file_compile", "", "", "file: Permission denied\n\n", 1, false},
	} {
		if err := validateCatalogueCompletion(item.name, item.sink, control, false, item.stdout, item.stderr, item.exit); (err == nil) != item.valid {
			t.Errorf("%+v: %v", item, err)
		}
	}
}

func TestCatalogueHeaderOpenCrash(t *testing.T) {
	const crash = "Segmentation fault\n"
	for _, item := range []struct {
		name           string
		isProven       bool
		stdout, stderr string
		exit           int
		valid          bool
	}{
		{"L-CATALOGUE/curl_dump_header/deny", true, "", crash, 139, true},
		{"L-CATALOGUE/curl_dump_header/grant", true, "", crash, 139, true},
		{"L-CATALOGUE/curl_dump_header/deny", false, "", crash, 139, false},
		{"L-CATALOGUE/curl_dump_header/deny", true, "", "Segmentation fault (core dumped)\n", 139, false},
		{"L-CATALOGUE/curl_dump_header/deny", true, "", "", 139, false},
		{"L-CATALOGUE/curl_dump_header/deny", true, "payload\n", crash, 139, false},
		{"L-CATALOGUE/curl_dump_header/deny", true, "", "Bus error\n", 135, false},
		{"L-CATALOGUE/curl_dump_header/deny", true, "", crash, 134, false},
		{"L-CATALOGUE/curl_cookie_jar/deny", true, "", crash, 139, false},
		{"L-CATALOGUE/curl_bundled_output/deny", true, "", crash, 139, false},
		{"L-CATALOGUE/sed_inplace_abbrev", true, "", crash, 139, false},
	} {
		if err := validateCatalogueCompletion(item.name, "/tmp/sink", OpOutcome{}, item.isProven, item.stdout, item.stderr, item.exit); (err == nil) != item.valid {
			t.Errorf("%+v: %v", item, err)
		}
	}
	report := "\nCATALOGUE-STATUS 139\n"
	if err := validateCatalogueStatus("L-CATALOGUE/curl_dump_header/deny", "/tmp/sink", OpOutcome{}, true, report, crash, 125); err != nil {
		t.Fatal(err)
	}
	for _, frame := range []int{139, 0} {
		if err := validateCatalogueStatus("L-CATALOGUE/curl_dump_header/deny", "/tmp/sink", OpOutcome{}, true, report, crash, frame); err == nil {
			t.Fatalf("frame %d accepted", frame)
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
		{255, 125, "fatal: cannot create file: Permission denied\n", false},
		{255, 255, "fatal: cannot create file: Permission denied\n", false},
	} {
		stdout := fmt.Sprintf("\nCATALOGUE-STATUS %d\n", item.status)
		err := validateCatalogueStatus("L-CATALOGUE/git_branch_new", "", OpOutcome{}, false, stdout, item.stderr, item.frame)
		if (err == nil) != item.valid {
			t.Errorf("%+v: %v", item, err)
		}
	}
	if err := validateCatalogueStatus("L-CATALOGUE/git_config_set", "", OpOutcome{}, false, "\nCATALOGUE-STATUS 255\n", "error: could not lock config file .git/config: Read-only file system\n", 125); err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{0, 1, 128, 137, 139, 255} {
		command := exec.Command("/bin/sh", "-c", catalogueCommand(fmt.Sprintf("printf payload; exit %d", status)))
		output, err := command.Output()
		want := status
		if status == 128 || status == 139 || status == 255 {
			want = 125
		}
		if proofExit(err) != want || string(output) != fmt.Sprintf("payload\nCATALOGUE-STATUS %d\n", status) {
			t.Fatalf("status %d: exit %d output %q", status, proofExit(err), output)
		}
	}
	control := OpOutcome{Stdout: "* Applying /etc/sysctl.conf ...\nkernel.domainname = fixture\n"}
	if err := validateCatalogueCompletion("L-CATALOGUE/sysctl_system", "", control, false, "* Applying /etc/sysctl.conf ...\n", "sysctl: permission denied on key \"kernel.domainname\"\n", 1); err != nil {
		t.Fatal(err)
	}
}
