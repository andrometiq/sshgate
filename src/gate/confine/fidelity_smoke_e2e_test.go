//go:build linux && jail_e2e

package confine

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestFidelitySmoke(t *testing.T) {
	golden, err := os.ReadFile("../../../tests/testdata/fidelity-expected-smoke.txt")
	mutationSetup(t, err)
	expected := map[string]string{}
	for _, line := range strings.Split(string(golden), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, category, ok := strings.Cut(line, " → ")
		if !ok || expected[name] != "" {
			t.Fatalf("bad smoke golden row %q", line)
		}
		expected[name] = category
	}
	for _, tool := range []string{"ps", "ss", "ip", "df", "ls", "cat", "git", "sqlite3", "journalctl", "getent", "id"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("SETUP: required smoke tool %s: %v", tool, err)
		}
	}
	directory, err := os.MkdirTemp("/tmp", "sshgate-smoke-")
	mutationSetup(t, err)
	t.Cleanup(func() { os.RemoveAll(directory) })
	write(t, filepath.Join(directory, "visible"), "smoke-canary\n")
	control := exec.Command("git", "init", "-q", directory)
	mutationSetup(t, control.Run())
	control = exec.Command("sqlite3", filepath.Join(directory, "db"), "create table smoke (id integer);")
	mutationSetup(t, control.Run())
	home := homeDir(t)
	homeFile, err := os.CreateTemp(home, ".sshgate-smoke-")
	mutationSetup(t, err)
	_, err = homeFile.WriteString("home-canary\n")
	mutationSetup(t, err)
	mutationSetup(t, homeFile.Close())
	t.Cleanup(func() { os.Remove(homeFile.Name()) })
	rows := []struct{ name, command, cwd string }{
		{"ps aux", "ps aux", "/"},
		{"ss -tuna", "ss -tuna", "/"}, {"ip a", "ip a", "/"}, {"df -h", "df -h", "/"}, {"ls -l /", "ls -l /", "/"},
		{"cat /tmp/<f>", "cat " + directory + "/visible", "/"}, {"git in /tmp", "git status --porcelain", directory},
		{"sqlite3 <db> .tables", "sqlite3 " + directory + "/db .tables", "/"}, {"journalctl -n 20", "journalctl -n 20 --no-pager -o cat", "/"},
		{"getent passwd", "getent passwd", "/"}, {"id", "id", "/"}, {"relative home read", "cat " + filepath.Base(homeFile.Name()), home},
	}
	for _, cfg := range []struct {
		name string
		abi  int
	}{{"native", 0}, {"abi1", 1}} {
		t.Run(cfg.name, func(t *testing.T) {
			for _, row := range rows {
				t.Run(row.name, func(t *testing.T) {
					command := exec.Command("/bin/sh", "-c", row.command)
					command.Dir = row.cwd
					baseline, controlErr := command.CombinedOutput()
					if controlErr != nil {
						t.Fatalf("SETUP: smoke control: %v: %s", controlErr, baseline)
					}
					result := runP12(t, Spec{Profile: ProfileROv1, Net: false, ForceABI: cfg.abi, Cwd: row.cwd}, row.command, nil)
					if result.setupErr != nil {
						t.Fatalf("SETUP: smoke jail: %+v", result)
					}
					if result.exit != 0 {
						t.Fatalf("smoke command failed: %+v", result)
					}
					before, after := projectIdentity(t, row.name, string(baseline)), result.stdout+result.stderr
					if row.name == "ps aux" {
						if result.stderr != "" {
							t.Errorf("unlisted fidelity difference: ps stderr: %s", result.stderr)
						}
						// PID 1 and this test process live throughout both samples.
						// Other rows and accounting columns may change between runs.
						stable := map[string]string{}
						initial := psRows(before)
						for _, pid := range []string{"1", strconv.Itoa(os.Getpid())} {
							if initial[pid] == "" {
								t.Fatalf("SETUP: host ps missing PID %s", pid)
							}
							stable[pid] = initial[pid]
						}
						if !strings.HasPrefix(strings.TrimSpace(after), "USER") || !strings.Contains(strings.SplitN(after, "\n", 2)[0], "PID") {
							t.Errorf("unlisted fidelity difference: ps header missing: %q", after)
						}
						before = stablePS(before, stable)
						after = stablePS(after, stable)
					}
					changed := result.exit != 0 || normalizeSmoke(row.name, before) != normalizeSmoke(row.name, after)
					category := expected[row.name]
					if changed && category == "" {
						t.Errorf("unlisted fidelity difference\ncontrol: %s\njail: %+v", baseline, result)
					}
					if !changed && category != "" {
						t.Errorf("listed difference %s disappeared", category)
					}
					if category != "" {
						t.Logf("FIDELITY %s → %s", row.name, category)
					}
				})
			}
		})
	}
	for name := range expected {
		found := false
		for _, row := range rows {
			found = found || row.name == name
		}
		if !found {
			t.Errorf("unexecuted golden row %s", name)
		}
	}
}
func normalizeSmoke(name, output string) string {
	if name == "df -h" {
		var lines []string
		for _, line := range strings.Split(output, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				lines = append(lines, fields[0]+" "+fields[1]+" "+fields[len(fields)-1])
			}
		}
		sort.Strings(lines)
		return strings.Join(lines, "\n")
	}
	if name == "ip a" {
		output = regexp.MustCompile(`valid_lft \S+ preferred_lft \S+`).ReplaceAllString(output, "lifetimes")
	}
	if name == "ss -tuna" {
		var lines []string
		for _, line := range strings.Split(output, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				lines = append(lines, fields[0]+" "+fields[1]+" "+strings.Join(fields[4:], " "))
			}
		}
		sort.Strings(lines)
		return strings.Join(lines, "\n")
	}
	if name == "ls -l /" {
		var lines []string
		for _, line := range strings.Split(output, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 9 {
				// Mount covers change metadata, but must preserve entry names/types.
				lines = append(lines, fields[0][:1]+" "+strings.Join(fields[8:], " "))
			} else if len(fields) > 0 && fields[0] != "total" {
				lines = append(lines, line)
			}
		}
		return strings.TrimSpace(strings.Join(lines, "\n"))
	}
	return strings.TrimSpace(output)
}

// Retain process identity and command, excluding dynamic accounting columns.
func psRows(output string) map[string]string {
	rows := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 11 && fields[1] != "PID" {
			rows[fields[1]] = fields[0] + " " + strings.Join(fields[10:], " ")
		}
	}
	return rows
}
func stablePS(output string, stable map[string]string) string {
	var rows []string
	for pid, line := range psRows(output) {
		if _, ok := stable[pid]; ok {
			rows = append(rows, pid+" "+line)
		}
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n")
}

// Project only the control through the clone's single-ID mapping. Keep the
// jailed identity fields intact, so an incorrect mapping remains a difference.
func projectIdentity(t *testing.T, name, output string) string {
	t.Helper()
	if os.Getuid() == 0 {
		return output
	}
	own, err := user.Current()
	mutationSetup(t, err)
	group, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	mutationSetup(t, err)
	overflowUID, err := os.ReadFile("/proc/sys/kernel/overflowuid")
	mutationSetup(t, err)
	overflowGID, err := os.ReadFile("/proc/sys/kernel/overflowgid")
	mutationSetup(t, err)
	uid, gid := strings.TrimSpace(string(overflowUID)), strings.TrimSpace(string(overflowGID))
	otherUser, otherGroup := uid, gid
	if value, err := user.LookupId(uid); err == nil {
		otherUser = value.Username
	}
	if value, err := user.LookupGroupId(gid); err == nil {
		otherGroup = value.Name
	}
	mapped := func(value, number, label, overflow string) string {
		if value == number || value == label || strings.HasSuffix(value, "+") && strings.HasPrefix(label, strings.TrimSuffix(value, "+")) {
			return value
		}
		return overflow
	}
	lines := strings.Split(output, "\n")
	switch name {
	case "ps aux":
		for i, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 11 && fields[1] != "PID" {
				fields[0] = mapped(fields[0], own.Uid, own.Username, otherUser)
				lines[i] = strings.Join(fields, " ")
			}
		}
	case "ls -l /":
		for i, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 9 {
				fields[2] = mapped(fields[2], own.Uid, own.Username, otherUser)
				fields[3] = mapped(fields[3], group.Gid, group.Name, otherGroup)
				lines[i] = strings.Join(fields, " ")
			}
		}
	case "id":
		prefix, groups, ok := strings.Cut(strings.TrimSpace(output), " groups=")
		if !ok {
			return output
		}
		var projected []string
		seen := map[string]bool{}
		for _, entry := range strings.Split(groups, ",") {
			number, _, _ := strings.Cut(entry, "(")
			if number != group.Gid {
				entry = gid
				if otherGroup != gid {
					entry += "(" + otherGroup + ")"
				}
			}
			if !seen[entry] {
				projected = append(projected, entry)
				seen[entry] = true
			}
		}
		return prefix + " groups=" + strings.Join(projected, ",")
	}
	return strings.Join(lines, "\n")
}

func TestSmokeRootListingProjection(t *testing.T) {
	control := "total 12\ndrwxr-xr-x 20 root root 4096 Oct 4 10:00 dev\nlrwxrwxrwx 1 root root 7 Oct 4 10:00 bin -> usr/bin\n"
	rebound := "total 0\ndrwxr-xr-x 2 nobody nobody 60 Oct 4 11:00 dev\nlrwxrwxrwx 1 nobody nobody 7 Oct 4 10:00 bin -> usr/bin\n"
	if normalizeSmoke("ls -l /", control) != normalizeSmoke("ls -l /", rebound) {
		t.Fatal("mount metadata caused a fidelity difference")
	}
	for _, changed := range []string{strings.Replace(rebound, " dev", " lost", 1), strings.Replace(rebound, "drwx", "-rwx", 1), strings.Replace(rebound, "usr/bin", "usr/sbin", 1)} {
		if normalizeSmoke("ls -l /", control) == normalizeSmoke("ls -l /", changed) {
			t.Fatal("entry identity loss was hidden")
		}
	}
}

func TestSmokeProcessProjection(t *testing.T) {
	control := "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\nroot 1 0 0 1 1 ? Ss 10:00 0:00 /sbin/init\nuser 42 0 0 1 1 ? S 10:00 0:00 test\nuser 43 0 0 1 1 ? S 10:00 0:00 ps aux\n"
	jailed := strings.ReplaceAll(control, "0:00", "0:01")
	jailed = strings.Replace(jailed, "43", "44", 1)
	anchors := map[string]string{"1": "", "42": ""}
	if stablePS(control, anchors) != stablePS(jailed, anchors) {
		t.Fatal("process churn caused a fidelity difference")
	}
	for _, changed := range []string{strings.Replace(jailed, "root 1 ", "root 2 ", 1), strings.Replace(jailed, "/sbin/init", "/other", 1), strings.Replace(jailed, "user 42 ", "user 45 ", 1)} {
		if stablePS(control, anchors) == stablePS(changed, anchors) {
			t.Fatal("host process identity loss was hidden")
		}
	}
}
