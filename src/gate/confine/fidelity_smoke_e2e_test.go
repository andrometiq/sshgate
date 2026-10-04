//go:build linux && jail_e2e

package confine

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
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
	for _, tool := range []string{"ps", "top", "pgrep", "pidof", "ss", "ip", "df", "ls", "cat", "git", "sqlite3", "journalctl", "getent", "id", "readlink"} {
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
	sleepPath, err := exec.LookPath("sleep")
	mutationSetup(t, err)
	sleepBinary, err := os.ReadFile(sleepPath)
	mutationSetup(t, err)
	victim, err := os.CreateTemp(directory, "sg")
	mutationSetup(t, err)
	mutationSetup(t, victim.Close())
	mutationSetup(t, os.WriteFile(victim.Name(), sleepBinary, 0755))
	mutationSetup(t, os.Chmod(victim.Name(), 0755))
	victimName := filepath.Base(victim.Name()) // Short enough for Linux comm (15 bytes).
	sleeper := exec.Command(victim.Name(), "600")
	// Exercise pidof's exe fallback, independently of its argv[0] matching.
	sleeper.Args[0] = victimName + "-argv"
	mutationSetup(t, sleeper.Start())
	defer func() { sleeper.Process.Kill(); sleeper.Wait() }()
	rows := []struct{ name, command, cwd string }{
		{"ps aux", "ps aux", "/"},
		{"top -bn1", fmt.Sprintf("top -bn1 -p %d", os.Getpid()), "/"},
		{"pgrep", "pgrep -x " + victimName, "/"},
		{"pidof executable", "pidof " + victim.Name(), "/"},
		{"pidof", "pidof " + sleeper.Args[0], "/"},
		{"ss -tuna", "ss -tuna", "/"}, {"ip a", "ip a", "/"}, {"df -h", "df -h", "/"}, {"ls -l /", "ls -l /", "/"},
		{"cat /tmp/<f>", "cat " + directory + "/visible", "/"}, {"git in /tmp", "git status --porcelain", directory},
		{"sqlite3 <db> .tables", "sqlite3 " + directory + "/db .tables", "/"}, {"journalctl -n 20", "journalctl -n 20 --no-pager -o cat", "/"},
		{"getent passwd", "getent passwd", "/"}, {"id", "id", "/"}, {"relative home read", "", ""},
	}
	for _, cfg := range []struct {
		name string
		abi  int
	}{{"native", 0}, {"abi1", 1}} {
		t.Run(cfg.name, func(t *testing.T) {
			for _, row := range rows {
				t.Run(row.name, func(t *testing.T) {
					if row.name == "relative home read" {
						home := homeDir(t)
						homeFile, err := os.CreateTemp(home, ".sshgate-smoke-")
						mutationSetup(t, err)
						_, err = homeFile.WriteString("home-canary\n")
						mutationSetup(t, err)
						mutationSetup(t, homeFile.Close())
						t.Cleanup(func() { os.Remove(homeFile.Name()) })
						row.command = "cat " + filepath.Base(homeFile.Name())
						row.cwd = home
					}
					repetitions := 1
					if row.name == "ps aux" || row.name == "top -bn1" || row.name == "pgrep" {
						repetitions = 20
					}
					for repetition := 0; repetition < repetitions; repetition++ {
						var socketAnchors []string
						if row.name == "ss -tuna" {
							for _, address := range []struct{ network, local, peer string }{
								{"tcp4", "127.0.0.1:0", "0.0.0.0:*"},
								{"tcp6", "[::]:0", "[::]:*"},
							} {
								listener, err := net.Listen(address.network, address.local)
								mutationSetup(t, err)
								defer listener.Close()
								socketAnchors = append(socketAnchors, "tcp LISTEN "+listener.Addr().String()+" "+address.peer)
								if address.network == "tcp4" {
									connection, err := net.DialTimeout("tcp4", listener.Addr().String(), 5*time.Second)
									mutationSetup(t, err)
									defer connection.Close()
									mutationSetup(t, listener.(*net.TCPListener).SetDeadline(time.Now().Add(5*time.Second)))
									peer, err := listener.Accept()
									mutationSetup(t, err)
									defer peer.Close()
									socketAnchors = append(socketAnchors,
										"tcp ESTAB "+connection.LocalAddr().String()+" "+connection.RemoteAddr().String(),
										"tcp ESTAB "+peer.LocalAddr().String()+" "+peer.RemoteAddr().String())
								}
							}
							if expected[row.name] != "SS-PROCFS-V6ONLY" {
								t.Fatal("missing SS-PROCFS-V6ONLY category")
							}
						}
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
						if row.name == "pidof executable" {
							if expected[row.name] != "PIDOF-EXE-DENIED" || string(baseline) != strconv.Itoa(sleeper.Process.Pid)+"\n" {
								t.Fatalf("pidof control/category: %q / %q", baseline, expected[row.name])
							}
							if result.exit != 1 || result.stdout != "" || result.stderr != "" {
								t.Fatalf("unlisted pidof difference: %+v", result)
							}
							link := fmt.Sprintf("/proc/%d/exe", sleeper.Process.Pid)
							resolved, err := os.Readlink(link)
							mutationSetup(t, err)
							if resolved != victim.Name() {
								t.Fatalf("victim executable: %q", resolved)
							}
							denied := runP12(t, Spec{Profile: ProfileROv1, Net: false, ForceABI: cfg.abi, Cwd: "/"}, "LC_ALL=C readlink -v "+link, nil)
							wantError := "readlink: " + link + ": Permission denied\n"
							if denied.setupErr != nil || denied.exit != 1 || denied.stdout != "" || denied.stderr != wantError {
								t.Fatalf("pidof exe denial not established: %+v", denied)
							}
							t.Log("FIDELITY pidof executable → PIDOF-EXE-DENIED; pgrep -x checks the same victim")
							continue
						}
						if result.exit != 0 {
							t.Fatalf("smoke command failed: %+v", result)
						}
						if row.name == "ss -tuna" {
							command = exec.Command("/bin/sh", "-c", row.command)
							command.Dir = row.cwd
							final, err := command.CombinedOutput()
							if err != nil {
								t.Fatalf("SETUP: final ss control: %v: %s", err, final)
							}
							for _, output := range []string{string(baseline), string(final)} {
								sockets, err := smokeSocketRows(output, false)
								if err != nil {
									t.Fatalf("SETUP: ss control: %v", err)
								}
								for _, anchor := range socketAnchors {
									if !sockets[anchor] {
										t.Fatalf("SETUP: ss control missing held socket %s: %s", anchor, output)
									}
								}
							}
							if err := compareSmokeSockets(string(baseline), result.stdout, string(final), result.stderr); err != nil {
								t.Errorf("unlisted fidelity difference: %v", err)
							}
							t.Log("FIDELITY ss -tuna → SS-PROCFS-V6ONLY")
							return
						}
						if row.name == "top -bn1" || row.name == "pgrep" || row.name == "pidof" {
							pid := strconv.Itoa(sleeper.Process.Pid)
							if row.name == "top -bn1" {
								pid = strconv.Itoa(os.Getpid())
							}
							for _, output := range []string{string(baseline), result.stdout} {
								found := false
								for _, field := range strings.Fields(output) {
									found = found || field == pid
								}
								if !found {
									t.Fatalf("process observer %s lost PID %s: %s", row.name, pid, output)
								}
							}
							if result.stderr != "" {
								t.Fatalf("observer stderr: %s", result.stderr)
							}
							if (row.name == "pgrep" || row.name == "pidof") && (string(baseline) != pid+"\n" || result.stdout != pid+"\n") {
								t.Fatalf("%s returned unexpected PIDs: control %q, jail %q", row.name, baseline, result.stdout)
							}
							continue
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
					}
					if repetitions > 1 {
						t.Logf("%s: %d jailed repetitions passed", row.name, repetitions)
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

func smokeSocketRows(output string, projectProcfs bool) (map[string]bool, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	header := strings.Join(strings.Fields(lines[0]), " ")
	if header != "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port" && header != "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process" {
		return nil, fmt.Errorf("ss header: %q", lines[0])
	}
	rows := map[string]bool{}
	iface := regexp.MustCompile(`%[^:\]\s]+`)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) != 6 || (fields[0] != "tcp" && fields[0] != "udp") {
			return nil, fmt.Errorf("ss row: %q", line)
		}
		for _, queue := range fields[2:4] {
			if _, err := strconv.ParseUint(queue, 10, 64); err != nil {
				return nil, fmt.Errorf("ss queue: %q", line)
			}
		}
		for i := 4; i < 6; i++ {
			fields[i] = iface.ReplaceAllString(fields[i], "")
			if projectProcfs {
				fields[i] = strings.ReplaceAll(fields[i], "[::]:", "*:")
			}
		}
		rows[fields[0]+" "+fields[1]+" "+fields[4]+" "+fields[5]] = true
	}
	return rows, nil
}

func compareSmokeSockets(before, jailed, after, stderr string) error {
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		if line != "" && line != "Cannot open netlink socket: Operation not permitted" {
			return fmt.Errorf("ss stderr: %q", line)
		}
	}
	// Procfs lacks v6only; ss prints unspecified IPv6 endpoints as "*".
	// Project controls only: the jailed rows must retain every stable socket identity.
	initial, err := smokeSocketRows(before, true)
	if err != nil {
		return err
	}
	final, err := smokeSocketRows(after, true)
	if err != nil {
		return err
	}
	confined, err := smokeSocketRows(jailed, false)
	if err != nil {
		return err
	}
	stable := 0
	for row := range initial {
		if final[row] {
			stable++
			if !confined[row] {
				return fmt.Errorf("ss lost stable socket: %s", row)
			}
		}
	}
	if stable == 0 {
		return fmt.Errorf("ss controls contain no stable sockets")
	}
	for row := range confined {
		// Connection states can exist only between the bracketing controls.
		switch strings.Fields(row)[1] {
		case "ESTAB", "TIME-WAIT", "SYN-SENT", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "LAST-ACK", "CLOSING":
			continue
		}
		if !initial[row] && !final[row] {
			return fmt.Errorf("ss unexpected socket: %s", row)
		}
	}
	return nil
}

func TestSmokeSocketProjection(t *testing.T) {
	header := "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
	stable := "tcp LISTEN 0 128 127.0.0.1:1234 0.0.0.0:*\n"
	scoped := "udp UNCONN 0 0 192.0.2.1%eth0:53 0.0.0.0:*\n"
	transient := "tcp ESTAB 0 0 127.0.0.1:5678 127.0.0.1:1234\n"
	ipv6 := "tcp LISTEN 0 128 [::]:3306 [::]:*\n" +
		"udp UNCONN 0 0 [::]:41641 [::]:*\n" +
		"udp UNCONN 0 0 [fd7a:115c:a1e0::c]%eth0:52238 [::]:*\n"
	before, after := header+stable+scoped+ipv6+transient, header+stable+scoped+ipv6
	jailed := header + strings.Replace(stable, "128", "0", 1) + strings.Replace(scoped, "%eth0", "", 1) + strings.ReplaceAll(strings.ReplaceAll(ipv6, "[::]:", "*:"), "%eth0", "")
	if err := compareSmokeSockets(before, jailed, after, "Cannot open netlink socket: Operation not permitted\n"); err != nil {
		t.Fatal(err)
	}
	if err := compareSmokeSockets(strings.ReplaceAll(before, "[::]:", "[::]%eth0:"), jailed, strings.ReplaceAll(after, "[::]:", "[::]%eth0:"), ""); err != nil {
		t.Fatal(err)
	}
	withProcess := strings.TrimSuffix(header, "\n") + " Process\n"
	if err := compareSmokeSockets(strings.Replace(before, header, withProcess, 1), strings.Replace(jailed, header, withProcess, 1), after, ""); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{header + scoped, strings.Replace(jailed, "1234", "9999", 1), strings.Replace(jailed, "LISTEN", "CLOSE", 1), strings.Replace(jailed, "Netid", "Other", 1), jailed + "unexpected\n", jailed + "tcp LISTEN 0 0 *:99 *:* process-detail\n", strings.Replace(jailed, header, strings.TrimSuffix(header, "\n")+" Unknown\n", 1),
		strings.Replace(jailed, "*:3306", "*:3307", 1),
		strings.Replace(jailed, "[fd7a:115c:a1e0::c]", "[fd7a:115c:a1e0::d]", 1),
		strings.Replace(jailed, "*:3306", "[::]:3306", 1),
		header + stable + scoped,
		jailed + "udp UNCONN 0 0 [::1]:9999 *:*\n"} {
		if compareSmokeSockets(before, changed, after, "") == nil {
			t.Fatalf("unlisted change accepted: %q", changed)
		}
	}
	for _, state := range []string{"ESTAB", "TIME-WAIT", "SYN-SENT", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "LAST-ACK", "CLOSING"} {
		t.Run(state, func(t *testing.T) {
			connection := strings.Replace(transient, "ESTAB", state, 1)
			controls := header + stable
			for _, samples := range [][3]string{
				{controls, controls + connection, controls},
				{controls + connection, controls, controls},
				{controls, controls, controls + connection},
				{controls + connection, controls + connection, controls + connection},
			} {
				if err := compareSmokeSockets(samples[0], samples[1], samples[2], ""); err != nil {
					t.Fatal(err)
				}
			}
			if compareSmokeSockets(controls+connection, controls, controls+connection, "") == nil {
				t.Fatal("stable connection loss accepted")
			}
		})
	}
	for _, socket := range []string{stable, scoped} {
		if compareSmokeSockets(header+transient, header+transient+socket, header+transient, "") == nil {
			t.Fatal("unexpected listening/bound socket accepted")
		}
	}
	if compareSmokeSockets(before, jailed, after, "unexpected") == nil {
		t.Fatal("unexpected stderr accepted")
	}
}

func TestSmokeSocketProcfsIPv6(t *testing.T) {
	directory := t.TempDir()
	// Deterministic procfs records exercise the installed ss inside the real jail.
	header := "sl local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	write(t, filepath.Join(directory, "tcp"), header)
	write(t, filepath.Join(directory, "udp"), header)
	write(t, filepath.Join(directory, "tcp6"), header+
		"0: 00000000000000000000000000000000:0CEA 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0\n"+
		"1: 00000000000000000000000001000000:1234 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12346 1 0000000000000000 100 0 0 10 0\n")
	write(t, filepath.Join(directory, "udp6"), header+
		"0: 00000000000000000000000000000000:A2A9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 12347 2 0000000000000000 0\n")
	var environment []string
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		environment = append(environment, "PROC_NET_"+strings.ToUpper(table)+"="+filepath.Join(directory, table))
	}
	want := "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n" +
		"tcp LISTEN 0 0 *:3306 *:*\n" +
		"tcp LISTEN 0 0 [::1]:4660 *:*\n" +
		"udp UNCONN 0 0 *:41641 *:*\n"
	for _, abi := range []int{0, 1} {
		t.Run(fmt.Sprintf("abi%d", abi), func(t *testing.T) {
			result := runP12(t, Spec{Profile: ProfileROv1, Net: false, ForceABI: abi, Cwd: "/"}, "ss -tuna", func(jailed *Jailed) {
				jailed.Cmd.Env = append(jailed.Cmd.Env, environment...)
			})
			if result.setupErr != nil || result.exit != 0 {
				t.Fatalf("ss procfs fixture: %+v", result)
			}
			if err := compareSmokeSockets(want, result.stdout, want, result.stderr); err != nil {
				t.Fatal(err)
			}
		})
	}
}
