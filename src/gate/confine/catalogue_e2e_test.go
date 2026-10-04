//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"testing"
)

var catalogueNetworkKinds = []string{"curl_bundled_output", "curl_remote_name", "curl_dump_header", "curl_cookie_jar", "curl_json_post"}
var catalogueMountKinds = []string{"mount_inline_options", "mount_source_target"}
var catalogueSysctlKinds = []string{"sysctl_reload_bundle", "sysctl_system"}

func TestJailMatrixCatalogue(t *testing.T) {
	for _, cfg := range []struct {
		name string
		abi  int
	}{{"native", 0}, {"abi1", 1}} {
		t.Run(cfg.name, func(t *testing.T) {
			spec := Spec{Profile: ProfileROv1, ForceABI: cfg.abi}
			t.Run("L-CATALOGUE", func(t *testing.T) {
				for _, row := range catalogueFiles() {
					t.Run(row.name, func(t *testing.T) { catalogueFile(t, spec, row) })
				}
				for _, kind := range catalogueNetworkKinds {
					t.Run(kind, func(t *testing.T) { catalogueNetwork(t, spec, kind) })
				}
				for _, name := range catalogueMountKinds {
					t.Run(name, func(t *testing.T) { catalogueMount(t, spec, name == "mount_source_target") })
				}
				for _, name := range catalogueSysctlKinds {
					t.Run(name, func(t *testing.T) { catalogueSysctl(t, spec, name == "sysctl_system") })
				}
			})
		})
	}
}
func catalogueTool(t *testing.T, tool string) bool {
	t.Helper()
	if _, err := exec.LookPath(tool); err != nil {
		if os.Getenv("SSHGATE_JAIL_CI") == "1" {
			t.Fatalf("SETUP: catalogue requires %s: %v", tool, err)
		}
		t.Logf("NOT-APPLICABLE: catalogue tool %s unavailable", tool)
		return false
	}
	return true
}
func catalogueFiles() []bypassRow {
	var rows []bypassRow
	for _, row := range bypassCorpus() {
		switch row.name {
		case "sed_inplace_abbrev", "file_compile_bundle", "tree_bundled_output", "awk_include_directive":
			rows = append(rows, row)
		}
	}
	for _, name := range []string{"zgrep_GREP_injection", "zdiff_DIFF_injection"} {
		name := name
		tool := "zgrep"
		if strings.HasPrefix(name, "zdiff") {
			tool = "zdiff"
		}
		rows = append(rows, bypassRow{name: name, tool: tool, build: func(t *testing.T, dir, target string) (string, string) {
			script, err := filepath.Abs("../../../tests/testdata/greppy.sh")
			mutationSetup(t, err)
			input := filepath.Join(dir, "input.gz")
			f, err := os.Create(input)
			mutationSetup(t, err)
			compressed := gzip.NewWriter(f)
			_, err = compressed.Write([]byte("PATTERN\n"))
			mutationSetup(t, err)
			mutationSetup(t, compressed.Close())
			mutationSetup(t, f.Close())
			sink := filepath.Join(dir, "marker")
			if tool == "zgrep" {
				return "SINK=" + coverQuote(sink) + " GREP=" + coverQuote(script) + " zgrep PATTERN " + coverQuote(input), sink
			}
			return "SINK=" + coverQuote(sink) + " DIFF=" + coverQuote(script) + " zdiff " + coverQuote(input) + " " + coverQuote(input), sink
		}})
	}
	for _, kind := range []string{"git_config_set", "git_branch_new", "git_remote_add", "git_diff_output", "git_show_output", "git_log_output", "git_grep_open_files_in_pager"} {
		kind := kind
		rows = append(rows, bypassRow{name: kind, tool: "git", build: func(t *testing.T, dir, target string) (string, string) {
			repo := filepath.Join(dir, "repo")
			mustGitRepo(t, repo)
			prefix := "GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git -C " + coverQuote(repo) + " "
			switch kind {
			case "git_config_set":
				return prefix + "config catalogue.value changed", filepath.Join(repo, ".git", "config")
			case "git_branch_new":
				return prefix + "branch catalogue-new", filepath.Join(repo, ".git", "refs", "heads", "catalogue-new")
			case "git_remote_add":
				return prefix + "remote add catalogue https://example.invalid/catalogue", filepath.Join(repo, ".git", "config")
			case "git_diff_output":
				mutationSetup(t, os.WriteFile(filepath.Join(repo, "f"), []byte("changed\n"), 0644))
				return prefix + "diff --output=" + coverQuote(target), ""
			case "git_show_output":
				return prefix + "show --output=" + coverQuote(target), ""
			case "git_log_output":
				return prefix + "log --output=" + coverQuote(target), ""
			default:
				sink := filepath.Join(dir, "marker")
				pager := "sh -c " + coverQuote(": > "+coverQuote(sink))
				return prefix + "grep --op=" + coverQuote(pager) + " hello", sink
			}
		}})
	}
	rows = append(rows, bypassRow{name: "file_compile", tool: "file", build: func(t *testing.T, dir, target string) (string, string) {
		magic := filepath.Join(dir, "magic")
		mutationSetup(t, os.WriteFile(magic, []byte("0 string MAGIC fixture\n"), 0644))
		return "cd " + coverQuote(dir) + " && file -C -m magic", magic + ".mgc"
	}})
	rows = append(rows, bypassRow{name: "command_v_exec", tool: "sh", build: func(t *testing.T, dir, target string) (string, string) {
		sink := filepath.Join(dir, "marker")
		return "command sh -c " + coverQuote(": > "+coverQuote(sink)) + " -v", sink
	}})
	return rows
}

type catalogueState struct {
	exists  bool
	content []byte
}

func catalogueSnapshot(t *testing.T, path string) catalogueState {
	t.Helper()
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return catalogueState{}
	}
	mutationSetup(t, err)
	return catalogueState{true, content}
}
func catalogueChanged(t *testing.T, path string, before catalogueState) bool {
	after := catalogueSnapshot(t, path)
	return after.exists != before.exists || !bytes.Equal(after.content, before.content)
}
func catalogueFile(t *testing.T, spec Spec, row bypassRow) {
	p := newProof(t, catalogueName(t, []string{"L-CATALOGUE/sed_inplace_abbrev", "L-CATALOGUE/file_compile_bundle", "L-CATALOGUE/tree_bundled_output", "L-CATALOGUE/awk_include_directive", "L-CATALOGUE/zgrep_GREP_injection", "L-CATALOGUE/zdiff_DIFF_injection", "L-CATALOGUE/git_config_set", "L-CATALOGUE/git_branch_new", "L-CATALOGUE/git_remote_add", "L-CATALOGUE/git_diff_output", "L-CATALOGUE/git_show_output", "L-CATALOGUE/git_log_output", "L-CATALOGUE/git_grep_open_files_in_pager", "L-CATALOGUE/file_compile", "L-CATALOGUE/command_v_exec"}))
	if !catalogueTool(t, row.tool) {
		p.Omit("tool-unavailable")
		return
	}
	prepare := func() (string, string, catalogueState) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		mutationSetup(t, os.WriteFile(target, []byte("original-content\n"), 0644))
		command, marker := row.build(t, dir, target)
		if marker != "" {
			target = marker
		}
		return command, target, catalogueSnapshot(t, target)
	}
	command, target, before := prepare()
	control := catalogueControl(t, command)
	if !catalogueChanged(t, target, before) {
		t.Fatalf("SETUP: catalogue control %s did not change sink: %s", row.name, command)
	}
	p.Control("effect", ControlResult{Valid: true, Detail: "unjailed command changed the sink"})
	command, target, before = prepare()
	result := catalogueRun(t, p, spec, command, target, control)
	p.Jailed("command", result)
	mutationEffect(t, p.caseDef.Name, "file", catalogueChanged(t, target, before))
	p.Observed("effect", Observation{Valid: true, Sealed: result.validated, Conclusive: true, Detail: "sink snapshot after framed command completion"})
	p.Finish()
}

func catalogueNetwork(t *testing.T, spec Spec, kind string) {
	for _, allow := range []bool{false, true} {
		name := "deny"
		if allow {
			name = "grant"
		}
		t.Run(name, func(t *testing.T) { spec.Net = allow; catalogueNetworkAttempt(t, spec, kind) })
	}
}
func catalogueNetworkAttempt(t *testing.T, spec Spec, kind string) {
	p := newProof(t, catalogueName(t, []string{"L-CATALOGUE/curl_bundled_output/deny", "L-CATALOGUE/curl_bundled_output/grant", "L-CATALOGUE/curl_remote_name/deny", "L-CATALOGUE/curl_remote_name/grant", "L-CATALOGUE/curl_dump_header/deny", "L-CATALOGUE/curl_dump_header/grant", "L-CATALOGUE/curl_cookie_jar/deny", "L-CATALOGUE/curl_cookie_jar/grant", "L-CATALOGUE/curl_json_post/deny", "L-CATALOGUE/curl_json_post/grant"}))
	if !catalogueTool(t, "curl") {
		p.Omit("tool-unavailable")
		return
	}
	var requests atomic.Int64
	var posts atomic.Int64
	socket, err := net.Listen("tcp4", "127.0.0.1:0")
	mutationSetup(t, err)
	listener := &httptest.Server{Listener: socket, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		w.Header().Set("Set-Cookie", "fixture=changed; Path=/")
		fmt.Fprintln(w, "network-payload")
	})}}
	listener.Start()
	defer listener.Close()
	dir := t.TempDir()
	sink := filepath.Join(dir, "payload")
	seed := []byte("original-content\n")
	mutationSetup(t, os.WriteFile(sink, seed, 0644))
	url := listener.URL + "/payload"
	prefix := "curl --silent --show-error --noproxy '*' --max-time 3 "
	var command string
	switch kind {
	case "curl_bundled_output":
		command = prefix + "-so " + coverQuote(sink) + " " + url
	case "curl_remote_name":
		command = "cd " + coverQuote(dir) + " && " + prefix + "-sO " + url
	case "curl_dump_header":
		command = prefix + "-sD " + coverQuote(sink) + " " + url
	case "curl_cookie_jar":
		command = prefix + "-sc " + coverQuote(sink) + " " + url
	case "curl_json_post":
		command = prefix + "--json '{\"admin\":true}' " + url
	}
	before := catalogueSnapshot(t, sink)
	control := catalogueControl(t, command)
	if requests.Load() != 1 || (kind == "curl_json_post" && posts.Load() != 1) || (kind != "curl_json_post" && !catalogueChanged(t, sink, before)) {
		t.Fatalf("SETUP: network control did not land request and sink (%s)", kind)
	}
	mutationSetup(t, os.WriteFile(sink, seed, 0644))
	p.Control("effect", ControlResult{Valid: true, Detail: "unjailed request and file sink verified"})
	beforeRequests := requests.Load()
	result := catalogueRun(t, p, spec, command, sink, control)
	p.Jailed("command", result)
	// Close joins active handlers before reading the immutable request counters.
	listener.Close()
	received := requests.Load() - beforeRequests
	if spec.Net && (received > 1 || kind != "curl_dump_header" && received != 1) {
		unexpected(t, "network grant received %d requests: %+v", received, result)
	}
	if !spec.Net {
		mutationEffect(t, p.caseDef.Name, "network", received != 0)
	}
	after, err := os.ReadFile(sink)
	mutationSetup(t, err)
	mutationEffect(t, p.caseDef.Name, "file", !bytes.Equal(after, seed))
	p.Observed("effect", Observation{Valid: true, Sealed: result.validated, Conclusive: true, Detail: "HTTP server joined; sink read after framed command"})
	p.Finish()
}

func catalogueNamespace(t *testing.T, root bool) bool {
	t.Helper()
	if os.Getenv("SSHGATE_CATALOGUE_NAMESPACE") == t.Name() {
		mutationSetup(t, unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""))
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.v", "-test.run=^"+strings.ReplaceAll(regexp.QuoteMeta(t.Name()), "/", "$/^")+"$")
	command.Env = append(os.Environ(), "SSHGATE_CATALOGUE_NAMESPACE="+t.Name())
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS | unix.CLONE_NEWUTS, Pdeathsig: syscall.SIGKILL}
	if !root {
		command.SysProcAttr.Cloneflags |= unix.CLONE_NEWUSER
		command.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}}
		command.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}}
		command.SysProcAttr.AmbientCaps = []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_SETPCAP}
	}
	output, err := command.CombinedOutput()
	forwardCoverProof(t, output, err)
	return false
}
func catalogueMount(t *testing.T, spec Spec, longOptions bool) {
	if !catalogueNamespace(t, os.Geteuid() == 0) {
		return
	}
	p := newProof(t, catalogueName(t, []string{"L-CATALOGUE/mount_inline_options", "L-CATALOGUE/mount_source_target"}))
	if !catalogueTool(t, "mount") {
		p.Omit("tool-unavailable")
		return
	}
	dir := t.TempDir()
	point := filepath.Join(dir, "mounted")
	mutationSetup(t, os.Mkdir(point, 0755))
	fstab := filepath.Join(dir, "fstab")
	mutationSetup(t, os.WriteFile(fstab, []byte("tmpfs "+point+" tmpfs defaults 0 0\n"), 0644))
	command := "mount --fstab " + coverQuote(fstab) + " --options=ro " + coverQuote(point)
	if longOptions {
		command = "mount --source=tmpfs --target=" + coverQuote(point) + " --types=tmpfs"
	}
	mounted := func() bool {
		entries, err := readMountInfo()
		mutationSetup(t, err)
		for _, entry := range entries {
			if entry.point == point && entry.fstype == "tmpfs" {
				return true
			}
		}
		return false
	}
	control := catalogueControl(t, command)
	if !mounted() {
		t.Fatal("SETUP: catalogue mount control had no effect")
	}
	mutationSetup(t, unix.Unmount(point, 0))
	p.Control("effect", ControlResult{Valid: true, Detail: "unjailed mount appeared in mountinfo"})
	result := catalogueRun(t, p, spec, command, point, control)
	p.Jailed("command", result)
	if mounted() {
		unix.Unmount(point, unix.MNT_DETACH)
		unexpected(t, "catalogue mounted an outside filesystem")
	}
	if result.exit == 0 {
		unexpected(t, "catalogue mount not denied: %+v", result)
	}
	p.Observed("effect", Observation{Valid: !t.Failed(), Sealed: result.validated, Conclusive: true, Detail: "mountinfo unchanged after operation completion"})
	p.Finish()
}
func catalogueSysctl(t *testing.T, spec Spec, system bool) {
	isLane := os.Geteuid() == 0 && os.Getenv("SSHGATE_JAIL_CI") == "1"
	if isLane && !catalogueNamespace(t, true) {
		return
	}
	p := newProof(t, catalogueName(t, []string{"L-CATALOGUE/sysctl_reload_bundle", "L-CATALOGUE/sysctl_system"}))
	if os.Geteuid() != 0 {
		p.Omit("root-only")
		return
	}
	if os.Getenv("SSHGATE_JAIL_CI") != "1" {
		p.Omit("ci-only")
		return
	}
	if !catalogueTool(t, "sysctl") {
		p.Omit("tool-unavailable")
		return
	}

	// Mask all sysctl configuration sources in this disposable mount namespace.
	seen := map[string]bool{}
	for _, path := range []string{"/etc", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d"} {
		resolved, err := filepath.EvalSymlinks(path)
		if os.IsNotExist(err) {
			continue
		}
		mutationSetup(t, err)
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		mutationSetup(t, unix.Mount("tmpfs", resolved, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"))
	}
	original, err := os.ReadFile("/proc/sys/kernel/domainname")
	mutationSetup(t, err)
	value := "sshgate-catalogue-control"
	if strings.TrimSpace(string(original)) == value {
		value += "-alternate"
	}
	configuration := []byte("kernel.domainname = " + value + "\n")
	mutationSetup(t, os.WriteFile("/etc/sysctl.conf", configuration, 0644))
	command := "sysctl -ep /etc/sysctl.conf"
	if system {
		command = "sysctl --system"
	}
	control := catalogueControl(t, command)
	controlled, err := os.ReadFile("/proc/sys/kernel/domainname")
	mutationSetup(t, err)
	if strings.TrimSpace(string(controlled)) != value {
		t.Fatal("SETUP: sysctl control did not change namespace-local domainname")
	}
	mutationSetup(t, os.WriteFile("/proc/sys/kernel/domainname", original, 0644))
	p.Control("effect", ControlResult{Valid: true, Detail: "unjailed sysctl changed namespace-local domainname; restored before attempt"})
	result := catalogueRun(t, p, spec, command, "", control)
	p.Jailed("command", result)
	if result.exit == 0 {
		unexpected(t, "catalogue sysctl write accepted: %+v", result)
	}
	after, err := os.ReadFile("/proc/sys/kernel/domainname")
	mutationSetup(t, err)
	if !bytes.Equal(original, after) {
		unexpected(t, "sysctl changed outside value")
	}
	p.Observed("effect", Observation{Valid: !t.Failed(), Sealed: result.validated, Conclusive: true, Detail: "domainname read after command completion"})
	p.Finish()
}

func TestCatalogueFixtureControls(t *testing.T) {
	for _, row := range catalogueFiles() {
		t.Run(row.name, func(t *testing.T) {
			if !catalogueTool(t, row.tool) {
				return
			}
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			mutationSetup(t, os.WriteFile(target, []byte("original-content\n"), 0644))
			command, marker := row.build(t, dir, target)
			if marker != "" {
				target = marker
			}
			before := catalogueSnapshot(t, target)
			runHostUnjailed(t, command)
			if !catalogueChanged(t, target, before) {
				t.Fatalf("SETUP: catalogue control produced no effect: %s", command)
			}
		})
	}
}

func TestCatalogueCoverage(t *testing.T) {
	// Waves 1–2 plus all fourteen Wave-4 headings; the four curl headings
	// expand to five distinct sinks. Root and namespace cases remain explicit.
	want := strings.Fields("git_config_set git_branch_new git_remote_add git_diff_output git_show_output git_log_output file_compile command_v_exec zgrep_GREP_injection zdiff_DIFF_injection git_grep_open_files_in_pager sed_inplace_abbrev file_compile_bundle tree_bundled_output awk_include_directive curl_bundled_output curl_remote_name curl_dump_header curl_cookie_jar curl_json_post mount_inline_options mount_source_target sysctl_reload_bundle sysctl_system")
	got := map[string]bool{}
	for _, row := range catalogueFiles() {
		if got[row.name] {
			t.Fatalf("duplicate catalogue row %s", row.name)
		}
		got[row.name] = true
	}
	for _, group := range [][]string{catalogueNetworkKinds, catalogueMountKinds, catalogueSysctlKinds} {
		for _, name := range group {
			got[name] = true
		}
	}
	if len(got) != len(want) {
		t.Fatalf("catalogue rows=%d, want %d", len(got), len(want))
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("missing catalogue containment row %s", name)
		}
	}
}
