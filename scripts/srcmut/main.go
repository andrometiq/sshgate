// srcmut checks source-patch mutations using Go overlays; it never edits a target.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

type redTest struct {
	Test    string
	Markers []string
}
type entry struct {
	ID, Name, Package, File, Old, New, Tags string
	Env                                     map[string]string
	Red                                     []redTest
	Green                                   []string
}
type runner struct {
	root, temporary, wrapper string
	timeout, grace           time.Duration
}
type result struct {
	stream, stderr []byte
	code           int
	status         string
	timedOut       bool
}
type event struct{ Action, Package, Test, Output string }
type testResult struct {
	ran      bool
	terminal string
	output   string
}

func main() {
	timeout := flag.Duration("timeout", 10*time.Minute, "per-run test timeout (process group killed 30s later)")
	flag.Parse()
	if err := run(*timeout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(timeout time.Duration) error {
	root, err := moduleRoot()
	if err != nil {
		return err
	}
	entries, err := loadEntries(filepath.Join(root, "scripts/srcmut/sets"), os.Getenv("SRCMUT"))
	if err != nil {
		return err
	}
	r, cleanup, err := newRunner(root, timeout)
	if err != nil {
		return err
	}
	defer cleanup()
	return checkEntries(r, entries, os.Stdout)
}

func checkEntries(r *runner, entries []entry, output io.Writer) error {
	for _, e := range entries {
		err := r.check(e)
		if err != nil {
			return fmt.Errorf("%s: %w", e.Name, err)
		}
		if _, err := fmt.Fprintf(output, "%s: detected\n", e.Name); err != nil {
			return err
		}
	}
	return nil
}
func moduleRoot() (string, error) {
	command := exec.Command("go", "env", "GOMOD")
	command.Env = environment(entry{})
	data, err := command.Output()
	if err != nil {
		return "", err
	}
	path := strings.TrimSpace(string(data))
	if !filepath.IsAbs(path) || path == os.DevNull {
		return "", errors.New("no module root")
	}
	return filepath.Dir(path), nil
}
func loadEntries(directory, filter string) ([]entry, error) {
	paths, err := filepath.Glob(filepath.Join(directory, "*.json"))
	if err != nil {
		return nil, err
	}
	var entries []entry
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var group []entry
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&group); err != nil {
			return nil, err
		}
		if decoder.Decode(new(any)) != io.EOF {
			return nil, errors.New("trailing set data")
		}
		entries = append(entries, group...)
	}
	return selectEntries(entries, filter)
}

var idPattern = regexp.MustCompile(`^P-[A-Z0-9-]+$`)

func selectEntries(entries []entry, filter string) ([]entry, error) {
	names, ids := map[string]bool{}, map[string]bool{}
	for _, e := range entries {
		if names[e.Name] {
			return nil, fmt.Errorf("duplicate name %q", e.Name)
		}
		names[e.Name] = true
		ids[e.ID] = true
		if err := validate(e); err != nil {
			return nil, err
		}
	}
	selected := map[string]bool{}
	if filter != "" {
		for _, id := range strings.Split(filter, ",") {
			if !idPattern.MatchString(id) {
				return nil, errors.New("malformed filter")
			}
			if !ids[id] {
				return nil, fmt.Errorf("unknown ID %s", id)
			}
			selected[id] = true
		}
	}
	var out []entry
	for _, e := range entries {
		if filter == "" || selected[e.ID] {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("empty selection")
	}
	return out, nil
}
func validate(e entry) error {
	if !idPattern.MatchString(e.ID) || e.Name == "" || e.Package == "" || e.Old == "" || e.Old == e.New {
		return errors.New("invalid entry")
	}
	if len(e.Red) == 0 {
		return errors.New("empty red list")
	}
	names := append([]string{}, e.Green...)
	for _, red := range e.Red {
		if len(red.Markers) == 0 {
			return errors.New("empty markers")
		}
		seen := map[string]bool{}
		for _, m := range red.Markers {
			if strings.TrimSpace(m) != m || m == "" || strings.ContainsAny(m, "\r\n") || seen[m] {
				return errors.New("invalid markers")
			}
			seen[m] = true
		}
		names = append(names, red.Test)
	}
	for i, a := range names {
		if !strings.HasPrefix(a, "Test") || strings.ContainsAny(a, "\r\n") {
			return errors.New("invalid test path")
		}
		for _, part := range strings.Split(a, "/") {
			if part == "" {
				return errors.New("empty test path level")
			}
		}
		for j, b := range names {
			if i != j && (a == b || strings.HasPrefix(b, a+"/")) {
				return errors.New("name leaves, not parents")
			}
		}
	}
	for k, v := range e.Env {
		if k == "" || strings.ContainsAny(k, "=\x00") || strings.ContainsRune(v, 0) || k == "SRCMUT_STATUS_FILE" {
			return errors.New("invalid environment")
		}
	}
	return nil
}
func newRunner(root string, timeout time.Duration) (*runner, func(), error) {
	if timeout <= 0 {
		return nil, nil, errors.New("timeout must be positive")
	}
	dir, err := os.MkdirTemp("", "srcmut-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	r := &runner{root: root, temporary: dir, wrapper: filepath.Join(dir, "execwrap"), timeout: timeout, grace: 30 * time.Second}
	command := exec.Command("go", "build", "-o", r.wrapper, "./scripts/srcmut/execwrap")
	command.Dir = root
	command.Env = environment(entry{})
	if data, err := command.CombinedOutput(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("build execwrap: %w: %s", err, data)
	}
	return r, cleanup, nil
}
func environment(e entry) []string {
	env := os.Environ()
	for k, v := range e.Env {
		env = append(env, k+"="+v)
	}
	// A nonempty blank also overrides flags persisted by go env -w.
	return append(env, "GOFLAGS= ")
}
func (r *runner) overlay(e entry) (string, error) {
	target := e.File
	if !filepath.IsAbs(target) {
		target = filepath.Join(r.root, target)
	}
	target, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(r.root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || !strings.HasSuffix(target, ".go") || strings.HasSuffix(target, "_test.go") {
		return "", errors.New("invalid patch target")
	}
	args := []string{"list", "-deps", "-test", "-json"}
	if e.Tags != "" {
		args = append(args, "-tags", e.Tags)
	}
	args = append(args, e.Package)
	command := exec.Command("go", args...)
	command.Dir = r.root
	command.Env = environment(e)
	data, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("list dependencies: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	found := false
	for {
		var p struct {
			Dir               string
			GoFiles, CgoFiles []string
			Module            *struct{ Dir string }
		}
		err := decoder.Decode(&p)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if p.Module == nil || p.Module.Dir != r.root {
			continue
		}
		for _, f := range append(p.GoFiles, p.CgoFiles...) {
			if filepath.Join(p.Dir, f) == target {
				found = true
			}
		}
	}
	if !found {
		return "", errors.New("patch target not in the test binary")
	}
	data, err = os.ReadFile(target)
	if err != nil {
		return "", err
	}
	command = exec.Command("git", "show", "HEAD:"+filepath.ToSlash(relative))
	command.Dir = r.root
	head, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("patch target unavailable at HEAD: %w", err)
	}
	if bytes.Count(head, []byte(e.Old)) != 1 {
		return "", errors.New("patch no longer applies")
	}
	if !bytes.Equal(data, head) {
		return "", errors.New("patch target differs from HEAD")
	}
	dir, err := os.MkdirTemp(r.temporary, "overlay-")
	if err != nil {
		return "", err
	}
	patched := filepath.Join(dir, "patched.go")
	if err = os.WriteFile(patched, bytes.Replace(data, []byte(e.Old), []byte(e.New), 1), 0600); err != nil {
		return "", err
	}
	overlay := filepath.Join(dir, "overlay.json")
	data, err = json.Marshal(struct{ Replace map[string]string }{map[string]string{target: patched}})
	if err != nil {
		return "", err
	}
	return overlay, os.WriteFile(overlay, data, 0600)
}
func selection(e entry) string {
	names := append([]string{}, e.Green...)
	for _, red := range e.Red {
		names = append(names, red.Test)
	}
	for i, name := range names {
		levels := strings.Split(name, "/")
		for j, level := range levels {
			levels[j] = "^" + regexp.QuoteMeta(level) + "$"
		}
		names[i] = strings.Join(levels, "/")
	}
	return strings.Join(names, "|")
}
func (r *runner) execute(e entry, overlay string) result {
	dir, err := os.MkdirTemp(r.temporary, "run-")
	if err != nil {
		return result{stderr: []byte(err.Error()), code: -1}
	}
	status := filepath.Join(dir, "status.json")
	args := []string{"test", "-count=1", "-json", "-timeout", r.timeout.String(), "-exec", r.wrapper, "-run", selection(e)}
	if e.Tags != "" {
		args = append(args, "-tags", e.Tags)
	}
	if overlay != "" {
		args = append(args, "-vet=off", "-overlay", overlay)
	}
	args = append(args, e.Package)
	command := exec.Command("go", args...)
	command.Dir = r.root
	command.Env = append(environment(e), "SRCMUT_STATUS_FILE="+status)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err = command.Start(); err != nil {
		return result{stderr: []byte(err.Error()), code: -1}
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(r.timeout + r.grace)
	defer timer.Stop()
	timedOut := false
	select {
	case err := <-done:
		if err != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
	case <-timer.C:
		timedOut = true
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		<-done
	}
	return result{stdout.Bytes(), stderr.Bytes(), command.ProcessState.ExitCode(), status, timedOut}
}
func (r *runner) check(e entry) error {
	if err := validate(e); err != nil {
		return err
	}
	overlay, err := r.overlay(e)
	if err != nil {
		return fmt.Errorf("infrastructure: %w", err)
	}
	if err = judge(e, r.execute(e, ""), false); err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	return judge(e, r.execute(e, overlay), true)
}
func childCode(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return -1, errors.New("missing child status")
	}
	var record struct {
		Exited   *bool `json:"exited"`
		Code     *int  `json:"code"`
		Signaled *bool `json:"signaled"`
		Signal   *int  `json:"signal"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return -1, errors.New("invalid child status")
	}
	if decoder.Decode(new(any)) != io.EOF || record.Exited == nil || record.Code == nil || record.Signaled == nil || record.Signal == nil || !*record.Exited || *record.Signaled || *record.Signal != 0 {
		return -1, errors.New("invalid child status")
	}
	return *record.Code, nil
}

var diagnostics = []string{"panic:", "fatal error:", "runtime: ", "WARNING: DATA RACE", "[build failed]", "[setup failed]", "signal: ", "exit status 2", "testing: warning: no tests to run", "--- FAIL: TestMain"}

func suspicious(s string) bool {
	for _, d := range diagnostics {
		if strings.Contains(s, d) {
			return true
		}
	}
	return false
}

var framePattern = regexp.MustCompile(`^(=== (RUN|PAUSE|CONT|NAME)\s+\S+|--- FAIL: \S+ \([0-9.]+s\))$`)

func framing(output string) bool {
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if !framePattern.MatchString(strings.TrimSpace(line)) {
			return false
		}
	}
	return true
}
func markers(output string) []string {
	var out []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, ": "); i >= 0 && strings.Contains(line[:i], ".go:") {
			line = line[i+2:]
		}
		if strings.Contains(line, "MUTATION-EFFECT") {
			out = append(out, line)
		}
	}
	slices.Sort(out)
	return out
}

func judge(e entry, run result, mutated bool) error {
	infra := func(message string) error { return errors.New("infrastructure: " + message) }
	child, err := childCode(run.status)
	if err != nil {
		return infra(err.Error())
	}
	if run.timedOut || len(run.stderr) != 0 {
		return infra("deadline or stderr: " + string(run.stderr))
	}
	if child < 0 || child > 1 || run.code != child {
		return infra("unexpected child or launcher exit")
	}
	named := map[string]bool{}
	reds := map[string][]string{}
	for _, red := range e.Red {
		named[red.Test] = true
		reds[red.Test] = red.Markers
	}
	for _, name := range e.Green {
		named[name] = true
	}
	tests := map[string]*testResult{}
	terminal := ""
	pkg := ""
	var trailer *regexp.Regexp
	started := false
	scanner := bufio.NewScanner(bytes.NewReader(run.stream))
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		var ev event
		if json.Unmarshal(scanner.Bytes(), &ev) != nil || ev.Package == "" || terminal != "" || suspicious(ev.Output) {
			return infra("invalid event stream or diagnostic")
		}
		if pkg == "" {
			pkg = ev.Package
			trailer = regexp.MustCompile(`^(ok  |FAIL)\t` + regexp.QuoteMeta(pkg) + `\t[0-9]+\.[0-9]+s$`)
		}
		if pkg != ev.Package {
			return infra("multiple packages")
		}
		if ev.Test == "" {
			switch ev.Action {
			case "start":
				if started {
					return infra("duplicate package start")
				}
				started = true
			case "pass", "fail", "skip":
				terminal = ev.Action
			case "output":
				for _, line := range strings.Split(strings.TrimSuffix(ev.Output, "\n"), "\n") {
					if line != "PASS" && line != "FAIL" && !trailer.MatchString(line) {
						return infra("unexpected package output: " + line)
					}
				}
			default:
				return infra("invalid package event")
			}
			continue
		}
		t := tests[ev.Test]
		if t == nil {
			t = &testResult{}
			tests[ev.Test] = t
		}
		switch ev.Action {
		case "run":
			if t.ran || t.terminal != "" {
				return infra("duplicate test run")
			}
			t.ran = true
			for name := range named {
				if strings.HasPrefix(ev.Test, name+"/") {
					return infra("name leaves, not parents: " + name)
				}
			}
		case "pass", "fail", "skip":
			if !t.ran || t.terminal != "" {
				return infra("invalid test terminal")
			}
			t.terminal = ev.Action
		case "output":
			t.output += ev.Output
		case "pause", "cont":
			if !t.ran || t.terminal != "" {
				return infra("invalid test scheduling")
			}
		default:
			return infra("unknown test event")
		}
	}
	if scanner.Err() != nil || !started || terminal == "" {
		return infra("incomplete stream")
	}
	for name, t := range tests {
		if !t.ran || t.terminal == "" {
			return infra("unfinished test: " + name)
		}
	}
	for name := range named {
		t := tests[name]
		if t == nil || !t.ran || t.terminal == "skip" {
			return infra("missing or skipped named test: " + name)
		}
	}
	for name, t := range tests {
		if len(markers(t.output)) != 0 && (!mutated || reds[name] == nil) {
			return infra("unexpected markers: " + name)
		}
		if t.terminal != "fail" {
			continue
		}
		if !mutated {
			return infra("baseline test failed")
		}
		if _, ok := reds[name]; ok {
			continue
		}
		ancestor := false
		for red := range reds {
			if strings.HasPrefix(red, name+"/") && tests[red].terminal == "fail" {
				ancestor = true
			}
		}
		if !ancestor || !framing(t.output) {
			return infra("independent failure: " + name)
		}
	}
	for _, name := range e.Green {
		if tests[name].terminal != "pass" {
			return infra("green failed")
		}
	}
	notDetected := false
	for name, want := range reds {
		t := tests[name]
		if !mutated {
			if t.terminal != "pass" {
				return infra("baseline red failed")
			}
			continue
		}
		if t.terminal == "pass" {
			notDetected = true
			if len(markers(t.output)) != 0 {
				return infra("markers without failure")
			}
			continue
		}
		expected := make([]string, len(want))
		for i, m := range want {
			expected[i] = "MUTATION-EFFECT " + m
		}
		slices.Sort(expected)
		if !slices.Equal(markers(t.output), expected) {
			return infra("wrong markers: " + name)
		}
	}
	expectedTerminal := "pass"
	expectedCode := 0
	if mutated && !notDetected {
		expectedTerminal = "fail"
		expectedCode = 1
	}
	if mutated && notDetected {
		// A partial detection still has a normally failing package.
		for _, t := range tests {
			if t.terminal == "fail" {
				expectedTerminal = "fail"
				expectedCode = 1
			}
		}
	}
	if terminal != expectedTerminal || child != expectedCode {
		return infra("unexpected termination")
	}
	if notDetected {
		return errors.New("not detected")
	}
	return nil
}
