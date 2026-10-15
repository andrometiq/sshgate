package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func fixtureEntry() entry {
	return entry{ID: "P-A", Name: "guard", Package: "./scripts/srcmut/testdata/fixture", File: "scripts/srcmut/testdata/fixture/guard.go", Old: "return true", New: "return false", Red: []redTest{{"TestRed", []string{"red"}}}, Green: []string{"TestGreen"}}
}
func testRunner(t *testing.T) *runner {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	r, cleanup, err := newRunner(root, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return r
}
func TestFixtures(t *testing.T) {
	r := testRunner(t)
	cases := []struct {
		name   string
		change func(*entry)
		want   string
	}{
		{"detected", func(e *entry) {}, ""},
		{"stale", func(e *entry) { e.Old = "absent" }, "patch no longer applies"},
		{"ambiguous-patch", func(e *entry) { e.Old = "r" }, "patch no longer applies"},
		{"build-error", func(e *entry) { e.New = "return invalid_symbol" }, "infrastructure"},
		{"not-detected", func(e *entry) { e.Env = map[string]string{"MODE": "pass"} }, "not detected"},
		{"missing-marker", func(e *entry) { e.Env = map[string]string{"MODE": "missing"} }, "infrastructure"},
		{"extra-marker", func(e *entry) { e.Env = map[string]string{"MODE": "extra"} }, "infrastructure"},
		{"green-fails", func(e *entry) { e.Env = map[string]string{"GREEN_FAIL": "1"} }, "infrastructure"},
		{"green-missing", func(e *entry) { e.Green = []string{"TestAbsent"} }, "infrastructure"},
		{"red-missing", func(e *entry) { e.Red[0].Test = "TestAbsent" }, "infrastructure"},
		{"tag", func(e *entry) { e.Red[0].Test = "TestTagged"; e.Tags = "srcmut_fixture" }, ""},
		{"tag-omitted", func(e *entry) { e.Red[0].Test = "TestTagged" }, "infrastructure"},
		{"environment", func(e *entry) { e.Red[0].Test = "TestEnv"; e.Env = map[string]string{"EFFECT": "yes"} }, ""},
		{"environment-omitted", func(e *entry) { e.Red[0].Test = "TestEnv" }, "not detected"},
		{"test-target", func(e *entry) { e.File = "scripts/srcmut/testdata/fixture/guard_test.go" }, "invalid patch target"},
		{"dependency", func(e *entry) {
			e.File = "scripts/srcmut/testdata/dependency/guard.go"
			e.Red[0].Test = "TestDependency"
		}, ""},
		{"unlinked", func(e *entry) { e.File = "scripts/srcmut/testdata/unlinked/guard.go" }, "patch target not in the test binary"},
		{"selected-child", func(e *entry) { e.Red = []redTest{{"TestP/a", []string{"ma"}}}; e.Green = nil }, ""},
		{"leaves", func(e *entry) { e.Red = []redTest{{"TestP/a", []string{"ma"}}, {"TestP/b", []string{"mb"}}} }, ""},
		{"swapped", func(e *entry) { e.Red = []redTest{{"TestP/a", []string{"mb"}}, {"TestP/b", []string{"ma"}}} }, "infrastructure"},
		{"parent", func(e *entry) { e.Red = []redTest{{"TestP", []string{"ma", "mb"}}} }, "infrastructure"},
		{"parent-child", func(e *entry) { e.Red = []redTest{{"TestP", []string{"ma"}}, {"TestP/a", []string{"ma"}}} }, "name leaves"},
		{"green-parent-mutated-skip", func(e *entry) { e.Green = []string{"TestG"}; e.Env = map[string]string{"SKIP_CONTROL": "mutated"} }, "infrastructure"},
		{"green-parent-always-skip", func(e *entry) { e.Green = []string{"TestG"}; e.Env = map[string]string{"SKIP_CONTROL": "always"} }, "infrastructure"},
		{"green-leaf", func(e *entry) { e.Green = []string{"TestG/control"} }, ""},
		{"green-leaf-skip", func(e *entry) {
			e.Green = []string{"TestG/control"}
			e.Env = map[string]string{"SKIP_CONTROL": "mutated"}
		}, "infrastructure"},
		{"passing-sibling", func(e *entry) { e.Red = []redTest{{"TestP/a", []string{"ma"}}}; e.Green = []string{"TestP/green"} }, ""},
		{"failing-parent", func(e *entry) {
			e.Red = []redTest{{"TestP/a", []string{"ma"}}}
			e.Env = map[string]string{"PARENT_FAIL": "1"}
		}, "infrastructure"},
		{"cleanup-panic", func(e *entry) { e.Env = map[string]string{"CLEANUP": "panic"} }, "infrastructure"},
		{"red-panic", func(e *entry) { e.Env = map[string]string{"MODE": "panic"} }, "infrastructure"},
		{"exit2", func(e *entry) { e.Env = map[string]string{"MODE": "exit2"} }, "infrastructure"},
		{"killed-mid-test", func(e *entry) { e.Env = map[string]string{"MODE": "kill"} }, "infrastructure"},
		{"silent-exit2", func(e *entry) { e.Env = map[string]string{"CLEANUP": "exit2"} }, "infrastructure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := fixtureEntry()
			tc.change(&e)
			err := r.check(e)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v; want %s", err, tc.want)
			}
		})
	}
}
func TestWorkloads(t *testing.T) {
	a := fixtureEntry()
	b := fixtureEntry()
	b.Name = "second"
	for _, filter := range []string{"", "P-A"} {
		got, err := selectEntries([]entry{a, b}, filter)
		if err != nil || len(got) != 2 || got[0].Name == got[1].Name {
			t.Fatalf("%v %v", got, err)
		}
	}
	for _, filter := range []string{"P-A,,P-B", " P-A", "p-a"} {
		_, err := selectEntries([]entry{a}, filter)
		if err == nil || !strings.Contains(err.Error(), "malformed filter") {
			t.Fatal(err)
		}
	}
	for _, filter := range []string{"", "P-X"} {
		_, err := selectEntries(nil, filter)
		if err == nil {
			t.Fatal("empty accepted")
		}
	}
	_, err := selectEntries([]entry{a}, "P-X")
	if err == nil {
		t.Fatal("unknown accepted")
	}
	for _, change := range []func(*entry){func(e *entry) { e.Red = nil }, func(e *entry) { e.Red[0].Markers = nil }} {
		e := fixtureEntry()
		change(&e)
		if validate(e) == nil {
			t.Fatal("invalid accepted")
		}
	}
	dir := t.TempDir()
	for _, filter := range []string{"", "P-A"} {
		if _, err := loadEntries(dir, filter); err == nil {
			t.Fatal("empty accepted")
		}
	}
	for _, name := range []string{"a.json", "b.json"} {
		data, _ := json.Marshal([]entry{a})
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadEntries(dir, ""); err == nil || !strings.Contains(err.Error(), "duplicate name") {
		t.Fatal(err)
	}
}
func TestOverlayAndTermination(t *testing.T) {
	r := testRunner(t)
	e := fixtureEntry()
	overlay, err := r.overlay(e)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(overlay)
	if err != nil {
		t.Fatal(err)
	}
	var mapping struct{ Replace map[string]string }
	if err = json.Unmarshal(data, &mapping); err != nil {
		t.Fatal(err)
	}
	for k, v := range mapping.Replace {
		if !filepath.IsAbs(k) || !filepath.IsAbs(v) {
			t.Fatal(mapping)
		}
	}
	good := r.execute(e, overlay)
	if err = judge(e, good, true); err != nil {
		t.Fatal(err)
	}
	t.Run("silent-exit-status", func(t *testing.T) {
		e.Env = map[string]string{"CLEANUP": "exit2"}
		run := r.execute(e, overlay)
		code, err := childCode(run.status)
		if err != nil || code != 2 || run.code != 1 {
			t.Fatalf("child %d launcher %d: %v", code, run.code, err)
		}
		if !strings.HasSuffix(strings.TrimSpace(string(run.stream)), `}`) {
			t.Fatal("incomplete JSON")
		}
		if judge(e, run, true) == nil {
			t.Fatal("exit2 accepted")
		}
		normal := run
		normal.status = statusFile(t, []byte(`{"exited":true,"code":1,"signaled":false,"signal":0}`))
		if err := judge(e, normal, true); err != nil {
			t.Fatalf("silent exit2 fixture has another defect: %v", err)
		}

		e.Env = nil
	})
	for _, tc := range []struct {
		name   string
		change func(*result)
	}{
		{"missing-status", func(r *result) { r.status = filepath.Join(t.TempDir(), "missing") }},
		{"duplicate-status", func(r *result) {
			data, err := os.ReadFile(r.status)
			if err != nil {
				t.Fatal(err)
			}
			r.status = statusFile(t, append(data, data...))
		}},
		{"malformed-status", func(r *result) { r.status = statusFile(t, []byte("{")) }},
		{"truncated", func(r *result) { r.stream = r.stream[:len(r.stream)/2] }},
		{"trailing", func(r *result) { r.stream = append(append([]byte{}, r.stream...), []byte("{}\n")...) }},
		{"deadline", func(r *result) { r.timedOut = true }},
		{"launcher", func(r *result) { r.code = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := good
			tc.change(&run)
			if judge(e, run, true) == nil {
				t.Fatal("invalid accepted")
			}
		})
	}

	t.Run("deleted-record", func(t *testing.T) {
		if err := os.Remove(good.status); err != nil {
			t.Fatal(err)
		}
		if judge(e, good, true) == nil {
			t.Fatal("deleted record accepted")
		}
	})
	// TestMain hangs before testing starts its own timer, exercising group cleanup.
	r.timeout = 2 * time.Second
	r.grace = 0
	pidPath := filepath.Join(t.TempDir(), "pid")
	e.Env = map[string]string{"HANG_PID": pidPath}
	run := r.execute(e, overlay)
	if !run.timedOut || judge(e, run, true) == nil {
		t.Fatal("deadline accepted")
	}
	pidData, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("test binary never started: %v", err)
	}
	pid, err := strconv.Atoi(string(pidData))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if syscall.Kill(pid, 0) == syscall.ESRCH {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("test process survived deadline")
}

func TestUnnamedSibling(t *testing.T) {
	r := testRunner(t)
	e := fixtureEntry()
	e.Red = []redTest{{"TestP/a", []string{"ma"}}, {"TestP/b", []string{"mb"}}}
	overlay, err := r.overlay(e)
	if err != nil {
		t.Fatal(err)
	}
	run := r.execute(e, overlay)
	if err = judge(e, run, true); err != nil {
		t.Fatal(err)
	}
	e.Red = e.Red[:1]
	if err = judge(e, run, true); err == nil || !strings.Contains(err.Error(), "infrastructure") {
		t.Fatalf("unnamed sibling accepted: %v", err)
	}
}

func eventRun(t *testing.T, events []event, code int) result {
	var stream []byte
	for _, e := range events {
		data, _ := json.Marshal(e)
		stream = append(stream, append(data, '\n')...)
	}
	status, _ := json.Marshal(map[string]any{"exited": true, "code": code, "signaled": false, "signal": 0})
	return result{stream: stream, status: statusFile(t, status), code: code}
}
func TestJudgeEvidence(t *testing.T) {
	e := fixtureEntry()
	e.Green = nil
	events := []event{
		{Action: "start", Package: "fixture"},
		{Action: "run", Package: "fixture", Test: "TestRed"},
		{Action: "output", Package: "fixture", Test: "TestRed", Output: "    fixture_test.go:1: MUTATION-EFFECT red\n"},
		{Action: "fail", Package: "fixture", Test: "TestRed"},
		{Action: "output", Package: "fixture", Output: "FAIL\n"},
		{Action: "fail", Package: "fixture"},
	}
	if err := judge(e, eventRun(t, events, 1), true); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func([]event) []event
	}{
		{"missing-run", func(v []event) []event { return append(v[:1], v[2:]...) }},
		{"missing-terminal", func(v []event) []event { return append(v[:3], v[4:]...) }},
		{"duplicate-terminal", func(v []event) []event { return append(v[:4], append([]event{v[3]}, v[4:]...)...) }},
		{"package-output", func(v []event) []event { v[4].Output = "cleanup error\n"; return v }},
		{"fake-trailer", func(v []event) []event { v[4].Output = "FAIL\tfixture\tcleanup error\n"; return v }},
		{"missing-package-terminal", func(v []event) []event { return v[:len(v)-1] }},
		{"skipped", func(v []event) []event { v[3].Action = "skip"; return v }},
		{"marker-prefix", func(v []event) []event { v[2].Output = "not an effect: MUTATION-EFFECT red\n"; return v }},
		{"duplicate-marker", func(v []event) []event { v[2].Output += v[2].Output; return v }},
		{"unknown-action", func(v []event) []event { v[2].Action = "unexpected"; return v }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := judge(e, eventRun(t, tc.edit(append([]event{}, events...)), 1), true); err == nil {
				t.Fatal("accepted invalid evidence")
			}
		})
	}
	for _, diagnostic := range diagnostics {
		t.Run(diagnostic, func(t *testing.T) {
			v := append([]event{}, events...)
			v[2].Output += diagnostic + "\n"
			if judge(e, eventRun(t, v, 1), true) == nil {
				t.Fatal("accepted diagnostic")
			}
		})
	}
	for _, status := range []string{"", `{}`, `{"exited":true,"code":1,"signaled":true,"signal":15}`, `{"exited":true,"code":1,"signaled":false,"signal":0} {}`} {
		r := eventRun(t, events, 1)
		r.status = statusFile(t, []byte(status))
		if judge(e, r, true) == nil {
			t.Fatal("accepted invalid status")
		}
	}
}

func TestSelectedReports(t *testing.T) {
	r := testRunner(t)
	a, b := fixtureEntry(), fixtureEntry()
	b.Name = "other"
	selected, err := selectEntries([]entry{a, b}, "P-A")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err = checkEntries(r, selected, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "guard: detected\nother: detected\n" {
		t.Fatal(output.String())
	}
}

func statusFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "status.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*entry)
	}{
		{"empty-red", func(e *entry) { e.Red = nil }},
		{"empty-markers", func(e *entry) { e.Red[0].Markers = nil }},
		{"empty-marker", func(e *entry) { e.Red[0].Markers = []string{""} }},
		{"duplicate-marker", func(e *entry) { e.Red[0].Markers = []string{"red", "red"} }},
		{"parent-child", func(e *entry) { e.Red[0].Test = "TestP"; e.Green = []string{"TestP/a"} }},
		{"duplicate-leaf", func(e *entry) { e.Green = []string{"TestRed"} }},
		{"empty-level", func(e *entry) { e.Red[0].Test = "TestP/" }},
		{"reserved-environment", func(e *entry) { e.Env = map[string]string{"SRCMUT_STATUS_FILE": "replacement"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixtureEntry()
			tc.change(&e)
			if validate(e) == nil {
				t.Fatal("invalid workload accepted")
			}
		})
	}
	dir := t.TempDir()
	e := fixtureEntry()
	data, _ := json.Marshal([]entry{e})
	if err := os.WriteFile(filepath.Join(dir, "fixture.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SRCMUT", "")
	for _, present := range []bool{false, true} {
		if present {
			if err := os.Setenv("SRCMUT", ""); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.Unsetenv("SRCMUT"); err != nil {
				t.Fatal(err)
			}
		}
		entries, err := loadEntries(dir, os.Getenv("SRCMUT"))
		if err != nil || len(entries) != 1 {
			t.Fatalf("present=%v: %v", present, err)
		}
		if _, err = loadEntries(t.TempDir(), os.Getenv("SRCMUT")); err == nil || !strings.Contains(err.Error(), "empty selection") {
			t.Fatal(err)
		}
	}
}
