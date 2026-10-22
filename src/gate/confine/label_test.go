package confine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const daemonSystemctl = "daemon read, limited verbs: systemctl (not kernel read-only)"

// TestLabelTable pins every BUILD-PLAN label row at both switch values.
func TestLabelTable(t *testing.T) {
	kernel := func(s LabelState) LabelState {
		s.Outcome, s.Profile, s.ABI = RunKernel, ProfileROv1, 3
		return s
	}
	unmet := []string{"fs-view:fuse@/x"}
	rows := []struct {
		name    string
		state   LabelState
		net     bool
		off, on string
	}{
		{"pinned net=deny", kernel(LabelState{Pinned: true, Strict: true}), false, LabelKernelNoLabel, LabelReadOnlyKernel},
		{"pinned net=deny at ABI 1", LabelState{Pinned: true, Strict: true, Outcome: RunKernel, Profile: ProfileROv1, ABI: 1}, false, LabelKernelNoLabel, LabelReadOnlyKernel},
		{"pinned net=allow", kernel(LabelState{Pinned: true, Strict: true}), true, LabelNetworkOpen, LabelNetworkOpen},
		{"unpinned strict with a grant", kernel(LabelState{Strict: true}), true, LabelNetworkOpen, LabelNetworkOpen},
		{"unpinned, profile applied", kernel(LabelState{}), false, LabelPinToClaim, LabelPinToClaim},
		{"unpinned strict, no network", kernel(LabelState{Strict: true}), false, LabelPinToClaim, LabelPinToClaim},
		{"unpinned with unmet clauses", kernel(LabelState{Unmet: unmet}), false, LabelClassifierOnly, LabelClassifierOnly},
		{"daemon read unpinned", LabelState{Outcome: RunDaemonRead, Binary: "systemctl"}, true, daemonSystemctl, daemonSystemctl},
		{"daemon read pinned", LabelState{Pinned: true, Strict: true, Outcome: RunDaemonRead, Binary: "systemctl"}, true, daemonSystemctl, daemonSystemctl},
		{"unpinned absent", LabelState{Outcome: RunAbsent}, false, LabelClassifierOnly, LabelClassifierOnly},
		{"unpinned absent with no facts", LabelState{Outcome: RunAbsent, Profile: "", ABI: 0}, true, LabelClassifierOnly, LabelClassifierOnly},
		{"pinned absent", LabelState{Pinned: true, Strict: true, Outcome: RunAbsent}, false, LabelDenied, LabelDenied},
		{"absent on a read that requires confinement", LabelState{Strict: true, Outcome: RunAbsent}, false, LabelDenied, LabelDenied},
		{"failed unpinned", LabelState{Outcome: RunFailed}, false, LabelDenied, LabelDenied},
		{"failed pinned", LabelState{Pinned: true, Strict: true, Outcome: RunFailed}, false, LabelDenied, LabelDenied},
		{"damaged pin", kernel(LabelState{Damaged: true}), false, LabelDenied, LabelDenied},
		{"damaged pin, daemon read", LabelState{Damaged: true, Outcome: RunDaemonRead, Binary: "systemctl"}, false, LabelDenied, LabelDenied},
		{"strict run with unmet", kernel(LabelState{Pinned: true, Strict: true, Unmet: unmet}), false, LabelDenied, LabelDenied},
		{"strict networked run with unmet", kernel(LabelState{Strict: true, Unmet: unmet}), true, LabelDenied, LabelDenied},
		{"network without a strict run", kernel(LabelState{}), true, LabelDenied, LabelDenied},
		{"pinned run that was not strict", kernel(LabelState{Pinned: true, Unmet: unmet}), false, LabelDenied, LabelDenied},
		{"wrong profile", LabelState{Pinned: true, Strict: true, Outcome: RunKernel, ABI: 3}, false, LabelDenied, LabelDenied},
		{"no Landlock ABI", LabelState{Pinned: true, Strict: true, Outcome: RunKernel, Profile: ProfileROv1}, false, LabelDenied, LabelDenied},
		{"no outcome", LabelState{Pinned: true, Strict: true, Profile: ProfileROv1, ABI: 3}, false, LabelDenied, LabelDenied},
		{"daemon read without a binary", LabelState{Outcome: RunDaemonRead}, false, LabelDenied, LabelDenied},
		{"daemon read with a non-printable binary", LabelState{Outcome: RunDaemonRead, Binary: "system\nctl"}, false, LabelDenied, LabelDenied},
		{"daemon read with a space", LabelState{Outcome: RunDaemonRead, Binary: "a b"}, false, LabelDenied, LabelDenied},
	}
	for _, row := range rows {
		if got := Label(row.state, row.net, false); got != row.off {
			t.Errorf("%s, switch off: got %q, want %q", row.name, got, row.off)
		}
		if got := Label(row.state, row.net, true); got != row.on {
			t.Errorf("%s, switch on: got %q, want %q", row.name, got, row.on)
		}
	}
}

// TestLabelNeverClaimsReadOnlyWrongly enumerates every state and checks the
// label's invariants over all of them.
func TestLabelNeverClaimsReadOnlyWrongly(t *testing.T) {
	daemon := daemonSystemctl
	known := map[string]bool{LabelReadOnlyKernel: true, LabelKernelNoLabel: true, LabelNetworkOpen: true,
		LabelPinToClaim: true, LabelClassifierOnly: true, LabelDenied: true, daemon: true}
	bools := []bool{false, true}
	outcomes := []RunOutcome{0, RunKernel, RunAbsent, RunFailed, RunDaemonRead, RunDaemonRead + 1}
	count := 0
	for _, pinned := range bools {
		for _, damaged := range bools {
			for _, strict := range bools {
				for _, outcome := range outcomes {
					for _, profile := range []string{ProfileROv1, ""} {
						for _, abi := range []int{0, 3} {
							for _, unmet := range [][]string{nil, {"fs-view:fuse@/x"}} {
								for _, binary := range []string{"", "systemctl"} {
									for _, net := range bools {
										for _, enabled := range bools {
											s := LabelState{Pinned: pinned, Damaged: damaged, Strict: strict, Outcome: outcome, Profile: profile, ABI: abi, Unmet: unmet, Binary: binary}
											got := Label(s, net, enabled)
											count++
											if !known[got] {
												t.Fatalf("%+v net=%v enabled=%v: unknown label %q", s, net, enabled, got)
											}
											if got == LabelReadOnlyKernel && (!enabled || len(unmet) > 0 || net || damaged || !pinned || !strict || outcome != RunKernel || profile != ProfileROv1 || abi < 1) {
												t.Errorf("%+v net=%v enabled=%v: claimed read-only", s, net, enabled)
											}
											if got == LabelKernelNoLabel && (enabled || len(unmet) > 0 || net || damaged || !pinned || !strict || outcome != RunKernel) {
												t.Errorf("%+v net=%v enabled=%v: claimed a kernel jail", s, net, enabled)
											}
											if got == LabelNetworkOpen && (!net || !strict || damaged || len(unmet) > 0 || outcome != RunKernel) {
												t.Errorf("%+v net=%v enabled=%v: claimed a strict network run", s, net, enabled)
											}
											if got == daemon && (outcome != RunDaemonRead || damaged) {
												t.Errorf("%+v net=%v enabled=%v: claimed a daemon read", s, net, enabled)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if count != 2*2*2*len(outcomes)*2*2*2*2*2*2 {
		t.Fatalf("enumerated %d states", count)
	}
}

// TestLabelStringsMatchBuildPlan keeps the constants byte-exact with the
// labels table in docs/BUILD-PLAN.md.
func TestLabelStringsMatchBuildPlan(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(moduleRoot(t), "docs", "BUILD-PLAN.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, table, ok := strings.Cut(string(data), "### Labels (exact strings)")
	if !ok {
		t.Fatal("BUILD-PLAN has no labels table")
	}
	table, _, _ = strings.Cut(table, "\n### ")
	for _, label := range []string{LabelReadOnlyKernel, LabelKernelNoLabel, LabelNetworkOpen, LabelPinToClaim, LabelClassifierOnly, LabelDenied,
		"daemon read, limited verbs: <binary> (not kernel read-only)"} {
		if !strings.Contains(table, "`"+label+"`") {
			t.Errorf("label %q is not in the BUILD-PLAN labels table", label)
		}
	}
	if KernelLabelEnabled {
		t.Error("KernelLabelEnabled is on before P7.1")
	}
}

// TestLabelCallersPassTheSwitch is the AST guard: every non-test call of
// confine.Label passes KernelLabelEnabled, and the read-only string appears
// only in this package's label.go.
func TestLabelCallersPassTheSwitch(t *testing.T) {
	root := moduleRoot(t)
	const confinePath = "github.com/karthikeyan5/sshgate/src/gate/confine"
	files := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		files++
		rel, _ := filepath.Rel(root, path)
		inConfine := filepath.Dir(rel) == filepath.Join("src", "gate", "confine")
		confineNames := map[string]bool{}
		for _, imp := range file.Imports {
			if importPath, _ := strconv.Unquote(imp.Path.Value); importPath == confinePath {
				local := "confine"
				if imp.Name != nil {
					local = imp.Name.Name
				}
				confineNames[local] = true
			}
		}
		isConfine := func(expr ast.Expr, name string) bool {
			switch e := expr.(type) {
			case *ast.Ident:
				return inConfine && e.Name == name
			case *ast.SelectorExpr:
				x, ok := e.X.(*ast.Ident)
				return ok && confineNames[x.Name] && e.Sel.Name == name
			}
			return false
		}
		called := map[ast.Expr]bool{}
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.FuncDecl:
				called[n.Name] = true // the declaration itself
			case *ast.CallExpr:
				if isConfine(n.Fun, "Label") {
					called[n.Fun] = true
					if len(n.Args) != 3 || !isConfine(n.Args[2], "KernelLabelEnabled") {
						t.Errorf("%s: confine.Label must be called with KernelLabelEnabled", rel)
					}
				}
			case *ast.BasicLit:
				if value, err := strconv.Unquote(n.Value); n.Kind == token.STRING && err == nil && strings.Contains(value, LabelReadOnlyKernel) && rel != filepath.Join("src", "gate", "confine", "label.go") {
					t.Errorf("%s: the read-only label literal appears outside confine/label.go", rel)
				}
			}
			return true
		})
		ast.Inspect(file, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok {
				if isConfine(selector, "Label") && !called[selector] {
					t.Errorf("%s: confine.Label used other than as a direct call", rel)
				}
				return false
			}
			if ident, ok := node.(*ast.Ident); ok && isConfine(ident, "Label") && !called[ident] {
				t.Errorf("%s: Label used other than as a direct call", rel)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 {
		t.Fatalf("scanned only %d files", files)
	}
}

// moduleRoot is the directory holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the package")
		}
		dir = parent
	}
}
