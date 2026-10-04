package confine

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Exceptions own unjailed controls, fixture processes, or the one jailed launcher.
// Each names one function (methods as Type.Method); none is granted by file name,
// and none permits a migrated leg to call a legacy jail helper.
var proofScanExceptions = map[string]string{
	"phase1_reexec_e2e_test.go:L-RED":   "failure-transport fixture, not a protection leg",
	"phase1_reexec_e2e_test.go:L-OTHER": "unrelated-failure transport fixture, not a protection leg",
}

var proofLaunchExceptions = map[string]string{
	"proof_execution_test.go:runJailed":                     "the sole jailed execution primitive",
	"cover_fixture_e2e_test.go:coverNamespace":              "unjailed namespace fixture and child-test proof transport",
	"cover_fixture_e2e_test.go:startCoverFuse":              "unjailed FUSE daemon observer startup",
	"cover_fixture_e2e_test.go:fuseFixture.Stop":            "FUSE observer shutdown and verdict join",
	"cover_fixture_e2e_test.go:coverControlAfterX":          "unjailed positive control with bounded handshake",
	"cover_fixture_e2e_test.go:coverPropagationControl":     "unjailed positive propagation control",
	"user_retune_e2e_test.go:runDisposableIdentity":         "unjailed disposable-uid fixture and strictly judged child proof transport",
	"proof_m2_hostpid_observer_test.go:newM2Recipient":      "unjailed signal-recipient observer startup and cleanup reap",
	"proof_m2_hostpid_observer_test.go:m2Recipient.Seal":    "unjailed signal-recipient observer verdict join",
	"proof_m2_hostpid_observer_test.go:m2Recipient.Stop":    "unjailed signal-recipient observer teardown",
	"proof_m2_hostpid_observer_test.go:m2ProcessOwner.Stop": "unjailed victim process teardown",
	"proof_m2_user_observer_test.go:userRetuneVictim.Stop":  "unjailed USER retune victim teardown",
}

type proofFunction struct {
	file, name, key string
	body            *ast.BlockStmt
}

// parseProofFunctions indexes every test function in directories by its plain
// name (the walk follows calls by name); key is file:Name or file:Type.Method.
func parseProofFunctions(t *testing.T, fs *token.FileSet, directories ...string) map[string][]proofFunction {
	t.Helper()
	functions := map[string][]proofFunction{}
	for _, directory := range directories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(directory, entry.Name())
			file, err := parser.ParseFile(fs, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Body == nil {
					continue
				}
				name := function.Name.Name
				if function.Recv != nil && len(function.Recv.List) == 1 {
					receiver := function.Recv.List[0].Type
					if star, ok := receiver.(*ast.StarExpr); ok {
						receiver = star.X
					}
					if index, ok := receiver.(*ast.IndexExpr); ok {
						receiver = index.X
					}
					if ident, ok := receiver.(*ast.Ident); ok {
						name = ident.Name + "." + name
					}
				}
				item := proofFunction{file: path, name: function.Name.Name, key: entry.Name() + ":" + name, body: function.Body}
				functions[item.name] = append(functions[item.name], item)
			}
		}
	}
	return functions
}

// proofRoots are the functions that open a proof: every one is scanned.
func proofRoots(functions map[string][]proofFunction) map[string]bool {
	roots := map[string]bool{}
	for name, items := range functions {
		for _, function := range items {
			ast.Inspect(function.body, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok {
					if target, ok := call.Fun.(*ast.Ident); ok && (target.Name == "newProof" || target.Name == "RunCase") {
						roots[name] = true
					}
				}
				return true
			})
		}
	}
	return roots
}

// proofLaunchViolations walks every function reachable from roots, in the
// root's own directory, and reports each jailed launch outside the named
// exceptions.
func proofLaunchViolations(fs *token.FileSet, functions map[string][]proofFunction, roots map[string]bool, exceptions map[string]string) []string {
	var violations []string
	visited := map[string]bool{}
	var walk func(string, string)
	walk = func(name, directory string) {
		if visited[directory+":"+name] {
			return
		}
		visited[directory+":"+name] = true
		for _, function := range functions[name] {
			if filepath.Dir(function.file) != directory || exceptions[function.key] != "" {
				continue
			}
			ast.Inspect(function.body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch target := call.Fun.(type) {
				case *ast.Ident:
					if target.Name == "runP12" || target.Name == "coverResult" || target.Name == "runLegacyJailed" || target.Name == "runJailedTimeout" {
						violations = append(violations, fmt.Sprintf("%s: forbidden legacy jail launch %s", fs.Position(call.Pos()), target.Name))
						return false
					}
					walk(target.Name, directory)
				case *ast.SelectorExpr:
					walk(target.Sel.Name, directory)
					if target.Sel.Name == "Command" {
						if qualifier, ok := target.X.(*ast.Ident); !ok || qualifier.Name != "exec" {
							violations = append(violations, fmt.Sprintf("%s: direct jailed Command outside primitive", fs.Position(call.Pos())))
						}
					}
					if target.Sel.Name == "Wait" {
						violations = append(violations, fmt.Sprintf("%s: Wait outside primitive or declared observer", fs.Position(call.Pos())))
					}
				}
				return true
			})
		}
	}
	for root := range roots {
		for _, function := range functions[root] {
			walk(root, filepath.Dir(function.file))
		}
	}
	return violations
}

func TestLegsUseProofAPI(t *testing.T) {
	if len(pendingMigration) == 0 {
		t.Log("all registered legs migrated")
	}
	known := map[string]bool{}
	for _, c := range legCases {
		known[c.Name] = true
		if _, pending := pendingMigration[c.Name]; pending {
			t.Errorf("migrated case still pending: %s", c.Name)
		}
	}
	for name, reason := range pendingMigration {
		if reason == "" {
			t.Errorf("pending case lacks reason: %s", name)
		}
	}
	for _, protection := range completeRegistry() {
		for _, set := range protection.MutationSets {
			for _, leg := range set.Legs {
				if !known[leg.Name] && pendingMigration[leg.Name] == "" {
					t.Errorf("registered leg neither migrated nor pending: %s", leg.Name)
				}
			}
		}
	}
	fs := token.NewFileSet()
	functions := parseProofFunctions(t, fs, ".", "..", "../cmd/sshgate-gate")
	roots := proofRoots(functions)
	for _, items := range functions {
		for _, function := range items {
			ast.Inspect(function.body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Run" && len(call.Args) > 0 {
					if literal, ok := call.Args[0].(*ast.BasicLit); ok && literal.Kind == token.STRING {
						name, _ := strconv.Unquote(literal.Value)
						if strings.HasPrefix(name, "L-") || strings.HasPrefix(name, "U-") || strings.HasPrefix(name, "G-") {
							declared := known[name] || pendingMigration[name] != "" || proofScanExceptions[filepath.Base(function.file)+":"+name] != ""
							for full := range known {
								declared = declared || strings.HasPrefix(full, name+"/")
							}
							if !declared {
								t.Errorf("%s: literal leg neither migrated nor pending: %s", fs.Position(call.Pos()), name)
							}
						}
					}
				}
				return true
			})
		}
	}
	// A declaration removed from its body cannot escape the scan simply by deleting newProof.
	for _, name := range []string{"TestJailMatrixPhase1", "TestPhase1Tables", "TestJailMatrixCovers", "legCoverWalkDenied", "legSelfcheckDeniedSafe"} {
		roots[name] = true
	}
	for _, violation := range proofLaunchViolations(fs, functions, roots, proofLaunchExceptions) {
		t.Error(violation)
	}
	// Every table case must have a named proof root or an explicitly enumerated dynamic family.
	for _, c := range legCases {
		found := false
		for _, items := range functions {
			for _, function := range items {
				if !roots[function.name] {
					continue
				}
				ast.Inspect(function.body, func(node ast.Node) bool {
					literal, ok := node.(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						return true
					}
					value, _ := strconv.Unquote(literal.Value)
					if value == c.Name {
						found = true
					}
					return true
				})
			}
		}
		if !found {
			switch {
			case strings.HasPrefix(c.Name, "L-FAULT-"), strings.HasPrefix(c.Name, "L-CLONE-"), strings.HasPrefix(c.Name, "L-COVER-WALKDENIED/"), strings.HasPrefix(c.Name, "L-SELFCHECK-DENIED-SAFE/"):
				found = true
			}
		}
		if !found {
			t.Errorf("case lacks proof API body: %s", c.Name)
		}
	}
}

// TestProofScanRejectsSecondLauncher runs the scan on fixture sources: a jailed
// launcher in a proof_* file, or beside the primitive in its own file, is
// rejected under the real exceptions; a leg through runJailed is clean.
func TestProofScanRejectsSecondLauncher(t *testing.T) {
	const primitive = "package confine\nfunc runJailed(t *testing.T, p *proof, spec Spec, plan RunPlan) JailedResult {\n\tj, _ := spec.Command(nil, plan.Command)\n\t_ = j.Cmd.Wait()\n\treturn JailedResult{}\n}\n"
	const leg = "package confine\nfunc TestFixtureLeg(t *testing.T) {\n\tp := newProof(t, \"L-FIXTURE\")\n\trunLifecycle(t, p, Spec{}, \"true\")\n\tp.Finish()\n}\n"
	const direct = "func runLifecycle(t *testing.T, p *proof, spec Spec, command string) JailedResult {\n\tjailed, _ := spec.Command(nil, command)\n\t_ = jailed.Cmd.Start()\n\t_ = jailed.Cmd.Wait()\n\treturn JailedResult{}\n}\n"
	const shared = "package confine\nfunc runLifecycle(t *testing.T, p *proof, spec Spec, command string) JailedResult {\n\treturn runJailed(t, p, spec, RunPlan{Mode: Unframed, Command: command})\n}\n"
	for _, tc := range []struct {
		name      string
		files     map[string]string
		violating string
	}{
		{"shared-primitive", map[string]string{"proof_execution_test.go": primitive, "proof_lifecycle_test.go": shared}, ""},
		{"proof-file-launcher", map[string]string{"proof_execution_test.go": primitive, "proof_lifecycle_test.go": "package confine\n" + direct}, "proof_lifecycle_test.go"},
		{"primitive-file-sibling", map[string]string{"proof_execution_test.go": primitive + direct}, "proof_execution_test.go"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			tc.files["hostpid_e2e_test.go"] = leg
			for name, source := range tc.files {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			fs := token.NewFileSet()
			functions := parseProofFunctions(t, fs, directory)
			violations := proofLaunchViolations(fs, functions, proofRoots(functions), proofLaunchExceptions)
			if tc.violating == "" {
				if len(violations) != 0 {
					t.Fatalf("shared primitive rejected: %q", violations)
				}
				return
			}
			want := []string{"direct jailed Command outside primitive", "Wait outside primitive or declared observer"}
			if len(violations) != len(want) {
				t.Fatalf("violations = %q, want %q", violations, want)
			}
			for i, violation := range violations {
				if !strings.Contains(violation, tc.violating+":") || !strings.HasSuffix(violation, want[i]) {
					t.Fatalf("violation %d = %q, want %s in %s", i, violation, want[i], tc.violating)
				}
			}
		})
	}
}
