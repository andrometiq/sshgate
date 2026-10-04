package confine

import (
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
// None permits a migrated leg to call a legacy jail helper.
var proofScanExceptions = map[string]string{
	"phase1_reexec_e2e_test.go:L-RED":   "failure-transport fixture, not a protection leg",
	"phase1_reexec_e2e_test.go:L-OTHER": "unrelated-failure transport fixture, not a protection leg",
}

var proofLaunchExceptions = map[string]string{
	"proof_execution_test.go:runJailed":                 "the sole jailed execution primitive",
	"cover_fixture_e2e_test.go:coverNamespace":          "unjailed namespace fixture and child-test proof transport",
	"cover_fixture_e2e_test.go:startCoverFuse":          "unjailed FUSE daemon observer startup",
	"cover_fixture_e2e_test.go:Stop":                    "FUSE observer shutdown and verdict join",
	"cover_fixture_e2e_test.go:coverControlAfterX":      "unjailed positive control with bounded handshake",
	"cover_fixture_e2e_test.go:coverPropagationControl": "unjailed positive propagation control",
	"user_retune_e2e_test.go:runDisposableIdentity":     "unjailed disposable-uid fixture and strictly judged child proof transport",
}

type proofFunction struct {
	file, name string
	body       *ast.BlockStmt
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
	functions := map[string][]proofFunction{}
	roots := map[string]bool{}
	fs := token.NewFileSet()
	for _, directory := range []string{".", "..", "../cmd/sshgate-gate"} {
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
				item := proofFunction{file: path, name: function.Name.Name, body: function.Body}
				functions[item.name] = append(functions[item.name], item)
				if strings.HasPrefix(entry.Name(), "proof_") {
					continue
				}
				ast.Inspect(function.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					if name, ok := call.Fun.(*ast.Ident); ok && (name.Name == "newProof" || name.Name == "RunCase") {
						roots[item.name] = true
					}

					if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Run" && len(call.Args) > 0 {
						if literal, ok := call.Args[0].(*ast.BasicLit); ok && literal.Kind == token.STRING {
							name, _ := strconv.Unquote(literal.Value)
							if strings.HasPrefix(name, "L-") || strings.HasPrefix(name, "U-") || strings.HasPrefix(name, "G-") {
								declared := known[name] || pendingMigration[name] != "" || proofScanExceptions[filepath.Base(path)+":"+name] != ""
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
	}
	// A declaration removed from its body cannot escape the scan simply by deleting newProof.
	for _, name := range []string{"TestJailMatrixPhase1", "TestPhase1Tables", "TestJailMatrixCovers", "legCoverWalkDenied", "legSelfcheckDeniedSafe"} {
		roots[name] = true
	}
	visited := map[string]bool{}
	var walk func(string, string)
	walk = func(name, directory string) {
		if visited[directory+":"+name] {
			return
		}
		visited[directory+":"+name] = true
		for _, function := range functions[name] {
			if filepath.Dir(function.file) != directory {
				continue
			}
			key := filepath.Base(function.file) + ":" + function.name
			if proofLaunchExceptions[key] != "" {
				continue
			}
			if strings.HasPrefix(filepath.Base(function.file), "proof_") {
				continue
			} // proof plumbing is tested directly
			ast.Inspect(function.body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch target := call.Fun.(type) {
				case *ast.Ident:
					if target.Name == "runP12" || target.Name == "coverResult" || target.Name == "runLegacyJailed" || target.Name == "runJailedTimeout" {
						t.Errorf("%s: forbidden legacy jail launch %s", fs.Position(call.Pos()), target.Name)
						return false
					}
					walk(target.Name, directory)
				case *ast.SelectorExpr:
					walk(target.Sel.Name, directory)
					if target.Sel.Name == "Command" {
						if qualifier, ok := target.X.(*ast.Ident); !ok || qualifier.Name != "exec" {
							t.Errorf("%s: direct jailed Command outside primitive", fs.Position(call.Pos()))
						}
					}
					if target.Sel.Name == "Wait" {
						t.Errorf("%s: Wait outside primitive or declared observer", fs.Position(call.Pos()))
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
