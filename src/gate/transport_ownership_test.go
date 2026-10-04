package gate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Direct client writes belong only to the legacy executor and admin/probe replies.
func TestReadPathClientSinkOwnership(t *testing.T) {
	for _, path := range []string{"executor.go", "confined_execution.go", "cmd/sshgate-gate/main.go"} {
		files := token.NewFileSet()
		file, err := parser.ParseFile(files, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if path == "executor.go" && function.Name.Name == "runRedacted" {
				continue
			} // nil-Confine compatibility path
			if path == "cmd/sshgate-gate/main.go" && function.Name.Name == "doRevoke" {
				continue
			} // protocol/admin stdout replies
			ast.Inspect(function, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if isClientDescriptor(selector.X) {
					t.Errorf("direct client write at %s", files.Position(call.Pos()))
				}
				name, ok := selector.X.(*ast.Ident)
				if ok && name.Name == "fmt" {
					switch selector.Sel.Name {
					case "Print", "Printf", "Println":
						if path == "cmd/sshgate-gate/main.go" && function.Name.Name == "run" && selector.Sel.Name == "Println" && len(call.Args) == 1 {
							if literal, ok := call.Args[0].(*ast.BasicLit); ok && literal.Value == `"SSHGATE_OK"` {
								return true
							}
							if probe, ok := call.Args[0].(*ast.CallExpr); ok && len(probe.Args) == 0 {
								if name, ok := probe.Fun.(*ast.Ident); ok && name.Name == "runningGateVersion" {
									return true
								}
							}
						}
						t.Errorf("implicit stdout at %s", files.Position(call.Pos()))
					case "Fprint", "Fprintf", "Fprintln":
						if len(call.Args) > 0 && isClientDescriptor(call.Args[0]) {
							t.Errorf("direct client write at %s", files.Position(call.Pos()))
						}
					}
				}
				return true
			})
		}
	}
}
func isClientDescriptor(expression ast.Expr) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	name, ok := selector.X.(*ast.Ident)
	return ok && name.Name == "os" && (selector.Sel.Name == "Stdout" || selector.Sel.Name == "Stderr")
}
