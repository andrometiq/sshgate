package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func checkHostedDiagnosticClosure(t *testing.T) {
	t.Helper()
	args := []string{"list", "-deps", "-json"}
	overlay := struct{ Replace map[string]string }{}
	// Go overlays affect compilation, not runtime source reads.
	if path := os.Getenv("SSHGATE_TEST_SOURCE_OVERLAY"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &overlay); err != nil {
			t.Fatal(err)
		}
		args = append(args, "-overlay", path)
	}
	args = append(args, ".")
	output, err := exec.Command("go", args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	transports := 0
	for {
		var pkg struct {
			ImportPath, Dir   string
			GoFiles, CgoFiles []string
		}
		err := decoder.Decode(&pkg)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !hostedDiagnosticPackage(pkg.ImportPath) {
			continue
		}
		for _, name := range append(pkg.GoFiles, pkg.CgoFiles...) {
			path := filepath.Join(pkg.Dir, name)
			if replacement, ok := overlay.Replace[path]; ok {
				path = replacement
			}
			fs := token.NewFileSet()
			file, err := parser.ParseFile(fs, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			allowed := pkg.ImportPath == "github.com/karthikeyan5/sshgate/src/signer-server/cmd/sshgate-signer-server" && name == "main.go"
			count, violations := diagnosticViolations(file, allowed)
			transports += count
			for _, pos := range violations {
				t.Errorf("raw stderr access on signer-server dependency path: %s", fs.Position(pos))
			}
		}
	}
	if transports != 1 {
		t.Fatalf("process transport constructions = %d, want 1", transports)
	}
}

// Custody control diagnostics (custody.go) and local handlers (daemon.go,
// daemon_approvals.go, socket.go) are unreachable from signer-server, per gap
// ruling 6. A dependency source scan cannot distinguish their unreachable paths
// from shared signing code, so inspect only the hosted front-end packages.
func hostedDiagnosticPackage(path string) bool {
	const root = "github.com/karthikeyan5/sshgate/"
	return path == root+"src/signer-server" || path == root+"pkg/signerkit/hosted" || strings.HasPrefix(path, root+"pkg/signerkit/hosted/") || strings.HasPrefix(path, root+"src/signer-server/")
}

// Inspect direct stderr access, including aliases and literal fd-2 writes.
func diagnosticViolations(file *ast.File, allowTransport bool) (int, []token.Pos) {
	imports := map[string]string{}
	for _, imp := range file.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		name := filepath.Base(path)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		imports[name] = path
	}
	allowed := map[ast.Node]bool{}
	if allowTransport {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			fun, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || fun.Sel.Name != "NewProcessAuditSink" {
				return true
			}
			pkg, ok := fun.X.(*ast.Ident)
			if ok && imports[pkg.Name] == "github.com/karthikeyan5/sshgate/pkg/signerkit/hosted" {
				if arg, ok := call.Args[0].(*ast.SelectorExpr); ok && arg.Sel.Name == "Stderr" {
					if pkg, ok := arg.X.(*ast.Ident); ok && imports[pkg.Name] == "os" {
						allowed[arg] = true
					}
				}
			}
			return true
		})
	}
	var violations []token.Pos
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := node.X.(*ast.Ident); ok && node.Sel.Name == "Stderr" && !allowed[node] {
				switch imports[pkg.Name] {
				case "os", "syscall", "golang.org/x/sys/unix":
					violations = append(violations, node.Pos())
				}
			}
		case *ast.CallExpr:
			if fun, ok := node.Fun.(*ast.Ident); ok && (fun.Name == "print" || fun.Name == "println") {
				violations = append(violations, node.Pos())
			}
			if fun, ok := node.Fun.(*ast.SelectorExpr); ok && len(node.Args) > 0 {
				if pkg, ok := fun.X.(*ast.Ident); ok && (imports[pkg.Name] == "os" || imports[pkg.Name] == "syscall" || imports[pkg.Name] == "golang.org/x/sys/unix") {
					if path, ok := node.Args[0].(*ast.BasicLit); ok && path.Kind == token.STRING && (fun.Sel.Name == "Open" || fun.Sel.Name == "OpenFile" || fun.Sel.Name == "Create" || fun.Sel.Name == "WriteFile") {
						value, _ := strconv.Unquote(path.Value)
						if value == "/dev/stderr" || value == "/proc/self/fd/2" {
							violations = append(violations, node.Pos())
						}
					}
					if fd, ok := node.Args[0].(*ast.BasicLit); ok && fd.Kind == token.INT && (fun.Sel.Name == "NewFile" || fun.Sel.Name == "Write" || fun.Sel.Name == "Writev") {
						value, _ := strconv.ParseInt(fd.Value, 0, 64)
						if value == 2 {
							violations = append(violations, node.Pos())
						}
					}
				}
			}
		}
		return true
	})
	return len(allowed), violations
}

func TestDiagnosticClosureRejectsRawWriters(t *testing.T) {
	for _, body := range []string{`fmt.Fprint(o.Stderr,"bad")`, `o.Stderr.Write(nil)`, `syscall.Write(2,nil)`, `o.NewFile(2,"stderr")`, `println("bad")`, `o.OpenFile("/dev/stderr",1,0)`, `o.WriteFile("/dev/stderr",nil,0600)`} {
		source := `package fixture; import (o "os"; "fmt"; "syscall"); func f(){` + body + `}`
		file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, bad := diagnosticViolations(file, false); len(bad) == 0 {
			t.Errorf("raw writer accepted: %s", body)
		}
	}
}

func TestHostedDiagnosticPackageScope(t *testing.T) {
	const root = "github.com/karthikeyan5/sshgate/"
	for path, want := range map[string]bool{
		"src/signer-server":                           true,
		"src/signer-server/cmd/sshgate-signer-server": true,
		"pkg/signerkit/hosted":                        true,
		"pkg/signerkit/hosted/refapp":                 true,
		"pkg/signerkit":                               false,
		"pkg/signerkit/lifecycle":                     false,
		"pkg/signerkit/hosted-other":                  false,
		"src/signer-server-other":                     false,
	} {
		if got := hostedDiagnosticPackage(root + path); got != want {
			t.Errorf("scope %s = %v, want %v", path, got, want)
		}
	}
}
