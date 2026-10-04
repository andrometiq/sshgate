//go:build linux

package confine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// envReaders are the calls that read the process environment, by import path.
var envReaders = map[string]map[string]bool{
	"os":                    {"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true},
	"syscall":               {"Getenv": true, "Environ": true},
	"golang.org/x/sys/unix": {"Getenv": true, "Environ": true},
}

// envAllowed lists the only permitted env reads as "func:pkg.Name": jailEnv
// copies os.Environ into the env PASSED to /bin/sh, which is not a policy input.
var envAllowed = map[string]bool{"jailEnv:os.Environ": true}

// envViolations returns every non-allow-listed env read in f as "pkg.Name",
// resolving import aliases.
func envViolations(f *ast.File) []string {
	local := map[string]string{} // local import name -> import path
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if envReaders[path] == nil {
			continue
		}
		n := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			n = imp.Name.Name
		}
		local[n] = path
	}
	var out []string
	for _, decl := range f.Decls {
		fn := "<top-level>"
		if fd, ok := decl.(*ast.FuncDecl); ok {
			fn = fd.Name.Name
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || !envReaders[local[id.Name]][sel.Sel.Name] {
				return true
			}
			path := local[id.Name]
			call := path[strings.LastIndex(path, "/")+1:] + "." + sel.Sel.Name
			if !envAllowed[fn+":"+call] {
				out = append(out, call)
			}
			return true
		})
	}
	return out
}

// TestNoEnvDrivenPolicy is a reviewer-checkable guard: no non-test source in
// this package may read the environment (except the one allow-listed site), because the confinement Spec (rung, ABI cap, inject) must
// come only from the parent-written sentinel argv and host probes — never from an
// environment variable an SSH client could set.
func TestNoEnvDrivenPolicy(t *testing.T) {
	pkgs, err := parser.ParseDir(token.NewFileSet(), ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	for _, pkg := range pkgs {
		for name, f := range pkg.Files {
			files++
			for _, v := range envViolations(f) {
				t.Errorf("%s reads the environment via %s — confinement policy must not be env-driven", name, v)
			}
		}
	}
	if files == 0 {
		t.Fatal("guard scanned no source files")
	}
}

// TestNoEnvGuardSelfTest proves the guard flags each env reader, through an
// aliased import too, and honours only the exact allow-listed site.
func TestNoEnvGuardSelfTest(t *testing.T) {
	src := `package x
import (
	"os"
	sys "syscall"
	"golang.org/x/sys/unix"
)
func a() { _ = os.Getenv("A"); _, _ = os.LookupEnv("B"); _ = os.ExpandEnv("$C") }
func b() { _, _ = sys.Getenv("D"); _ = unix.Environ(); _ = os.Environ() }
func jailEnv() { _ = os.Environ() }
`
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := "os.Getenv os.LookupEnv os.ExpandEnv syscall.Getenv unix.Environ os.Environ"
	if got := strings.Join(envViolations(f), " "); got != want {
		t.Errorf("guard flagged %q, want %q", got, want)
	}
}
