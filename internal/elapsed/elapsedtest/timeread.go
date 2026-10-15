package elapsedtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbidden lists the direct time reads and timer constructors a holder may
// not use outside its adapter and wake-up sites (SA-1 rule 3.4): each either
// reads the clock or ends something on Go's monotonic timer.
var forbidden = map[string]map[string]bool{
	"time": {
		"Now": true, "Since": true, "Until": true, "After": true, "AfterFunc": true,
		"NewTimer": true, "NewTicker": true, "Tick": true,
	},
	"context": {"WithTimeout": true, "WithDeadline": true},
}

// AssertNoDirectTimeReads parses each file and fails t for every reference
// to a forbidden time or context function, and for any dot import of either
// package. allow names the exceptions: "path" exempts a whole file (the clock
// adapter), and "path:Func" exempts the body of one top-level function or
// method (a named wake-up site). Paths compare after filepath.Clean.
func AssertNoDirectTimeReads(t testing.TB, files []string, allow ...string) {
	t.Helper()
	allowedFiles, allowedFuncs := parseAllow(allow)
	for _, path := range files {
		path = filepath.Clean(path)
		if allowedFiles[path] {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Errorf("AssertNoDirectTimeReads: parse %s: %v", path, err)
			continue
		}
		local := forbiddenImports(t, fset, file)
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && allowedFuncs[path+":"+funcName(fn)] {
				continue
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				if names, ok := local[pkg.Name]; ok && names[sel.Sel.Name] {
					t.Errorf("%s: direct %s.%s; read time through elapsed.Clock", fset.Position(sel.Pos()), pkg.Name, sel.Sel.Name)
				}
				return true
			})
		}
	}
}

// forbiddenImports maps each local name the file gives "time" or "context" to
// that package's forbidden functions, and fails t on a dot import.
func forbiddenImports(t testing.TB, fset *token.FileSet, file *ast.File) map[string]map[string]bool {
	t.Helper()
	local := map[string]map[string]bool{}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || forbidden[path] == nil {
			continue
		}
		name := path
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "." {
			t.Errorf("%s: dot import of %q hides direct time reads", fset.Position(imp.Pos()), path)
			continue
		}
		local[name] = forbidden[path]
	}
	return local
}

func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := fn.Recv.List[0].Type
	if star, ok := recv.(*ast.StarExpr); ok {
		recv = star.X
	}
	if idx, ok := recv.(*ast.IndexExpr); ok {
		recv = idx.X
	}
	if id, ok := recv.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

func parseAllow(allow []string) (files, funcs map[string]bool) {
	files, funcs = map[string]bool{}, map[string]bool{}
	for _, a := range allow {
		if i := strings.LastIndexByte(a, ':'); i >= 0 && !strings.ContainsAny(a[i:], `/\`) {
			funcs[filepath.Clean(a[:i])+a[i:]] = true
		} else {
			files[filepath.Clean(a)] = true
		}
	}
	return files, funcs
}
