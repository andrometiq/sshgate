package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLane2TrustDefaults(t *testing.T) {
	expected := map[string]string{
		"lane2BinDirs":         `[]string{"/usr/bin", "/bin", "/usr/sbin"}`,
		"lane2TrustedUIDs":     `[]uint32{0}`,
		"lane2SystemEndpoints": `lane2Endpoints{docker: "/run/docker.sock", bus: "/run/dbus/system_bus_socket", private: "/run/systemd/private"}`,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	isSeam := func(name string) bool {
		return expected[name] != "" || (name == "lane2AfterAdmitHook" || name == "readAdmittedHook" || name == "envelopeParsedHook")
	}
	compact := func(s string) string {
		expression, err := parser.ParseExpr(s)
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := printer.Fprint(&output, token.NewFileSet(), expression); err != nil {
			t.Fatal(err)
		}
		return output.String()
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, path, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			bad := false
			switch n := node.(type) {
			case *ast.ValueSpec:
				for i, name := range n.Names {
					if !isSeam(name.Name) {
						continue
					}
					seen[name.Name] = true
					if name.Name == "lane2AfterAdmitHook" || name.Name == "readAdmittedHook" || name.Name == "envelopeParsedHook" {
						if len(n.Values) != 0 {
							bad = true
						}
						continue
					}
					if len(n.Values) != len(n.Names) {
						bad = true
						continue
					}
					value := n.Values[i]
					source := string(data[set.Position(value.Pos()).Offset:set.Position(value.End()).Offset])
					if compact(source) != compact(expected[name.Name]) {
						t.Errorf("%s: changed initializer for %s: %s", path, name.Name, source)
					}
				}
			}
			bad = bad || lane2TrustMutation(node)
			if bad {
				t.Errorf("%s: production mutation of trust seam", set.Position(node.Pos()))
			}
			return true
		})
	}
	for _, name := range []string{"readAdmittedHook", "envelopeParsedHook", "lane2AfterAdmitHook", "lane2BinDirs", "lane2TrustedUIDs", "lane2SystemEndpoints"} {
		if !seen[name] {
			t.Errorf("missing declaration %s", name)
		}
	}
}

func lane2TrustTarget(node ast.Node) bool {
	switch n := node.(type) {
	case *ast.Ident:
		return n.Name == "lane2TrustedUIDs" || n.Name == "lane2SystemEndpoints" || n.Name == "lane2BinDirs" || n.Name == "lane2AfterAdmitHook" || n.Name == "readAdmittedHook" || n.Name == "envelopeParsedHook"
	case *ast.IndexExpr:
		return lane2TrustTarget(n.X)
	case *ast.SliceExpr:
		return lane2TrustTarget(n.X)
	case *ast.SelectorExpr:
		return lane2TrustTarget(n.X)
	case *ast.StarExpr:
		return lane2TrustTarget(n.X)
	case *ast.ParenExpr:
		return lane2TrustTarget(n.X)
	}
	return false
}

func lane2TrustMutation(node ast.Node) bool {
	switch n := node.(type) {
	case *ast.AssignStmt:
		for _, lhs := range n.Lhs {
			if lane2TrustTarget(lhs) {
				return true
			}
		}
	case *ast.RangeStmt:
		return lane2TrustTarget(n.Key) || lane2TrustTarget(n.Value)
	case *ast.IncDecStmt:
		return lane2TrustTarget(n.X)
	case *ast.UnaryExpr:
		return n.Op == token.AND && lane2TrustTarget(n.X)
	case *ast.CallExpr:
		if name, ok := n.Fun.(*ast.Ident); ok && len(n.Args) > 0 {
			switch name.Name {
			case "append", "copy", "clear", "delete":
				return lane2TrustTarget(n.Args[0])
			}
		}
	}
	return false
}

func TestLane2TrustGuardMutations(t *testing.T) {
	for _, source := range []string{
		`lane2TrustedUIDs = []uint32{1000}`, `lane2TrustedUIDs[0] = 1000`,
		`lane2SystemEndpoints["docker"] = []string{"/tmp/socket"}`, `lane2BinDirs[0] = "/tmp"`,
		`readAdmittedHook = f`, `envelopeParsedHook = f`, `x := &envelopeParsedHook`, `lane2AfterAdmitHook = f`, `lane2TrustedUIDs[0]++`, `lane2TrustedUIDs[0]--`,
		`append(lane2TrustedUIDs, 1000)`, `copy(lane2TrustedUIDs, other)`, `clear(lane2SystemEndpoints)`,
		`delete(lane2SystemEndpoints,"docker")`, `x := &lane2TrustedUIDs[0]`,
		`for _, lane2TrustedUIDs[0] = range []uint32{1000} {}`, `for lane2TrustedUIDs[0] = range other {}`,
		`lane2AfterAdmitHook.field = f`, `lane2SystemEndpoints.docker = "/tmp/socket"`, `x := &lane2SystemEndpoints.bus`,
	} {
		t.Run(source, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "snippet.go", "package main; func f(){"+source+"}", 0)
			if err != nil {
				t.Fatal(err)
			}
			caught := false
			ast.Inspect(file, func(node ast.Node) bool { caught = caught || lane2TrustMutation(node); return true })
			if !caught {
				t.Fatal("production seam mutation escaped guard")
			}
		})
	}
}
