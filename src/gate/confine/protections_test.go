package confine

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

type prot = harness.Protection

var registry = append(append(p12Registry(), p15Registry()...), hostPIDRegistry()...)

func p12Leg(name, marker string) harness.Leg {
	leg := harness.Leg{Name: name, Package: "./src/gate/confine", Names: map[string]string{"native": "TestJailMatrixP12/native/" + name, "abi1": "TestJailMatrixP12/abi1/" + name}}
	if marker != "" {
		leg.Markers = []string{marker}
	}
	return leg
}

func p12Registry() []prot {
	var protections []prot
	add := func(id, site string, legs ...harness.Leg) {
		protections = append(protections, prot{ID: id, Site: site, Class: "single", DirectLeg: legs[0].Name, MutationSets: []harness.MutationSet{{IDs: []string{id}, Legs: legs}}})
	}
	add("P-SPEC", "decodeSpec / Spec.validate", p12Leg("L-SPEC-REJECT", "MUTATION-EFFECT reached-exec"))
	nsLegs := []harness.Leg{}
	for _, name := range []string{"L-NSVERIFY-user", "L-NSVERIFY-mnt", "L-NSVERIFY-pid", "L-NSVERIFY-ipc", "L-FAULT-nsverify"} {
		nsLegs = append(nsLegs, p12Leg(name, "MUTATION-EFFECT reached-exec"))
	}
	nsLegs = append(nsLegs, p12Leg("L-HOSTMOUNTS-UNCHANGED", "MUTATION-ABORT private"))
	executor := harness.Leg{Markers: []string{"MUTATION-ABORT private"}, Name: "L-NSVERIFY", Package: "./src/gate", Names: map[string]string{"native": "TestExecWithRedactionConfineNSVerify/native/L-NSVERIFY", "abi1": "TestExecWithRedactionConfineNSVerify/abi1/L-NSVERIFY"}}
	nsLegs = append(nsLegs, executor)
	add("P-NSVERIFY", "RunWorker before setupMounts", nsLegs...)
	for _, stage := range []string{"spec", "cmdread", "mounts", "nnp", "caps", "rlimits", "landlock", "seccomp", "fds", "cwd", "session", "exec"} {
		legs := []harness.Leg{p12Leg("L-FAULT-"+stage, "MUTATION-EFFECT reached-exec")}
		if stage == "caps" {
			root := p12Leg("L-ROOT-STATE", "")
			root.Root = true
			legs = append(legs, root)
		}
		if stage == "rlimits" {
			root := p12Leg("L-ROOT-NPROC", "")
			root.Root = true
			legs = append(legs, root)
		}
		if stage == "mounts" {
			root := p12Leg("L-ROOT-PROC", "")
			root.Root = true
			root.CIOnly = true
			legs = append(legs, root)
		}
		add("P-FAULT-"+stage, "RunWorker "+stage+" error check", legs...)
	}
	add("P-SC-TSYNC", "installSeccomp positive return check", p12Leg("L-FAULT-tsync", "MUTATION-EFFECT reached-exec"))
	add("P-SC-META", "metadata syscalls and generic fileattr ioctls", p12Leg("L-SCRATCH-META", "MUTATION-EFFECT metadata"), p12Leg("L-FILEATTR-ERRNO", "MUTATION-EFFECT fileattr-errno"), p15Leg("L-META-ERRNO", "MUTATION-EFFECT errno"))
	protections[len(protections)-1].Class = "multi"
	mqErrno := p12Leg("L-MQUEUE-ERRNO", "MUTATION-EFFECT mq-errno")
	mqCover := p12Leg("L-MQUEUE", "")
	for _, leg := range []*harness.Leg{&mqErrno, &mqCover} {
		for abi, name := range leg.Names {
			leg.Names[abi] = strings.Replace(name, "TestJailMatrixP12", "TestJailMatrixP14", 1)
		}
	}
	add("P-MQ", "POSIX mqueue syscall denies", mqErrno, mqCover)
	protections[len(protections)-1].Class = "multi"
	add("P-LL-REQUIRED", "applyLandlock ABI floor", p12Leg("L-LL-REQUIRED", "MUTATION-EFFECT reached-exec"))
	return protections
}

// Filled alongside the literal non-allow seccomp lists when those rows are hooked.
var mutationSeccompRows = strings.Fields(pinnedDeny + " " + pinnedEnosys + " " + pinnedFilters)

func TestMutationRegistryJSON(t *testing.T) {
	if err := harness.Validate(registry); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("JAILMUT-REGISTRY %s\n", data)
}

func TestRegistryMatchesHooks(t *testing.T) {
	hooks := map[string]bool{}
	hasGeneratedHook := false
	err := filepath.WalkDir("..", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		tree, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		aliases := map[string]bool{}
		for _, imp := range tree.Imports {
			value, _ := strconv.Unquote(imp.Path.Value)
			if strings.HasSuffix(value, "/confine/jailmut") {
				name := "jailmut"
				if imp.Name != nil {
					name = imp.Name.Name
				}
				if name == "." || name == "_" {
					t.Errorf("%s: mutation imports must be named", path)
				}
				aliases[name] = true
			}
		}
		ast.Inspect(tree, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "On" {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok || !aliases[ident.Name] {
				return true
			}
			if len(call.Args) != 1 {
				t.Errorf("%s: malformed mutation hook", path)
				return true
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok {
				expression, ok := call.Args[0].(*ast.BinaryExpr)
				if !ok {
					t.Errorf("%s: nonliteral mutation hook", path)
					return true
				}
				hasGeneratedHook = true
				prefix, ok := expression.X.(*ast.BasicLit)
				row, rowOK := expression.Y.(*ast.SelectorExpr)
				rowName := ""
				if rowOK {
					if ident, ok := row.X.(*ast.Ident); ok {
						rowName = ident.Name
					}
				}
				if !ok || prefix.Value != `"P-SC-"` || expression.Op != token.ADD || !rowOK || rowName != "row" || row.Sel.Name != "name" || len(mutationSeccompRows) == 0 {
					t.Errorf("%s: unknown generated mutation hook", path)
				}
				return true
			}
			id, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Error(err)
			} else {
				hooks[id] = true
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(mutationSeccompRows) > 0 && !hasGeneratedHook {
		t.Fatal("seccomp mutation rows without generated hook")
	}
	for _, row := range mutationSeccompRows {
		hooks["P-SC-"+row] = true
	}
	var got, want []string
	for id := range hooks {
		got = append(got, id)
	}
	for _, p := range registry {
		want = append(want, p.ID)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hooks %v != registry %v", got, want)
	}
	if err := harness.Validate(registry); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryLegsExist(t *testing.T) {
	for _, p := range registry {
		for _, set := range p.MutationSets {
			for _, leg := range set.Legs {
				directory := leg.Package
				const module = "github.com/karthikeyan5/sshgate/"
				directory = strings.TrimPrefix(directory, module)
				if !strings.HasPrefix(directory, "./") && !strings.HasPrefix(directory, "src/") {
					t.Fatalf("%s: package must be repository-relative: %s", leg.Name, leg.Package)
				}
				directory = filepath.Join("../../..", directory)
				files, err := filepath.Glob(filepath.Join(directory, "*_test.go"))
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, path := range files {
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.HasPrefix(leg.Name, "U-") && !isJailE2E(data) {
						continue
					}
					tree, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
					if err != nil {
						t.Fatal(err)
					}
					ast.Inspect(tree, func(node ast.Node) bool {
						call, ok := node.(*ast.CallExpr)
						if !ok || len(call.Args) == 0 {
							return true
						}
						selector, ok := call.Fun.(*ast.SelectorExpr)
						if !ok || selector.Sel.Name != "Run" {
							return true
						}
						literal, ok := call.Args[0].(*ast.BasicLit)
						if !ok {
							return true
						}
						name, err := strconv.Unquote(literal.Value)
						if err == nil && name == leg.Name {
							found = true
						}
						return true
					})
				}
				if !found {
					t.Errorf("%s: missing literal subtest %s in %s e2e files", p.ID, leg.Name, leg.Package)
				}
			}
		}
	}
}

func isJailE2E(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		if constraint.IsGoBuild(line) {
			expression, err := constraint.Parse(line)
			if err != nil {
				return false
			}
			// A tagged e2e file must require jail_e2e, whatever the host constraint.
			return !expression.Eval(func(tag string) bool { return tag != "jail_e2e" }) && expression.Eval(func(string) bool { return true })
		}
		if strings.HasPrefix(line, "package ") {
			break
		}
	}
	return false
}
