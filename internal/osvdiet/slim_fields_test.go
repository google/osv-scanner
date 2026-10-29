package osvdiet_test

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

const (
	osvdietPkgPath   = "github.com/google/osv-scanner/v2/internal/osvdiet"
	osvschemaPkgPath = "github.com/ossf/osv-schema/bindings/go/osvschema"

	// tests are run relative to their package's directory, so "../.." takes us to the repository root
	repoRoot = "../.."
)

// fieldRef identifies a field on one of the osvschema types,
// e.g. {Type: "Affected", Field: "EcosystemSpecific"}
type fieldRef struct {
	Type  string
	Field string
}

func (f fieldRef) String() string {
	return f.Type + "." + f.Field
}

// osvschemaTypeName returns the name of the osvschema type that t is (or
// points to), and false if t is not an osvschema type
func osvschemaTypeName(t types.Type) (string, bool) {
	t = types.Unalias(t)

	// if we've got a pointer, use its element type going forward
	// (mirroring Go's automatic dereferencing of p.f to (*p).f)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}

	named, ok := t.(*types.Named)

	if !ok || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != osvschemaPkgPath {
		return "", false
	}

	return named.Obj().Name(), true
}

// loadModule type-checks every package in the module, excluding tests
func loadModule(t *testing.T) []*packages.Package {
	t.Helper()

	pkgs, err := packages.Load(&packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		Dir:  repoRoot,
	}, "./...")

	if err != nil {
		t.Fatalf("failed to load packages: %v", err)
	}

	if packages.PrintErrors(pkgs) > 0 {
		t.Fatalf("errors while loading packages")
	}

	return pkgs
}

func findDietPkgAndSlimFunc(t *testing.T, pkgs []*packages.Package) (*packages.Package, *ast.FuncDecl) {
	t.Helper()

	for _, pkg := range pkgs {
		if pkg.PkgPath != osvdietPkgPath {
			continue
		}

		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)

				if !ok || fn.Name.Name != "slim" || fn.Recv != nil {
					continue
				}

				return pkg, fn
			}
		}
	}

	t.Fatalf("failed to find osvdiet.slim")

	return nil, nil
}

// collectClearedFields returns the osvschema fields that are assigned to
// within the slim function, which we treat as the fields being removed
func collectClearedFields(t *testing.T, pkgs []*packages.Package) map[fieldRef]bool {
	t.Helper()

	dietPkg, slimFunc := findDietPkgAndSlimFunc(t, pkgs)

	cleared := map[fieldRef]bool{}

	ast.Inspect(slimFunc.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)

		if !ok {
			return true
		}

		for _, lhs := range assign.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)

			if !ok {
				continue
			}

			selection, ok := dietPkg.TypesInfo.Selections[sel]

			if !ok || selection.Kind() != types.FieldVal {
				continue
			}

			// track the assignment if it's to a field whose type belongs to the osvschema package
			if typeName, ok := osvschemaTypeName(selection.Recv()); ok {
				cleared[fieldRef{Type: typeName, Field: sel.Sel.Name}] = true
			}
		}

		return true
	})

	if len(cleared) == 0 {
		t.Fatalf("did not find any fields being cleared in osvdiet.slim")
	}

	return cleared
}

// collectUsedFields returns every osvschema field that is read outside the
// osvdiet package, along with the positions it is read at
func collectUsedFields(t *testing.T, pkgs []*packages.Package) map[fieldRef][]token.Position {
	t.Helper()

	used := map[fieldRef][]token.Position{}

	for _, pkg := range pkgs {
		if pkg.PkgPath == osvdietPkgPath {
			continue
		}

		for sel, selection := range pkg.TypesInfo.Selections {
			typeName, ok := osvschemaTypeName(selection.Recv())

			// we only care about selections on types from osvschema
			if !ok {
				continue
			}

			name := selection.Obj().Name()

			// map protobuf getters back to the field they return
			if selection.Kind() != types.FieldVal {
				name = strings.TrimPrefix(name, "Get")
			}

			ref := fieldRef{Type: typeName, Field: name}

			// t.Logf("%s.%s is a field value", typeName, name)

			used[ref] = append(used[ref], pkg.Fset.Position(sel.Sel.Pos()))
		}
	}

	return used
}

// Test_slim_OnlyRemovesUnusedFields ensures that slimming does not remove
// fields that are used elsewhere in the codebase through static analysis
func Test_slim_OnlyRemovesUnusedFields(t *testing.T) {
	t.Parallel()

	pkgs := loadModule(t)

	cleared := collectClearedFields(t, pkgs)
	used := collectUsedFields(t, pkgs)

	for ref := range cleared {
		t.Logf("slim clears %s", ref)
	}

	root, err := filepath.Abs(repoRoot)

	if err != nil {
		t.Fatalf("failed to resolve repository root: %v", err)
	}

	for ref := range cleared {
		positions, ok := used[ref]

		if !ok {
			continue
		}

		lines := make([]string, 0, len(positions))
		for _, pos := range positions {
			// show paths relative to the repository root for consistency
			if rel, err := filepath.Rel(root, pos.Filename); err == nil {
				pos.Filename = rel
			}

			lines = append(lines, "  "+pos.String())
		}
		slices.Sort(lines)

		t.Errorf("slim clears %s, but it is used in:\n%s", ref, strings.Join(lines, "\n"))
	}
}
