package osvdiet_test

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"maps"
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

// clearing describes how slim modifies a field
type clearing struct {
	// partial is true when the field is a structpb.Struct which has been
	// reduced to only the keys in kept (via the "only" helper), rather than
	// being cleared entirely
	partial bool
	kept    map[string]bool
}

// parseOnlyCall returns the keys being kept if expr is a call to osvdiet.only
// with a literal list of strings, and false otherwise
func parseOnlyCall(t *testing.T, info *types.Info, expr ast.Expr) (map[string]bool, bool) {
	t.Helper()

	call, ok := ast.Unparen(expr).(*ast.CallExpr)

	if !ok || len(call.Args) != 2 {
		return nil, false
	}

	ident, ok := ast.Unparen(call.Fun).(*ast.Ident)

	if !ok {
		return nil, false
	}

	fn, ok := info.Uses[ident].(*types.Func)

	if !ok || fn.Name() != "only" || fn.Pkg() == nil || fn.Pkg().Path() != osvdietPkgPath {
		return nil, false
	}

	lit, ok := ast.Unparen(call.Args[1]).(*ast.CompositeLit)

	if !ok {
		t.Fatalf("osvdiet.only must be called with a literal list of keys to keep")
	}

	kept := map[string]bool{}

	for _, elt := range lit.Elts {
		tv, ok := info.Types[elt]

		if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
			t.Fatalf("osvdiet.only must be called with a literal list of keys to keep")
		}

		kept[constant.StringVal(tv.Value)] = true
	}

	return kept, true
}

// collectClearedFields returns the osvschema fields that are assigned to
// within the slim function, which we treat as the fields being removed
func collectClearedFields(t *testing.T, pkgs []*packages.Package) map[fieldRef]clearing {
	t.Helper()

	dietPkg, slimFunc := findDietPkgAndSlimFunc(t, pkgs)

	cleared := map[fieldRef]clearing{}

	ast.Inspect(slimFunc.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)

		if !ok {
			return true
		}

		for i, lhs := range assign.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)

			if !ok {
				continue
			}

			selection, ok := dietPkg.TypesInfo.Selections[sel]

			if !ok || selection.Kind() != types.FieldVal {
				continue
			}

			// track the assignment if it's to a field whose type belongs to the osvschema package
			typeName, ok := osvschemaTypeName(selection.Recv())

			if !ok {
				continue
			}

			ref := fieldRef{Type: typeName, Field: sel.Sel.Name}

			// slim should only ever be setting fields to nil, or to a subset of their keys
			switch rhs := assign.Rhs[i]; {
			case dietPkg.TypesInfo.Types[rhs].IsNil():
				cleared[ref] = clearing{}
			default:
				kept, ok := parseOnlyCall(t, dietPkg.TypesInfo, rhs)

				if !ok {
					t.Fatalf("slim assigns %s in a way this test does not understand (expected nil or a call to only)", ref)
				}

				cleared[ref] = clearing{partial: true, kept: kept}
			}
		}

		return true
	})

	if len(cleared) == 0 {
		t.Fatalf("did not find any fields being cleared in osvdiet.slim")
	}

	return cleared
}

// valueKind describes what a tracked expression evaluates to
type valueKind int

const (
	notTracked valueKind = iota
	// the *structpb.Struct stored in a partially cleared field
	trackedStruct
	// the map[string]*structpb.Value returned by GetFields on a trackedStruct
	trackedFields
)

// structKeyUsage describes how the keys of partially cleared fields are used
type structKeyUsage struct {
	// keys that are read via a constant string, along with where
	reads map[fieldRef]map[string][]token.Position
	// uses that cannot be resolved to specific keys, such as calling AsMap
	// or passing the struct to another function, which could read any key
	opaque map[fieldRef][]token.Position
}

// keyUsageCollector follows values from partially cleared fields through a
// package's code, to determine which of their keys are read.
//
// This only handles simple local data flow: values are followed through
// assignments to local variables and calls to GetFields, while anything
// it cannot follow (passing to a function, AsMap, etc) is reported as opaque
type keyUsageCollector struct {
	pkg     *packages.Package
	partial map[fieldRef]bool
	usage   *structKeyUsage

	// the variables which hold tracked values, and which field they came from
	vars map[types.Object]trackedVar
}

type trackedVar struct {
	kind valueKind
	ref  fieldRef
}

// classify returns what kind of tracked value expr evaluates to, if any,
// along with the field that it originates from
func (c *keyUsageCollector) classify(expr ast.Expr) (valueKind, fieldRef) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if v, ok := c.vars[c.pkg.TypesInfo.Uses[e]]; ok {
			return v.kind, v.ref
		}

	case *ast.SelectorExpr:
		// direct access of the field i.e. affected.EcosystemSpecific
		if ref, ok := c.partialFieldOf(e, types.FieldVal); ok {
			return trackedStruct, ref
		}

		// direct access of the struct fields i.e. affected.EcosystemSpecific.Fields
		if e.Sel.Name == "Fields" {
			if kind, ref := c.classify(e.X); kind == trackedStruct {
				return trackedFields, ref
			}
		}

	case *ast.CallExpr:
		sel, ok := ast.Unparen(e.Fun).(*ast.SelectorExpr)

		if !ok {
			break
		}

		// use of the field's getter i.e. affected.GetEcosystemSpecific()
		if ref, ok := c.partialFieldOf(sel, types.MethodVal); ok {
			return trackedStruct, ref
		}

		// use of the struct fields getter i.e. affected.GetEcosystemSpecific().GetFields()
		if sel.Sel.Name == "GetFields" {
			if kind, ref := c.classify(sel.X); kind == trackedStruct {
				return trackedFields, ref
			}
		}
	}

	return notTracked, fieldRef{}
}

// partialFieldOf returns the partially cleared field that sel selects,
// mapping protobuf getters back to the field that they return
func (c *keyUsageCollector) partialFieldOf(sel *ast.SelectorExpr, kind types.SelectionKind) (fieldRef, bool) {
	selection, ok := c.pkg.TypesInfo.Selections[sel]

	if !ok || selection.Kind() != kind {
		return fieldRef{}, false
	}

	typeName, ok := osvschemaTypeName(selection.Recv())

	if !ok {
		return fieldRef{}, false
	}

	name := selection.Obj().Name()

	if kind == types.MethodVal {
		name = strings.TrimPrefix(name, "Get")
	}

	ref := fieldRef{Type: typeName, Field: name}

	return ref, c.partial[ref]
}

func isNilIdent(info *types.Info, expr ast.Expr) bool {
	return info.Types[expr].IsNil()
}

// checkUse determines how a tracked expression is used based on its parent
func (c *keyUsageCollector) checkUse(expr ast.Expr, kind valueKind, ref fieldRef, parent ast.Node) {
	pos := c.pkg.Fset.Position(expr.Pos())

	switch p := parent.(type) {
	case *ast.SelectorExpr:
		// selecting the fields of the struct is handled when classifying the parent
		if kind == trackedStruct && (p.Sel.Name == "Fields" || p.Sel.Name == "GetFields") {
			return
		}

	case *ast.BinaryExpr:
		// comparing against nil doesn't read any keys
		if (p.Op == token.EQL || p.Op == token.NEQ) && (isNilIdent(c.pkg.TypesInfo, p.X) || isNilIdent(c.pkg.TypesInfo, p.Y)) {
			return
		}

	case *ast.IndexExpr:
		if kind == trackedFields && ast.Unparen(p.X) == expr {
			tv := c.pkg.TypesInfo.Types[p.Index]

			if tv.Value != nil && tv.Value.Kind() == constant.String {
				key := constant.StringVal(tv.Value)

				if c.usage.reads[ref] == nil {
					c.usage.reads[ref] = map[string][]token.Position{}
				}

				c.usage.reads[ref][key] = append(c.usage.reads[ref][key], pos)

				return
			}
		}

	case *ast.AssignStmt:
		if c.trackAssignment(expr, kind, ref, p.Lhs, p.Rhs) {
			return
		}

	case *ast.ValueSpec:
		lhs := make([]ast.Expr, len(p.Names))
		for i, name := range p.Names {
			lhs[i] = name
		}

		if c.trackAssignment(expr, kind, ref, lhs, p.Values) {
			return
		}
	}

	c.usage.opaque[ref] = append(c.usage.opaque[ref], pos)
}

// trackAssignment starts tracking the variable that expr is being assigned to,
// returning false if the assignment is not to a local variable
func (c *keyUsageCollector) trackAssignment(expr ast.Expr, kind valueKind, ref fieldRef, lhs, rhs []ast.Expr) bool {
	if len(lhs) != len(rhs) {
		return false
	}

	for i, r := range rhs {
		if ast.Unparen(r) != expr {
			continue
		}

		ident, ok := lhs[i].(*ast.Ident)

		if !ok {
			return false
		}

		// assigning to the blank identifier doesn't read anything
		if ident.Name == "_" {
			return true
		}

		obj := c.pkg.TypesInfo.Defs[ident]

		if obj == nil {
			obj = c.pkg.TypesInfo.Uses[ident]
		}

		// only follow local variables, as package level ones could be read anywhere
		if v, ok := obj.(*types.Var); !ok || v.Parent() == nil || v.Parent() == v.Pkg().Scope() {
			return false
		}

		c.vars[obj] = trackedVar{kind: kind, ref: ref}

		return true
	}

	return false
}

func (c *keyUsageCollector) collect(file *ast.File) {
	var stack []ast.Node

	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]

			return true
		}

		var parent ast.Node

		// find the nearest parent, skipping any parentheses
		for _, s := range slices.Backward(stack) {
			if _, ok := s.(*ast.ParenExpr); !ok {
				parent = s

				break
			}
		}

		stack = append(stack, n)

		expr, ok := n.(ast.Expr)

		// parentheses are skipped over, with the expression they wrap being checked instead
		if _, isParen := n.(*ast.ParenExpr); !ok || isParen {
			return true
		}

		// ignore writes to variables, which are not uses of the value
		if assign, ok := parent.(*ast.AssignStmt); ok && slices.Contains(assign.Lhs, expr) {
			return true
		}

		if kind, ref := c.classify(expr); kind != notTracked {
			c.checkUse(ast.Unparen(expr), kind, ref, parent)
		}

		return true
	})
}

// collectStructKeyUsage returns how the keys of the given partially cleared
// fields are used outside the osvdiet package
func collectStructKeyUsage(pkgs []*packages.Package, partial map[fieldRef]bool) structKeyUsage {
	usage := structKeyUsage{
		reads:  map[fieldRef]map[string][]token.Position{},
		opaque: map[fieldRef][]token.Position{},
	}

	for _, pkg := range pkgs {
		if pkg.PkgPath == osvdietPkgPath {
			continue
		}

		c := &keyUsageCollector{
			pkg:     pkg,
			partial: partial,
			usage:   &usage,
			vars:    map[types.Object]trackedVar{},
		}

		for _, file := range pkg.Syntax {
			c.collect(file)
		}
	}

	return usage
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

	partial := map[fieldRef]bool{}

	for ref, c := range cleared {
		if c.partial {
			partial[ref] = true
			t.Logf("slim clears %s, except for %v", ref, slices.Sorted(maps.Keys(c.kept)))
		} else {
			t.Logf("slim clears %s", ref)
		}
	}

	root, err := filepath.Abs(repoRoot)

	if err != nil {
		t.Fatalf("failed to resolve repository root: %v", err)
	}

	formatPositions := func(positions []token.Position) string {
		lines := make([]string, 0, len(positions))
		for _, pos := range positions {
			// show paths relative to the repository root for consistency
			if rel, err := filepath.Rel(root, pos.Filename); err == nil {
				pos.Filename = rel
			}

			lines = append(lines, "  "+pos.String())
		}
		slices.Sort(lines)

		return strings.Join(lines, "\n")
	}

	for ref, c := range cleared {
		// partially cleared fields are checked based on the keys that are used
		if c.partial {
			continue
		}

		if positions, ok := used[ref]; ok {
			t.Errorf("slim clears %s, but it is used in:\n%s", ref, formatPositions(positions))
		}
	}

	if len(partial) == 0 {
		return
	}

	usage := collectStructKeyUsage(pkgs, partial)

	for ref := range partial {
		for key, positions := range usage.reads[ref] {
			if !cleared[ref].kept[key] {
				t.Errorf("slim clears %s[%q], but it is read in:\n%s", ref, key, formatPositions(positions))
			}
		}

		if positions, ok := usage.opaque[ref]; ok {
			t.Errorf(
				"slim clears some keys of %s, but it is used in ways that could read any key in:\n%s",
				ref,
				formatPositions(positions),
			)
		}
	}
}
