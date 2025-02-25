package javareach

import (
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type ReachabilityResult struct {
	Classes                 []string
	UsesDynamicCodeLoading  []string
	UsesDependencyInjection []string
}

type DynamicCodeStrategy int

const (
	// Don't do any kind of special handling.
	DontHandleDynamicCode DynamicCodeStrategy = 0
	// Assume that the entirety of all direct dependencies are fully reachable.
	AssumeAllDirectDepsReachable = 1 << 0
	// Assume that every single class from the current dependency are fully reachable.
	AssumeAllClassesReachable = 1 << 1
)

type ReachabilityEnumerator struct {
	ClassPath                   string
	PackageFinder               MavenPackageFinder
	CodeLoadingStrategy         DynamicCodeStrategy
	DependencyInjectionStrategy DynamicCodeStrategy
}

func (r *ReachabilityEnumerator) EnumerateReachabilityFromClass(mainClass string) (*ReachabilityResult, error) {
	cf, err := findClass(r.ClassPath, mainClass)
	if err != nil {
		return nil, err
	}

	return r.EnumerateReachability([]*ClassFile{cf})
}

// TODO:
//   - See if we should do a finer grained analysis to only consider referenced
//     classes where a method is called/referenced.
func (r *ReachabilityEnumerator) EnumerateReachability(roots []*ClassFile) (*ReachabilityResult, error) {
	seen := map[string]struct{}{}
	codeLoading := map[string]struct{}{}
	depInjection := map[string]struct{}{}
	for _, root := range roots {
		if err := r.enumerateReachability(root, seen, codeLoading, depInjection); err != nil {
			return nil, err
		}
	}

	return &ReachabilityResult{
		Classes:                 slices.Collect(maps.Keys(seen)),
		UsesDynamicCodeLoading:  slices.Collect(maps.Keys(codeLoading)),
		UsesDependencyInjection: slices.Collect(maps.Keys(depInjection)),
	}, nil
}

func findClass(classPath string, className string) (*ClassFile, error) {
	classFilepath := filepath.Join(classPath, className)
	if !strings.HasPrefix(classFilepath, filepath.Clean(classPath)+string(os.PathSeparator)) {
		return nil, fmt.Errorf("directory traversal: %s", classFilepath)
	}

	if !strings.HasSuffix(classFilepath, ".class") {
		classFilepath += ".class"
	}
	classFile, err := os.Open(classFilepath)
	if err != nil {
		return nil, err
	}
	return ParseClass(classFile)
}

func isDynamicCodeLoading(method string, descriptor string) bool {
	// https://docs.oracle.com/en/java/javase/23/docs/api/java.base/java/lang/ClassLoader.html#loadClass(java.lang.String)
	if strings.Contains(method, "loadClass") && strings.HasSuffix(descriptor, "Ljava/lang/Class;") {
		return true
	}

	// https://docs.oracle.com/en/java/javase/23/docs/api/java.base/java/lang/Class.html#forName(java.lang.String)
	if strings.Contains(method, "forName") && strings.HasSuffix(descriptor, "Ljava/lang/Class;") {
		return true
	}

	return false
}

func isDependencyInjection(class string) bool {
	if strings.HasPrefix(class, "javax/inject") {
		return true
	}

	if strings.HasPrefix(class, "org/springframework") {
		return true
	}

	if strings.HasPrefix(class, "com/google/inject") {
		return true
	}

	if strings.HasPrefix(class, "dagger/") {
		return true
	}

	return false
}

func (r *ReachabilityEnumerator) handleDynamicCode(q *UniqueQueue[string, *ClassFile], class string, strategy DynamicCodeStrategy) error {
	if strategy == DontHandleDynamicCode {
		return nil
	}

	pkgs, err := r.PackageFinder.Find(class)
	if err != nil {
		return err
	}

	// Assume all classes that belong to the package are reachable.
	if strategy&AssumeAllClassesReachable > 0 {
		for _, pkg := range pkgs {
			classes, err := r.PackageFinder.Classes(pkg)
			if err != nil {
				return err
			}

			for _, class := range classes {
				cf, err := findClass(r.ClassPath, class)
				if err == nil {
					slog.Debug("assuming all package classes are reachable", "class", class, "pkg", pkg)
					q.Push(class, cf)
				} else {
					slog.Error("failed to find class", "class", class, "from", pkg, "err", err)
				}
			}
		}
	}

	// Assume all classes that belong to the direct dependencies of the package are reachable.
	if strategy&AssumeAllDirectDepsReachable > 0 {
		// TODO
	}

	return nil
}

// TODO: retain edges and compute confidence scores based on use of dynamic code
// loading in the path leading up to a dependency.
func (r *ReachabilityEnumerator) enumerateReachability(
	cf *ClassFile, seen map[string]struct{}, codeLoading map[string]struct{}, depInjection map[string]struct{}) error {

	thisClass, err := cf.ConstantPoolClass(int(cf.ThisClass))
	if err != nil {
		return err
	}

	q := NewQueue[string, *ClassFile](seen)
	q.Push(thisClass, cf)

	for !q.Empty() {
		thisClass, cf := q.Pop()
		slog.Debug("Analyzing", "class", thisClass)

		// Find uses of dynamic code loading.
		for i, cp := range cf.ConstantPool {
			if cp.Type() == ConstantKindMethodref {
				_, method, descriptor, err := cf.ConstantPoolMethodref(i)
				if err != nil {
					return err
				}

				if isDynamicCodeLoading(method, descriptor) {
					slog.Debug("found dynamic class loading", "thisClass", thisClass, "method", method, "descriptor", descriptor)
					if _, ok := codeLoading[thisClass]; !ok {
						codeLoading[thisClass] = struct{}{}
						err := r.handleDynamicCode(q, thisClass, r.CodeLoadingStrategy)
						if err != nil {
							slog.Error("failed to handle dynamic code", "thisClass", thisClass, "err", err)
						}
					}
				}
			} else if cp.Type() == ConstantKindClass {
				class, err := cf.ConstantPoolClass(i)
				if err != nil {
					return err
				}

				if isDependencyInjection(class) {
					slog.Debug("found dependency injection", "thisClass", thisClass, "injector", class)
					if _, ok := depInjection[thisClass]; !ok {
						depInjection[thisClass] = struct{}{}
						err := r.handleDynamicCode(q, thisClass, r.DependencyInjectionStrategy)
						if err != nil {
							slog.Error("failed to handle dynamic code", "thisClass", thisClass, "err", err)
						}
					}
				}
			}
		}

		// Enumerate class references.
		for i, cp := range cf.ConstantPool {
			if int(cf.ThisClass) == i {
				// Don't consider this class itself.
				continue
			}
			if cp.Type() != ConstantKindClass {
				continue
			}

			class, err := cf.ConstantPoolClass(i)
			if err != nil {
				return err
			}

			// Handle arrays.
			if len(class) > 0 && class[0] == '[' {
				// "[" can appear multiple times (nested arrays).
				class = strings.TrimLeft(class, "[")

				// Array of class type. Extract the class name.
				if len(class) > 0 && class[0] == 'L' {
					class = strings.TrimSuffix(class[1:], ";")
				} else if slices.Contains(BinaryBaseTypes, class) {
					// Base type (e.g. integer): just ignore this.
					continue
				} else {
					// We don't know what the type is.
					return fmt.Errorf("unknown class type %s", class)
				}
			}

			if IsStdLib(class) {
				continue
			}

			slog.Debug("found", "dependency", class)
			if q.Seen(class) {
				continue
			}

			depcf, err := findClass(r.ClassPath, class)
			if err != nil {
				// Dependencies can be optional, so this is not a fatal error.
				slog.Error("failed to find class", "class", class, "from", thisClass, "cp idx", i, "error", err)
				continue
			}

			q.Push(class, depcf)
		}
	}

	return nil
}
