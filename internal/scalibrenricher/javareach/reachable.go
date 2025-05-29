// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package javareach provides Java reachability function
package javareach

import (
	"archive/zip"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/log"
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
	// Assume that the entirety of all direct dependencies (i.e. all their
	// classes) are fully reachable.
	AssumeAllDirectDepsReachable = 1 << 0
	// Assume that every single class belonging to the current dependency are
	// fully reachable.
	AssumeAllClassesReachable = 1 << 1
)

const (
	BootInfClasses  = "BOOT-INF/classes"
	MetaInfVersions = "META-INF/versions"
)

type ReachabilityEnumerator struct {
	ClassPaths                  []string
	PackageFinder               MavenPackageFinder
	CodeLoadingStrategy         DynamicCodeStrategy
	DependencyInjectionStrategy DynamicCodeStrategy

	loadedJARs map[string]*zip.Reader
}

func NewReachabilityEnumerator(
	classPaths []string, packageFinder MavenPackageFinder,
	codeLoadingStrategy DynamicCodeStrategy, dependencyInjectionStrategy DynamicCodeStrategy) *ReachabilityEnumerator {
	return &ReachabilityEnumerator{
		ClassPaths:                  classPaths,
		PackageFinder:               packageFinder,
		CodeLoadingStrategy:         codeLoadingStrategy,
		DependencyInjectionStrategy: dependencyInjectionStrategy,
		loadedJARs:                  map[string]*zip.Reader{},
	}
}

func (r *ReachabilityEnumerator) EnumerateReachabilityFromClasses(mainClasses []string, optionalRootClasses []string) (*ReachabilityResult, error) {
	var roots []*ClassFile
	for _, mainClass := range mainClasses {
		cf, err := r.findClass(r.ClassPaths, mainClass)
		if err != nil {
			return nil, fmt.Errorf("failed to find main class %s: %w", mainClass, err)
		}
		roots = append(roots, cf)
	}

	// optionalRootClasses include those from META-INF/services. They might not exist in the Jar.
	for _, serviceClass := range optionalRootClasses {
		cf, err := r.findClass(r.ClassPaths, serviceClass)
		if err != nil {
			continue
		}
		roots = append(roots, cf)
	}

	return r.EnumerateReachability(roots)
}

// TODO(#787):
//   - See if we should do a finer grained analysis to only consider referenced
//     classes where a method is called/referenced.
//
// EnumerateReachability enumerates the reachable classes from a set of root
// classes.
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

// findClassInJAR finds the relevant parsed .class file from a .jar.
func (r *ReachabilityEnumerator) findClassInJAR(jarPath string, className string) (*ClassFile, error) {
	if _, ok := r.loadedJARs[jarPath]; !ok {
		// Repeatedly opening zip files is very slow, so cache the opened JARs.
		f, err := os.Open(jarPath)
		if err != nil {
			return nil, err
		}
		stat, err := f.Stat()
		if err != nil {
			return nil, err
		}

		zipr, err := zip.NewReader(f, stat.Size())
		if err != nil {
			return nil, err
		}
		r.loadedJARs[jarPath] = zipr
	}

	zipr := r.loadedJARs[jarPath]
	class, err := zipr.Open(className + ".class")
	if err != nil {
		if os.IsNotExist(err) {
			// class not found in this .jar. not an error.
			return nil, nil
		}
		return nil, err
	}

	return ParseClass(class)
}

// findClass finds the relevant parsed .class file from a list of classpaths.
func (r *ReachabilityEnumerator) findClass(classPaths []string, className string) (*ClassFile, error) {
	// TODO(#787): Support META-INF/versions (multi release JARs) if necessary.

	// Remove generics from the class name.
	// TODO(#787): Verify that this is correct.
	genericRE := regexp.MustCompile(`<.*>`)
	className = genericRE.ReplaceAllString(className, "")

	// Handle inner class names. The class filename will have a "$" in place of the ".".
	className = strings.ReplaceAll(className, ".", "$")

	for _, classPath := range classPaths {
		if strings.HasSuffix(classPath, ".jar") {
			cf, err := r.findClassInJAR(classPath, className)
			if err != nil {
				return nil, err
			}

			if cf != nil {
				log.Debug("found class in nested .jar", "class", className, "path", classPath)
				return cf, nil
			}
			continue
		}

		// Look inside the class directory.
		classFilepath := filepath.Join(classPath, className)
		if !strings.HasPrefix(classFilepath, filepath.Clean(classPath)+string(os.PathSeparator)) {
			return nil, fmt.Errorf("directory traversal: %s", classFilepath)
		}

		if !strings.HasSuffix(classFilepath, ".class") {
			classFilepath += ".class"
		}

		if _, err := os.Stat(classFilepath); os.IsNotExist(err) {
			// Class not found in this directory. Move onto the next classpath.
			continue
		}

		classFile, err := os.Open(classFilepath)
		if err != nil {
			return nil, err
		}
		cf, err := ParseClass(classFile)
		if err != nil {
			return nil, err
		}
		log.Debug("found class in directory", "class", className, "path", classPath)

		return cf, nil
	}

	return nil, errors.New("class not found")
}

// isDynamicCodeLoading returns whether a method and its descriptor represents a
// call to a dynamic code loading method.
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

// isDependencyInjection returns whether a class provides dependency injection functionality.
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

// handleDynamicCode handles the enumeration of class reachability when there is
// dynamic code loading, taking into account a user specified strategy.
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
				if q.Seen(class) {
					continue
				}
				cf, err := r.findClass(r.ClassPaths, class)
				if err == nil {
					log.Debug("assuming all package classes are reachable", "class", class, "pkg", pkg)
					q.Push(class, cf)
				} else {
					log.Error("failed to find class", "class", class, "from", pkg, "err", err)
				}
			}
		}
	}
	// Assume all classes that belong to the direct dependencies of the package
	// are reachable.
	// TODO(#787): implement this.
	// if strategy&AssumeAllDirectDepsReachable > 0 {
	// }
	return nil
}

// TODO(#787): retain edges and compute confidence scores based on use of dynamic code
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
		log.Debug("Analyzing", "class", thisClass)

		// Find uses of dynamic code loading.
		for i, cp := range cf.ConstantPool {
			if cp.Type() == ConstantKindMethodref {
				_, method, descriptor, err := cf.ConstantPoolMethodref(i)
				if err != nil {
					return err
				}

				if isDynamicCodeLoading(method, descriptor) {
					log.Debug("found dynamic class loading", "thisClass", thisClass, "method", method, "descriptor", descriptor)
					if _, ok := codeLoading[thisClass]; !ok {
						codeLoading[thisClass] = struct{}{}
						err := r.handleDynamicCode(q, thisClass, r.CodeLoadingStrategy)
						if err != nil {
							log.Error("failed to handle dynamic code", "thisClass", thisClass, "err", err)
						}
					}
				}
			} else if cp.Type() == ConstantKindClass {
				class, err := cf.ConstantPoolClass(i)
				if err != nil {
					return err
				}

				if isDependencyInjection(class) {
					log.Debug("found dependency injection", "thisClass", thisClass, "injector", class)
					if _, ok := depInjection[thisClass]; !ok {
						depInjection[thisClass] = struct{}{}
						err := r.handleDynamicCode(q, thisClass, r.DependencyInjectionStrategy)
						if err != nil {
							log.Error("failed to handle dynamic code", "thisClass", thisClass, "err", err)
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

			class := ""
			if cp.Type() == ConstantKindClass {
				class, err = cf.ConstantPoolClass(i)
				if err != nil {
					return err
				}
			} else if cp.Type() == ConstantKindUtf8 {
				// Also check strings for references to classes.
				val, err := cf.ConstantPoolUtf8(i)
				if err != nil {
					continue
				}

				// Found a string with the `Lpath/to/class;` format. This is
				// likely a reference to a class. Annotations appear this way.
				if val != "" && val[0] == 'L' && val[len(val)-1] == ';' {
					class = val[1 : len(val)-1]
				}
			}

			if class == "" {
				continue
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

			log.Debug("found", "dependency", class)
			if q.Seen(class) {
				continue
			}

			depcf, err := r.findClass(r.ClassPaths, class)
			if err != nil {
				// Dependencies can be optional, so this is not a fatal error.
				log.Error("failed to find class", "class", class, "from", thisClass, "cp idx", i, "error", err)
				continue
			}

			q.Push(class, depcf)
		}
	}

	return nil
}
