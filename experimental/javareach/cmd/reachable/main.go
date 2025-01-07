package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scanner/experimental/javareach"
)

// Usage:
//
//	go run ./cmd/reachable -classpath=<classpath> path/to/root/class
//
// Note that <classpath> currently only supports a single directory path containing .class files.
// This is unlike classpaths supported by Java runtimes (which supports
// specifying multiple directories and .jar files)
//
// TODO: Support unpacking .jar files (uber jars that contain all dependencies)
// TODO: Support non-uber jars by transitively resolving pom.xml files and
// automatically downloading dependencies if the pom.xml exists in the .jar
// (e.g. META-INF/maven/pom.xml)
// TODO: Map classes back to Maven dependencies.
func main() {
	classPath := flag.String("classpath", "", "(Required) A single directory containing Java class files with a directory structure that mirrors the package hierarchy.")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s <arguments> <root class name> <root class name 2...>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *classPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	for _, className := range flag.Args() {
		cf, err := findClass(*classPath, className)
		if err != nil {
			slog.Error("Failed to find", "class", className, "error", err)
			os.Exit(1)
		}

		err = EnumerateReachability(cf, *classPath)
		if err != nil {
			slog.Error("Failed to enumerate reachability", "class", className, "error", err)
			os.Exit(1)
		}
	}
}

func findClass(classPath string, className string) (*javareach.ClassFile, error) {
	classFilepath := filepath.Join(classPath, className)
	if !strings.HasSuffix(classFilepath, ".class") {
		classFilepath += ".class"
	}
	classFile, err := os.Open(classFilepath)
	if err != nil {
		return nil, err
	}
	return javareach.ParseClass(classFile)
}

// TODO:
//   - Detect uses of reflection
//   - See if we should do a finer grained analysis to only consider referenced
//     classes where a method is called/referenced.
func EnumerateReachability(cf *javareach.ClassFile, classPath string) error {
	seen := map[string]struct{}{}
	if err := enumerateReachability(cf, classPath, seen); err != nil {
		return err
	}

	for k, _ := range seen {
		fmt.Println(k)
	}
	return nil
}

func enumerateReachability(cf *javareach.ClassFile, classPath string, seen map[string]struct{}) error {
	thisClass, err := cf.ConstantPoolClass(int(cf.ThisClass))
	if err != nil {
		return err
	}

	if _, ok := seen[thisClass]; ok {
		return nil
	}
	slog.Debug("Analyzing", "class", thisClass)
	seen[thisClass] = struct{}{}

	for i, cp := range cf.ConstantPool {
		if int(cf.ThisClass) == i {
			// Don't consider this class itself.
			continue
		}

		if cp.Type() == javareach.ConstantKindClass {
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
				} else if slices.Contains(javareach.BinaryBaseTypes, class) {
					// Base type (e.g. integer): just ignore this.
					continue
				} else {
					// We don't know what the type is.
					return fmt.Errorf("unknown class type %s", class)
				}
			}

			if javareach.IsStdLib(class) {
				continue
			}

			slog.Debug("found", "dependency", class)
			depcf, err := findClass(classPath, class)
			if err != nil {
				// Dependencies can be optional, so this is not a fatal error.
				slog.Error("failed to find class", "class", class, "from", thisClass, "cp idx", i, "error", err)
				continue
			}
			if err := enumerateReachability(depcf, classPath, seen); err != nil {
				return err
			}
		}
	}

	return nil
}
