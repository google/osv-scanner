package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/experimental/javareach"
)

// Usage:
//
//	go run ./cmd/reachable -classpath=<classpath> path/to/root/class
//
// Note that <classpath> currently only supports a single directory path, unlike
// classpaths supported by Java runtimes (which supports specifying multiple
// directories and .jar files)
//
// TODO: Support unpacking .jar files, and transitively resolving pom.xml files
// and automatically downloading building and downloading dependencies if the
// pom.xml exists in the root .jar file.
func main() {
	classPath := flag.String("classpath", "", "(Required) A single directory containing class files to look for.")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s <arguments> <root class name>\n", os.Args[0])
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
			log.Fatalf("Failed to find class %s", className)
		}

		EnumerateReachability(cf, *classPath)
	}
}

func findClass(classPath string, className string) (*javareach.ClassFile, error) {
	classFilepath := filepath.Join(classPath, className) + ".class"
	classFile, err := os.Open(classFilepath)
	if err != nil {
		return nil, err
	}
	cf, err := javareach.ParseClass(classFile)
	if err != nil {
		return nil, err
	}

	return cf, nil
}

// TODO:
//   - Detect uses of reflection
//   - See if we should do a finer grained analysis to only consider referenced
//     classes where a method is called/referenced.
func EnumerateReachability(cf *javareach.ClassFile, classPath string) error {
	seen := map[string]struct{}{}
	return enumerateReachability(cf, classPath, seen)
}

func enumerateReachability(cf *javareach.ClassFile, classPath string, seen map[string]struct{}) error {
	thisClass, err := cf.ConstantPoolClass(int(cf.ThisClass))
	if err != nil {
		return err
	}

	if _, ok := seen[thisClass]; ok {
		return nil
	}
	fmt.Printf("this class: %s\n", thisClass)
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
			fmt.Printf("class: %s\n", class)

			if strings.HasPrefix(class, "java/") || strings.HasPrefix(class, "javax/") {
				// Standard library
				continue
			}

			depcf, err := findClass(classPath, class)
			if err != nil {
				return err
			}
			if err := enumerateReachability(depcf, classPath, seen); err != nil {
				return err
			}
		}
	}

	return nil
}
