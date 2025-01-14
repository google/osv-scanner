package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"github.com/google/osv-scanner/experimental/javareach"
)

// Usage:
//
//	go run ./cmd/reachable -classpath=<classpath> path/to/root/class
//	go run ./cmd/reachable path/to/file.jar
//
// Note that <classpath> currently only supports a single directory path containing .class files.
// This is unlike classpaths supported by Java runtimes (which supports
// specifying multiple directories and .jar files)
//
// TODO: Support non-uber jars by downloading dependencie on demand from registries. This requires
// a reliable index of class -> Maven jar mappings for the entire Maven universe.
func main() {
	classPath := flag.String("classpath", "", "A single directory containing Java class files with a directory structure that mirrors the package hierarchy.")
	verbose := flag.Bool("verbose", false, "Enable debug logs.")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s <arguments> <root class name> <root class name 2...>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	for _, arg := range flag.Args() {
		if strings.HasSuffix(arg, ".jar") {
			if err := enumerateReachabilityForJar(arg); err != nil {
				slog.Error("Failed to enumerate reachability for", "jar", arg, "error", err)
				os.Exit(1)
			}
		} else {
			if *classPath == "" {
				flag.Usage()
				os.Exit(1)
			}

			classes, err := EnumerateReachabilityFromClass(arg, *classPath)
			if err != nil {
				slog.Error("Failed to enumerate reachability for", "class", arg, "error", err)
				os.Exit(1)
			}

			for _, class := range classes {
				slog.Info("Reachable", "class", class)
			}
		}
	}
}

func enumerateReachabilityForJar(jarPath string) error {
	jarfile, err := os.Open(jarPath)
	if err != nil {
		return err
	}
	allDeps, err := javareach.ExtractDependencies(jarfile)
	for _, dep := range allDeps {
		slog.Debug("extracted dep",
			"group id", dep.Metadata.(*archive.Metadata).GroupID, "artifact id", dep.Name, "version", dep.Version)
	}

	classFinder, err := javareach.NewDefaultPackageFinder(allDeps)
	if err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	slog.Info("Unzipping", "jar", jarPath, "to", tmpDir)
	err = unzipJar(jarPath, tmpDir)
	if err != nil {
		return err
	}

	manifest, err := os.Open(filepath.Join(tmpDir, "META-INF/MANIFEST.MF"))
	if err != nil {
		return err
	}

	mainClass, err := javareach.GetMainClass(manifest)
	if err != nil {
		return err
	}
	slog.Info("Found", "main class", mainClass)
	classes, err := EnumerateReachabilityFromClass(mainClass, tmpDir)
	if err != nil {
		return err
	}

	reachableDeps := map[string]struct{}{}
	for _, class := range classes {
		deps, err := classFinder.Find(class)
		if err != nil {
			slog.Error("Failed to find", "class", class, "error", err)
			continue
		}

		for _, dep := range deps {
			reachableDeps[dep] = struct{}{}
		}
	}

	for dep, _ := range reachableDeps {
		slog.Info("Reachable", "dep", dep)
	}

	for _, dep := range allDeps {
		name := fmt.Sprintf("%s:%s", dep.Metadata.(*archive.Metadata).GroupID, dep.Name)
		if _, ok := reachableDeps[name]; !ok {
			slog.Info("Not reachable", "dep", name)
		}
	}
	return nil
}

func EnumerateReachabilityFromClass(mainClass string, classPath string) ([]string, error) {
	cf, err := findClass(classPath, mainClass)
	if err != nil {
		return nil, err
	}

	return EnumerateReachability([]*javareach.ClassFile{cf}, classPath)
}

func findClass(classPath string, className string) (*javareach.ClassFile, error) {
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
	return javareach.ParseClass(classFile)
}

// TODO:
//   - Detect uses of reflection and dynamic class loading -> Consider all dependencies used.
//   - See if we should do a finer grained analysis to only consider referenced
//     classes where a method is called/referenced.
func EnumerateReachability(roots []*javareach.ClassFile, classPath string) ([]string, error) {
	seen := map[string]struct{}{}
	for _, root := range roots {
		if err := enumerateReachability(root, classPath, seen); err != nil {
			return nil, err
		}
	}

	return slices.Collect(maps.Keys(seen)), nil
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
		if cp.Type() != javareach.ConstantKindClass {
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
		if _, ok := seen[class]; ok {
			continue
		}

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

	return nil
}

func unzipJar(jarPath string, tmpDir string) error {
	r, err := zip.OpenReader(jarPath)
	if err != nil {
		return err
	}

	for _, file := range r.File {
		path := filepath.Join(tmpDir, file.Name)
		if !strings.HasPrefix(path, filepath.Clean(tmpDir)+string(os.PathSeparator)) {
			return fmt.Errorf("directory traversal: %s", path)
		}

		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0755); err != nil {
				return err
			}
		} else {
			source, err := file.Open()
			if err != nil {
				return err
			}

			f, err := os.Create(path)
			if err != nil {
				return err
			}

			_, err = io.Copy(f, source)
			if err != nil {
				f.Close()
				return err
			}
			f.Close()
		}

	}
	return nil
}
