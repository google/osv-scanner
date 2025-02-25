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

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"github.com/google/osv-scanner/experimental/javareach"
)

// Usage:
//
//	go run ./cmd/reachable path/to/file.jar
//
// TODO: Support non-uber jars by downloading dependencies on demand from registries. This requires
// a reliable index of class -> Maven jar mappings for the entire Maven universe.
func main() {
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
		}
	}
}

func fmtJavaInventory(i *extractor.Inventory) string {
	return fmt.Sprintf("%s:%s", i.Metadata.(*archive.Metadata).GroupID, i.Name)
}

func enumerateReachabilityForJar(jarPath string) error {
	jarfile, err := os.Open(jarPath)
	if err != nil {
		return err
	}

	// Extract dependencies from the .jar (from META-INF/maven/**/pom.properties)
	allDeps, err := javareach.ExtractDependencies(jarfile)
	if err != nil {
		return err
	}
	slices.SortFunc(allDeps, func(i1 *extractor.Inventory, i2 *extractor.Inventory) int {
		return strings.Compare(fmtJavaInventory(i1), fmtJavaInventory(i2))
	})
	for _, dep := range allDeps {
		slog.Debug("extracted dep",
			"group id", dep.Metadata.(*archive.Metadata).GroupID, "artifact id", dep.Name, "version", dep.Version)
	}

	// Build .class -> Maven group ID:artifact ID mappings.
	// TODO: Handle BOOT-INF and loading .jar dependencies from there.
	classFinder, err := javareach.NewDefaultPackageFinder(allDeps)
	if err != nil {
		return err
	}

	// Unpack .jar
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

	// Extract the main entrypoint.
	manifest, err := os.Open(filepath.Join(tmpDir, "META-INF/MANIFEST.MF"))
	if err != nil {
		return err
	}

	mainClass, err := javareach.GetMainClass(manifest)
	if err != nil {
		return err
	}
	slog.Info("Found", "main class", mainClass)

	// Enumerate reachable classes.
	// TODO: Look inside static files (e.g. META-INF/services, XML beans configurations).
	enumerator := javareach.ReachabilityEnumerator{
		ClassPath:                   tmpDir,
		PackageFinder:               classFinder,
		CodeLoadingStrategy:         javareach.AssumeAllClassesReachable,
		DependencyInjectionStrategy: javareach.AssumeAllClassesReachable,
	}

	result, err := enumerator.EnumerateReachabilityFromClass(mainClass)
	if err != nil {
		return err
	}

	// Map reachable classes back to Maven group ID:artifact ID.
	reachableDeps := map[string]struct{}{}
	for _, class := range result.Classes {
		deps, err := classFinder.Find(class)
		if err != nil {
			slog.Error("Failed to find dep mapping", "class", class, "error", err)
			continue
		}

		for _, dep := range deps {
			reachableDeps[dep] = struct{}{}
		}
	}

	// Find Maven deps that use dynamic code loading and dependency injection.
	dynamicLoadingDeps := map[string]struct{}{}
	injectionDeps := map[string]struct{}{}
	slices.Sort(result.UsesDynamicCodeLoading)
	for _, class := range result.UsesDynamicCodeLoading {
		slog.Info("Found use of dynamic code loading", "class", class)
		deps, err := classFinder.Find(class)
		if err != nil {
			slog.Error("Failed to find dep mapping", "class", class, "error", err)
			continue
		}
		for _, dep := range deps {
			dynamicLoadingDeps[dep] = struct{}{}
		}
	}
	for _, class := range result.UsesDependencyInjection {
		slog.Info("Found use of dependency injection", "class", class)
		deps, err := classFinder.Find(class)
		if err != nil {
			slog.Error("Failed to find dep mapping", "class", class, "error", err)
			continue
		}
		for _, dep := range deps {
			injectionDeps[dep] = struct{}{}
		}
	}

	// Print results.
	for _, dep := range slices.Sorted(maps.Keys(reachableDeps)) {
		_, dynamicLoading := dynamicLoadingDeps[dep]
		_, injection := injectionDeps[dep]
		slog.Info("Reachable", "dep", dep, "dynamic code", dynamicLoading, "dep injection", injection)
	}

	for _, dep := range allDeps {
		name := fmtJavaInventory(dep)
		if _, ok := reachableDeps[name]; !ok {
			slog.Info("Not reachable", "dep", name)
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
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return err
			}

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
