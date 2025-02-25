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
	"runtime/pprof"
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
	profile := flag.String("profile", "", "Enable profiling.")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s <arguments> <root class name> <root class name 2...>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	if *profile != "" {
		f, err := os.Create(*profile)
		if err != nil {
			slog.Error("could not create CPU profile", "err", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			slog.Error("could not start CPU profile", "err", err)
			os.Exit(1)
		}
		defer pprof.StopCPUProfile()
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
	nestedJARs, err := unzipJAR(jarPath, tmpDir)
	if err != nil {
		return err
	}

	// Extract the main entrypoint.
	manifest, err := os.Open(filepath.Join(tmpDir, "META-INF/MANIFEST.MF"))
	if err != nil {
		return err
	}

	mainClasses, err := javareach.GetMainClasses(manifest)
	if err != nil {
		return err
	}
	slog.Info("Found", "main classes", mainClasses)

	classPaths := []string{tmpDir}
	classPaths = append(classPaths, nestedJARs...)

	// Spring Boot applications have classes in BOOT-INF/classes.
	bootInfClasses := filepath.Join(tmpDir, "BOOT-INF/classes")
	if _, err := os.Stat(bootInfClasses); err == nil {
		classPaths = append(classPaths, bootInfClasses)
	}

	// Enumerate reachable classes.
	// TODO: Look inside static files (e.g. META-INF/services, XML beans configurations).
	enumerator := javareach.NewReachabilityEnumerator(classPaths, classFinder, javareach.AssumeAllClassesReachable, javareach.AssumeAllClassesReachable)
	result, err := enumerator.EnumerateReachabilityFromClasses(mainClasses)
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

// unzipJAR unzips a JAR to a target directory. It also returns a list of paths
// to all the nested JARs found while unzipping.
func unzipJAR(jarPath string, tmpDir string) (nestedJARs []string, err error) {
	r, err := zip.OpenReader(jarPath)
	if err != nil {
		return nil, err
	}

	for _, file := range r.File {
		path := filepath.Join(tmpDir, file.Name)
		if !strings.HasPrefix(path, filepath.Clean(tmpDir)+string(os.PathSeparator)) {
			return nil, fmt.Errorf("directory traversal: %s", path)
		}

		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0755); err != nil {
				return nil, err
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return nil, err
			}

			if strings.HasSuffix(path, ".jar") {
				nestedJARs = append(nestedJARs, path)
			}

			source, err := file.Open()
			if err != nil {
				return nil, err
			}

			f, err := os.Create(path)
			if err != nil {
				return nil, err
			}

			_, err = io.Copy(f, source)
			if err != nil {
				f.Close()
				return nil, err
			}
			f.Close()
		}

	}
	return nestedJARs, nil
}
