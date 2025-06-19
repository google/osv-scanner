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

package javareach

import (
	"archive/zip"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this detector.
	Name = "javareach"
	// MetaDirPath is the path to the META-INF directory.
	MetaDirPath   = "META-INF"
	PathSeparator = '/'
)

var (
	// ManifestFilePath is the path to the MANIFEST.MF file.
	ManifestFilePath = path.Join(MetaDirPath, "MANIFEST.MF")
	// MavenDepDirPath is the path to the Maven dependency directory.
	MavenDepDirPath = path.Join(MetaDirPath, "maven")
	// ServiceDirPath is the path to the META-INF/services directory.
	ServiceDirPath = path.Join(MetaDirPath, "services")

	// ErrMavenDependencyNotFound is returned when a JAR is not a Maven dependency.
	ErrMavenDependencyNotFound = errors.New(MavenDepDirPath + " directory not found")
)

// Enricher is the Java Reach enricher.
type Enricher struct {
	client *http.Client
}

// Name returns the name of the enricher.
func (Enricher) Name() string {
	return Name
}

// Version returns the version of the enricher.
func (Enricher) Version() int {
	return 0
}

// Requirements returns the requirements of the enricher.
func (Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network: plugin.NetworkOnline,
	}
}

// RequiredPlugins returns the names of the plugins required by the enricher.
func (Enricher) RequiredPlugins() []string {
	return []string{archive.Name}
}

// NewEnricher creates a new Enricher.
// It accepts an http.Client as a dependency. If the provided client is nil,
// it defaults to the standard http.DefaultClient.
func NewEnricher(client *http.Client) *Enricher {
	if client == nil {
		client = http.DefaultClient
	}

	return &Enricher{
		client: client,
	}
}

// NewDefault returns a new javareach enricher with the default configuration.
func NewDefault() enricher.Enricher {
	return &Enricher{
		client: http.DefaultClient,
	}
}

// Enrich enriches the inventory with Java Reach data.
func (enr Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	client := enr.client
	if client == nil {
		client = http.DefaultClient
	}
	jars := make(map[string]struct{})
	for i := range inv.Packages {
		for _, extractorName := range inv.Packages[i].Plugins {
			if extractorName == archive.Name {
				jars[inv.Packages[i].Locations[0]] = struct{}{}
				break
			}
		}
	}

	for jar := range jars {
		err := enumerateReachabilityForJar(ctx, jar, input, inv, client)
		if err != nil {
			return err
		}
	}

	return nil
}

func getFullPackageName(i *extractor.Package) string {
	return fmt.Sprintf("%s:%s", i.Metadata.(*archivemeta.Metadata).GroupID,
		i.Metadata.(*archivemeta.Metadata).ArtifactID)
}

func enumerateReachabilityForJar(ctx context.Context, jarPath string, input *enricher.ScanInput, inv *inventory.Inventory, client *http.Client) error {
	var allDeps []*extractor.Package
	if client == nil {
		client = http.DefaultClient
	}
	for i := range inv.Packages {
		if inv.Packages[i].Locations[0] == jarPath {
			allDeps = append(allDeps, inv.Packages[i])
		}
	}

	slices.SortFunc(allDeps, func(i1 *extractor.Package, i2 *extractor.Package) int {
		return strings.Compare(getFullPackageName(i1), getFullPackageName(i2))
	})
	for _, dep := range allDeps {
		log.Debug("extracted dep",
			"group id", dep.Metadata.(*archivemeta.Metadata).GroupID, "artifact id", dep.Name, "version", dep.Version)
	}

	// Unpack .jar
	jarDir, err := os.MkdirTemp("", "osv-scalibr-javareach-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(jarDir)
	log.Debug("Unzipping", "jar", jarPath, "to", jarDir)

	jarRoot, err := os.OpenRoot(jarDir)
	if err != nil {
		return err
	}

	nestedJARs, err := unzipJAR(jarPath, input, jarRoot)
	if err != nil {
		return err
	}

	// Reachability analysis is limited to Maven-built JARs for now.
	// Check for the existence of the Maven metadata directory.
	_, err = jarRoot.Stat(MavenDepDirPath)
	if err != nil {
		log.Error("reachability analysis is only supported for JARs built with Maven.")
		return ErrMavenDependencyNotFound
	}

	// Build .class -> Maven group ID:artifact ID mappings.
	// TODO(#787): Handle BOOT-INF and loading .jar dependencies from there.
	classFinder, err := NewDefaultPackageFinder(ctx, allDeps, jarRoot, client)
	if err != nil {
		return err
	}

	// Extract the main entrypoint.
	manifest, err := jarRoot.Open(ManifestFilePath)
	if err != nil {
		return err
	}

	mainClasses, err := GetMainClasses(manifest)
	if err != nil {
		return err
	}
	log.Debug("Found", "main classes", mainClasses)

	classPaths := []string{"./"}
	classPaths = append(classPaths, nestedJARs...)

	// Spring Boot applications have classes in BOOT-INF/classes.
	if _, err := jarRoot.Stat(BootInfClasses); err == nil {
		classPaths = append(classPaths, BootInfClasses)
	}

	// Look inside META-INF/services, which is used by
	// https://docs.oracle.com/javase/8/docs/api/java/util/ServiceLoader.html
	var optionalRootClasses []string

	if _, err := jarRoot.Stat(ServiceDirPath); err == nil {
		var entries []string
		err = fs.WalkDir(jarRoot.FS(), ServiceDirPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if !d.IsDir() {
				entries = append(entries, path)
			}

			return nil
		})

		if err != nil {
			return err
		}

		for _, entry := range entries {
			f, err := jarRoot.Open(entry)
			if err != nil {
				return err
			}

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				provider := scanner.Text()
				provider = strings.Split(provider, "#")[0] // remove comments

				// Some files specify the class name using the format: "class = foo".
				if strings.Contains(provider, "=") {
					provider = strings.Split(provider, "=")[1]
				}

				provider = strings.TrimSpace(provider)

				if len(provider) == 0 {
					continue
				}

				log.Debug("adding META-INF/services provider", "provider", provider, "from", entry)
				optionalRootClasses = append(optionalRootClasses, strings.ReplaceAll(provider, ".", "/"))
			}
			if err := scanner.Err(); err != nil {
				return err
			}
		}
	}

	// Enumerate reachable classes.
	enumerator := NewReachabilityEnumerator(classPaths, classFinder, AssumeAllClassesReachable, AssumeAllClassesReachable)
	result, err := enumerator.EnumerateReachabilityFromClasses(jarRoot, mainClasses, optionalRootClasses)
	if err != nil {
		return err
	}

	// Map reachable classes back to Maven group ID:artifact ID.
	reachableDeps := map[string]struct{}{}
	for _, class := range result.Classes {
		deps, err := classFinder.Find(class)
		if err != nil {
			log.Debug("Failed to find dep mapping", "class", class, "error", err)
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
		log.Debug("Found use of dynamic code loading", "class", class)
		deps, err := classFinder.Find(class)
		if err != nil {
			log.Debug("Failed to find dep mapping", "class", class, "error", err)
			continue
		}
		for _, dep := range deps {
			dynamicLoadingDeps[dep] = struct{}{}
		}
	}
	for _, class := range result.UsesDependencyInjection {
		log.Debug("Found use of dependency injection", "class", class)
		deps, err := classFinder.Find(class)
		if err != nil {
			log.Debug("Failed to find dep mapping", "class", class, "error", err)
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
		log.Debug("Reachable", "dep", dep, "dynamic code", dynamicLoading, "dep injection", injection)
	}

	for _, dep := range allDeps {
		name := getFullPackageName(dep)
		if _, ok := reachableDeps[name]; !ok {
			log.Debug("Not reachable", "dep", name)
		}
	}

	log.Debug("finished analysis", "reachable", len(reachableDeps), "unreachable", len(allDeps)-len(reachableDeps), "all", len(allDeps))

	for i := range inv.Packages {
		if inv.Packages[i].Locations[0] != jarPath {
			continue
		}
		metadata := inv.Packages[i].Metadata.(*archivemeta.Metadata)
		artifactName := fmt.Sprintf("%s:%s", metadata.GroupID, metadata.ArtifactID)
		if _, exists := reachableDeps[artifactName]; !exists {
			inv.Packages[i].Annotations = append(inv.Packages[i].Annotations, extractor.Unknown)
			log.Infof("Annotated unreachable package '%s' with: %v", artifactName, inv.Packages[i].Annotations)
		}
	}

	return nil
}

// unzipJAR unzips a JAR to a target directory. It also returns a list of paths
// to all the nested JARs found while unzipping.
func unzipJAR(jarPath string, input *enricher.ScanInput, jarRoot *os.Root) (nestedJARs []string, err error) {
	file, err := input.ScanRoot.FS.Open(filepath.ToSlash(jarPath))
	if err != nil {
		return nil, err
	}

	fileReaderAt, _ := file.(io.ReaderAt)

	defer file.Close()

	info, _ := file.Stat()
	l := info.Size()

	r, err := zip.NewReader(fileReaderAt, l)

	if err != nil {
		return nil, err
	}

	maxFileSize := 500 * 1024 * 1024 // 500 MB in bytes

	for _, file := range r.File {
		relativePath := file.Name
		if err != nil {
			return nil, err
		}

		if file.FileInfo().IsDir() {
			if err := mkdirAll(jarRoot, relativePath, 0755); err != nil {
				return nil, err
			}
		} else {
			if err := mkdirAll(jarRoot, path.Dir(relativePath), 0755); err != nil {
				return nil, err
			}

			if strings.HasSuffix(relativePath, ".jar") {
				nestedJARs = append(nestedJARs, relativePath)
			}

			source, err := file.Open()
			if err != nil {
				return nil, err
			}

			f, err := jarRoot.Create(relativePath)
			if err != nil {
				return nil, err
			}

			limitedSource := &io.LimitedReader{R: source, N: int64(maxFileSize)}
			_, err = io.Copy(f, limitedSource)
			if err != nil {
				f.Close()
				return nil, err
			}
			f.Close()
		}
	}

	return nestedJARs, nil
}
