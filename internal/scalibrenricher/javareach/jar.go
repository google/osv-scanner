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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/osv-scalibr/extractor"
	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	"github.com/google/osv-scalibr/log"
	"golang.org/x/sync/errgroup"
)

const (
	maxGoroutines = 4

	rootArtifact = "<root>"
)

var (
	ErrClassNotFound    = errors.New("class not found")
	ErrArtifactNotFound = errors.New("artifact not found")
)

// MavenPackageFinder is an interface for finding Maven packages that contain a
// class path.
type MavenPackageFinder interface {
	// Find returns a list of package names that contain a class path.
	Find(classPath string) ([]string, error)
	// Find returns a list of class names that are part of a package.
	Classes(artifact string) ([]string, error)
}

// DefaultPackageFinder implements a MavenPackageFinder that downloads all .jar
// dependencies on demand and computes a local class to jar mapping.
type DefaultPackageFinder struct {
	// map of class to maven dependencies.
	classMap map[string][]string
	// map of maven dependency to class files.
	artifactMap map[string][]string
}

// loadJARMappings loads class mappings from a JAR archive.
func loadJARMappings(metadata *archivemeta.Metadata, reader *zip.Reader, classMap map[string][]string, artifactMap map[string][]string, lock *sync.Mutex) {
	// TODO(#787): Validate that we can rely on the directory structure to mirror the
	// class package path.
	lock.Lock()
	for _, f := range reader.File {
		if strings.HasSuffix(f.Name, ".class") {
			artifactName := fmt.Sprintf("%s:%s", metadata.GroupID, metadata.ArtifactID)
			addClassMapping(artifactName, f.Name, classMap, artifactMap)
		}
	}
	lock.Unlock()
}

func addClassMapping(artifactName, class string, classMap map[string][]string, artifactMap map[string][]string) {
	name := strings.TrimSuffix(class, ".class")
	if strings.HasPrefix(name, MetaInfVersions) {
		// Strip the version after the META-INF/versions/<version>/
		name = strings.TrimPrefix(name, MetaInfVersions)[1:]
		name = name[strings.Index(name, "/")+1:]
	}

	classMap[name] = append(classMap[name], artifactName)
	artifactMap[artifactName] = append(artifactMap[artifactName], name)
	log.Debug("mapping", "name", name, "to", classMap[name])
}

// openNestedJAR opens a nested JAR given by `jarPaths` containing progressively
// deeper relative paths of JARs.
func openNestedJAR(jarPaths []string) (*zip.Reader, error) {
	var zipr *zip.Reader
	var nbytes int64

	for len(jarPaths) > 0 {
		var file fs.File

		if zipr == nil {
			// Path the first JAR, which lives on the filesystem.
			var err error
			file, err = os.Open(jarPaths[0])
			if err != nil {
				return nil, err
			}
		} else {
			// Nested JAR, which must be opened from the current JAR archive.
			var err error
			file, err = zipr.Open(jarPaths[0])
			if err != nil {
				return nil, err
			}
		}

		data, err := io.ReadAll(file)
		if err != nil {
			file.Close()
			return nil, err
		}
		file.Close()
		nbytes = int64(len(data))
		zipr, err = zip.NewReader(bytes.NewReader(data), nbytes)
		if err != nil {
			return nil, err
		}
		jarPaths = jarPaths[1:]
	}
	return zipr, nil
}

func checkNestedJARContains(inv *extractor.Package) ([]string, bool) {
	metadata := inv.Metadata.(*archivemeta.Metadata)
	for i := len(inv.Locations) - 1; i >= 0; i-- {
		// Find /path/root.jar/path/to/nested.jar
		const jarBoundary = ".jar/"
		loc := inv.Locations[i]
		if !strings.HasSuffix(loc, ".jar") || !strings.Contains(loc, jarBoundary) {
			continue
		}

		// Nested .jar found.
		// Separate the path components into /path/root.jar, path/to/nested.jar
		var jarPaths []string
		for strings.Contains(loc, jarBoundary) {
			idx := strings.Index(loc, jarBoundary) + len(jarBoundary)
			path := loc[:idx-1]
			jarPaths = append(jarPaths, path)
			loc = loc[idx:]
		}
		jarPaths = append(jarPaths, loc)

		// Check if the artifact ID is in the jar name to make sure the jar is for the artifact.
		if strings.Contains(jarPaths[len(jarPaths)-1], metadata.ArtifactID) {
			log.Debug("nested jar", "paths", jarPaths, "groupId", metadata.GroupID, "artifactId", metadata.ArtifactID)
			return jarPaths, true
		}
		break
	}

	return nil, false
}

// extractClassMappings extracts class mappings from a .jar dependency by
// downloading and unpacking the .jar from the relevant registry.
func extractClassMappings(ctx context.Context, inv *extractor.Package, classMap map[string][]string, artifactMap map[string][]string, lock *sync.Mutex) error {
	var reader *zip.Reader

	metadata := inv.Metadata.(*archivemeta.Metadata)
	if jarPaths, ok := checkNestedJARContains(inv); ok {
		var err error
		reader, err = openNestedJAR(jarPaths)
		if err != nil {
			return err
		}
	}

	if reader == nil {
		// Didn't found a nested JAR containing the artifact.
		// Try downloading the same package from Maven.
		// TODO(#787): Handle Non-Maven central repositories.
		jarURL := fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar",
			strings.ReplaceAll(metadata.GroupID, ".", "/"), metadata.ArtifactID, inv.Version, metadata.ArtifactID, inv.Version)

		file, err := os.CreateTemp("", "")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		defer file.Close()

		log.Debug("downloading", "jar", jarURL)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jarURL, nil)
		if err != nil {
			return err
		}

		client := &http.Client{}
		resp, _ := client.Do(req)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("jar not found: %s", jarURL)
		}

		nbytes, err := io.Copy(file, resp.Body)
		if err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()

		_, err = file.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}

		reader, err = zip.NewReader(file, nbytes)
		if err != nil {
			return err
		}
	}

	loadJARMappings(metadata, reader, classMap, artifactMap, lock)

	return nil
}

// NewDefaultPackageFinder creates a new DefaultPackageFinder based on a set of
// inventory.
func NewDefaultPackageFinder(ctx context.Context, inv []*extractor.Package, jarDir string) (*DefaultPackageFinder, error) {
	// Download pkg, unpack, and store class mappings for each detected dependency.
	classMap := map[string][]string{}
	artifactMap := map[string][]string{}
	lock := new(sync.Mutex)
	group := new(errgroup.Group)
	group.SetLimit(maxGoroutines)

	for _, i := range inv {
		group.Go(func() error {
			return extractClassMappings(ctx, i, classMap, artifactMap, lock)
		})
	}

	if err := group.Wait(); err != nil {
		// Tolerate some errors.
		log.Error("failed to download package", "err", err)
	}

	if err := mapRootClasses(jarDir, classMap, artifactMap); err != nil {
		return nil, err
	}

	return &DefaultPackageFinder{
		classMap:    classMap,
		artifactMap: artifactMap,
	}, nil
}

// mapRootClasses maps class files to the root application where we can determine that association.
func mapRootClasses(jarDir string, classMap map[string][]string, artifactMap map[string][]string) error {
	// Spring Boot.
	// TODO(#787): Handle non-Spring Boot applications. We could add heuristic for
	// detecting root application classes when the class structure is flat based
	// on the class hierarchy.
	bootInfClasses := filepath.Join(jarDir, BootInfClasses)
	if _, err := os.Stat(bootInfClasses); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	log.Debug("Found Spring Boot classes", "classes", bootInfClasses)
	return filepath.Walk(bootInfClasses, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".class") {
			name, err := filepath.Rel(bootInfClasses, path)
			if err != nil {
				return err
			}

			addClassMapping(rootArtifact, name, classMap, artifactMap)
			return nil
		}

		return nil
	})
}

// Find returns a list of package names that contain a class path.
func (f *DefaultPackageFinder) Find(classPath string) ([]string, error) {
	if pkg, ok := f.classMap[classPath]; ok {
		return pkg, nil
	}

	return nil, ErrClassNotFound
}

// Find returns a list of package names that contain a class path.
func (f *DefaultPackageFinder) Classes(artifact string) ([]string, error) {
	if classes, ok := f.artifactMap[artifact]; ok {
		return classes, nil
	}

	return nil, ErrArtifactNotFound
}

// GetMainClass extracts the main class name from the MANIFEST.MF file in a .jar.
func GetMainClasses(manifest io.Reader) ([]string, error) {
	// Extract the Main-Class specified in MANIFEST.MF:
	// https://docs.oracle.com/javase/tutorial/deployment/jar/appman.html
	const mainClass = "Main-Class:"
	// Spring Boot specific metadata.
	const startClass = "Start-Class:"
	markers := []string{mainClass, startClass}

	scanner := bufio.NewScanner(manifest)

	var classes []string
	var lines []string

	// Read all lines into memory for easier processing.
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	for i := range lines {
		line := strings.TrimSpace(lines[i])
		for _, marker := range markers {
			if strings.HasPrefix(line, marker) {
				class := strings.TrimSpace(strings.TrimPrefix(line, marker))
				// Handle wrapped lines. Class names exceeding line length limits
				// may be split across multiple lines, starting with a space.
				for index := i + 1; index < len(lines); index++ {
					nextLine := lines[index]
					if strings.HasPrefix(nextLine, " ") {
						class += strings.TrimSpace(nextLine)
					} else {
						break
					}
				}
				classes = append(classes, strings.ReplaceAll(class, ".", "/"))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(classes) > 0 {
		return classes, nil
	}

	return nil, errors.New("no main class")
}
