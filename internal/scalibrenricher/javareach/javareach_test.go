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

package javareach_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/v2/internal/scalibrenricher/javareach"
)

const (
	testJar               = "javareach-test.jar"
	reachableJar          = "reachable-dep-test.jar"
	unreachableJar        = "unreachable-dep-test.jar"
	reachableGroupID      = "org.apache.commons"
	reachableArtifactID   = "commons-lang3"
	unreachableGroupID    = "org.eclipse.jetty"
	unreachableArtifactID = "jetty-servlets"
)

func TestScan(t *testing.T) {
	t.Parallel()
	jar := filepath.Join("testdata", reachableJar)

	mockClient := mockClient(t)
	enr := javareach.NewEnricher(mockClient)

	pkgs := setupPackages([]string{testJar})
	input := enricher.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: jar,
			FS:   scalibrfs.DirFS("."),
		},
	}
	inv := inventory.Inventory{
		Packages: pkgs,
	}
	err := enr.Enrich(t.Context(), &input, &inv)
	if err != nil {
		t.Fatalf("Javareach enrich failed: %s", err)
	}

	for _, pkg := range inv.Packages {
		if pkg.Metadata.(*archivemeta.Metadata).ArtifactID == reachableArtifactID {
			for _, annotation := range pkg.Annotations {
				if annotation == extractor.Unknown {
					t.Fatalf("Javareach enrich failed, expected %s to be reachable, but marked as unreachable", pkg.Name)
				}
			}
		}
		if pkg.Metadata.(*archivemeta.Metadata).ArtifactID == unreachableArtifactID {
			hasUnreachableAnnotation := false
			for _, annotation := range pkg.Annotations {
				if annotation == extractor.Unknown {
					hasUnreachableAnnotation = true
				}
			}
			if !hasUnreachableAnnotation {
				t.Fatalf("Javareach enrich failed, expected %s to be unreachable, but marked as reachable", pkg.Name)
			}
		}
	}
}

func mockClient(t *testing.T) *http.Client {
	t.Helper()
	// mock a server to act as Maven Central to avoid network requests.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath := r.URL.Path
		if strings.Contains(requestPath, unreachableArtifactID) {
			http.ServeFile(w, r, filepath.Join("testdata", unreachableJar))
		} else if strings.Contains(requestPath, reachableArtifactID) {
			http.ServeFile(w, r, filepath.Join("testdata", reachableJar))
		}
	}))

	originalURL := javareach.MavenBaseURL
	javareach.MavenBaseURL = server.URL

	t.Cleanup(func() {
		javareach.MavenBaseURL = originalURL
		server.Close()
	})

	return server.Client()
}

func setupPackages(names []string) []*extractor.Package {
	pkgs := []*extractor.Package{}
	var reachablePkgName = fmt.Sprintf("%s:%s", reachableGroupID, reachableArtifactID)
	var unreachablePkgName = fmt.Sprintf("%s:%s", unreachableGroupID, unreachableArtifactID)

	for _, n := range names {
		reachablePkg := &extractor.Package{
			Name:      reachablePkgName,
			Version:   "3.12.0",
			PURLType:  purl.TypeMaven,
			Metadata:  &archivemeta.Metadata{ArtifactID: reachableArtifactID, GroupID: reachableGroupID},
			Locations: []string{filepath.Join("testdata", n)},
			Plugins:   []string{archive.Name},
		}

		unreachablePkg := &extractor.Package{
			Name:      unreachablePkgName,
			Version:   "9.4.40.v20210413",
			PURLType:  purl.TypeMaven,
			Metadata:  &archivemeta.Metadata{ArtifactID: unreachableArtifactID, GroupID: unreachableGroupID},
			Locations: []string{filepath.Join("testdata", n)},
			Plugins:   []string{archive.Name},
		}

		pkgs = append(pkgs, reachablePkg, unreachablePkg)
	}

	return pkgs
}
