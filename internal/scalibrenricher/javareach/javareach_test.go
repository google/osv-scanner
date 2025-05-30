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
	"context"
	"path/filepath"
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

const testJar = "hello-tester.jar"
const reachablePkgName = "com.fasterxml.jackson.core:jackson-annotations"
const unreachablePkgName = "org.eclipse.jetty:jetty-continuation"

func TestScan(t *testing.T) {
	enr := javareach.Enricher{}
	pkgs := setupPackages([]string{testJar})
	input := enricher.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: filepath.Join("testdata", testJar),
			FS:   scalibrfs.DirFS("."),
		},
	}
	inv := inventory.Inventory{
		Packages: pkgs,
	}
	err := enr.Enrich(context.Background(), &input, &inv)
	if err != nil {
		t.Fatalf("enricher.Enrich(%v): Expected an error, got none", pkgs)
	}

	for _, pkg := range inv.Packages {
		if pkg.Name == reachablePkgName {
			for _, annotation := range pkg.Annotations {
				// TODO (gongh@): use UNKNOWN annotation for now until we add Unreachable.
				if annotation == extractor.Unknown {
					t.Fatalf("Javareach enrich failed, expected %s to be reachable, but marked as unreachable", pkg.Name)
				}
			}
		}
		if pkg.Name == unreachablePkgName {
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

func setupPackages(names []string) []*extractor.Package {
	pkgs := []*extractor.Package{}

	for _, n := range names {
		reachablePkg := &extractor.Package{
			Name:      reachablePkgName,
			Version:   "2.0.0",
			PURLType:  purl.TypeMaven,
			Metadata:  &archivemeta.Metadata{ArtifactID: "jackson-annotations", GroupID: "com.fasterxml.jackson.core"},
			Locations: []string{filepath.Join("testdata", n)},
			Extractor: &archive.Extractor{},
		}

		unreachablePkg := &extractor.Package{
			Name:      unreachablePkgName,
			Version:   "9.4.7.RC0",
			PURLType:  purl.TypeMaven,
			Metadata:  &archivemeta.Metadata{ArtifactID: "jetty-continuation", GroupID: "org.eclipse.jetty"},
			Locations: []string{filepath.Join("testdata", n)},
			Extractor: &archive.Extractor{},
		}

		pkgs = append(pkgs, reachablePkg, unreachablePkg)
	}

	return pkgs
}
