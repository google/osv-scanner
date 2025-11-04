// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package source

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const testdata = "./testdata"
const reachableVulnID = "GO-2023-1558"
const unreachableVulnID = "GO-2021-0053"

func TestEnricher(t *testing.T) {
	t.Parallel()
	pkgs := setupPackages()
	vulns := setupPackageVulns()
	input := enricher.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: testdata,
			FS:   scalibrfs.DirFS("."),
		},
	}

	inv := inventory.Inventory{
		Packages:     pkgs,
		PackageVulns: vulns,
	}

	enr := NewEnricher()
	err := enr.Enrich(t.Context(), &input, &inv)

	if err != nil {
		t.Fatalf("govulncheck enrich failed: %s", err)
	}

	for _, vuln := range inv.PackageVulns {
		switch vuln.Vulnerability.Id {
		case reachableVulnID:
			if len(vuln.ExploitabilitySignals) != 0 {
				t.Fatalf("govulncheck enrich failed, expected %s to be reachable, but marked as unreachable", reachableVulnID)
			}
		case unreachableVulnID:
			if len(vuln.ExploitabilitySignals) == 0 || vuln.ExploitabilitySignals[0].Justification != vex.VulnerableCodeNotInExecutePath {
				t.Fatalf("govulncheck enrich failed, expected %s to be unreachable, but marked as reachable", unreachableVulnID)
			}
		}
	}
}

func setupPackages() []*extractor.Package {
	pkgs := []*extractor.Package{}

	pkgs = append(pkgs, &extractor.Package{
		Name:      "stdlib",
		Version:   "1.19",
		PURLType:  purl.TypeGolang,
		Locations: []string{filepath.Join(".", "go.mod")},
		Plugins:   []string{gomod.Name},
	})

	pkgs = append(pkgs, &extractor.Package{
		Name:      "github.com/gogo/protobuf",
		Version:   "1.3.1",
		PURLType:  purl.TypeGolang,
		Locations: []string{filepath.Join(".", "go.mod")},
		Plugins:   []string{gomod.Name},
	})

	pkgs = append(pkgs, &extractor.Package{
		Name:      "github.com/ipfs/go-bitfield",
		Version:   "1.0.0",
		PURLType:  purl.TypeGolang,
		Locations: []string{filepath.Join(".", "go.mod")},
		Plugins:   []string{gomod.Name},
	})

	pkgs = append(pkgs, &extractor.Package{
		Name:      "golang.org/x/image",
		Version:   "0.4.0",
		PURLType:  purl.TypeGolang,
		Locations: []string{filepath.Join(".", "go.mod")},
		Plugins:   []string{gomod.Name},
	})

	return pkgs
}

func setupPackageVulns() []*inventory.PackageVuln {
	vulns := []*inventory.PackageVuln{}

	vulns = append(vulns, &inventory.PackageVuln{
		Vulnerability: &osvschema.Vulnerability{
			Id: reachableVulnID,
		},
	})

	vulns = append(vulns, &inventory.PackageVuln{
		Vulnerability: &osvschema.Vulnerability{
			Id: unreachableVulnID,
		},
	})

	return vulns
}
