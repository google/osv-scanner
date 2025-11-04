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

// Package source provides an enricher that uses govulncheck to scan Go source code.
package source

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"golang.org/x/vuln/scan"
)

const (
	// Name is the unique name of this enricher.
	Name = "enricher/reachability/govulncheck/source"
)

// Enricher is an enricher that runs govulncheck on Go source code.
type Enricher struct{}

// Name returns the name of the enricher.
func (e *Enricher) Name() string {
	return Name
}

// Version returns the version of the enricher.
func (e *Enricher) Version() int {
	return 0
}

// Requirements returns the requirements of the enricher.
func (e *Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network:  plugin.NetworkOnline,
		DirectFS: true,
	}
}

// RequiredPlugins returns the names of the plugins required by this enricher.
func (e *Enricher) RequiredPlugins() []string {
	return []string{gomod.Name}
}

func NewEnricher() Enricher {
	return Enricher{}
}

// Enrich runs govulncheck on the Go modules in the inventory.
func (e *Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	cmd := exec.CommandContext(ctx, "go", "version")
	_, err := cmd.Output()
	if err != nil {
		log.Infof("Skipping call analysis on Go code since Go is not installed.")
		return nil //nolint:nilerr
	}

	goModVersions := make(map[string]string)
	for _, pkg := range inv.Packages {
		if !slices.Contains(pkg.Plugins, gomod.Name) {
			continue
		}
		if pkg.Name == "stdlib" {
			for _, l := range pkg.Locations {
				if goModVersions[l] != "" {
					continue
				}

				// Set GOVERSION to the Go version in go.mod.
				goModVersions[l] = pkg.Version

				continue
			}
		}
	}

	for goModLocation, goVersion := range goModVersions {
		modDir := filepath.Dir(goModLocation)
		absModDir := filepath.Join(input.ScanRoot.Path, modDir)
		findings, err := e.runGovulncheck(ctx, absModDir, goVersion)
		if err != nil {
			log.Errorf("govulncheck on %s: %v", modDir, err)
			continue
		}

		if len(findings) == 0 {
			continue
		}

		e.addSignals(inv, findings)
	}

	return nil
}

func (e *Enricher) addSignals(inv *inventory.Inventory, idToFindings map[string][]*Finding) {
	for _, pv := range inv.PackageVulns {
		findings, exist := idToFindings[pv.Vulnerability.Id]
		// Skip if no findings for this package vulnerability ID
		if !exist {
			continue
		}

		isReachable := false
		for _, f := range findings {
			if len(f.Trace) > 0 && f.Trace[0].Function != "" {
				isReachable = true
				break
			}
		}

		if !isReachable {
			pv.ExploitabilitySignals = append(pv.ExploitabilitySignals, &vex.FindingExploitabilitySignal{
				Plugin:        Name,
				Justification: vex.VulnerableCodeNotInExecutePath,
			})
		}
	}
}

func (e *Enricher) runGovulncheck(ctx context.Context, absModDir string, goVersion string) (map[string][]*Finding, error) {
	cmd := scan.Command(ctx, "-C", absModDir, "-json", "./...")
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Env = append(os.Environ(), "GOVERSION=go"+goVersion)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	// Group the output of govulncheck based on the OSV ID.
	h := &osvHandler{
		idToFindings: map[string][]*Finding{},
	}
	if err := handleJSON(bytes.NewReader(b.Bytes()), h); err != nil {
		return nil, err
	}

	return h.idToFindings, nil
}

type osvHandler struct {
	idToFindings map[string][]*Finding
}

func (h *osvHandler) Finding(f *Finding) {
	h.idToFindings[f.OSV] = append(h.idToFindings[f.OSV], f)
}

func handleJSON(from io.Reader, to *osvHandler) error {
	dec := json.NewDecoder(from)
	for dec.More() {
		msg := Message{}
		if err := dec.Decode(&msg); err != nil {
			return err
		}
		if msg.Finding != nil {
			to.Finding(msg.Finding)
		}
	}

	return nil
}

// New returns a new govulncheck source enricher.
func New() enricher.Enricher {
	return &Enricher{}
}
