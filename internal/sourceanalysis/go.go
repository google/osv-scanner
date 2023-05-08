package sourceanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/osv-scanner/internal/sourceanalysis/govulncheck"
	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/slices"
	"golang.org/x/vuln/scan"
)

func goAnalysis(dir string, pkgs []models.PackageVulns) (_ []models.PackageVulns, err error) {
	vulns, vulnsByID := vulnsFromAllPkgs(pkgs)

	dbdir, err := os.MkdirTemp("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		rerr := os.RemoveAll(dir)
		if err == nil {
			err = rerr
		}
	}()

	for _, vuln := range vulns {
		dat, err := json.Marshal(vuln)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(fmt.Sprintf("%s.json", vuln.ID), dat, 0644); err != nil {
			return nil, err
		}
	}

	cmd := scan.Command(context.Background(), "-db", fmt.Sprintf("file://%s", dbdir), "-C", dir, "-json", "./...")
	var b bytes.Buffer
	cmd.Stdout = &b
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	h := &osvHandler{
		osvToFinding: map[string]*govulncheck.Finding{},
	}
	if err := handleJSON(bytes.NewReader(b.Bytes()), h); err != nil {
		return nil, err
	}
	return matchAnalysisWithPackageVulns(pkgs, h.osvToFinding, vulnsByID), nil
}

type osvHandler struct {
	osvToFinding map[string]*govulncheck.Finding
}

func (h *osvHandler) Finding(f *govulncheck.Finding) {
	h.osvToFinding[f.OSV] = f
}

func handleJSON(from io.Reader, to *osvHandler) error {
	dec := json.NewDecoder(from)
	for dec.More() {
		msg := govulncheck.Message{}
		// decode the next message in the stream
		if err := dec.Decode(&msg); err != nil {
			return err
		}
		if msg.Finding != nil {
			to.Finding(msg.Finding)
		}
	}

	return nil
}

func matchAnalysisWithPackageVulns(pkgs []models.PackageVulns, gvcResByVulnID map[string]*govulncheck.Finding, vulnsByID map[string]models.Vulnerability) []models.PackageVulns {
	for _, pv := range pkgs {
		// Use index to keep reference to original element in slice
		for groupIdx := range pv.Groups {
			for _, vulnID := range pv.Groups[groupIdx].IDs {
				analysis := &pv.Groups[groupIdx].ExperimentalAnalysis
				if *analysis == nil {
					*analysis = make(map[string]models.AnalysisInfo)
				}

				gvcVuln, ok := gvcResByVulnID[vulnID]
				if !ok { // If vulnerability not found, check if it contain any source information
					fillNotImportedAnalysisInfo(vulnsByID, vulnID, pv, analysis)
					continue
				}
				// Module list is unlikely to be very big, linear search is fine
				containsModule := slices.ContainsFunc(gvcVuln.Modules, func(module *govulncheck.Module) bool {
					return module.Path == pv.Package.Name
				})

				if !containsModule {
					// Code does not import module, so definitely not called
					(*analysis)[vulnID] = models.AnalysisInfo{
						Called: false,
					}
				} else {
					// Code does import module, check if it's called
					(*analysis)[vulnID] = models.AnalysisInfo{
						Called: isCalled(gvcVuln),
					}
				}
			}
		}
	}
	return pkgs
}

// isCalled reports whether the vulnerability is called, therefore
// affecting the target source code or binary.
func isCalled(v *govulncheck.Finding) bool {
	for _, m := range v.Modules {
		for _, p := range m.Packages {
			if len(p.CallStacks) > 0 {
				return true
			}
		}
	}
	return false
}

// fillNotImportedAnalysisInfo checks for any source information in advisories, and sets called to false
func fillNotImportedAnalysisInfo(vulnsByID map[string]models.Vulnerability, vulnID string, pv models.PackageVulns, analysis *map[string]models.AnalysisInfo) {
	for _, v := range vulnsByID[vulnID].Affected {
		// TODO: Compare versions to see if this is the correct affected element
		// ver, err := semantic.Parse(pv.Package.Version, semantic.SemverVersion)
		if v.Package.Name != pv.Package.Name {
			continue
		}
		_, hasImportsField := v.EcosystemSpecific["imports"]
		if hasImportsField {
			// If there is source information, then analysis has been performed, and
			// code does not import the vulnerable package, so definitely not called
			(*analysis)[vulnID] = models.AnalysisInfo{
				Called: false,
			}
		}
	}
}
