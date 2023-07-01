package sourceanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/google/osv-scanner/internal/sourceanalysis/govulncheck"
	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/vuln/scan"
)

// goAnalysis runs govulncheck on the module inside moddir, and marks whether a
// given package vulnerability is called or not.
func goAnalysis(moddir string, pkgs []models.PackageVulns) (_ []models.PackageVulns, err error) {
	vulns, idToVuln := vulnsFromAllPkgs(pkgs)
	idToFinding, err := runGovulncheck(moddir, vulns)
	if err != nil {
		return nil, err
	}

	return packageVulnsWithCalledInfo(pkgs, idToFinding, idToVuln), nil
}

func runGovulncheck(moddir string, vulns []models.Vulnerability) (map[string]*govulncheck.Finding, error) {
	// Create a temporary directory containing all of the vulnerabilities that
	// are passed in to check against govulncheck.
	//
	// This enables OSV scanner to supply the OSV vulnerabilities to run
	// against govulncheck and manage the database separately from vuln.go.dev.
	dbdir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}
	defer func() {
		rerr := os.RemoveAll(dbdir)
		if err == nil {
			err = rerr
		}
	}()

	for _, vuln := range vulns {
		dat, err := json.Marshal(vuln)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(fmt.Sprintf("%s/%s.json", dbdir, vuln.ID), dat, 0600); err != nil {
			return nil, err
		}
	}

	// Run govulncheck on the module at moddir and vulnerability database that
	// was just created.
	cmd := scan.Command(context.Background(), "-db", fmt.Sprintf("file://%s", dbdir), "-C", moddir, "-json", "./...")
	var b bytes.Buffer
	cmd.Stdout = &b
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	// Group the output of govulncheck based on the OSV ID.
	h := &osvHandler{
		idToFinding: map[string]*govulncheck.Finding{},
	}
	if err := handleJSON(bytes.NewReader(b.Bytes()), h); err != nil {
		return nil, err
	}

	return h.idToFinding, nil
}

type osvHandler struct {
	idToFinding map[string]*govulncheck.Finding
}

func (h *osvHandler) Finding(f *govulncheck.Finding) {
	h.idToFinding[f.OSV] = f
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

func packageVulnsWithCalledInfo(pkgs []models.PackageVulns, idToFinding map[string]*govulncheck.Finding, idToVuln map[string]models.Vulnerability) (output []models.PackageVulns) {
	for _, pkg := range pkgs {
		for groupIdx := range pkg.Groups {
			if pkg.Groups[groupIdx].ExperimentalAnalysis == nil {
				pkg.Groups[groupIdx].ExperimentalAnalysis = map[string]*models.AnalysisInfo{}
			}

			for fid, finding := range idToFinding {
				if !isRelevantFinding(pkg, finding) {
					continue
				}

				called := isCalled(finding)
				pkg.Groups[groupIdx].ExperimentalAnalysis[fid] = &models.AnalysisInfo{
					Called: called,
				}
			}
		}
		for vid, vuln := range idToVuln {
			if _, ok := idToFinding[vid]; ok {
				// This OSV will already be accounted for above.
				continue
			}
			for _, aff := range vuln.Affected {
				if _, ok := aff.EcosystemSpecific["imports"]; !ok {
					continue
				}
				if aff.Package.Name != pkg.Package.Name {
					continue
				}
				for groupIdx := range pkg.Groups {
					if _, ok := pkg.Groups[groupIdx].ExperimentalAnalysis[vid]; !ok {
						pkg.Groups[groupIdx].ExperimentalAnalysis[vid] = &models.AnalysisInfo{
							Called: false,
						}
					}
				}
			}
		}
		output = append(output, pkg)
	}

	return output
}

// isCalled reports whether the vulnerability is called, therefore
// affecting the target source code or binary.
func isCalled(finding *govulncheck.Finding) bool {
	// If a vulnerability is called, the first stack in the trace will contain
	// the name of the vulnerable function.
	return finding.Trace[0].Function != ""
}

func isRelevantFinding(pkg models.PackageVulns, finding *govulncheck.Finding) bool {
	if pkg.Package.Name != finding.Trace[0].Module {
		return false
	}
	for groupIdx := range pkg.Groups {
		for _, gid := range pkg.Groups[groupIdx].IDs {
			if gid == finding.OSV {
				return true
			}
		}
	}

	return false
}
