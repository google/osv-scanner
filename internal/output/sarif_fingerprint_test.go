package output

import (
	"fmt"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
)

// Common test parameter values used by both test functions
var (
	testVulnIDs = []string{"CVE-2021-1234", "CVE-2022-5678"}
	testArtifactPaths = []string{"/path/to/package.json", "/different/path/go.mod"}
	testPackages = []models.PackageInfo{
		{Name: "pkg1", Version: "1.0.0"},
		{Name: "pkg2", Version: "1.0.0"},
		{Name: "pkg1", Version: "2.0.0"},
		{Name: "pkg1", Commit: "abc123"},
	}
)

func Test_createSARIFFingerprint(t *testing.T) {
	t.Parallel()

	// Generate all combinations from common test parameters
	for i, vulnID := range testVulnIDs {
		for j, artifactPath := range testArtifactPaths {
			for k, pkg := range testPackages {
				testName := fmt.Sprintf("vuln_%d_path_%d_pkg_%d", i, j, k)
				vulnID := vulnID
				artifactPath := artifactPath
				pkg := pkg

				t.Run(testName, func(t *testing.T) {
					t.Parallel()

					got := createSARIFFingerprint(vulnID, artifactPath, pkg)

					// Verify it returns a 64-character hex string (SHA-256 produces 32 bytes = 64 hex chars)
					if len(got) != 64 {
						t.Errorf("createSARIFFingerprint() returned fingerprint of length %d, want 64", len(got))
					}

					// Verify determinism by calling it again with the same inputs
					got2 := createSARIFFingerprint(vulnID, artifactPath, pkg)
					if got != got2 {
						t.Errorf("createSARIFFingerprint() is not deterministic: first call = %v, second call = %v", got, got2)
					}
				})
			}
		}
	}
}

func Test_createSARIFFingerprint_DifferentInputs(t *testing.T) {
	t.Parallel()

	// Generate all combinations from common test parameters and their fingerprints
	type testCase struct {
		vulnID       string
		artifactPath string
		pkg          models.PackageInfo
		fingerprint  string
	}

	var testCases []testCase
	for _, vulnID := range testVulnIDs {
		for _, artifactPath := range testArtifactPaths {
			for _, pkg := range testPackages {
				fp := createSARIFFingerprint(vulnID, artifactPath, pkg)
				testCases = append(testCases, testCase{
					vulnID:       vulnID,
					artifactPath: artifactPath,
					pkg:          pkg,
					fingerprint:  fp,
				})
			}
		}
	}

	// Verify that all fingerprints are unique
	for i := range testCases {
		for j := i + 1; j < len(testCases); j++ {
			if testCases[i].fingerprint == testCases[j].fingerprint {
				t.Errorf("Expected different fingerprints but got same:\n"+
					"  Input 1: vulnID=%q, path=%q, pkg=%+v\n"+
					"  Input 2: vulnID=%q, path=%q, pkg=%+v\n"+
					"  Fingerprint: %s",
					testCases[i].vulnID, testCases[i].artifactPath, testCases[i].pkg,
					testCases[j].vulnID, testCases[j].artifactPath, testCases[j].pkg,
					testCases[i].fingerprint)
			}
		}
	}
}
