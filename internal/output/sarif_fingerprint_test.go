package output

import (
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
)

func Test_createSARIFFingerprint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		vulnID       string
		artifactPath string
		pkg          models.PackageInfo
	}{
		{
			name:         "basic fingerprint",
			vulnID:       "CVE-2021-1234",
			artifactPath: "/path/to/package.json",
			pkg: models.PackageInfo{
				Name:    "example-package",
				Version: "1.0.0",
			},
		},
		{
			name:         "different vulnerability ID",
			vulnID:       "CVE-2022-5678",
			artifactPath: "/path/to/package.json",
			pkg: models.PackageInfo{
				Name:    "example-package",
				Version: "1.0.0",
			},
		},
		{
			name:         "different artifact path",
			vulnID:       "CVE-2021-1234",
			artifactPath: "/different/path/package.json",
			pkg: models.PackageInfo{
				Name:    "example-package",
				Version: "1.0.0",
			},
		},
		{
			name:         "different package name",
			vulnID:       "CVE-2021-1234",
			artifactPath: "/path/to/package.json",
			pkg: models.PackageInfo{
				Name:    "different-package",
				Version: "1.0.0",
			},
		},
		{
			name:         "different package version",
			vulnID:       "CVE-2021-1234",
			artifactPath: "/path/to/package.json",
			pkg: models.PackageInfo{
				Name:    "example-package",
				Version: "2.0.0",
			},
		},
		{
			name:         "package with commit",
			vulnID:       "CVE-2021-1234",
			artifactPath: "/path/to/go.mod",
			pkg: models.PackageInfo{
				Name:   "example-package",
				Commit: "abc123def456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := createSARIFFingerprint(tt.vulnID, tt.artifactPath, tt.pkg)

			// Verify it returns a 64-character hex string (SHA-256 produces 32 bytes = 64 hex chars)
			if len(got) != 64 {
				t.Errorf("createSARIFFingerprint() returned fingerprint of length %d, want 64", len(got))
			}

			// Verify determinism by calling it again with the same inputs
			got2 := createSARIFFingerprint(tt.vulnID, tt.artifactPath, tt.pkg)
			if got != got2 {
				t.Errorf("createSARIFFingerprint() is not deterministic: first call = %v, second call = %v", got, got2)
			}
		})
	}
}

func Test_createSARIFFingerprint_DifferentInputs(t *testing.T) {
	t.Parallel()

	// Define test dimensions - different values for each parameter
	vulnIDs := []string{"CVE-2021-1234", "CVE-2022-5678"}
	artifactPaths := []string{"/path/to/package.json", "/different/path/go.mod"}
	packages := []models.PackageInfo{
		{Name: "pkg1", Version: "1.0.0"},
		{Name: "pkg2", Version: "1.0.0"},
		{Name: "pkg1", Version: "2.0.0"},
		{Name: "pkg1", Commit: "abc123"},
	}

	// Generate all combinations and their fingerprints
	type testCase struct {
		vulnID       string
		artifactPath string
		pkg          models.PackageInfo
		fingerprint  string
	}

	var testCases []testCase
	for _, vulnID := range vulnIDs {
		for _, artifactPath := range artifactPaths {
			for _, pkg := range packages {
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
