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

	// Test that different inputs produce different fingerprints
	fp1 := createSARIFFingerprint("CVE-1", "/path/to/file1", models.PackageInfo{Name: "pkg1", Version: "1.0.0"})
	fp2 := createSARIFFingerprint("CVE-2", "/path/to/file1", models.PackageInfo{Name: "pkg1", Version: "1.0.0"})
	fp3 := createSARIFFingerprint("CVE-1", "/path/to/file2", models.PackageInfo{Name: "pkg1", Version: "1.0.0"})
	fp4 := createSARIFFingerprint("CVE-1", "/path/to/file1", models.PackageInfo{Name: "pkg2", Version: "1.0.0"})
	fp5 := createSARIFFingerprint("CVE-1", "/path/to/file1", models.PackageInfo{Name: "pkg1", Version: "2.0.0"})

	fingerprints := []string{fp1, fp2, fp3, fp4, fp5}
	for i := range fingerprints {
		for j := i + 1; j < len(fingerprints); j++ {
			if fingerprints[i] == fingerprints[j] {
				t.Errorf("Expected different fingerprints for different inputs, but got same: %v", fingerprints[i])
			}
		}
	}
}
