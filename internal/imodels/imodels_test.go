package imodels

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
)

func Test_Name(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		pkg  *extractor.Package
		want string
	}{
		{
			name: "Regular_package",
			pkg: &extractor.Package{
				Name: "regular-pkg",
			},
			want: "regular-pkg",
		},
		{
			name: "GIT_ecosystem_with_repo",
			pkg: &extractor.Package{
				Name: "openssl@3.5",
				SourceCode: &extractor.SourceCodeIdentifier{
					Repo: "github.com/openssl/openssl",
				},
				Metadata: &osvscannerjson.Metadata{
					Ecosystem: "GIT",
				},
			},
			want: "github.com/openssl/openssl",
		},
		{
			name: "GIT_ecosystem_without_repo",
			pkg: &extractor.Package{
				Name: "openssl@3.5",
				SourceCode: &extractor.SourceCodeIdentifier{
					Repo: "",
				},
				Metadata: &osvscannerjson.Metadata{
					Ecosystem: "GIT",
				},
			},
			want: "openssl@3.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Name(tt.pkg); got != tt.want {
				t.Errorf("Name(*extractor.Package) = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ClearCache(t *testing.T) {
	t.Parallel()

	// Start the first scan
	StartScan()

	pkg := &extractor.Package{
		Name:     "pkg",
		Version:  "1.0",
		PURLType: "npm",
		Plugins:  []string{cdx.Name},
	}

	// First call should populate the cache
	if name := Name(pkg); name != "pkg" {
		t.Errorf("expected Name(pkg) = %q, got %q", "pkg", name)
	}

	// Modify package name, but keep same pointer
	pkg.Name = "pkg-modified"

	// Calling Name(pkg) again without ending the scan should return cached name "pkg"
	if name := Name(pkg); name != "pkg" {
		t.Errorf("expected Name(pkg) = %q (cached), got %q", "pkg", name)
	}

	// Start a second concurrent scan
	StartScan()

	// End the first scan
	EndScan()

	// Cache should NOT be cleared because the second scan is still active.
	// So calling Name(pkg) should still return cached name "pkg".
	if name := Name(pkg); name != "pkg" {
		t.Errorf("expected Name(pkg) = %q (cached, active scan remaining), got %q", "pkg", name)
	}

	// End the second scan (no scans remaining)
	EndScan()

	// Calling Name(pkg) after all scans ended should return new name "pkg-modified"
	if name := Name(pkg); name != "pkg-modified" {
		t.Errorf("expected Name(pkg) = %q (recached, all scans ended), got %q", "pkg-modified", name)
	}
}
