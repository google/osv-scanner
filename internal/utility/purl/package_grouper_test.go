package purl_test

import (
	"reflect"
	"testing"

	"github.com/google/osv-scanner/v2/internal/utility/purl"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestGroupPackageByPURL_ShouldUnifyPackages(t *testing.T) {
	t.Parallel()
	input := []models.PackageSource{
		{
			Source: models.SourceInfo{
				Path: "/dir/lockfile.xml",
				Type: "",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(osvconstants.EcosystemMaven),
					},
					Vulnerabilities: []*osvschema.Vulnerability{
						{Id: "GHSA-456"},
					},
					Groups: []models.GroupInfo{
						{
							IDs:     []string{"GHSA-456"},
							Aliases: []string{"GHSA-456"},
						},
					},
					DepGroups: []string{"build"},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(osvconstants.EcosystemMaven),
					},
					Vulnerabilities: []*osvschema.Vulnerability{
						{Id: "GHSA-456"},
					},
					Groups: []models.GroupInfo{
						{
							IDs:     []string{"GHSA-456"},
							Aliases: []string{"GHSA-456"},
						},
					},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(osvconstants.EcosystemMaven),
					},
					Vulnerabilities: []*osvschema.Vulnerability{
						{Id: "GHSA-456"},
					},
					Groups: []models.GroupInfo{
						{
							IDs:     []string{"GHSA-456"},
							Aliases: []string{"GHSA-456"},
						},
					},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:package-2",
						Ecosystem: string(osvconstants.EcosystemMaven),
						Version:   "1.0.0",
					},
				},
			},
		},
		{
			Source: models.SourceInfo{
				Path: "/dir2/lockfile.json",
				Type: "",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(osvconstants.EcosystemMaven),
					},
					Vulnerabilities: []*osvschema.Vulnerability{
						{Id: "GHSA-456"},
					},
					Groups: []models.GroupInfo{
						{
							IDs:     []string{"GHSA-456"},
							Aliases: []string{"GHSA-456"},
						},
					},
					DepGroups: []string{"test"},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:package-2",
						Ecosystem: string(osvconstants.EcosystemMaven),
						Version:   "1.0.0",
					},
				},
			},
		},
	}

	result, errors := purl.Group(input)

	expected := map[string]models.PackageVulns{
		"pkg:maven/foo.bar/the-first-package@1.0.0": {
			Package: models.PackageInfo{
				Name:      "foo.bar:the-first-package",
				Version:   "1.0.0",
				Ecosystem: string(osvconstants.EcosystemMaven),
			},
			Vulnerabilities: []*osvschema.Vulnerability{
				{Id: "GHSA-456"},
			},
			Groups: []models.GroupInfo{
				{
					IDs:     []string{"GHSA-456"},
					Aliases: []string{"GHSA-456"},
				},
			},
			DepGroups: []string{"build", "test"},
		},
		"pkg:maven/foo.bar/package-2@1.0.0": {
			Package: models.PackageInfo{
				Name:      "foo.bar:package-2",
				Version:   "1.0.0",
				Ecosystem: string(osvconstants.EcosystemMaven),
			},
		},
	}

	if len(errors) > 0 {
		t.Errorf("Unexpected errors: %v", errors)
	}
	if len(result) != len(expected) {
		t.Errorf("Expected %d packages, got %d", len(expected), len(result))
	}
	for expectedPURL, expectedInfo := range expected {
		info, exists := result[expectedPURL]

		if !exists {
			t.Errorf("Expected package %s to be in the results", expectedPURL)
		}
		if !reflect.DeepEqual(info, expectedInfo) {
			t.Errorf("Expected package %s to be %v, got %v", expectedPURL, expectedInfo, info)
		}
	}
}

func TestGroupPackageByPURL_NpmScopedPackage(t *testing.T) {
	t.Parallel()
	input := []models.PackageSource{
		{
			Source: models.SourceInfo{
				Path: "/dir/package-lock.json",
				Type: "",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "@babel/traverse",
						Version:   "7.23.0",
						Ecosystem: string(osvconstants.EcosystemNPM),
					},
				},
				{
					Package: models.PackageInfo{
						Name:      "lodash",
						Version:   "4.17.21",
						Ecosystem: string(osvconstants.EcosystemNPM),
					},
				},
			},
		},
	}

	result, errors := purl.Group(input)
	if len(errors) > 0 {
		t.Fatalf("Unexpected errors: %v", errors)
	}

	expectedScopedPURL := "pkg:npm/%40babel/traverse@7.23.0"
	if _, ok := result[expectedScopedPURL]; !ok {
		t.Errorf("Expected result to contain canonical scoped npm PURL %q", expectedScopedPURL)
	}

	expectedUnscopedPURL := "pkg:npm/lodash@4.17.21"
	if _, ok := result[expectedUnscopedPURL]; !ok {
		t.Errorf("Expected result to contain canonical unscoped npm PURL %q", expectedUnscopedPURL)
	}
}
