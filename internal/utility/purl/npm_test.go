package purl_test

import (
	"testing"

	"github.com/google/osv-scanner/v2/internal/utility/purl"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

func TestNpmExtraction_shouldExtractPackages(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name              string
		packageInfo       models.PackageInfo
		expectedNamespace string
		expectedName      string
	}{
		{
			name: "unscoped_package",
			packageInfo: models.PackageInfo{
				Name:      "lodash",
				Version:   "4.17.21",
				Ecosystem: string(osvconstants.EcosystemNPM),
			},
			expectedNamespace: "",
			expectedName:      "lodash",
		},
		{
			name: "scoped_package",
			packageInfo: models.PackageInfo{
				Name:      "@babel/traverse",
				Version:   "7.23.0",
				Ecosystem: string(osvconstants.EcosystemNPM),
			},
			expectedNamespace: "@babel",
			expectedName:      "traverse",
		},
	}

	for _, tc := range testCases {
		testCase := tc
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			namespace, name, err := purl.FromNpm(testCase.packageInfo)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if namespace != testCase.expectedNamespace {
				t.Errorf("got namespace %q, want %q", namespace, testCase.expectedNamespace)
			}
			if name != testCase.expectedName {
				t.Errorf("got name %q, want %q", name, testCase.expectedName)
			}
		})
	}
}

func TestNpmExtraction_shouldFilterPackages(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name        string
		packageInfo models.PackageInfo
	}{
		{
			name: "empty_name",
			packageInfo: models.PackageInfo{
				Name:      "",
				Version:   "1.0.0",
				Ecosystem: string(osvconstants.EcosystemNPM),
			},
		},
		{
			name: "scoped_missing_package_name",
			packageInfo: models.PackageInfo{
				Name:      "@babel/",
				Version:   "1.0.0",
				Ecosystem: string(osvconstants.EcosystemNPM),
			},
		},
		{
			name: "scoped_missing_scope_name",
			packageInfo: models.PackageInfo{
				Name:      "@/traverse",
				Version:   "1.0.0",
				Ecosystem: string(osvconstants.EcosystemNPM),
			},
		},
		{
			name: "scoped_multiple_slashes",
			packageInfo: models.PackageInfo{
				Name:      "@babel/traverse/extra",
				Version:   "1.0.0",
				Ecosystem: string(osvconstants.EcosystemNPM),
			},
		},
		{
			name: "unscoped_with_slash",
			packageInfo: models.PackageInfo{
				Name:      "babel/traverse",
				Version:   "1.0.0",
				Ecosystem: string(osvconstants.EcosystemNPM),
			},
		},
	}

	for _, tc := range testCases {
		testCase := tc
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := purl.FromNpm(testCase.packageInfo)
			if err == nil {
				t.Errorf("Package %v should have returned error", testCase.packageInfo)
			}
		})
	}
}

func TestFromPackage_NpmCanonicalPURL(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name     string
		pkg      models.PackageInfo
		expected string
	}{
		{
			name: "unscoped",
			pkg: models.PackageInfo{
				Name:      "lodash",
				Version:   "4.17.21",
				Ecosystem: string(osvconstants.EcosystemNPM),
			},
			expected: "pkg:npm/lodash@4.17.21",
		},
		{
			name: "scoped",
			pkg: models.PackageInfo{
				Name:      "@babel/traverse",
				Version:   "7.23.0",
				Ecosystem: string(osvconstants.EcosystemNPM),
			},
			expected: "pkg:npm/%40babel/traverse@7.23.0",
		},
	}

	for _, tc := range testCases {
		testCase := tc
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			p, err := purl.FromPackage(testCase.pkg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.ToString() != testCase.expected {
				t.Errorf("got %s, want %s", p.ToString(), testCase.expected)
			}
		})
	}
}
