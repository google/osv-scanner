package purl_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/utility/purl"

	"github.com/google/osv-scanner/pkg/models"
)

func TestGolangExtraction_shouldExtractPackages(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name              string
		packageInfo       models.PackageInfo
		expectedNamespace string
		expectedName      string
	}{
		{
			name: "when_package_comes_from_go_registry",
			packageInfo: models.PackageInfo{
				Name:      "golang.org/x/mod",
				Version:   "v0.14.0",
				Ecosystem: string(models.EcosystemGo),
				Commit:    "",
			},
			expectedNamespace: "golang.org/x",
			expectedName:      "mod",
		},
		{
			name: "when_package_comes_from_github",
			packageInfo: models.PackageInfo{
				Name:      "github.com/urfave/cli/v2",
				Version:   "v2.26.0",
				Ecosystem: string(models.EcosystemGo),
				Commit:    "",
			},
			expectedNamespace: "github.com/urfave/cli",
			expectedName:      "v2",
		},
		{
			name: "when_package_uses_a_domain",
			packageInfo: models.PackageInfo{
				Name:      "go.opencensus.io",
				Version:   "v0.24.0",
				Ecosystem: string(models.EcosystemGo),
				Commit:    "",
			},
			expectedNamespace: "",
			expectedName:      "go.opencensus.io",
		},
	}

	for _, test := range testCases {
		testCase := test
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			namespace, name, err := purl.FromGo(testCase.packageInfo)

			if err != nil {
				t.Errorf("Extraction didn't succeed, package has been wrongfully filtered")
			}
			if namespace != testCase.expectedNamespace {
				t.Errorf("got %s; want %s", namespace, testCase.expectedNamespace)
			}
			if name != testCase.expectedName {
				t.Errorf("got %s; want %s", name, testCase.expectedName)
			}
		})
	}
}

func TestGolangExtraction_shouldFilterPackages(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name        string
		packageInfo models.PackageInfo
	}{
		{
			name: "when_package_have_no_name",
			packageInfo: models.PackageInfo{
				Name:      "",
				Version:   "v2.26.0",
				Ecosystem: string(models.EcosystemGo),
				Commit:    "",
			},
		},
	}

	for _, test := range testCases {
		testCase := test
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := purl.FromGo(testCase.packageInfo)

			if err == nil {
				t.Errorf("Package %v should have been filtered\n", testCase.packageInfo)
			}
		})
	}
}
