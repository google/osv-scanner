package purl_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/utility/purl"

	"github.com/google/osv-scanner/pkg/models"
)

func TestComposerExtraction_shouldExtractPackages(t *testing.T) {
	t.Parallel()
	testCase := struct {
		packageInfo       models.PackageInfo
		expectedNamespace string
		expectedName      string
	}{
		packageInfo: models.PackageInfo{
			Name:      "symfony/yaml",
			Version:   "7.0.0",
			Ecosystem: string(models.EcosystemPackagist),
			Commit:    "",
		},
		expectedNamespace: "symfony",
		expectedName:      "yaml",
	}

	namespace, name, err := purl.FromComposer(testCase.packageInfo)

	if err != nil {
		t.Errorf("Extraction didn't succeed, package has been wrongfully filtered")
	}
	if namespace != testCase.expectedNamespace {
		t.Errorf("got %s; want %s", namespace, testCase.expectedNamespace)
	}
	if name != testCase.expectedName {
		t.Errorf("got %s; want %s", name, testCase.expectedName)
	}
}

func TestComposerExtraction_shouldFilterPackages(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name        string
		packageInfo models.PackageInfo
	}{
		{
			name: "when_package_contains_less_than_2_parts",
			packageInfo: models.PackageInfo{
				Name:      "symfony",
				Version:   "7.0.0",
				Ecosystem: string(models.EcosystemPackagist),
				Commit:    "",
			},
		},
		{
			name: "when_package_have_no_name",
			packageInfo: models.PackageInfo{
				Name:      "",
				Version:   "7.0.0",
				Ecosystem: string(models.EcosystemPackagist),
				Commit:    "",
			},
		},
	}

	for _, test := range testCases {
		testCase := test
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := purl.FromComposer(testCase.packageInfo)

			if err == nil {
				t.Errorf("Package %v should have been filtered\n", testCase.packageInfo)
			}
		})
	}
}
