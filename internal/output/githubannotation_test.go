package output_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func TestPrintGHAnnotationReport_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintGHAnnotationReport(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing GH annotation output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintGHAnnotationReport_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintGHAnnotationReport(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing GH annotation output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintGHAnnotationReport_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintGHAnnotationReport(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing GH annotation output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintGHAnnotationReport_Escaping(t *testing.T) {
	t.Parallel()

	cwd := filepath.ToSlash(testutility.GetCurrentWorkingDirectory(t))

	vulnerablePackage := func(name string) models.PackageVulns {
		return models.PackageVulns{
			Package: models.PackageInfo{Name: name, Version: "1.2.3", Ecosystem: "npm"},
			Groups:  []models.GroupInfo{{IDs: []string{"OSV-1"}, MaxSeverity: "7.5"}},
		}
	}

	deprecatedPackage := func(name string) models.PackageVulns {
		return models.PackageVulns{
			Package: models.PackageInfo{Name: name, Version: "1.2.3", Ecosystem: "npm", Deprecated: true},
		}
	}

	tests := []struct {
		name string
		path string
		pkg  models.PackageVulns
	}{
		{
			name: "path_with_newlines",
			path: cwd + "/path/with\r\n::warning::newlines/lockfile",
			pkg:  vulnerablePackage("mine1"),
		},
		{
			name: "path_with_colons_and_commas",
			path: cwd + "/path/with::colons,and=commas/lockfile",
			pkg:  vulnerablePackage("mine1"),
		},
		{
			name: "path_with_percent_encoded_sequences",
			path: cwd + "/path/with%0A%0D%25%3A%2C/lockfile",
			pkg:  vulnerablePackage("mine1"),
		},
		{
			name: "path_outside_working_directory",
			path: filepath.ToSlash(filepath.Dir(cwd)) + "/elsewhere\n::warning::/lockfile",
			pkg:  vulnerablePackage("mine1"),
		},
		{
			name: "relative_path",
			path: "relative/path\n::warning::to/lockfile",
			pkg:  vulnerablePackage("mine1"),
		},
		{
			name: "package_name_with_special_characters",
			path: cwd + "/path/to/lockfile",
			pkg:  vulnerablePackage("mine\r\n::warning::1%0A::,"),
		},
		{
			name: "deprecated_package_with_special_characters",
			path: cwd + "/path/with\r\n::warning::%0A,/lockfile",
			pkg:  deprecatedPackage("mine\r\n::warning::1%0A::,"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			vulnResult := &models.VulnerabilityResults{
				Results: []models.PackageSource{
					{
						Source:   models.SourceInfo{Path: tt.path, Type: models.SourceTypeProjectPackage},
						Packages: []models.PackageVulns{tt.pkg},
					},
				},
			}

			outputWriter := &bytes.Buffer{}
			err := output.PrintGHAnnotationReport(vulnResult, outputWriter)

			if err != nil {
				t.Errorf("Error writing GH annotation output: %s", err)
			}

			testutility.NewSnapshot().MatchText(t, outputWriter.String())
		})
	}
}
