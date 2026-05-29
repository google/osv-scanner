package output_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestPrintVerticalResults_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintVerticalResults(args.vulnResult, outputWriter, true)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintVerticalResults_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintVerticalResults(args.vulnResult, outputWriter, false)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintVerticalResults_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintVerticalResults(args.vulnResult, outputWriter, false)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

// TestPrintVerticalResults_CRSanitization verifies that carriage-return bytes
// embedded in package name and version fields are URL-encoded as %0D in the
// vertical output. Raw \r bytes reach the GHA runner as line boundaries,
// enabling workflow command injection (e.g. ::stop-commands::, ::add-mask::).
// This covers the three call sites in vertical.go that were not sanitized by
// the original fix in PR #2750: printVerticalVulnerabilitiesForPackages,
// printVerticalLicenseViolations, and printVerticalPkgDeprecatedSummary.
func TestPrintVerticalResults_CRSanitization(t *testing.T) {
	t.Parallel()

	injectedName := "lodash\r::stop-commands::DISABLEDXYZ\r"
	injectedVersion := "4.17.20\r::stop-commands::DISABLEDXYZ\r"

	assertSanitized := func(t *testing.T, result string) {
		t.Helper()
		if strings.Contains(result, "\r") {
			t.Errorf("vertical output contains raw \\r — workflow command injection possible.\nOutput: %q", result)
		}
		if !strings.Contains(result, "%0D") {
			t.Errorf("vertical output does not contain %%0D encoding for \\r.\nOutput: %q", result)
		}
	}

	t.Run("vulnerability_output", func(t *testing.T) {
		t.Parallel()

		vulnResult := &models.VulnerabilityResults{
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{Path: "/lock/package-lock.json", Type: models.SourceTypeProjectPackage},
					Packages: []models.PackageVulns{
						{
							Package: models.PackageInfo{
								Name:      injectedName,
								Version:   injectedVersion,
								Ecosystem: "npm",
							},
							Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}, MaxSeverity: "7.5"}},
							Vulnerabilities: []*osvschema.Vulnerability{
								{Id: "OSV-1", Summary: "Test vulnerability"},
							},
						},
					},
				},
			},
		}

		buf := &bytes.Buffer{}
		output.PrintVerticalResults(vulnResult, buf, true)
		assertSanitized(t, buf.String())
	})

	t.Run("license_violation_output", func(t *testing.T) {
		t.Parallel()

		vulnResult := &models.VulnerabilityResults{
			ExperimentalAnalysisConfig: models.ExperimentalAnalysisConfig{
				Licenses: models.ExperimentalLicenseConfig{
					Allowlist: []models.License{"ISC"},
				},
			},
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{Path: "/lock/package-lock.json", Type: models.SourceTypeProjectPackage},
					Packages: []models.PackageVulns{
						{
							Package: models.PackageInfo{
								Name:      injectedName,
								Version:   injectedVersion,
								Ecosystem: "npm",
							},
							LicenseViolations: []models.License{"MIT"},
						},
					},
				},
			},
		}

		buf := &bytes.Buffer{}
		output.PrintVerticalResults(vulnResult, buf, false)
		assertSanitized(t, buf.String())
	})

	t.Run("deprecated_package_output", func(t *testing.T) {
		t.Parallel()

		vulnResult := &models.VulnerabilityResults{
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{Path: "/lock/package-lock.json", Type: models.SourceTypeProjectPackage},
					Packages: []models.PackageVulns{
						{
							Package: models.PackageInfo{
								Name:       injectedName,
								Version:    injectedVersion,
								Ecosystem:  "npm",
								Deprecated: true,
							},
							Vulnerabilities: []*osvschema.Vulnerability{},
						},
					},
				},
			},
		}

		buf := &bytes.Buffer{}
		output.PrintVerticalResults(vulnResult, buf, false)
		assertSanitized(t, buf.String())
	})
}
