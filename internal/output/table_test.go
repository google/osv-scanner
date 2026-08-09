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

func TestPrintTableResults_StandardTerminalWidth_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, 80, true)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintTableResults_StandardTerminalWidth_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, 80, false)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintTableResults_StandardTerminalWidth_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, 80, true)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintTableResults_LongTerminalWidth_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, 800, true)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintTableResults_LongTerminalWidth_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, 800, false)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintTableResults_LongTerminalWidth_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, 800, true)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintTableResults_NoTerminalWidth_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, -1, true)

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintTableResults_NoTerminalWidth_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, -1, false)

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintTableResults_NoTerminalWidth_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, -1, true)

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

// TestPrintTableResults_CRSanitization verifies that carriage-return bytes
// embedded in package name and version fields are URL-encoded as %0D in the
// table output. Raw \r bytes reach the GHA runner as line boundaries,
// enabling workflow command injection (e.g. ::stop-commands::, ::add-mask::).
// The table library writes directly to outputWriter via SetOutputMirror, with
// no intermediate render-then-sanitize step, so this covers the main
// vulnerability table call site in table.go that was not covered by the
// sanitization already applied elsewhere in this file (source title, license
// violations, binary package names). The filtered/hidden-vulnerability table
// (table.go's second, analogous call site) receives the identical fix but
// isn't independently covered here, since constructing a fixture that
// exercises the "hidden vuln" filtering path requires internal aggregation
// logic not reachable from this package's public test surface.
func TestPrintTableResults_CRSanitization(t *testing.T) {
	t.Parallel()

	injectedName := "lodash\r::stop-commands::DISABLEDXYZ\r"
	injectedVersion := "4.17.20\r::stop-commands::DISABLEDXYZ\r"

	assertSanitized := func(t *testing.T, result string) {
		t.Helper()
		if strings.Contains(result, "\r") {
			t.Errorf("table output contains raw \\r — workflow command injection possible.\nOutput: %q", result)
		}
		if !strings.Contains(result, "%0D") {
			t.Errorf("table output does not contain %%0D encoding for \\r.\nOutput: %q", result)
		}
	}

	// containsOSResult (and therefore which of table.go's two top-level table
	// builders PrintTableResults dispatches to) is decided per source.Type:
	// a non-OS source type (e.g. a regular project lockfile) routes through
	// tableBuilder/tableBuilderInner; an OS-package source type routes
	// through printSummaryResult instead. The two sub-tests below exercise
	// both paths so each fixed call site is actually reached.

	t.Run("tableBuilderInner_non_git_branch", func(t *testing.T) {
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
		output.PrintTableResults(vulnResult, buf, 80, true)
		assertSanitized(t, buf.String())
	})

	t.Run("tableBuilderInner_git_commit_branch", func(t *testing.T) {
		t.Parallel()

		vulnResult := &models.VulnerabilityResults{
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{Path: "/repo/dep", Type: models.SourceTypeProjectPackage},
					Packages: []models.PackageVulns{
						{
							Package: models.PackageInfo{
								Name:      injectedName,
								Version:   injectedVersion,
								Ecosystem: "",
								Commit:    "1234567890abcdef1234567890abcdef12345678",
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
		output.PrintTableResults(vulnResult, buf, 80, true)
		assertSanitized(t, buf.String())
	})

	t.Run("printSummaryResult_main_table", func(t *testing.T) {
		t.Parallel()

		vulnResult := &models.VulnerabilityResults{
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{Path: "/os/dpkg", Type: models.SourceTypeOSPackage},
					Packages: []models.PackageVulns{
						{
							Package: models.PackageInfo{
								Name:      injectedName,
								Version:   injectedVersion,
								Ecosystem: "Debian",
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
		output.PrintTableResults(vulnResult, buf, 80, true)
		assertSanitized(t, buf.String())
	})

	t.Run("license_summary_table", func(t *testing.T) {
		t.Parallel()

		vulnResult := &models.VulnerabilityResults{
			ExperimentalAnalysisConfig: models.ExperimentalAnalysisConfig{
				Licenses: models.ExperimentalLicenseConfig{Summary: true},
			},
			LicenseSummary: []models.LicenseCount{
				{Name: models.License(injectedName), Count: 1},
			},
			Results: []models.PackageSource{
				{
					Source: models.SourceInfo{Path: "/lock/package-lock.json", Type: models.SourceTypeProjectPackage},
					Packages: []models.PackageVulns{
						{
							Package: models.PackageInfo{Name: "clean-pkg", Version: "1.0.0", Ecosystem: "npm"},
						},
					},
				},
			},
		}

		buf := &bytes.Buffer{}
		output.PrintTableResults(vulnResult, buf, 80, true)
		assertSanitized(t, buf.String())
	})
}
