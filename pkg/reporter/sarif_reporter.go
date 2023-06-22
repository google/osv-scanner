package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type SARIFReporter struct {
	hasPrintedError bool
	stdout          io.Writer
	stderr          io.Writer
}

func NewSarifReporter(stdout io.Writer, stderr io.Writer) *SARIFReporter {
	return &SARIFReporter{
		stdout:          stdout,
		stderr:          stderr,
		hasPrintedError: false,
	}
}

func (r *SARIFReporter) PrintError(msg string) {
	fmt.Fprint(r.stderr, msg)
	r.hasPrintedError = true
}

func (r *SARIFReporter) HasPrintedError() bool {
	return r.hasPrintedError
}

func (r *SARIFReporter) PrintText(msg string) {
	fmt.Fprint(r.stderr, msg)
}

func (r *SARIFReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRunWithInformationURI("osv-scanner", "https://github.com/google/osv-scanner")
	run.AddRule("vulnerable-packages").
		WithDescription("This manifest file contains one or more vulnerable packages.")
	flattened := vulnResult.Flatten()

	groupFixedVersions := output.GroupFixedVersions(flattened)

	for _, source := range vulnResult.Results {
		// TODO: Support docker images
		artifactPath := "file:///" + source.Source.Path
		run.AddDistinctArtifact(artifactPath)

		remediationTable := output.CreateSourceRemediationTable(source, groupFixedVersions)

		run.CreateResultForRule("vulnerable-packages").
			WithLevel("warning").
			WithMessage(sarif.NewMessage().WithMarkdown(remediationTable.RenderMarkdown()).WithText(remediationTable.Render())).
			AddLocation(
				sarif.NewLocationWithPhysicalLocation(
					sarif.NewPhysicalLocation().
						WithArtifactLocation(
							sarif.NewSimpleArtifactLocation(artifactPath))))
	}

	report.AddRun(run)

	err = report.PrettyWrite(r.stdout)
	if err != nil {
		return err
	}
	fmt.Fprintln(r.stdout)

	return nil
}
