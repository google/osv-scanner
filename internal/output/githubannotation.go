package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

// PrintGHAnnotationReport prints Github specific annotations to outputWriter
func PrintGHAnnotationReport(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	flattened := vulnResult.Flatten()

	// TODO: Also support last affected
	groupFixedVersions := GroupFixedVersions(flattened)
	workingDir, workingDirErr := os.Getwd()

	for _, source := range vulnResult.Results {
		// TODO: Support docker images

		var artifactPath string
		var err error
		if workingDirErr == nil {
			artifactPath, err = filepath.Rel(workingDir, source.Source.Path)
			if err != nil {
				artifactPath = source.Source.Path
			}
		} else {
			artifactPath = source.Source.Path
		}

		remediationTable := CreateSourceRemediationTable(source, groupFixedVersions)

		renderedTable := remediationTable.Render()
		// // This is required since the github message rendering is a mixture of
		// // monospaced font text and markdown. Continuous spaces will be compressed
		// // down to one space, breaking the table rendering
		// renderedTable = strings.ReplaceAll(renderedTable, "  ", " &nbsp;")
		// This is required as github action annotations must be on the same terminal line
		// so we URL encode the new line character
		renderedTable = strings.ReplaceAll(renderedTable, "\n", "%0A")
		fmt.Fprintf(outputWriter, "::error file=%s::%s", artifactPath, renderedTable)
	}

	return nil
}
