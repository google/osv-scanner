package output

import (
	"fmt"
	"io"
	"log"
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
	workingDir, err := os.Getwd()
	if err != nil {
		log.Panicf("can't get working dir: %v", err)
	}

	for _, source := range vulnResult.Results {
		// TODO: Support docker images

		var artifactPath string
		var err error
		artifactPath, err = filepath.Rel(workingDir, source.Source.Path)
		if err != nil {
			artifactPath = source.Source.Path
		}

		remediationTable := CreateSourceRemediationTable(source, groupFixedVersions)

		renderedTable := remediationTable.Render()
		// This is required as github action annotations must be on the same terminal line
		// so we URL encode the new line character
		renderedTable = strings.ReplaceAll(renderedTable, "\n", "%0A")
		// Prepend the table with a new line to look nicer in the output
		fmt.Fprintf(outputWriter, "::error file=%s::%s%s", artifactPath, artifactPath, "%0A"+renderedTable)
	}

	return nil
}
