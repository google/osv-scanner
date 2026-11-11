package helper_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/helper"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func mockVulnResult() *models.VulnerabilityResults {
	return &models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{
					Path: "requirements.txt",
					Type: "lockfile",
				},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{
							Name:      "requests",
							Version:   "2.19.1",
							Ecosystem: "PyPI",
						},
						Vulnerabilities: []*osvschema.Vulnerability{
							{
								Id: "GHSA-xxxx-yyyy-zzzz",
							},
						},
						Groups: []models.GroupInfo{
							{
								IDs: []string{"GHSA-xxxx-yyyy-zzzz"},
							},
						},
					},
				},
			},
		},
	}
}

func TestPrintResult_GHAnnotations_WithOutputFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "annotations.txt")

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	vulns := mockVulnResult()

	err := helper.PrintResult(stdout, stderr, outputPath, "gh-annotations", vulns, false)
	if err != nil {
		t.Fatalf("PrintResult returned unexpected error: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	outputStr := string(content)
	if !strings.Contains(outputStr, "::error") || !strings.Contains(outputStr, "GHSA-xxxx-yyyy-zzzz") {
		t.Errorf("Expected output file to contain GitHub annotation '::error', got: %q", outputStr)
	}

	if stderr.Len() != 0 {
		t.Errorf("Expected stderr to be empty when output-file is specified, got: %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("Expected stdout to be empty when output-file is specified, got: %q", stdout.String())
	}
}

func TestPrintResult_GHAnnotations_NoOutputFile(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	vulns := mockVulnResult()

	err := helper.PrintResult(stdout, stderr, "", "gh-annotations", vulns, false)
	if err != nil {
		t.Fatalf("PrintResult returned unexpected error: %v", err)
	}

	if !strings.Contains(stderr.String(), "::error") {
		t.Errorf("Expected stderr to contain GitHub annotation '::error', got: %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("Expected stdout to be empty when output-file is empty, got: %q", stdout.String())
	}
}

func TestPrintResult_JSON_WithOutputFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	vulns := mockVulnResult()

	err := helper.PrintResult(stdout, stderr, outputPath, "json", vulns, false)
	if err != nil {
		t.Fatalf("PrintResult returned unexpected error: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	if !strings.Contains(string(content), "GHSA-xxxx-yyyy-zzzz") {
		t.Errorf("Expected JSON output file to contain vulnerability ID, got: %q", string(content))
	}
}
