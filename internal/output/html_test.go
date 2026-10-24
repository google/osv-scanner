package output_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
	"golang.org/x/net/html"
)

func TestPrintHTMLResults_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintHTMLResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Fatalf("Error writing HTML output: %s", err)
		}
		checkHTMLFixFilter(t, args.vulnResult, outputWriter.Bytes())
	})
}

func TestPrintHTMLResults_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintHTMLResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Fatalf("Error writing HTML output: %s", err)
		}
		checkHTMLFixFilter(t, args.vulnResult, outputWriter.Bytes())
	})
}

func TestPrintHTMLResults_WithLicenseSummary(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseSummary(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintHTMLResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Fatalf("Error writing HTML output: %s", err)
		}
		checkHTMLFixFilter(t, args.vulnResult, outputWriter.Bytes())
	})
}

func TestPrintHTMLResults_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintHTMLResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Fatalf("Error writing HTML output: %s", err)
		}
		checkHTMLFixFilter(t, args.vulnResult, outputWriter.Bytes())
	})
}

func TestPrintHTMLResults_FixableContainerVulnerabilities(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/html-fix-filter.json")
	if err != nil {
		t.Fatal(err)
	}
	var vulnResult models.VulnerabilityResults
	if err := json.Unmarshal(data, &vulnResult); err != nil {
		t.Fatal(err)
	}

	var rendered bytes.Buffer
	if err := output.PrintHTMLResults(&vulnResult, &rendered); err != nil {
		t.Fatal(err)
	}
	rows := checkHTMLFixFilter(t, &vulnResult, rendered.Bytes())

	// Hidden fixable vulnerabilities must have metadata for filtering, but must
	// not contribute to the regular vulnerability count on the checkbox.
	if got := output.BuildResults(&vulnResult).VulnCount.FixableCount.Fixed; got != 2 {
		t.Errorf("Got %d regular fixable vulnerabilities, want 2", got)
	}
	for _, id := range []string{"OSV-UNCALLED-FIX", "OSV-UNIMPORTANT-FIX"} {
		if rows[id+"/true/true"] != 1 {
			t.Errorf("Missing fixability metadata for hidden vulnerability %s", id)
		}
	}
}

// Check the rendered DOM contract used by the filter, including hidden rows and
// reports without OS results or vulnerabilities.
func checkHTMLFixFilter(t *testing.T, vulnResult *models.VulnerabilityResults, rendered []byte) map[string]int {
	t.Helper()

	doc, err := html.Parse(bytes.NewReader(rendered))
	if err != nil {
		t.Fatalf("Parsing HTML output: %s", err)
	}

	result := output.BuildResults(vulnResult)
	wantRows := map[string]int{}
	for _, ecosystem := range result.Ecosystems {
		for _, source := range ecosystem.Sources {
			for _, pkg := range source.Packages {
				for _, vuln := range pkg.RegularVulns {
					wantRows[fmt.Sprintf("%s/%t/false", vuln.ID, vuln.IsFixable)] += 1
				}
				for _, vuln := range pkg.HiddenVulns {
					wantRows[fmt.Sprintf("%s/%t/true", vuln.ID, vuln.IsFixable)] += 1
				}
			}
		}
	}

	gotRows := map[string]int{}
	checkboxCount := 0
	for node := range doc.Descendants() {
		if node.Type != html.ElementNode {
			continue
		}

		if htmlAttribute(node, "id") == "fixable-checkbox" {
			checkboxCount += 1
			if node.Data != "input" || htmlAttribute(node, "type") != "checkbox" {
				t.Error("Fix availability control must be a checkbox")
			}
			for _, attr := range node.Attr {
				if attr.Key == "checked" {
					t.Error("Fix availability filter must be off by default")
				}
			}
			if node.Parent == nil || htmlAttribute(node.Parent, "for") != "fixable-checkbox" {
				t.Fatal("Fix availability checkbox must have an associated label")
			}
			if node.Parent.Parent == nil || htmlAttribute(node.Parent.Parent, "id") != "type-filter-option-container" {
				t.Error("Fix availability checkbox must be inside the existing Filters dropdown")
			}
			var label strings.Builder
			for child := range node.Parent.Descendants() {
				if child.Type == html.TextNode {
					label.WriteString(child.Data)
				}
			}
			if got, want := strings.Join(strings.Fields(label.String()), " "), fmt.Sprintf("Fix available (%d)", result.VulnCount.FixableCount.Fixed); got != want {
				t.Errorf("Fix availability label = %q, want %q", got, want)
			}
		}

		classes := strings.Fields(htmlAttribute(node, "class"))
		if node.Data == "tr" && slices.Contains(classes, "vuln-tr") {
			fixable := htmlAttribute(node, "data-fixable")
			if fixable != "true" && fixable != "false" {
				t.Errorf("Vulnerability %q has invalid fixability %q", htmlAttribute(node, "data-vuln-id"), fixable)
			}
			key := htmlAttribute(node, "data-vuln-id") + "/" + fixable + "/" + strconv.FormatBool(slices.Contains(classes, "uncalled-tr"))
			gotRows[key] += 1
		}
	}

	if checkboxCount != 1 {
		t.Errorf("Got %d fix availability checkboxes, want 1", checkboxCount)
	}
	if diff := cmp.Diff(wantRows, gotRows); diff != "" {
		t.Errorf("Rendered vulnerability fixability (-want +got):\n%s", diff)
	}

	return gotRows
}

func htmlAttribute(node *html.Node, key string) string {
	for _, attr := range node.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}

	return ""
}
