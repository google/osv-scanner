package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/jedib0t/go-pretty/v6/text"
)

func TestPrintVerticalHeaderEscapesGitHubActionsCommandChars(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	printVerticalHeader(SourceResult{
		Name:             "safe\r::warning::pwn\nnext",
		PackageTypeCount: AnalysisCount{Regular: 1},
	}, out)

	got := text.StripEscape(out.String())
	if strings.ContainsAny(got, "\r") {
		t.Fatalf("vertical output contains raw carriage return: %q", got)
	}

	if !strings.Contains(got, "safe%0D::warning::pwn%0Anext") {
		t.Fatalf("vertical output does not contain escaped source name: %q", got)
	}
}

func TestTableBuilderInnerEscapesSourceColumnCommandChars(t *testing.T) {
	t.Parallel()

	rows := tableBuilderInner(Result{
		Ecosystems: []EcosystemResult{
			{
				Name: "npm",
				Sources: []SourceResult{
					{
						Name: "lockfiles\r::warning::pwn\nnext/package-lock.json",
						Type: models.SourceTypeProjectPackage,
						Packages: []PackageResult{
							{
								Name:             "lodash",
								InstalledVersion: "4.17.20",
								RegularVulns: []VulnResult{
									{
										GroupIDs:         []string{"GHSA-35jh-r3h4-6jhm"},
										SeverityScore:    "7.2",
										IsFixable:        false,
										VulnAnalysisType: VulnTypeRegular,
									},
								},
							},
						},
					},
				},
			},
		},
	}, VulnTypeRegular)

	if len(rows) != 1 {
		t.Fatalf("tableBuilderInner returned %d rows, want 1", len(rows))
	}

	sourceColumn, ok := rows[0].row[len(rows[0].row)-1].(string)
	if !ok {
		t.Fatalf("source column has type %T, want string", rows[0].row[len(rows[0].row)-1])
	}

	if strings.ContainsAny(sourceColumn, "\r\n") {
		t.Fatalf("source column contains raw line terminator: %q", sourceColumn)
	}

	if !strings.Contains(sourceColumn, "lockfiles%0D::warning::pwn%0Anext/package-lock.json") {
		t.Fatalf("source column does not contain escaped source name: %q", sourceColumn)
	}
}
