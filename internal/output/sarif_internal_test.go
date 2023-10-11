package output

import (
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
)

func Test_createSARIFHelpText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		gv       groupedSARIFFinding
		wantPath string
	}{
		{
			gv:       testutility.LoadJSONFixture[groupedSARIFFinding](t, "fixtures/vuln-grouped.json"),
			wantPath: "fixtures/sarif-output.md",
		},
		{
			gv:       testutility.LoadJSONFixture[groupedSARIFFinding](t, "fixtures/commit-grouped.json"),
			wantPath: "fixtures/sarif-commit-output.md",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sarifHelpText := createSARIFHelpText(&tt.gv)
			testutility.AssertMatchFixtureText(t, tt.wantPath, sarifHelpText)
		})
	}
}
