package output

import (
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
)

func Test_createSARIFHelpText(t *testing.T) {
	tests := []struct {
		name     string
		gv       groupedSARIFFinding
		wantPath string
	}{
		{
			gv:       testutility.LoadJSONFixture[groupedSARIFFinding](t, "fixtures/vuln-grouped.json"),
			wantPath: "fixtures/sarif-output.md",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sarifHelpText := createSARIFHelpText(&tt.gv)
			testutility.AssertMatchFixtureText(t, tt.wantPath, sarifHelpText)
		})
	}
}
