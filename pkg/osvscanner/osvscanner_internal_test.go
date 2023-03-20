package osvscanner

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/config"
	"github.com/google/osv-scanner/pkg/models"
)

func Test_filterResults(t *testing.T) {
	t.Parallel()

	type testCase struct {
		input       models.VulnerabilityResults
		want        models.VulnerabilityResults
		numFiltered int
		path        string
	}

	loadTestCase := func(path string) testCase {
		var testCase testCase
		testCase.input = testutility.LoadJSONFixture[models.VulnerabilityResults](t, filepath.Join(path, "input.json"))
		testCase.want = testutility.LoadJSONFixture[models.VulnerabilityResults](t, filepath.Join(path, "want.json"))
		testCase.numFiltered = len(testCase.input.Flatten()) - len(testCase.want.Flatten())
		testCase.path = path

		return testCase
	}
	tests := []struct {
		name     string
		testCase testCase
	}{
		{
			name:     "filter_everything",
			testCase: loadTestCase("fixtures/filter/all/"),
		},
		{
			name:     "filter_nothing",
			testCase: loadTestCase("fixtures/filter/none/"),
		},
		{
			name:     "filter_partially",
			testCase: loadTestCase("fixtures/filter/some/"),
		},
	}
	for _, tt := range tests {
		tt := tt // Reinitialize for t.Parallel()
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := output.NewVoidReporter()
			// ConfigManager looks for osv-scanner.toml in the source path.
			// Sources in the test input should point to files/folders in the text fixture folder for this to work correctly.
			configManager := config.ConfigManager{
				DefaultConfig: config.Config{},
				ConfigMap:     make(map[string]config.Config),
			}
			got := tt.testCase.input
			filtered := filterResults(r, &got, &configManager)
			if diff := cmp.Diff(tt.testCase.want, got); diff != "" {
				out := filepath.Join(tt.testCase.path, "out.json")
				t.Errorf("filterResults() returned an unexpected results (-want, +got):\n%s\n"+
					"Full json output written to %s", diff, out)
				testutility.CreateJSONFixture(t, out, got)
			}
			if filtered != tt.testCase.numFiltered {
				t.Errorf("filterResults() = %v, want %v", filtered, tt.testCase.numFiltered)
			}
		})
	}
}
