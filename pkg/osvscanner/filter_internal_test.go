package osvscanner

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/reporter"
)

func Test_filterResults(t *testing.T) {
	// t.Parallel()

	tests := []struct {
		name string
		path string
		want int
	}{
		{
			name: "filter_everything",
			path: "fixtures/filter/all",
			want: 15,
		},
		{
			name: "filter_nothing",
			path: "fixtures/filter/none",
			want: 0,
		},
		{
			name: "filter_partially",
			path: "fixtures/filter/some",
			want: 10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.Parallel()
			r := &reporter.VoidReporter{}
			// configManager looks for osv-scanner.toml in the source path.
			// Sources in the test input should point to files/folders in the text fixture folder for this to work correctly.
			configManager := config.Manager{
				DefaultConfig: config.Config{},
				ConfigMap:     make(map[string]config.Config),
			}

			got := testutility.LoadJSONFixture[models.VulnerabilityResults](t, filepath.Join(tt.path, "input.json"))
			filtered := filterResults(r, &got, &configManager, false)

			testutility.NewSnapshot().MatchJSON(t, got)

			if filtered != tt.want {
				t.Errorf("filterResults() = %v, want %v", filtered, tt.want)
			}
		})
	}
}
