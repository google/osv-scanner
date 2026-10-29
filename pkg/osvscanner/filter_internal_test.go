package osvscanner

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func Test_filterResults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want int
	}{
		{
			name: "filter_everything",
			path: "testdata/filter/all",
			want: 15,
		},
		{
			name: "filter_nothing",
			path: "testdata/filter/none",
			want: 0,
		},
		{
			name: "filter_partially",
			path: "testdata/filter/some",
			want: 10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// configManager looks for osv-scanner.toml in the source path.
			// Sources in the test input should point to files/folders in the testdata folder for this to work correctly.
			configManager := config.Manager{
				DefaultConfig: config.Config{},
				ConfigMap:     make(map[string]config.Config),
			}

			got := testutility.LoadJSONFixture[models.VulnerabilityResults](t, filepath.Join(tt.path, "input.json"))
			filtered := filterResults(&got, &configManager, false)

			testutility.NewSnapshot().MatchJSON(t, got)

			if filtered != tt.want {
				t.Errorf("filterResults() = %v, want %v", filtered, tt.want)
			}
		})
	}
}

func Test_filterResults_CDXLocationSuffix(t *testing.T) {
	t.Parallel()

	configManager := config.Manager{
		DefaultConfig: config.Config{},
		ConfigMap:     make(map[string]config.Config),
	}

	got := testutility.LoadJSONFixture[models.VulnerabilityResults](t, filepath.Join("testdata/filter/all", "input.json"))
	for i := range got.Results {
		got.Results[i].Source.Type = models.SourceTypeSBOM
		got.Results[i].Source.Path += ":sub/package-lock.json"
	}

	filtered := filterResults(&got, &configManager, false)
	if filtered != 15 {
		t.Errorf("filterResults() with CDX location suffix = %v, want 15", filtered)
	}
}
