package output

import (
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
)

func Test_createSARIFHelpText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args groupedSARIFFinding
		want testutility.Snapshot
	}{
		{
			args: testutility.LoadJSONFixture[groupedSARIFFinding](t, "fixtures/vuln-grouped.json"),
			want: testutility.NewSnapshot().WithWindowsReplacements(map[string]string{
				"\\path\\to\\sub-rust-project\\osv-scanner.toml": "/path/to/sub-rust-project/osv-scanner.toml",
			}),
		},
		{
			args: testutility.LoadJSONFixture[groupedSARIFFinding](t, "fixtures/commit-grouped.json"),
			want: testutility.NewSnapshot().WithWindowsReplacements(map[string]string{
				"<rootdir>\\Documents\\Project\\engine\\osv-scanner.toml": "<rootdir>/Documents/Project/engine/osv-scanner.toml",
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := createSARIFHelpText(&tt.args)
			tt.want.MatchText(t, got)
		})
	}
}
