package output

import (
	"testing"

	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func Test_createSARIFHelpText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args groupedSARIFFinding
		want testutility.Snapshot
	}{
		{
			args: testutility.LoadJSONFixture[groupedSARIFFinding](t, "testdata/vuln-grouped.json"),
			want: testutility.NewSnapshot().WithWindowsReplacements(map[string]string{
				"\\path\\to\\sub-rust-project\\osv-scanner.toml": "/path/to/sub-rust-project/osv-scanner.toml",
			}),
		},
		{
			args: testutility.LoadJSONFixture[groupedSARIFFinding](t, "testdata/commit-grouped.json"),
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

func Test_createSARIFDeprecatedHelpText(t *testing.T) {
	t.Parallel()

	pkgs := []pkgWithSource{
		{
			Package: models.PackageInfo{
				Name:       "spin",
				Version:    "0.9.8",
				Ecosystem:  "crates.io",
				Deprecated: true,
			},
			Source: models.SourceInfo{
				Path: "/path/to/sub-rust-project/Cargo.lock",
				Type: "lockfile",
			},
		},
	}

	got := createSARIFDeprecatedHelpText(pkgs)
	testutility.NewSnapshot().WithWindowsReplacements(map[string]string{
		"\\path\\to\\sub-rust-project\\osv-scanner.toml": "/path/to/sub-rust-project/osv-scanner.toml",
	}).MatchText(t, got)
}
