package output

import (
	"testing"

	"github.com/google/osv-scanner/internal/testsnapshot"
)

func Test_createSARIFHelpText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args groupedSARIFFinding
		want testsnapshot.Snapshot
	}{
		{
			args: testsnapshot.LoadJSON[groupedSARIFFinding](t,
				testsnapshot.New(
					"fixtures/vuln-grouped.json",
					map[string]string{},
				),
			),
			want: testsnapshot.New(
				"fixtures/sarif-output.md",
				map[string]string{
					"/path/to/sub-rust-project/osv-scanner.toml": "\\path\\to\\sub-rust-project/osv-scanner.toml",
				},
			),
		},
		{
			args: testsnapshot.LoadJSON[groupedSARIFFinding](t,
				testsnapshot.New(
					"fixtures/commit-grouped.json",
					map[string]string{},
				),
			),
			want: testsnapshot.New(
				"fixtures/sarif-commit-output.md",
				map[string]string{
					"/usr/local/google/home/rexpan/Documents/Project/engine/osv-scanner.toml": "\\usr\\local\\google\\home\\rexpan\\Documents\\Project\\engine/osv-scanner.toml",
				},
			),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := createSARIFHelpText(&tt.args)
			testsnapshot.AssertText(t, tt.want, got)
		})
	}
}
