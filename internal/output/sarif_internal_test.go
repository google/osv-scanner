package output

import (
	"testing"

	"github.com/google/osv-scanner/internal/testfixture"
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
			args: testfixture.LoadJSON[groupedSARIFFinding](t, "fixtures/vuln-grouped.json"),
			want: testsnapshot.New(map[string]string{
				"/path/to/sub-rust-project/osv-scanner.toml": "\\path\\to\\sub-rust-project/osv-scanner.toml",
			}),
		},
		{
			args: testfixture.LoadJSON[groupedSARIFFinding](t, "fixtures/commit-grouped.json"),
			want: testsnapshot.New(map[string]string{
				"/usr/local/google/home/rexpan/Documents/Project/engine/osv-scanner.toml": "\\usr\\local\\google\\home\\rexpan\\Documents\\Project\\engine/osv-scanner.toml",
			}),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := createSARIFHelpText(&tt.args)
			tt.want.MatchText(t, got)
		})
	}
}
