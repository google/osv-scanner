package osvscanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/internal/config"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
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
			t.Parallel()
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

func Test_scanGit(t *testing.T) {
	t.Parallel()

	type args struct {
		r       reporter.Reporter
		repoDir string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		wantPkg []scannedPackage
	}{
		{
			name: "Example Git repo",
			args: args{
				r:       &reporter.VoidReporter{},
				repoDir: "fixtures/example-git",
			},
			wantErr: false,
			wantPkg: []scannedPackage{
				{
					Commit: "862ac4bd2703b622e85f29f55a2fd8cd6caf8182",
					Source: models.SourceInfo{
						Path: "fixtures/example-git",
						Type: "git",
					},
				},
			},
		},
	}

	err := os.Rename("fixtures/example-git/git-hidden", "fixtures/example-git/.git")
	if err != nil {
		t.Errorf("can't find git-hidden folder")
	}

	for _, tt := range tests {
		pkg, err := scanGit(tt.args.r, tt.args.repoDir)
		if (err != nil) != tt.wantErr {
			t.Errorf("scanGit() error = %v, wantErr %v", err, tt.wantErr)
		}
		if !cmp.Equal(tt.wantPkg, pkg) {
			t.Errorf("scanGit() package = %v, wantPackage %v", pkg, tt.wantPkg)
		}
	}

	err = os.Rename("fixtures/example-git/.git", "fixtures/example-git/git-hidden")
	if err != nil {
		t.Errorf("can't find .git folder")
	}
}
