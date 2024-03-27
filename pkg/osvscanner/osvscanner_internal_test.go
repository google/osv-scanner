package osvscanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/config"
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
		tt := tt // Reinitialize for t.Parallel()
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &reporter.VoidReporter{}
			// ConfigManager looks for osv-scanner.toml in the source path.
			// Sources in the test input should point to files/folders in the text fixture folder for this to work correctly.
			configManager := config.ConfigManager{
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

func Test_getSubmodulesVia_scanGit(t *testing.T) {
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
				repoDir: "fixtures/example-git-with-submodule",
			},
			wantErr: false,
			wantPkg: []scannedPackage{
				{
					Commit: "d96688a8b8e6aa0a88f63d36c1f30ca143d75291",
					Source: models.SourceInfo{
						Path: "fixtures/example-git-with-submodule",
						Type: "git",
					},
				},
				{
					Commit: "35689cf0b9cd25b127dcc6fd5461577dd1cbef25",
					Source: models.SourceInfo{
						Path: "fixtures/example-git-with-submodule/submodule-test",
						Type: "git",
					},
				},
			},
		},
	}

	makeSubmodulesFixtureDotGit(t)
	defer makeSubmodulesFixtureHiddenGit(t)

	for _, tt := range tests {
		pkg, err := scanGit(tt.args.r, tt.args.repoDir)
		if (err != nil) != tt.wantErr {
			t.Errorf("scanGit() error = %v, wantErr %v", err, tt.wantErr)
		}
		if diff := cmp.Diff(tt.wantPkg, pkg); diff != "" {
			t.Errorf("scanGit() package = %v, wantPackage %v", pkg, tt.wantPkg)
		}
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

	makeGitFixtureDotGit(t)
	defer makeGitFixtureHiddenGit(t)

	for _, tt := range tests {
		pkg, err := scanGit(tt.args.r, tt.args.repoDir)
		if (err != nil) != tt.wantErr {
			t.Errorf("scanGit() error = %v, wantErr %v", err, tt.wantErr)
		}
		if diff := cmp.Diff(tt.wantPkg, pkg); diff != "" {
			t.Errorf("scanGit() package = %v, wantPackage %v", pkg, tt.wantPkg)
		}
	}
}

func makeSubmodulesFixtureDotGit(t *testing.T) {
	t.Helper()

	err := os.Rename("fixtures/example-git-with-submodule/git-hidden", "fixtures/example-git-with-submodule/.git")
	if err != nil {
		t.Fatalf("can't rename git-hidden folder: %s", err)
	}

	err = os.Rename("fixtures/example-git-with-submodule/submodule-test/git-hidden",
		"fixtures/example-git-with-submodule/submodule-test/.git")
	if err != nil {
		t.Fatalf("can't rename subdir's git-hidden folder because: %s", err)
	}
}

func makeSubmodulesFixtureHiddenGit(t *testing.T) {
	// func makeGitFixtureHiddenGit(t *testing.T) {
	t.Helper()

	err := os.Rename("fixtures/example-git-with-submodule/.git", "fixtures/example-git-with-submodule/git-hidden")
	if err != nil {
		t.Fatalf("can't rename .git folder, because: %s", err)
	}

	err = os.Rename("fixtures/example-git-with-submodule/submodule-test/.git",
		"fixtures/example-git-with-submodule/submodule-test/git-hidden")
	if err != nil {
		t.Fatalf("can't rename subdir's .git folder, because: %s", err)
	}
}

func makeGitFixtureDotGit(t *testing.T) {
	t.Helper()

	err := os.Rename("fixtures/example-git/git-hidden", "fixtures/example-git/.git")
	if err != nil {
		t.Fatalf("can't rename git-hidden folder: %s", err)
	}
}

func makeGitFixtureHiddenGit(t *testing.T) {
	t.Helper()

	err := os.Rename("fixtures/example-git/.git", "fixtures/example-git/git-hidden")
	if err != nil {
		t.Fatalf("can't rename git-hidden folder: %s", err)
	}
}
