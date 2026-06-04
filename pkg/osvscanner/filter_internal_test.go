package osvscanner

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/internal/imodels/results"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func Test_sanitizeReasonForLog(t *testing.T) {
	t.Parallel()

	got := sanitizeReasonForLog("accepted risk\n::warning title=OSV_POC::injected")
	want := "accepted risk%0A::warning title=OSV_POC::injected"
	if got != want {
		t.Errorf("sanitizeReasonForLog() = %q, want %q", got, want)
	}

	got = sanitizeReasonForLog("")
	want = "(no reason given)"
	if got != want {
		t.Errorf("sanitizeReasonForLog(empty) = %q, want %q", got, want)
	}
}

func Test_formatExtractionErrorSanitizesWorkflowCommandFields(t *testing.T) {
	t.Parallel()

	extractorName, msg := formatExtractionError(&plugin.Status{
		Name: "npm\n::warning title=PLUGIN::injected",
		Status: &plugin.ScanStatus{
			FailureReason: "failed\n::warning title=FAILURE::injected",
			FileErrors: []*plugin.FileError{
				{
					FilePath:     "repo\n::warning title=PATH::injected/package-lock.json",
					ErrorMessage: "unexpected EOF\n::warning title=ERROR::injected",
				},
			},
		},
	})

	for _, got := range []string{extractorName, msg} {
		if strings.Contains(got, "\n::warning") {
			t.Errorf("formatted extraction error contains workflow command line break: %q", got)
		}
	}

	if !strings.Contains(extractorName, "%0A::warning title=PLUGIN::injected") {
		t.Errorf("extractorName = %q, want encoded workflow command newline", extractorName)
	}
	for _, want := range []string{
		"%0A::warning title=PATH::injected",
		"%0A::warning title=ERROR::injected",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("msg = %q, want substring %q", msg, want)
		}
	}
}

func Test_filterUnscannablePackages_shortCommitHash(t *testing.T) {
	t.Parallel()

	shortHash := "bca26e4"                                 // 7 chars -- what bun.lock stores
	fullHash := "bca26e4c1e3c1e3c1e3c1e3c1e3c1e3c1e3c1e3f" // 40 chars -- valid SHA1

	tests := []struct {
		name         string
		commit       string
		wantKept     int
		wantFiltered int
	}{
		{
			name:         "short hash is skipped",
			commit:       shortHash,
			wantKept:     0,
			wantFiltered: 0, // ShowAllPackages=false, so filtered slice is empty
		},
		{
			name:         "full hash is kept",
			commit:       fullHash,
			wantKept:     1,
			wantFiltered: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scanResults := &results.ScanResults{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{
						{
							Name: "some-git-dep",
							SourceCode: &extractor.SourceCodeIdentifier{
								Commit: tt.commit,
							},
						},
					},
				},
				ConfigManager: config.Manager{
					DefaultConfig: config.Config{},
					ConfigMap:     make(map[string]config.Config),
				},
			}

			filtered := filterUnscannablePackages(scanResults, ScannerActions{})

			if len(scanResults.Inventory.Packages) != tt.wantKept {
				t.Errorf("packages kept = %d, want %d", len(scanResults.Inventory.Packages), tt.wantKept)
			}

			if len(filtered) != tt.wantFiltered {
				t.Errorf("packages in filtered slice = %d, want %d", len(filtered), tt.wantFiltered)
			}
		})
	}
}

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
