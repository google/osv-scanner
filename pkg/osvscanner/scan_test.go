package osvscanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func Test_networkCapability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		actions ScannerActions
		want    plugin.Network
	}{
		{
			name: "default_online",
			want: plugin.NetworkOnline,
		},
		{
			name: "offline_vulnerabilities_keeps_network_online",
			actions: ScannerActions{
				CompareOffline: true,
			},
			want: plugin.NetworkOnline,
		},
		{
			name: "plugin_network_disabled_sets_network_offline",
			actions: ScannerActions{
				PluginNetworkDisabled: true,
			},
			want: plugin.NetworkOffline,
		},
		{
			name: "full_offline_sets_network_offline",
			actions: ScannerActions{
				CompareOffline:        true,
				PluginNetworkDisabled: true,
			},
			want: plugin.NetworkOffline,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := networkCapability(tt.actions); got != tt.want {
				t.Errorf("networkCapability(%+v) = %v, want %v", tt.actions, got, tt.want)
			}
		})
	}
}

type fakePlugin struct {
	name    string
	network plugin.Network
}

func (p fakePlugin) Name() string { return p.name }
func (fakePlugin) Version() int   { return 0 }
func (p fakePlugin) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{Network: p.network}
}

func Test_removeNetworkPluginsWhenOffline(t *testing.T) {
	t.Parallel()

	newPlugins := func() []plugin.Plugin {
		return []plugin.Plugin{
			fakePlugin{name: "os/chisel", network: plugin.NetworkAny},
			fakePlugin{name: "os/ubuntu/binarytosource", network: plugin.NetworkOnline},
			fakePlugin{name: "baseimage", network: plugin.NetworkOnline},
			fakePlugin{name: "offline/only", network: plugin.NetworkOffline},
			// osvlocal requires network when downloading databases
			fakePlugin{name: osvlocal.Name, network: plugin.NetworkOnline},
		}
	}

	tests := []struct {
		name    string
		actions ScannerActions
		want    []string
	}{
		{
			name:    "online_keeps_all_plugins",
			actions: ScannerActions{},
			want:    []string{"os/chisel", "os/ubuntu/binarytosource", "baseimage", "offline/only", osvlocal.Name},
		},
		{
			name:    "offline_vulnerabilities_keeps_all_plugins",
			actions: ScannerActions{CompareOffline: true, DownloadDatabases: true},
			want:    []string{"os/chisel", "os/ubuntu/binarytosource", "baseimage", "offline/only", osvlocal.Name},
		},
		{
			name:    "offline_removes_network_plugins",
			actions: ScannerActions{CompareOffline: true, PluginNetworkDisabled: true},
			want:    []string{"os/chisel", "offline/only", osvlocal.Name},
		},
		{
			name:    "offline_with_download_still_removes_network_plugins",
			actions: ScannerActions{CompareOffline: true, PluginNetworkDisabled: true, DownloadDatabases: true},
			want:    []string{"os/chisel", "offline/only", osvlocal.Name},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := make([]string, 0, len(tt.want))
			for _, p := range removeNetworkPluginsWhenOffline(newPlugins(), tt.actions) {
				got = append(got, p.Name())
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("removeNetworkPluginsWhenOffline() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_isDescendent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		potentialParent string
		path            string
		recursive       bool
		want            bool
	}{
		{
			name:            "same_path",
			potentialParent: "/a/b",
			path:            "/a/b",
			recursive:       true,
			want:            true,
		},
		{
			name:            "direct_child,_recursive",
			potentialParent: "/a/b",
			path:            "/a/b/c",
			recursive:       true,
			want:            true,
		},
		{
			name:            "direct_child,_non-recursive",
			potentialParent: "/a/b",
			path:            "/a/b/c",
			recursive:       false,
			want:            true,
		},
		{
			name:            "grandchild,_recursive",
			potentialParent: "/a/b",
			path:            "/a/b/c/d",
			recursive:       true,
			want:            true,
		},
		{
			name:            "grandchild,_non-recursive",
			potentialParent: "/a/b",
			path:            "/a/b/c/d",
			recursive:       false,
			want:            false,
		},
		{
			name:            "not_a_descendent",
			potentialParent: "/a/b",
			path:            "/a/c",
			recursive:       true,
			want:            false,
		},
		{
			name:            "different_root",
			potentialParent: "/a/b",
			path:            "/x/y",
			recursive:       true,
			want:            false,
		},
		{
			name:            "relative_path,_direct_child,_recursive",
			potentialParent: "a/b",
			path:            "a/b/c",
			recursive:       true,
			want:            true,
		},
		{
			name:            "relative_path,_grandchild,_non-recursive",
			potentialParent: "a/b",
			path:            "a/b/c/d",
			recursive:       false,
			want:            false,
		},
		{
			name:            "relative_path,_not_a_descendent",
			potentialParent: "a/b",
			path:            "a/c",
			recursive:       true,
			want:            false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Normalize paths for the current OS
			potentialParent := filepath.FromSlash(tt.potentialParent)
			path := filepath.FromSlash(tt.path)
			if got := isDescendent(potentialParent, path, tt.recursive); got != tt.want {
				t.Errorf("isDescendent(%q, %q, %v) = %v, want %v", tt.potentialParent, tt.path, tt.recursive, got, tt.want)
			}
		})
	}
}

func Test_diagnosticsFromStatuses(t *testing.T) {
	t.Parallel()

	statuses := []*plugin.Status{
		nil,
		{
			Name: "javascript/packagelockjson",
			Status: &plugin.ScanStatus{
				Status: plugin.ScanStatusSucceeded,
			},
		},
		{
			Name: "javascript/packagejson",
			Status: &plugin.ScanStatus{
				Status:        plugin.ScanStatusPartiallySucceeded,
				FailureReason: "encountered 1 error(s) while running plugin",
				FileErrors: []*plugin.FileError{
					{
						FilePath:     "work/node_modules/minimist/package.json",
						ErrorMessage: "failed to parse package.json",
					},
				},
			},
		},
		{
			Name: "vulnmatch/osvdev",
			Status: &plugin.ScanStatus{
				Status:        plugin.ScanStatusFailed,
				FailureReason: "connection refused",
			},
		},
	}

	got := diagnosticsFromStatuses(statuses, "/")
	want := []models.Diagnostic{
		{
			Phase:   "extraction",
			Plugin:  "javascript/packagejson",
			Path:    "/work/node_modules/minimist/package.json",
			Message: "failed to parse package.json",
		},
		{
			Phase:   "vulnerability_matching",
			Plugin:  "vulnmatch/osvdev",
			Message: "connection refused",
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diagnosticsFromStatuses() mismatch (-want +got):\n%s", diff)
	}
}

func TestDoScan_Diagnostics(t *testing.T) {
	t.Parallel()

	t.Run("extraction_failure_and_valid_package", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		lodashDir := filepath.Join(tmpDir, "node_modules", "lodash")
		minimistDir := filepath.Join(tmpDir, "node_modules", "minimist")
		if err := os.MkdirAll(lodashDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(minimistDir, 0o755); err != nil {
			t.Fatal(err)
		}

		lodashPath := filepath.Join(lodashDir, "package.json")
		minimistPath := filepath.Join(minimistDir, "package.json")
		if err := os.WriteFile(lodashPath, []byte(`{"name":"lodash","version":"4.17.20"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(minimistPath, []byte(`{"name":"minimist","version":"1.2.5","contributors":42}`), 0o600); err != nil {
			t.Fatal(err)
		}

		res, err := DoScan(ScannerActions{
			DirectoryPaths:   []string{tmpDir},
			Recursive:        true,
			NoIgnore:         true,
			ShowAllPackages:  true,
			CompareOffline:   true,
			ExperimentalScannerActions: ExperimentalScannerActions{
				PluginsEnabled:    []string{"javascript/packagejson"},
				PluginsNoDefaults: true,
			},
		})
		if err != nil {
			t.Fatalf("DoScan() unexpected error: %v", err)
		}

		if len(res.Results) != 1 {
			t.Fatalf("len(res.Results) = %d, want 1", len(res.Results))
		}

		var foundExtractionDiag, foundMatchingDiag bool
		wantMinimistPath := filepath.ToSlash(minimistPath)
		for _, d := range res.Diagnostics {
			if d.Phase == "extraction" && d.Plugin == "javascript/packagejson" && d.Path == wantMinimistPath {
				foundExtractionDiag = true
			}
			if d.Phase == "vulnerability_matching" && d.Plugin == osvlocal.Name {
				foundMatchingDiag = true
			}
		}
		if !foundExtractionDiag {
			t.Errorf("expected extraction diagnostic for %q in %+v", wantMinimistPath, res.Diagnostics)
		}
		if !foundMatchingDiag {
			t.Errorf("expected vulnerability_matching diagnostic for %q in %+v", osvlocal.Name, res.Diagnostics)
		}
	})

	t.Run("traversal_failure_and_valid_package", func(t *testing.T) {
		t.Parallel()

		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("skipping chmod 0000 traversal test on Windows or root")
		}

		tmpDir := t.TempDir()
		lodashDir := filepath.Join(tmpDir, "node_modules", "lodash")
		unreadableDir := filepath.Join(tmpDir, "unreadable_subtree")
		if err := os.MkdirAll(lodashDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(unreadableDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(lodashDir, "package.json"), []byte(`{"name":"lodash","version":"4.17.20"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unreadableDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = os.Chmod(unreadableDir, 0o755)
		})

		res, err := DoScan(ScannerActions{
			DirectoryPaths:  []string{tmpDir},
			Recursive:       true,
			NoIgnore:        true,
			ShowAllPackages: true,
			CompareOffline:  true,
			ExperimentalScannerActions: ExperimentalScannerActions{
				PluginsEnabled:    []string{"javascript/packagejson"},
				PluginsNoDefaults: true,
			},
		})
		if err != nil {
			t.Fatalf("DoScan() unexpected error: %v", err)
		}

		wantUnreadablePath := filepath.ToSlash(unreadableDir)
		var foundTraversalDiag bool
		for _, d := range res.Diagnostics {
			if d.Phase == "traversal" && d.Path == wantUnreadablePath {
				foundTraversalDiag = true
			}
		}
		if !foundTraversalDiag {
			t.Errorf("expected traversal diagnostic for %q in %+v", wantUnreadablePath, res.Diagnostics)
		}
	})

	t.Run("clean_results_omit_diagnostics_in_json", func(t *testing.T) {
		t.Parallel()

		res := models.VulnerabilityResults{
			Results: []models.PackageSource{},
		}
		raw, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"diagnostics"`) {
			t.Errorf("expected empty diagnostics to be omitted from JSON, got: %s", string(raw))
		}
	})
}
