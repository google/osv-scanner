package osvscanner

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/plugin"
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
