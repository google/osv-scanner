package output

import (
	"testing"

	"github.com/google/osv-scanner/v2/internal/testutility"
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

func Test_stripGitHubWorkspace(t *testing.T) {
	tests := []struct {
		name      string
		workspace string
		path      string
		want      string
	}{
		{
			name:      "container_prefix_with_env_var_unset",
			workspace: "",
			path:      "/github/workspace/path/to/package-lock.json",
			want:      "path/to/package-lock.json",
		},
		{
			name:      "path_outside_container_prefix_with_env_var_unset",
			workspace: "",
			path:      "/home/runner/work/repo/repo/path/to/package-lock.json",
			want:      "/home/runner/work/repo/repo/path/to/package-lock.json",
		},
		{
			name:      "env_var_prefix",
			workspace: "/home/runner/work/repo/repo",
			path:      "/home/runner/work/repo/repo/path/to/package-lock.json",
			want:      "path/to/package-lock.json",
		},
		{
			name:      "env_var_prefix_with_trailing_separator",
			workspace: "/home/runner/work/repo/repo/",
			path:      "/home/runner/work/repo/repo/path/to/package-lock.json",
			want:      "path/to/package-lock.json",
		},
		{
			name:      "env_var_prefix_with_path_equal_to_workspace",
			workspace: "/home/runner/work/repo/repo",
			path:      "/home/runner/work/repo/repo",
			want:      ".",
		},
		{
			name:      "env_var_prefix_with_path_equal_to_workspace_with_trailing_separator",
			workspace: "/home/runner/work/repo/repo/",
			path:      "/home/runner/work/repo/repo",
			want:      ".",
		},
		{
			name:      "container_prefix_with_path_equal_to_workspace",
			workspace: "",
			path:      "/github/workspace",
			want:      ".",
		},
		{
			name:      "env_var_set_to_root_separator",
			workspace: "/",
			path:      "/home/runner/work/repo/repo/path/to/package-lock.json",
			want:      "/home/runner/work/repo/repo/path/to/package-lock.json",
		},
		{
			name:      "env_var_set_to_windows_root_separator",
			workspace: `\`,
			path:      `D:\a\repo\repo\path\to\package-lock.json`,
			want:      `D:\a\repo\repo\path\to\package-lock.json`,
		},
		{
			name:      "env_var_set_but_path_outside_workspace",
			workspace: "/home/runner/work/repo/repo",
			path:      "/home/runner/work/other/other/path/to/package-lock.json",
			want:      "/home/runner/work/other/other/path/to/package-lock.json",
		},
		{
			name:      "env_var_set_but_path_only_shares_a_prefix",
			workspace: "/home/runner/work/repo/repo",
			path:      "/home/runner/work/repo/repo-other/path/to/package-lock.json",
			want:      "/home/runner/work/repo/repo-other/path/to/package-lock.json",
		},
		{
			name:      "env_var_set_and_path_in_container_prefix",
			workspace: "/home/runner/work/repo/repo",
			path:      "/github/workspace/path/to/package-lock.json",
			want:      "path/to/package-lock.json",
		},
		{
			name:      "env_var_set_to_container_prefix",
			workspace: "/github/workspace",
			path:      "/github/workspace/path/to/package-lock.json",
			want:      "path/to/package-lock.json",
		},
		{
			name:      "windows_style_separators",
			workspace: `D:\a\repo\repo`,
			path:      `D:\a\repo\repo\path\to\package-lock.json`,
			want:      `path\to\package-lock.json`,
		},
		{
			name:      "windows_style_separators_with_trailing_separator",
			workspace: `D:\a\repo\repo\`,
			path:      `D:\a\repo\repo\path\to\package-lock.json`,
			want:      `path\to\package-lock.json`,
		},
		{
			name:      "windows_style_separators_with_path_equal_to_workspace",
			workspace: `D:\a\repo\repo`,
			path:      `D:\a\repo\repo`,
			want:      ".",
		},
		{
			// comparison is a plain prefix match, so a path that uses different
			// separators or drive-letter casing to GITHUB_WORKSPACE is not stripped
			name:      "windows_style_separators_with_mismatched_separators_and_drive_case",
			workspace: `D:\a\repo\repo`,
			path:      `d:/a/repo/repo/path/to/package-lock.json`,
			want:      `d:/a/repo/repo/path/to/package-lock.json`,
		},
		{
			name:      "windows_style_separators_with_path_outside_workspace",
			workspace: `D:\a\repo\repo`,
			path:      `D:\a\repo-two\repo-two\path\to\package-lock.json`,
			want:      `D:\a\repo-two\repo-two\path\to\package-lock.json`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GITHUB_WORKSPACE", tt.workspace)

			if got := stripGitHubWorkspace(tt.path); got != tt.want {
				t.Errorf("stripGitHubWorkspace() = %q, want %q", got, tt.want)
			}
		})
	}
}
