package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	apkmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/purl"
)

// Attempts to normalize any file paths in the given `output` so that they can
// be compared reliably regardless of the file path separator being used.
//
// Namely, escaped forward slashes are replaced with backslashes.
func normalizeFilePaths(t *testing.T, output string) string {
	t.Helper()

	return strings.ReplaceAll(strings.ReplaceAll(output, "\\\\", "/"), "\\", "/")
}

func Test_normalizeConfigLoadPath(t *testing.T) {
	t.Parallel()

	type args struct {
		target string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "target_does_not_exist",
			args: args{
				target: "./testdata/testdatainner/does-not-exist",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "target_is_file_in_directory",
			args: args{
				target: "./testdata/testdatainner/innerFolder/test.yaml",
			},
			want:    "testdata/testdatainner/innerFolder/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target_is_inner_directory_with_trailing_slash",
			args: args{
				target: "./testdata/testdatainner/innerFolder/",
			},
			want:    "testdata/testdatainner/innerFolder/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target_is_inner_directory_without_trailing_slash",
			args: args{
				target: "./testdata/testdatainner/innerFolder",
			},
			want:    "testdata/testdatainner/innerFolder/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target_is_directory_with_trailing_slash",
			args: args{
				target: "./testdata/testdatainner/",
			},
			want:    "testdata/testdatainner/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target_is_file_in_directory",
			args: args{
				target: "./testdata/testdatainner/some-manifest.yaml",
			},
			want:    "testdata/testdatainner/osv-scanner.toml",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := normalizeConfigLoadPath(tt.args.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizeConfigLoadPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			got = normalizeFilePaths(t, got)
			if got != tt.want {
				t.Errorf("normalizeConfigLoadPath() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_tryLoadConfig(t *testing.T) {
	t.Parallel()

	type args struct {
		configPath string
	}
	tests := []struct {
		name    string
		args    args
		want    Config
		wantErr bool
	}{
		{
			name: "config_does_not_exist",
			args: args{
				configPath: "./testdata/testdatainner/does-not-exist",
			},
			want:    Config{},
			wantErr: true,
		},
		{
			name: "config_has_some_ignored_vulnerabilities_and_package_overrides",
			args: args{
				configPath: "./testdata/testdatainner/osv-scanner.toml",
			},
			want: Config{
				LoadPath: "./testdata/testdatainner/osv-scanner.toml",
				IgnoredVulns: []*IgnoreEntry{
					{
						ID: "GO-2022-0968",
					},
					{
						ID: "GO-2022-1059",
					},
				},
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:      "lib",
						Version:   "1.0.0",
						Ecosystem: "Go",
						Ignore:    true,
						Reason:    "abc",
					},
					{
						Name:      "my-pkg",
						Version:   "1.0.0",
						Ecosystem: "Go",
						Reason:    "abc",
						Ignore:    true,
						License: License{
							Override: []string{"MIT", "0BSD"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "load_path_cannot_be_overridden_via_config",
			args: args{
				configPath: "./testdata/testdatainner/osv-scanner-load-path.toml",
			},
			want: Config{
				LoadPath: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tryLoadConfig(tt.args.configPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("tryLoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("tryLoadConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTryLoadConfig_UnknownKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		configPath string
		unknownMsg string
	}{
		{
			configPath: "./testdata/unknown-key-1.toml",
			unknownMsg: "IgnoredVulns.ignoreUntilTime",
		},
		{
			configPath: "./testdata/unknown-key-2.toml",
			unknownMsg: "IgnoredVulns.ignoreUntiI",
		},
		{
			configPath: "./testdata/unknown-key-3.toml",
			unknownMsg: "IgnoredVulns.reasoning",
		},
		{
			configPath: "./testdata/unknown-key-4.toml",
			unknownMsg: "PackageOverrides.skip",
		},
		{
			configPath: "./testdata/unknown-key-5.toml",
			unknownMsg: "PackageOverrides.license.skip",
		},
		{
			configPath: "./testdata/unknown-key-6.toml",
			unknownMsg: "RustVersionOverride",
		},
		{
			configPath: "./testdata/unknown-key-7.toml",
			unknownMsg: "RustVersionOverride, PackageOverrides.skip",
		},
	}

	for _, testData := range tests {
		c, err := tryLoadConfig(testData.configPath)

		// we should always be returning an empty config on error
		if diff := cmp.Diff(Config{}, c); diff != "" {
			t.Errorf("tryLoadConfig() mismatch (-want +got):\n%s", diff)
		}
		if err == nil {
			t.Fatal("tryLoadConfig() did not return an error")
		}

		wantMsg := fmt.Sprintf("unknown keys in config file: %v", testData.unknownMsg)

		if err.Error() != wantMsg {
			t.Errorf("tryLoadConfig() error = '%v', want '%s'", err, wantMsg)
		}
	}
}

func TestConfig_ShouldIgnore(t *testing.T) {
	t.Parallel()

	type args struct {
		vulnID string
	}
	tests := []struct {
		name      string
		config    Config
		args      args
		wantOk    bool
		wantEntry *IgnoreEntry
	}{
		// entry exists
		{
			name: "",
			config: Config{
				IgnoredVulns: []*IgnoreEntry{
					{
						ID:          "GHSA-123",
						IgnoreUntil: time.Time{},
						Reason:      "",
					},
				},
			},
			args: args{
				vulnID: "GHSA-123",
			},
			wantOk: true,
			wantEntry: &IgnoreEntry{
				ID:          "GHSA-123",
				IgnoreUntil: time.Time{},
				Reason:      "",
			},
		},
		// entry does not exist
		{
			name: "",
			config: Config{
				IgnoredVulns: []*IgnoreEntry{
					{
						ID:          "GHSA-123",
						IgnoreUntil: time.Time{},
						Reason:      "",
					},
				},
			},
			args: args{
				vulnID: "nonexistent",
			},
			wantOk:    false,
			wantEntry: &IgnoreEntry{},
		},
		// ignored until a time in the past
		{
			name: "",
			config: Config{
				IgnoredVulns: []*IgnoreEntry{
					{
						ID:          "GHSA-123",
						IgnoreUntil: time.Now().Add(-time.Hour).Round(time.Second),
						Reason:      "",
					},
				},
			},
			args: args{
				vulnID: "GHSA-123",
			},
			wantOk: false,
			wantEntry: &IgnoreEntry{
				ID:          "GHSA-123",
				IgnoreUntil: time.Now().Add(-time.Hour).Round(time.Second),
				Reason:      "",
			},
		},
		// ignored until a time in the future
		{
			name: "",
			config: Config{
				IgnoredVulns: []*IgnoreEntry{
					{
						ID:          "GHSA-123",
						IgnoreUntil: time.Now().Add(time.Hour).Round(time.Second),
						Reason:      "",
					},
				},
			},
			args: args{
				vulnID: "GHSA-123",
			},
			wantOk: true,
			wantEntry: &IgnoreEntry{
				ID:          "GHSA-123",
				IgnoreUntil: time.Now().Add(time.Hour).Round(time.Second),
				Reason:      "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotOk, gotEntry := tt.config.ShouldIgnore(tt.args.vulnID)
			if gotOk != tt.wantOk {
				t.Errorf("ShouldIgnore() gotOk = %v, wantOk %v", gotOk, tt.wantOk)
			}
			if !reflect.DeepEqual(gotEntry, tt.wantEntry) {
				t.Errorf("ShouldIgnore() gotEntry = %v, wantEntry %v", gotEntry, tt.wantEntry)
			}
		})
	}
}

func TestConfig_ShouldIgnorePackage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    Config
		args      *extractor.Package
		wantOk    bool
		wantEntry PackageOverrideEntry
	}{
		{
			name: "Everything-level_entry_exists",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:    "lib1",
				Version: "1.0.0",
				Metadata: osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		// -------------------------------------------------------------------------
		{
			name: "Ecosystem-level_entry_exists_and_does_match",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Ecosystem:      "Go",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
				Metadata: osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Ecosystem:      "Go",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		{
			name: "Ecosystem-level_entry_exists_and_does_not_match",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Ecosystem:      "Go",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib2",
				Version:  "1.0.0",
				PURLType: "npm",
				Metadata: osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		// -------------------------------------------------------------------------
		{
			name: "Ecosystem-level_entry_with_suffix_exists_and_does_match",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Ecosystem:      "Alpine:v3.20",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "bin1",
				Version:  "1.0.0",
				PURLType: purl.TypeApk,
				Metadata: &apkmetadata.Metadata{
					PackageName: "bin1",
					OSID:        "Alpine",
					OSVersionID: "3.20",
				},
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Ecosystem:      "Alpine:v3.20",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		{
			name: "Ecosystem-level_entry_with_suffix_exists_and_does_not_match",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Ecosystem:      "Alpine:v3.20",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "bin2",
				Version:  "1.0.0",
				PURLType: purl.TypeApk,
				Metadata: &apkmetadata.Metadata{
					PackageName: "bin1",
					OSID:        "Alpine",
					OSVersionID: "3.19",
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		{
			name: "Ecosystem-level_entry_without_suffix_exists_and_does_match",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Ecosystem:      "Alpine",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "bin1",
				Version:  "1.0.0",
				PURLType: purl.TypeApk,
				Metadata: &apkmetadata.Metadata{
					PackageName: "bin1",
					OSID:        "Alpine",
					OSVersionID: "3.20",
				},
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Ecosystem:      "Alpine",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		// -------------------------------------------------------------------------
		{
			name: "Group-level_entry_exists_and_does_match",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Group:          "dev",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
				Metadata: osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Group:          "dev",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		{
			name: "Group-level_entry_exists_and_does_not_match",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Group:          "dev",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib2",
				Version:  "1.0.0",
				PURLType: "npm",
				Metadata: osv.DepGroupMetadata{
					DepGroupVals: []string{"optional"},
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		{
			name: "Group-level_entry_exists_and_does_not_match_when_empty",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Group:          "dev",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib2",
				Version:  "1.0.0",
				PURLType: "npm",
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		// -------------------------------------------------------------------------
		{
			name: "Version-level_entry_exists_and_does_match",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Version:        "1.0.0",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
				Metadata: osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Version:        "1.0.0",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		{
			name: "Version-level_entry_exists_and_does_not_match",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Version:        "1.0.0",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.1",
				PURLType: purl.TypeGolang,
				Metadata: osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		// -------------------------------------------------------------------------
		{
			name: "Name-level_entry_exists_and_does_match",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:           "lib1",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
				Metadata: osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Name:           "lib1",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		{
			name: "Name-level_entry_exists_and_does_not_match",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:           "lib1",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib2",
				Version:  "1.0.0",
				PURLType: "npm",
				Metadata: osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		// -------------------------------------------------------------------------
		{
			name: "Name,_Version,_and_Ecosystem_entry_exists",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:           "lib1",
						Version:        "1.0.0",
						Ecosystem:      "Go",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Name:           "lib1",
				Version:        "1.0.0",
				Ecosystem:      "Go",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		{
			name: "Name_and_Ecosystem_entry_exists",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:           "lib1",
						Ecosystem:      "Go",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Name:           "lib1",
				Ecosystem:      "Go",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		{
			name: "Name,_Ecosystem,_and_Group_entry_exists_and_matches",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:           "lib1",
						Ecosystem:      "Go",
						Group:          "dev",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
				Metadata: osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Name:           "lib1",
				Ecosystem:      "Go",
				Group:          "dev",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		{
			name: "Name,_Ecosystem,_and_Group_entry_exists_but_does_not_match",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:           "lib1",
						Ecosystem:      "Go",
						Group:          "dev",
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
				Metadata: osv.DepGroupMetadata{
					DepGroupVals: []string{"prod"},
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		{
			name: "Entry_doesn't_exist",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:           "lib1",
						Version:        "2.0.0",
						Ecosystem:      "Go",
						Ignore:         false,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
					{
						Name:           "lib2",
						Version:        "2.0.0",
						Ignore:         true,
						Ecosystem:      "Go",
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "2.0.0",
				PURLType: purl.TypeGolang,
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotOk, gotEntry := tt.config.ShouldIgnorePackage(tt.args)
			if gotOk != tt.wantOk {
				t.Errorf("ShouldIgnorePackage() gotOk = %v, wantOk %v", gotOk, tt.wantOk)
			}
			if !reflect.DeepEqual(gotEntry, tt.wantEntry) {
				t.Errorf("ShouldIgnorePackage() gotEntry = %v, wantEntry %v", gotEntry, tt.wantEntry)
			}
		})
	}
}

func TestConfig_ShouldIgnorePackageVulnerabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config Config
		args   *extractor.Package
		wantOk bool
	}{
		{
			name: "Exact_version_entry_exists_with_ignore",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:      "lib1",
						Version:   "1.0.0",
						Ecosystem: "Go",
						Vulnerability: Vulnerability{
							Ignore: true,
						},
						Reason: "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
			},
			wantOk: true,
		},
		{
			name: "Version_entry_doesn't_exist_with_ignore",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:      "lib1",
						Version:   "1.0.0",
						Ecosystem: "Go",
						Vulnerability: Vulnerability{
							Ignore: true,
						},
						Reason: "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.1",
				PURLType: purl.TypeGolang,
			},
			wantOk: false,
		},
		{
			name: "Name_matches_with_ignore",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:      "lib1",
						Ecosystem: "Go",
						Vulnerability: Vulnerability{
							Ignore: true,
						},
						Reason: "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.1",
				PURLType: purl.TypeGolang,
			},
			wantOk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotOk := tt.config.ShouldIgnorePackageVulnerabilities(tt.args)
			if gotOk != tt.wantOk {
				t.Errorf("ShouldIgnorePackageVulnerabilities() gotOk = %v, wantOk %v", gotOk, tt.wantOk)
			}
		})
	}
}

func TestConfig_ShouldOverridePackageLicense(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    Config
		args      *extractor.Package
		wantOk    bool
		wantEntry PackageOverrideEntry
	}{
		{
			name: "Exact_version_entry_exists_with_override",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:      "lib1",
						Version:   "1.0.0",
						Ecosystem: "Go",
						License: License{
							Override: []string{"mit"},
						},
						Reason: "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Name:      "lib1",
				Version:   "1.0.0",
				Ecosystem: "Go",
				License: License{
					Override: []string{"mit"},
				},
				Reason: "abc",
			},
		},
		{
			name: "Exact_version_entry_exists_with_ignore",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:      "lib1",
						Version:   "1.0.0",
						Ecosystem: "Go",
						License: License{
							Ignore: true,
						},
						Reason: "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Name:      "lib1",
				Version:   "1.0.0",
				Ecosystem: "Go",
				License: License{
					Ignore: true,
				},
				Reason: "abc",
			},
		},
		{
			name: "Version_entry_doesn't_exist_with_override",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:      "lib1",
						Version:   "1.0.0",
						Ecosystem: "Go",
						License: License{
							Override: []string{"mit"},
						},
						Reason: "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.1",
				PURLType: purl.TypeGolang,
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		{
			name: "Version_entry_doesn't_exist_with_ignore",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:      "lib1",
						Version:   "1.0.0",
						Ecosystem: "Go",
						License: License{
							Ignore: true,
						},
						Reason: "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.1",
				PURLType: purl.TypeGolang,
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		{
			name: "Name_matches_with_override",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:      "lib1",
						Ecosystem: "Go",
						License: License{
							Override: []string{"mit"},
						},
						Reason: "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.1",
				PURLType: purl.TypeGolang,
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Name:      "lib1",
				Ecosystem: "Go",
				License: License{
					Override: []string{"mit"},
				},
				Reason: "abc",
			},
		},
		{
			name: "Name_matches_with_ignore",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Name:      "lib1",
						Ecosystem: "Go",
						License: License{
							Ignore: true,
						},
						Reason: "abc",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.1",
				PURLType: purl.TypeGolang,
			},
			wantOk: true,
			wantEntry: PackageOverrideEntry{
				Name:      "lib1",
				Ecosystem: "Go",
				License: License{
					Ignore: true,
				},
				Reason: "abc",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotOk, gotEntry := tt.config.ShouldOverridePackageLicense(tt.args)
			if gotOk != tt.wantOk {
				t.Errorf("ShouldOverridePackageLicense() gotOk = %v, wantOk %v", gotOk, tt.wantOk)
			}
			if !reflect.DeepEqual(gotEntry, tt.wantEntry) {
				t.Errorf("ShouldOverridePackageLicense() gotEntry = %v, wantEntry %v", gotEntry, tt.wantEntry)
			}
		})
	}
}
