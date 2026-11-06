package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	apkmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
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
				PackageOverrides: []*PackageOverrideEntry{
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
		{
			name: "config_with_invalid_regex_in_package_override",
			args: args{
				configPath: "./testdata/testdatainner/osv-scanner-invalid-regex.toml",
			},
			want:    Config{},
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
			unknownMsg: "IgnoredVulns.effectiveUntilTime",
		},
		{
			configPath: "./testdata/unknown-key-2.toml",
			unknownMsg: "IgnoredVulns.effectiveUntiI",
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

func TestConfig_FindVulnIgnore(t *testing.T) {
	t.Parallel()

	type args struct {
		vulnID string
	}
	tests := []struct {
		name   string
		config Config
		args   args
		want   *IgnoreEntry
	}{
		{
			name: "ignore_matches",
			config: Config{
				IgnoredVulns: []*IgnoreEntry{
					{
						ID:             "GHSA-123",
						EffectiveUntil: time.Time{},
						Reason:         "",
					},
				},
			},
			args: args{
				vulnID: "GHSA-123",
			},
			want: &IgnoreEntry{
				ID:             "GHSA-123",
				EffectiveUntil: time.Time{},
				Reason:         "",
			},
		},
		{
			name: "ignore_no_match",
			config: Config{
				IgnoredVulns: []*IgnoreEntry{
					{
						ID:             "GHSA-123",
						EffectiveUntil: time.Time{},
						Reason:         "",
					},
				},
			},
			args: args{
				vulnID: "nonexistent",
			},
			want: nil,
		},
		{
			name: "ignore_matches_but_no_longer_effective",
			config: Config{
				IgnoredVulns: []*IgnoreEntry{
					{
						ID:             "GHSA-123",
						EffectiveUntil: time.Now().Add(-time.Hour).Round(time.Second),
						Reason:         "",
					},
				},
			},
			args: args{
				vulnID: "GHSA-123",
			},
			want: nil,
		},
		{
			name: "ignore_matches_if_effective_until_future",
			config: Config{
				IgnoredVulns: []*IgnoreEntry{
					{
						ID:             "GHSA-123",
						EffectiveUntil: time.Now().Add(time.Hour).Round(time.Second),
						Reason:         "",
					},
				},
			},
			args: args{
				vulnID: "GHSA-123",
			},
			want: &IgnoreEntry{
				ID:             "GHSA-123",
				EffectiveUntil: time.Now().Add(time.Hour).Round(time.Second),
				Reason:         "",
			},
		},
		{
			name: "only_first_match_considered",
			config: Config{
				IgnoredVulns: []*IgnoreEntry{
					{
						ID:     "GHSA-123",
						Reason: "first",
					},
					{
						ID:     "GHSA-123",
						Reason: "second",
					},
				},
			},
			args: args{
				vulnID: "GHSA-123",
			},
			want: &IgnoreEntry{
				ID:     "GHSA-123",
				Reason: "first",
			},
		},
		{
			name: "only_first_match_considered_even_if_not_effective",
			config: Config{
				IgnoredVulns: []*IgnoreEntry{
					{
						ID:             "GHSA-123",
						EffectiveUntil: time.Now().Add(-time.Hour).Round(time.Second),
						Reason:         "first",
					},
					{
						ID:             "GHSA-123",
						EffectiveUntil: time.Now().Add(time.Hour).Round(time.Second),
						Reason:         "second",
					},
				},
			},
			args: args{
				vulnID: "GHSA-123",
			},
			want: nil,
		},
		{
			name: "effective_until_is_preferred",
			config: Config{
				IgnoredVulns: []*IgnoreEntry{
					{
						ID:             "GHSA-123",
						EffectiveUntil: time.Now().Add(-time.Hour).Round(time.Second),
						IgnoreUntil:    time.Now().Add(time.Hour).Round(time.Second),
						Reason:         "",
					},
				},
			},
			args: args{
				vulnID: "GHSA-123",
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.FindVulnIgnore(tt.args.vulnID)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindVulnIgnore() got = %v, want %v", got, tt.want)
			}

			// IgnoreUntil should give the same results as EffectiveUntil
			for _, ignore := range tt.config.IgnoredVulns {
				ignore.IgnoreUntil = ignore.EffectiveUntil
				ignore.EffectiveUntil = time.Time{}
			}

			if tt.want != nil {
				tt.want.IgnoreUntil = tt.want.EffectiveUntil
				tt.want.EffectiveUntil = time.Time{}
			}

			got = tt.config.FindVulnIgnore(tt.args.vulnID)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindVulnIgnore() (using IgnoreUntil) got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_FindIgnorePackageOverride(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config Config
		args   *extractor.Package
		want   *PackageOverrideEntry
	}{
		{
			name: "Everything-level_entry_exists",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
				Metadata: &osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			want: &PackageOverrideEntry{
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		// -------------------------------------------------------------------------
		{
			name: "Ecosystem-level_entry_exists_and_does_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
				Metadata: &osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			want: &PackageOverrideEntry{
				Ecosystem:      "Go",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		{
			name: "Ecosystem-level_entry_exists_and_does_not_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
				Metadata: &osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			want: nil,
		},
		// -------------------------------------------------------------------------
		{
			name: "Ecosystem-level_entry_with_suffix_exists_and_does_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
			want: &PackageOverrideEntry{
				Ecosystem:      "Alpine:v3.20",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		{
			name: "Ecosystem-level_entry_with_suffix_exists_and_does_not_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
			want: nil,
		},
		{
			name: "Ecosystem-level_entry_without_suffix_exists_and_does_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
			want: &PackageOverrideEntry{
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
				PackageOverrides: []*PackageOverrideEntry{
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
				Metadata: &osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			want: &PackageOverrideEntry{
				Group:          "dev",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		{
			name: "Group-level_entry_exists_and_does_not_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
				Metadata: &osv.DepGroupMetadata{
					DepGroupVals: []string{"optional"},
				},
			},
			want: nil,
		},
		{
			name: "Group-level_entry_exists_and_does_not_match_when_empty",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
			want: nil,
		},
		// -------------------------------------------------------------------------
		{
			name: "Version-level_entry_exists_and_does_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
				Metadata: &osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			want: &PackageOverrideEntry{
				Version:        "1.0.0",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		{
			name: "Version-level_entry_exists_and_does_not_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
				Metadata: &osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			want: nil,
		},
		// -------------------------------------------------------------------------
		{
			name: "Name-level_entry_exists_and_does_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
				Metadata: &osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			want: &PackageOverrideEntry{
				Name:           "lib1",
				Ignore:         true,
				EffectiveUntil: time.Time{},
				Reason:         "abc",
			},
		},
		{
			name: "Name-level_entry_exists_and_does_not_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
				Metadata: &osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			want: nil,
		},
		// -------------------------------------------------------------------------
		{
			name: "Name,_Version,_and_Ecosystem_entry_exists",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
			want: &PackageOverrideEntry{
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
				PackageOverrides: []*PackageOverrideEntry{
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
			want: &PackageOverrideEntry{
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
				PackageOverrides: []*PackageOverrideEntry{
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
				Metadata: &osv.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				},
			},
			want: &PackageOverrideEntry{
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
				PackageOverrides: []*PackageOverrideEntry{
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
				Metadata: &osv.DepGroupMetadata{
					DepGroupVals: []string{"prod"},
				},
			},
			want: nil,
		},
		{
			name: "Entry_doesn't_exist",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.FindIgnorePackageOverride(tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindIgnorePackageOverride() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_FindIgnorePackageOverride_NameIsRegex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config Config
		args   *extractor.Package
		want   *PackageOverrideEntry
	}{
		{
			name: "Regex_matches_package_name",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
					{
						Name:        "lib.*",
						NameIsRegex: true,
						Ignore:      true,
						Reason:      "internal packages",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
			},
			want: &PackageOverrideEntry{
				Name:        "lib.*",
				NameIsRegex: true,
				Ignore:      true,
				Reason:      "internal packages",
			},
		},
		{
			name: "Regex_does_not_match_package_name",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
					{
						Name:        "lib.*",
						NameIsRegex: true,
						Ignore:      true,
						Reason:      "internal packages",
					},
				},
			},
			args: &extractor.Package{
				Name:     "other-pkg",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
			},
			want: nil,
		},
		{
			name: "Invalid_regex_does_not_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
					{
						Name:        "[invalid",
						NameIsRegex: true,
						Ignore:      true,
						Reason:      "bad regex",
					},
				},
			},
			args: &extractor.Package{
				Name:     "anything",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
			},
			want: nil,
		},
		{
			name: "NameIsRegex_false_uses_exact_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
					{
						Name:   "lib.*",
						Ignore: true,
						Reason: "exact match",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
			},
			want: nil,
		},
		{
			name: "Regex_with_empty_name_matches_all",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
					{
						Name:        "",
						NameIsRegex: true,
						Ignore:      true,
						Reason:      "match all",
					},
				},
			},
			args: &extractor.Package{
				Name:     "any-package",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
			},
			want: &PackageOverrideEntry{
				Name:        "",
				NameIsRegex: true,
				Ignore:      true,
				Reason:      "match all",
			},
		},
		{
			name: "Regex_is_anchored_and_does_not_partial_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
					{
						Name:        "lib",
						NameIsRegex: true,
						Ignore:      true,
						Reason:      "anchored",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
			},
			want: nil,
		},
		{
			name: "Regex_with_top_level_alternation_is_anchored_and_does_not_partial_match",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
					{
						Name:        "lib|other",
						NameIsRegex: true,
						Ignore:      true,
						Reason:      "anchored alternation",
					},
				},
			},
			args: &extractor.Package{
				Name:     "lib1",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
			},
			want: nil,
		},
		{
			name: "Regex_combined_with_ecosystem_filter",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
					{
						Name:        "internal-.*",
						NameIsRegex: true,
						Ecosystem:   "Go",
						Ignore:      true,
						Reason:      "internal Go packages",
					},
				},
			},
			args: &extractor.Package{
				Name:     "internal-lib",
				Version:  "1.0.0",
				PURLType: purl.TypeGolang,
			},
			want: &PackageOverrideEntry{
				Name:        "internal-.*",
				NameIsRegex: true,
				Ecosystem:   "Go",
				Ignore:      true,
				Reason:      "internal Go packages",
			},
		},
		{
			name: "Regex_matches_but_ecosystem_does_not",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
					{
						Name:        "internal-.*",
						NameIsRegex: true,
						Ecosystem:   "Go",
						Ignore:      true,
						Reason:      "internal Go packages",
					},
				},
			},
			args: &extractor.Package{
				Name:     "internal-lib",
				Version:  "1.0.0",
				PURLType: "npm",
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.FindIgnorePackageOverride(tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindIgnorePackageOverride() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_FindPackageVulnerabilitiesOverride(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config Config
		args   *extractor.Package
		want   *PackageOverrideEntry
	}{
		{
			name: "Exact_version_entry_exists_with_ignore",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
			want: &PackageOverrideEntry{
				Name:      "lib1",
				Version:   "1.0.0",
				Ecosystem: "Go",
				Vulnerability: Vulnerability{
					Ignore: true,
				},
				Reason: "abc",
			},
		},
		{
			name: "Version_entry_doesn't_exist_with_ignore",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
			want: nil,
		},
		{
			name: "Name_matches_with_ignore",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
			want: &PackageOverrideEntry{
				Name:      "lib1",
				Ecosystem: "Go",
				Vulnerability: Vulnerability{
					Ignore: true,
				},
				Reason: "abc",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.FindPackageVulnerabilitiesOverride(tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindPackageVulnerabilitiesOverride() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_FindPackageLicenseOverride(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config Config
		args   *extractor.Package
		want   *PackageOverrideEntry
	}{
		{
			name: "Exact_version_entry_exists_with_override",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
			want: &PackageOverrideEntry{
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
				PackageOverrides: []*PackageOverrideEntry{
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
			want: &PackageOverrideEntry{
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
				PackageOverrides: []*PackageOverrideEntry{
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
			want: nil,
		},
		{
			name: "Version_entry_doesn't_exist_with_ignore",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
			want: nil,
		},
		{
			name: "Name_matches_with_override",
			config: Config{
				PackageOverrides: []*PackageOverrideEntry{
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
			want: &PackageOverrideEntry{
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
				PackageOverrides: []*PackageOverrideEntry{
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
			want: &PackageOverrideEntry{
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

			got := tt.config.FindPackageLicenseOverride(tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindPackageLicenseOverride() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_UpdateFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    []*osvschema.Vulnerability
		input   string
		wantErr bool
	}{
		{
			name:  "nothing_happens_when_everything_is_empty",
			args:  []*osvschema.Vulnerability{},
			input: "",
		},
		{
			name: "empty_file_with_one_vuln",
			args: []*osvschema.Vulnerability{
				{Id: "GHSA-123"},
			},
		},
		{
			name: "empty_file_with_two_vulns",
			args: []*osvschema.Vulnerability{
				{Id: "GHSA-123"},
				{Id: "GHSA-456"},
			},
		},
		{
			name: "existing_properties_are_preserved",
			args: []*osvschema.Vulnerability{
				{Id: "GHSA-123"},
				{Id: "GHSA-456"},
				{Id: "GHSA-789"},
			},
			input: `
GoVersionOverride = "1.20.0"

[[PackageOverrides]]
name = "lib"
version = "1.0.0"
ecosystem = "Go"
group = "dev"

vulnerability.ignore = true
license.override = ["MIT", "0BSD"]

[[IgnoredVulns]]
id = "GHSA-123"
reason = "No ssh servers are connected to or hosted in Go lang"

[[IgnoredVulns]]
id = "GHSA-789"
effectiveUntil = 2020-01-01T01:00+09:00
ignoreUntil = 2020-05-01T01:00+09:00
`,
		},
		{
			name: "comments_are_not_preserved",
			args: []*osvschema.Vulnerability{
				{Id: "GHSA-123"},
				{Id: "GHSA-456"},
			},
			input: `
# TODO: we should patch this
[[IgnoredVulns]]
id = "GHSA-123"
`,
		},
		{
			name: "missing_vulns_are_removed",
			args: []*osvschema.Vulnerability{
				{Id: "GHSA-123"},
				{Id: "GHSA-456"},
			},
			input: `
[[IgnoredVulns]]
id = "GHSA-789"
`,
		},
		{
			name: "ids_are_deduplicated",
			args: []*osvschema.Vulnerability{
				{Id: "GHSA-123"},
				{Id: "GHSA-123"},
				{Id: "GHSA-456"},
			},
		},
		{
			name: "ids_are_deduplicated_including_already_existing",
			args: []*osvschema.Vulnerability{
				{Id: "GHSA-456"},
				{Id: "GHSA-123"},
				{Id: "GHSA-456"},
				{Id: "GHSA-789"},
			},
			input: `
[[IgnoredVulns]]
id = "GHSA-456"

[[IgnoredVulns]]
id = "GHSA-456"
`,
		},
		{
			name: "aliases_are_deduplicated",
			args: []*osvschema.Vulnerability{
				{Id: "GHSA-123"},
				{Id: "GHSA-456"},
				{Id: "GHSA-789", Aliases: []string{"GHSA-123"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := testutility.CreateTestDir(t)

			err := os.WriteFile(filepath.Join(dir, OSVScannerConfigName), []byte(tt.input), 0600)

			if err != nil {
				t.Fatal(err)
			}

			c, err := tryLoadConfig(filepath.Join(dir, OSVScannerConfigName))

			if err != nil {
				t.Fatalf("failed to load config: %v", err)
			}

			err = c.UpdateFile(tt.args)

			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateFile() error = %v, wantErr %v", err, tt.wantErr)
			}

			b, err := os.ReadFile(c.LoadPath)

			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}

			testutility.NewSnapshot().MatchText(t, string(b))
		})
	}
}
