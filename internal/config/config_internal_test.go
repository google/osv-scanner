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
	"github.com/google/osv-scanner/v2/internal/imodels"
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
			name: "target does not exist",
			args: args{
				target: "./testdata/testdatainner/does-not-exist",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "target is file in directory",
			args: args{
				target: "./testdata/testdatainner/innerFolder/test.yaml",
			},
			want:    "testdata/testdatainner/innerFolder/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target is inner directory with trailing slash",
			args: args{
				target: "./testdata/testdatainner/innerFolder/",
			},
			want:    "testdata/testdatainner/innerFolder/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target is inner directory without trailing slash",
			args: args{
				target: "./testdata/testdatainner/innerFolder",
			},
			want:    "testdata/testdatainner/innerFolder/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target is directory with trailing slash",
			args: args{
				target: "./testdata/testdatainner/",
			},
			want:    "testdata/testdatainner/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target is file in directory",
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
			name: "config does not exist",
			args: args{
				configPath: "./testdata/testdatainner/does-not-exist",
			},
			want:    Config{},
			wantErr: true,
		},
		{
			name: "config has some ignored vulnerabilities and package overrides",
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
			name: "load path cannot be overridden via config",
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
		args      imodels.PackageInfo
		wantOk    bool
		wantEntry PackageOverrideEntry
	}{
		{
			name: "Everything-level entry exists",
			config: Config{
				PackageOverrides: []PackageOverrideEntry{
					{
						Ignore:         true,
						EffectiveUntil: time.Time{},
						Reason:         "abc",
					},
				},
			},
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:    "lib1",
					Version: "1.0.0",
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
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
			name: "Ecosystem-level entry exists and does match",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
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
			name: "Ecosystem-level entry exists and does not match",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib2",
					Version:  "1.0.0",
					PURLType: "npm",
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		// -------------------------------------------------------------------------
		{
			name: "Ecosystem-level entry with suffix exists and does match",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "bin1",
					Version:  "1.0.0",
					PURLType: purl.TypeApk,
					Metadata: &apkmetadata.Metadata{
						PackageName: "bin1",
						OSID:        "Alpine",
						OSVersionID: "3.20",
					},
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
			name: "Ecosystem-level entry with suffix exists and does not match",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "bin2",
					Version:  "1.0.0",
					PURLType: purl.TypeApk,
					Metadata: &apkmetadata.Metadata{
						PackageName: "bin1",
						OSID:        "Alpine",
						OSVersionID: "3.19",
					},
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		{
			name: "Ecosystem-level entry without suffix exists and does match",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "bin1",
					Version:  "1.0.0",
					PURLType: purl.TypeApk,
					Metadata: &apkmetadata.Metadata{
						PackageName: "bin1",
						OSID:        "Alpine",
						OSVersionID: "3.20",
					},
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
			name: "Group-level entry exists and does match",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
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
			name: "Group-level entry exists and does not match",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib2",
					Version:  "1.0.0",
					PURLType: "npm",
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		{
			name: "Group-level entry exists and does not match when empty",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib2",
					Version:  "1.0.0",
					PURLType: "npm",
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		// -------------------------------------------------------------------------
		{
			name: "Version-level entry exists and does match",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
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
			name: "Version-level entry exists and does not match",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.1",
					PURLType: purl.TypeGolang,
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		// -------------------------------------------------------------------------
		{
			name: "Name-level entry exists and does match",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
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
			name: "Name-level entry exists and does not match",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib2",
					Version:  "1.0.0",
					PURLType: "npm",
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		// -------------------------------------------------------------------------
		{
			name: "Name, Version, and Ecosystem entry exists",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
				},
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
			name: "Name and Ecosystem entry exists",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
				},
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
			name: "Name, Ecosystem, and Group entry exists and matches",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
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
			name: "Name, Ecosystem, and Group entry exists but does not match",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"prod"},
					},
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		{
			name: "Entry doesn't exist",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "2.0.0",
					PURLType: purl.TypeGolang,
				},
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
		args   imodels.PackageInfo
		wantOk bool
	}{
		{
			name: "Exact version entry exists with ignore",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
				},
			},
			wantOk: true,
		},
		{
			name: "Version entry doesn't exist with ignore",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.1",
					PURLType: purl.TypeGolang,
				},
			},
			wantOk: false,
		},
		{
			name: "Name matches with ignore",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.1",
					PURLType: purl.TypeGolang,
				},
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
		args      imodels.PackageInfo
		wantOk    bool
		wantEntry PackageOverrideEntry
	}{
		{
			name: "Exact version entry exists with override",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
				},
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
			name: "Exact version entry exists with ignore",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.0",
					PURLType: purl.TypeGolang,
				},
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
			name: "Version entry doesn't exist with override",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.1",
					PURLType: purl.TypeGolang,
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		{
			name: "Version entry doesn't exist with ignore",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.1",
					PURLType: purl.TypeGolang,
				},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		{
			name: "Name matches with override",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.1",
					PURLType: purl.TypeGolang,
				},
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
			name: "Name matches with ignore",
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
			args: imodels.PackageInfo{
				Package: &extractor.Package{
					Name:     "lib1",
					Version:  "1.0.1",
					PURLType: purl.TypeGolang,
				},
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
