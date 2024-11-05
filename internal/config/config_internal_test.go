package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
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
				target: "./fixtures/testdatainner/does-not-exist",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "target is file in directory",
			args: args{
				target: "./fixtures/testdatainner/innerFolder/test.yaml",
			},
			want:    "fixtures/testdatainner/innerFolder/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target is inner directory with trailing slash",
			args: args{
				target: "./fixtures/testdatainner/innerFolder/",
			},
			want:    "fixtures/testdatainner/innerFolder/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target is inner directory without trailing slash",
			args: args{
				target: "./fixtures/testdatainner/innerFolder",
			},
			want:    "fixtures/testdatainner/innerFolder/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target is directory with trailing slash",
			args: args{
				target: "./fixtures/testdatainner/",
			},
			want:    "fixtures/testdatainner/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target is file in directory",
			args: args{
				target: "./fixtures/testdatainner/some-manifest.yaml",
			},
			want:    "fixtures/testdatainner/osv-scanner.toml",
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
				configPath: "./fixtures/testdatainner/does-not-exist",
			},
			want:    Config{},
			wantErr: true,
		},
		{
			name: "config has some ignored vulnerabilities and package overrides",
			args: args{
				configPath: "./fixtures/testdatainner/osv-scanner.toml",
			},
			want: Config{
				LoadPath: "./fixtures/testdatainner/osv-scanner.toml",
				IgnoredVulns: []IgnoreEntry{
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
				configPath: "./fixtures/testdatainner/osv-scanner-load-path.toml",
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

			got, err := tryLoadConfig(&reporter.VoidReporter{}, tt.args.configPath)
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
			configPath: "./fixtures/unknown-key-1.toml",
			unknownMsg: "IgnoredVulns.ignoreUntilTime",
		},
		{
			configPath: "./fixtures/unknown-key-2.toml",
			unknownMsg: "IgnoredVulns.ignoreUntiI",
		},
		{
			configPath: "./fixtures/unknown-key-3.toml",
			unknownMsg: "IgnoredVulns.reasoning",
		},
		{
			configPath: "./fixtures/unknown-key-4.toml",
			unknownMsg: "PackageOverrides.skip",
		},
		{
			configPath: "./fixtures/unknown-key-5.toml",
			unknownMsg: "PackageOverrides.license.skip",
		},
		{
			configPath: "./fixtures/unknown-key-6.toml",
			unknownMsg: "RustVersionOverride",
		},
		{
			configPath: "./fixtures/unknown-key-7.toml",
			unknownMsg: "RustVersionOverride, PackageOverrides.skip",
		},
	}

	for _, testData := range tests {
		c, err := tryLoadConfig(&reporter.VoidReporter{}, testData.configPath)

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
		wantEntry IgnoreEntry
	}{
		// entry exists
		{
			name: "",
			config: Config{
				IgnoredVulns: []IgnoreEntry{
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
			wantEntry: IgnoreEntry{
				ID:          "GHSA-123",
				IgnoreUntil: time.Time{},
				Reason:      "",
			},
		},
		// entry does not exist
		{
			name: "",
			config: Config{
				IgnoredVulns: []IgnoreEntry{
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
			wantEntry: IgnoreEntry{},
		},
		// ignored until a time in the past
		{
			name: "",
			config: Config{
				IgnoredVulns: []IgnoreEntry{
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
			wantEntry: IgnoreEntry{
				ID:          "GHSA-123",
				IgnoreUntil: time.Now().Add(-time.Hour).Round(time.Second),
				Reason:      "",
			},
		},
		// ignored until a time in the future
		{
			name: "",
			config: Config{
				IgnoredVulns: []IgnoreEntry{
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
			wantEntry: IgnoreEntry{
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
		args      models.PackageVulns
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.0",
					Ecosystem: "Go",
				},
				DepGroups: []string{"dev"},
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.0",
					Ecosystem: "Go",
				},
				DepGroups: []string{"dev"},
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib2",
					Version:   "1.0.0",
					Ecosystem: "npm",
				},
				DepGroups: []string{"dev"},
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.0",
					Ecosystem: "Go",
				},
				DepGroups: []string{"dev"},
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib2",
					Version:   "1.0.0",
					Ecosystem: "npm",
				},
				DepGroups: []string{"optional"},
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib2",
					Version:   "1.0.0",
					Ecosystem: "npm",
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.0",
					Ecosystem: "Go",
				},
				DepGroups: []string{"dev"},
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.1",
					Ecosystem: "Go",
				},
				DepGroups: []string{"dev"},
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.0",
					Ecosystem: "Go",
				},
				DepGroups: []string{"dev"},
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib2",
					Version:   "1.0.0",
					Ecosystem: "npm",
				},
				DepGroups: []string{"dev"},
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.0",
					Ecosystem: "Go",
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.0",
					Ecosystem: "Go",
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.0",
					Ecosystem: "Go",
				},
				DepGroups: []string{"dev"},
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.0",
					Ecosystem: "Go",
				},
				DepGroups: []string{"prod"},
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "2.0.0",
					Ecosystem: "Go",
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
		args   models.PackageVulns
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.0",
					Ecosystem: "Go",
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.1",
					Ecosystem: "Go",
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.1",
					Ecosystem: "Go",
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
		args      models.PackageVulns
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.0",
					Ecosystem: "Go",
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.0",
					Ecosystem: "Go",
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.1",
					Ecosystem: "Go",
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.1",
					Ecosystem: "Go",
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.1",
					Ecosystem: "Go",
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
			args: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "lib1",
					Version:   "1.0.1",
					Ecosystem: "Go",
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
