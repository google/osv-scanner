package config

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/pkg/models"
)

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
			name: "target is file in directory with config",
			args: args{
				target: "./fixtures/testdatainner/innerFolder/test.yaml",
			},
			want:    "fixtures/testdatainner/innerFolder/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target is directory with config, with trailing slash",
			args: args{
				target: "./fixtures/testdatainner/innerFolder/",
			},
			want:    "fixtures/testdatainner/innerFolder/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target is directory with config, without trailing slash",
			args: args{
				target: "./fixtures/testdatainner/innerFolder",
			},
			want:    "fixtures/testdatainner/innerFolder/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target is directory with config, with trailing slash",
			args: args{
				target: "./fixtures/testdatainner/",
			},
			want:    "fixtures/testdatainner/osv-scanner.toml",
			wantErr: false,
		},
		{
			name: "target is file in directory with config",
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

func TestConfig_ShouldIgnorePackageVersion(t *testing.T) {
	t.Parallel()

	type args struct {
		name      string
		version   string
		ecosystem string
	}
	tests := []struct {
		name      string
		config    Config
		args      args
		wantOk    bool
		wantEntry PackageOverrideEntry
	}{
		{
			name: "Version-level entry exists",
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
			args: args{
				name:      "lib1",
				version:   "1.0.0",
				ecosystem: "Go",
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
			name: "Package-level entry exists",
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
			args: args{
				name:      "lib1",
				version:   "1.0.0",
				ecosystem: "Go",
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
			args: args{
				name:      "lib1",
				version:   "2.0.0",
				ecosystem: "Go",
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotOk, gotEntry := tt.config.ShouldIgnorePackageVersion(tt.args.name, tt.args.version, tt.args.ecosystem)
			if gotOk != tt.wantOk {
				t.Errorf("ShouldIgnorePackageVersion() gotOk = %v, wantOk %v", gotOk, tt.wantOk)
			}
			if !reflect.DeepEqual(gotEntry, tt.wantEntry) {
				t.Errorf("ShouldIgnorePackageVersion() gotEntry = %v, wantEntry %v", gotEntry, tt.wantEntry)
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

func TestConfig_ShouldOverridePackageVersionLicense(t *testing.T) {
	t.Parallel()

	type args struct {
		name      string
		version   string
		ecosystem string
	}
	tests := []struct {
		name      string
		config    Config
		args      args
		wantOk    bool
		wantEntry PackageOverrideEntry
	}{
		{
			name: "Exact version entry exists",
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
			args: args{
				name:      "lib1",
				version:   "1.0.0",
				ecosystem: "Go",
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
			name: "Version entry doesn't exist",
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
			args: args{
				name:      "lib1",
				version:   "1.0.1",
				ecosystem: "Go",
			},
			wantOk:    false,
			wantEntry: PackageOverrideEntry{},
		},
		{
			name: "Name matches",
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
			args: args{
				name:      "lib1",
				version:   "1.0.1",
				ecosystem: "Go",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotOk, gotEntry := tt.config.ShouldOverridePackageVersionLicense(tt.args.name, tt.args.version, tt.args.ecosystem)
			if gotOk != tt.wantOk {
				t.Errorf("ShouldOverridePackageVersionLicense() gotOk = %v, wantOk %v", gotOk, tt.wantOk)
			}
			if !reflect.DeepEqual(gotEntry, tt.wantEntry) {
				t.Errorf("ShouldOverridePackageVersionLicense() gotEntry = %v, wantEntry %v", gotEntry, tt.wantEntry)
			}
		})
	}
}
