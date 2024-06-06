package config

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type testStruct struct {
	targetPath   string
	config       Config
	configHasErr bool
}

func TestTryLoadConfig(t *testing.T) {
	t.Parallel()

	expectedConfig := Config{
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
	}
	testPaths := []testStruct{
		{
			targetPath:   "../../fixtures/testdatainner/innerFolder/test.yaml",
			config:       Config{},
			configHasErr: true,
		},
		{
			targetPath:   "../../fixtures/testdatainner/innerFolder/",
			config:       Config{},
			configHasErr: true,
		},
		{ // Test no slash at the end
			targetPath:   "../../fixtures/testdatainner/innerFolder",
			config:       Config{},
			configHasErr: true,
		},
		{
			targetPath:   "../../fixtures/testdatainner/",
			config:       expectedConfig,
			configHasErr: false,
		},
		{
			targetPath:   "../../fixtures/testdatainner/some-manifest.yaml",
			config:       expectedConfig,
			configHasErr: false,
		},
	}

	for _, testData := range testPaths {
		absPath, err := filepath.Abs(testData.targetPath)
		if err != nil {
			t.Errorf("%s", err)
		}
		configPath, err := normalizeConfigLoadPath(absPath)
		if err != nil {
			t.Errorf("%s", err)
		}
		config, configErr := tryLoadConfig(configPath)
		if !cmp.Equal(config.IgnoredVulns, testData.config.IgnoredVulns) {
			t.Errorf("Configs not equal: %+v != %+v", config, testData.config)
		}
		if !cmp.Equal(config.PackageOverrides, testData.config.PackageOverrides) {
			t.Errorf("Configs not equal: %+v != %+v", config, testData.config)
		}
		if testData.configHasErr {
			if configErr == nil {
				t.Error("Config error not returned")
			}
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
		tt := tt
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
		tt := tt
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
		tt := tt
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
