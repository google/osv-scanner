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
		IgnoredPackageVersions: []IgnorePackageVersionEntry{
			{
				Name:      "lib",
				Version:   "1.0.0",
				Ecosystem: "Go",
				Reason:    "abc",
			},
		},
		OverridePackageVersionLicenses: []OverridePackageVersionLicenseEntry{
			{
				Name:            "my-pkg",
				ExactVersion:    "1.0.0",
				Ecosystem:       "Go",
				Reason:          "abc",
				LicenseOverride: []string{"MIT", "0BSD"},
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
		if !cmp.Equal(config.IgnoredPackageVersions, testData.config.IgnoredPackageVersions) {
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
		wantEntry IgnorePackageVersionEntry
	}{
		{
			name: "Version-level entry exists",
			config: Config{
				IgnoredPackageVersions: []IgnorePackageVersionEntry{
					{
						Name:        "lib1",
						Version:     "1.0.0",
						Ecosystem:   "Go",
						IgnoreUntil: time.Time{},
						Reason:      "abc",
					},
				},
			},
			args: args{
				name:      "lib1",
				version:   "1.0.0",
				ecosystem: "Go",
			},
			wantOk: true,
			wantEntry: IgnorePackageVersionEntry{
				Name:        "lib1",
				Version:     "1.0.0",
				Ecosystem:   "Go",
				IgnoreUntil: time.Time{},
				Reason:      "abc",
			},
		},
		{
			name: "Package-level entry exists",
			config: Config{
				IgnoredPackageVersions: []IgnorePackageVersionEntry{
					{
						Name:        "lib1",
						Ecosystem:   "Go",
						IgnoreUntil: time.Time{},
						Reason:      "abc",
					},
				},
			},
			args: args{
				name:      "lib1",
				version:   "1.0.0",
				ecosystem: "Go",
			},
			wantOk: true,
			wantEntry: IgnorePackageVersionEntry{
				Name:        "lib1",
				Ecosystem:   "Go",
				IgnoreUntil: time.Time{},
				Reason:      "abc",
			},
		},
		{
			name: "Entry doesn't exists",
			config: Config{
				IgnoredPackageVersions: []IgnorePackageVersionEntry{
					{
						Name:        "lib1",
						Version:     "1.0.0",
						Ecosystem:   "Go",
						IgnoreUntil: time.Time{},
						Reason:      "abc",
					},
					{
						Name:        "lib2",
						Version:     "2.0.0",
						Ecosystem:   "Go",
						IgnoreUntil: time.Time{},
						Reason:      "abc",
					},
				},
			},
			args: args{
				name:      "lib1",
				version:   "2.0.0",
				ecosystem: "Go",
			},
			wantOk:    false,
			wantEntry: IgnorePackageVersionEntry{},
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
		wantEntry OverridePackageVersionLicenseEntry
	}{
		{
			name: "Exact version entry exists",
			config: Config{
				OverridePackageVersionLicenses: []OverridePackageVersionLicenseEntry{
					{
						Name:            "lib1",
						ExactVersion:    "1.0.0",
						Ecosystem:       "Go",
						LicenseOverride: []string{"mit"},
						Reason:          "abc",
					},
				},
			},
			args: args{
				name:      "lib1",
				version:   "1.0.0",
				ecosystem: "Go",
			},
			wantOk: true,
			wantEntry: OverridePackageVersionLicenseEntry{
				Name:            "lib1",
				ExactVersion:    "1.0.0",
				Ecosystem:       "Go",
				LicenseOverride: []string{"mit"},
				Reason:          "abc",
			},
		},
		{
			name: "Exact version entry doesn't exist",
			config: Config{
				OverridePackageVersionLicenses: []OverridePackageVersionLicenseEntry{
					{
						Name:            "lib1",
						ExactVersion:    "1.0.0",
						Ecosystem:       "Go",
						LicenseOverride: []string{"mit"},
						Reason:          "abc",
					},
				},
			},
			args: args{
				name:      "lib1",
				version:   "1.0.1",
				ecosystem: "Go",
			},
			wantOk:    false,
			wantEntry: OverridePackageVersionLicenseEntry{},
		},
		{
			name: "Major version matches",
			config: Config{
				OverridePackageVersionLicenses: []OverridePackageVersionLicenseEntry{
					{
						Name:            "lib1",
						Major:           "1",
						Ecosystem:       "Go",
						LicenseOverride: []string{"mit"},
						Reason:          "abc",
					},
				},
			},
			args: args{
				name:      "lib1",
				version:   "1.0.1",
				ecosystem: "Go",
			},
			wantOk: true,
			wantEntry: OverridePackageVersionLicenseEntry{
				Name:            "lib1",
				Major:           "1",
				Ecosystem:       "Go",
				LicenseOverride: []string{"mit"},
				Reason:          "abc",
			},
		},
		{
			name: "Major and minor version matches",
			config: Config{
				OverridePackageVersionLicenses: []OverridePackageVersionLicenseEntry{
					{
						Name:            "lib1",
						Major:           "1",
						Minor:           "0",
						Ecosystem:       "Go",
						LicenseOverride: []string{"mit"},
						Reason:          "abc",
					},
				},
			},
			args: args{
				name:      "lib1",
				version:   "1.0.1",
				ecosystem: "Go",
			},
			wantOk: true,
			wantEntry: OverridePackageVersionLicenseEntry{
				Name:            "lib1",
				Major:           "1",
				Minor:           "0",
				Ecosystem:       "Go",
				LicenseOverride: []string{"mit"},
				Reason:          "abc",
			},
		},
		{
			name: "Major, minor and patch version matches",
			config: Config{
				OverridePackageVersionLicenses: []OverridePackageVersionLicenseEntry{
					{
						Name:            "lib1",
						Major:           "1",
						Minor:           "0",
						Patch:           "1",
						Ecosystem:       "Go",
						LicenseOverride: []string{"mit"},
						Reason:          "abc",
					},
				},
			},
			args: args{
				name:      "lib1",
				version:   "1.0.1",
				ecosystem: "Go",
			},
			wantOk: true,
			wantEntry: OverridePackageVersionLicenseEntry{
				Name:            "lib1",
				Major:           "1",
				Minor:           "0",
				Patch:           "1",
				Ecosystem:       "Go",
				LicenseOverride: []string{"mit"},
				Reason:          "abc",
			},
		},
		{
			name: "Major matches, minor doesn't",
			config: Config{
				OverridePackageVersionLicenses: []OverridePackageVersionLicenseEntry{
					{
						Name:            "lib1",
						Major:           "1",
						Minor:           "2",
						Ecosystem:       "Go",
						LicenseOverride: []string{"mit"},
						Reason:          "abc",
					},
				},
			},
			args: args{
				name:      "lib1",
				version:   "1.0.1",
				ecosystem: "Go",
			},
			wantOk:    false,
			wantEntry: OverridePackageVersionLicenseEntry{},
		},
		{
			name: "Major and minor matches, patch doesn't",
			config: Config{
				OverridePackageVersionLicenses: []OverridePackageVersionLicenseEntry{
					{
						Name:            "lib1",
						Major:           "1",
						Minor:           "0",
						Patch:           "3",
						Ecosystem:       "Go",
						LicenseOverride: []string{"mit"},
						Reason:          "abc",
					},
				},
			},
			args: args{
				name:      "lib1",
				version:   "1.0.1",
				ecosystem: "Go",
			},
			wantOk:    false,
			wantEntry: OverridePackageVersionLicenseEntry{},
		},
		{
			name: "Name matches",
			config: Config{
				OverridePackageVersionLicenses: []OverridePackageVersionLicenseEntry{
					{
						Name:            "lib1",
						Ecosystem:       "Go",
						LicenseOverride: []string{"mit"},
						Reason:          "abc",
					},
				},
			},
			args: args{
				name:      "lib1",
				version:   "1.0.1",
				ecosystem: "Go",
			},
			wantOk: true,
			wantEntry: OverridePackageVersionLicenseEntry{
				Name:            "lib1",
				Ecosystem:       "Go",
				LicenseOverride: []string{"mit"},
				Reason:          "abc",
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
