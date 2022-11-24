package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/internal/output"
)

type testStruct struct {
	targetPath   string
	config       Config
	configHasErr bool
}

func TestTryLoadConfig(t *testing.T) {

	expectedConfig := Config{
		IgnoredVulns: []IgnoreEntry{
			{
				ID: "GO-2022-0968",
			},
			{
				ID: "GO-2022-1059",
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
		config, configErr := tryLoadConfig(output.NewReporter(new(strings.Builder), new(strings.Builder), false), configPath)
		if !cmp.Equal(config.IgnoredVulns, testData.config.IgnoredVulns) {
			t.Errorf("Configs not equal: %+v != %+v", config, testData.config)
		}
		if testData.configHasErr {
			if configErr == nil {
				t.Error("Config error not returned")
			}
		}
	}
}
