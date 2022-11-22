package osvscanner

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
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
			config:       expectedConfig,
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
		configPath := normalizeConfigLoadPath(absPath)
		config, configErr := tryLoadConfig(configPath)
		cmp.Equal(config, testData.config)
		if testData.configHasErr {
			cmp.Equal(configErr, nil)
		}
	}
}
