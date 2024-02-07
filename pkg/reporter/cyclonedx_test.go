package reporter_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/stretchr/testify/assert"
)

type JsonMap = map[string]any

var vulnResults = models.VulnerabilityResults{
	Results: []models.PackageSource{
		{
			Source: models.SourceInfo{
				Path: "/path/to/lockfile.xml",
				Type: "",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "com.foo:the-greatest-package",
						Version:   "1.0.0",
						Ecosystem: string(models.EcosystemMaven),
						Line: models.Position{
							Start: 1,
							End:   3,
						},
						Column: models.Position{
							Start: 30,
							End:   35,
						},
					},
				},
			},
		},
		{
			Source: models.SourceInfo{
				Path: "/path/to/another-lockfile.xml",
				Type: "",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "com.foo:the-greatest-package",
						Version:   "1.0.0",
						Ecosystem: string(models.EcosystemMaven),
						Line: models.Position{
							Start: 11,
							End:   13,
						},
					},
				},
			},
		},
		{
			Source: models.SourceInfo{
				Path: "/path/to/npm/lockfile.lock",
				Type: "",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "the-npm-package",
						Version:   "1.1.0",
						Ecosystem: string(models.EcosystemNPM),
						Line: models.Position{
							Start: 12,
							End:   15,
						},
					},
				},
			},
		},
	},
}

func TestEncoding_EncodeComponentsInValidCycloneDX1_4(t *testing.T) {
	t.Parallel()
	var stdout, stderr strings.Builder
	cycloneDXReporter := reporter.NewCycloneDXReporter(&stdout, &stderr, reporter.CycloneDXVersion14)

	// First we format packages in CycloneDX format
	err := cycloneDXReporter.PrintResult(&vulnResults)
	require.NoError(t, err, "an error occurred when formatting")

	// Then we try to decode it using the CycloneDX library directly to check the content
	var bom cyclonedx.BOM
	decoder := cyclonedx.NewBOMDecoder(strings.NewReader(stdout.String()), cyclonedx.BOMFileFormatJSON)
	err = decoder.Decode(&bom)
	require.NoError(t, err, "an error occurred when decoding")

	expectedBOM := cyclonedx.BOM{
		JSONSchema:  "https://cyclonedx.org/schema/bom-1.4.schema.json",
		Version:     1,
		BOMFormat:   cyclonedx.BOMFormat,
		SpecVersion: cyclonedx.SpecVersion1_4,
		Components: &[]cyclonedx.Component{
			{
				BOMRef:     "pkg:maven/com.foo/the-greatest-package@1.0.0",
				PackageURL: "pkg:maven/com.foo/the-greatest-package@1.0.0",
				Name:       "com.foo:the-greatest-package",
				Version:    "1.0.0",
				Type:       "library",
			},
			{
				BOMRef:     "pkg:npm/the-npm-package@1.1.0",
				PackageURL: "pkg:npm/the-npm-package@1.1.0",
				Name:       "the-npm-package",
				Version:    "1.1.0",
				Type:       "library",
			},
		},
	}
	assert.EqualValuesf(t, expectedBOM, bom, "Decoded bom is different than expected bom")
}

func TestEncoding_EncodeComponentsInValidCycloneDX1_5(t *testing.T) {
	t.Parallel()
	var stdout, stderr strings.Builder
	cycloneDXReporter := reporter.NewCycloneDXReporter(&stdout, &stderr, reporter.CycloneDXVersion15)

	// First we format packages in CycloneDX format
	err := cycloneDXReporter.PrintResult(&vulnResults)
	require.NoError(t, err, "an error occurred when formatting")

	// Then we try to decode it using the CycloneDX library directly to check the content
	var bom cyclonedx.BOM
	decoder := cyclonedx.NewBOMDecoder(strings.NewReader(stdout.String()), cyclonedx.BOMFileFormatJSON)
	err = decoder.Decode(&bom)
	require.NoError(t, err, "an error occurred when decoding")

	expectedJsonLocations := []JsonMap{
		{
			"block": JsonMap{
				"file_name":    "/path/to/lockfile.xml",
				"line_start":   1,
				"line_end":     3,
				"column_start": 30,
				"column_end":   35,
			},
		},
		{
			"block": JsonMap{
				"file_name":    "/path/to/another-lockfile.xml",
				"line_start":   11,
				"line_end":     13,
				"column_start": 0,
				"column_end":   0,
			},
		},
	}
	expectedLocations := make([]string, 0)
	for index, jsonLocation := range expectedJsonLocations {
		builder := strings.Builder{}
		err = json.NewEncoder(&builder).Encode(jsonLocation)
		require.NoErrorf(t, err, "an error occurred when computing the expected json (index = %v)", index)
		expectedLocations = append(expectedLocations, builder.String())
	}

	expectedBOM := cyclonedx.BOM{
		JSONSchema:  "https://cyclonedx.org/schema/bom-1.5.schema.json",
		Version:     1,
		BOMFormat:   cyclonedx.BOMFormat,
		SpecVersion: cyclonedx.SpecVersion1_5,
		Components: &[]cyclonedx.Component{
			{
				BOMRef:     "pkg:maven/com.foo/the-greatest-package@1.0.0",
				PackageURL: "pkg:maven/com.foo/the-greatest-package@1.0.0",
				Name:       "com.foo:the-greatest-package",
				Version:    "1.0.0",
				Type:       "library",
				Evidence: &cyclonedx.Evidence{
					Occurrences: &[]cyclonedx.EvidenceOccurrence{
						{
							Location: expectedLocations[0],
						},
					},
				},
			},
			{
				BOMRef:     "pkg:npm/the-npm-package@1.1.0",
				PackageURL: "pkg:npm/the-npm-package@1.1.0",
				Name:       "the-npm-package",
				Version:    "1.1.0",
				Type:       "library",
				Evidence: &cyclonedx.Evidence{
					Occurrences: &[]cyclonedx.EvidenceOccurrence{
						{
							Location: expectedLocations[1],
						},
					},
				},
			},
		},
	}

	assertBaseBomEquals(t, expectedBOM, bom)
	for index, expectedComponent := range *expectedBOM.Components {
		actualComponent := (*bom.Components)[index]
		assertBaseComponentEquals(t, expectedComponent, actualComponent)
		assert.JSONEq(t, (*expectedComponent.Evidence.Occurrences)[0].Location, expectedLocations[index])
	}
}

func assertBaseComponentEquals(t *testing.T, expected, actual cyclonedx.Component) {
	assert.EqualValues(t, expected.Name, actual.Name)
	assert.EqualValues(t, expected.Version, actual.Version)
	assert.EqualValues(t, expected.BOMRef, actual.BOMRef)
	assert.EqualValues(t, expected.PackageURL, actual.PackageURL)
	assert.EqualValues(t, expected.Type, actual.Type)
}

func assertBaseBomEquals(t *testing.T, expected, actual cyclonedx.BOM) {
	assert.EqualValues(t, expected.JSONSchema, actual.JSONSchema)
	assert.EqualValues(t, expected.Version, actual.Version)
	assert.EqualValues(t, expected.BOMFormat, actual.BOMFormat)
	assert.EqualValues(t, expected.SpecVersion, actual.SpecVersion)
}
