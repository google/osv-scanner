package sbom_test

import (
	"encoding/json"
	"strings"
	"testing"

	sbom_test "github.com/google/osv-scanner/internal/utility/sbom"

	"github.com/google/osv-scanner/pkg/reporter/sbom"

	"github.com/stretchr/testify/require"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/stretchr/testify/assert"
)

type JSONMap = map[string]interface{}

var input = map[string]models.PackageDetails{
	"pkg:maven/com.foo/the-greatest-package@1.0.0": {
		Name:      "com.foo:the-greatest-package",
		Version:   "1.0.0",
		Ecosystem: string(models.EcosystemMaven),
		Locations: []models.PackageLocations{
			{
				Block: &models.PackageLocation{
					Filename:    "/path/to/lockfile.xml",
					LineStart:   1,
					LineEnd:     3,
					ColumnStart: 30,
					ColumnEnd:   35,
				},
			},
			{
				Block: &models.PackageLocation{
					Filename:    "/path/to/another-lockfile.xml",
					LineStart:   11,
					LineEnd:     13,
					ColumnStart: 0,
					ColumnEnd:   0,
				},
			},
		},
	},
	"pkg:npm/the-npm-package@1.1.0": {
		Name:      "the-npm-package",
		Version:   "1.1.0",
		Ecosystem: string(models.EcosystemMaven),
		Locations: []models.PackageLocations{
			{
				Block: &models.PackageLocation{
					Filename:    "/path/to/npm/lockfile.lock",
					LineStart:   12,
					LineEnd:     15,
					ColumnStart: 0,
					ColumnEnd:   0,
				},
			},
		},
	},
}

func TestEncoding_EncodeComponentsInValidCycloneDX1_4(t *testing.T) {
	t.Parallel()

	// Given
	bom := sbom.ToCycloneDX14Bom(&strings.Builder{}, input)

	// Then
	expectedBOM := cyclonedx.BOM{
		JSONSchema:  "http://cyclonedx.org/schema/bom-1.4.schema.json",
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

	assert.NotNil(t, bom)
	sbom_test.AssertBomEqual(t, expectedBOM, *bom, false)
}

func TestEncoding_EncodeComponentsInValidCycloneDX1_5(t *testing.T) {
	t.Parallel()
	// Given
	bom := sbom.ToCycloneDX15Bom(&strings.Builder{}, input)

	// Then
	expectedJSONLocations := map[string][]JSONMap{
		"pkg:maven/com.foo/the-greatest-package@1.0.0": {
			{
				"block": JSONMap{
					"file_name":    "/path/to/lockfile.xml",
					"line_start":   1,
					"line_end":     3,
					"column_start": 30,
					"column_end":   35,
				},
			},
			{
				"block": JSONMap{
					"file_name":    "/path/to/another-lockfile.xml",
					"line_start":   11,
					"line_end":     13,
					"column_start": 0,
					"column_end":   0,
				},
			},
		},
		"pkg:npm/the-npm-package@1.1.0": {
			{
				"block": JSONMap{
					"file_name":    "/path/to/npm/lockfile.lock",
					"line_start":   12,
					"line_end":     15,
					"column_start": 0,
					"column_end":   0,
				},
			},
		},
	}

	expectedBOM := cyclonedx.BOM{
		JSONSchema:  "http://cyclonedx.org/schema/bom-1.5.schema.json",
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
					Occurrences: buildOccurrences(t, "pkg:maven/com.foo/the-greatest-package@1.0.0", expectedJSONLocations),
				},
			},
			{
				BOMRef:     "pkg:npm/the-npm-package@1.1.0",
				PackageURL: "pkg:npm/the-npm-package@1.1.0",
				Name:       "the-npm-package",
				Version:    "1.1.0",
				Type:       "library",
				Evidence: &cyclonedx.Evidence{
					Occurrences: buildOccurrences(t, "pkg:npm/the-npm-package@1.1.0", expectedJSONLocations),
				},
			},
		},
	}

	assert.NotNil(t, bom)
	sbom_test.AssertBomEqual(t, expectedBOM, *bom, true)
}

func buildOccurrences(t *testing.T, purl string, expectedLocations map[string][]JSONMap) *[]cyclonedx.EvidenceOccurrence {
	t.Helper()
	locations, ok := expectedLocations[purl]

	if !ok {
		return nil
	}

	result := make([]cyclonedx.EvidenceOccurrence, len(locations))
	for index, location := range locations {
		builder := strings.Builder{}
		err := json.NewEncoder(&builder).Encode(location)
		require.NoError(t, err)
		result[index] = cyclonedx.EvidenceOccurrence{
			Location: builder.String(),
		}
	}

	return &result
}
