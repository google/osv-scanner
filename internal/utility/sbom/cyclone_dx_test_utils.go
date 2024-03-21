package sbom_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func AssertBomEqual(t *testing.T, expected, actual cyclonedx.BOM, assertLocations bool) {
	t.Helper()
	assertBaseBomEquals(t, expected, actual)
	for _, expectedComponent := range *expected.Components {
		matchedComponent := assertComponentsContains(t, expectedComponent, *actual.Components)
		if assertLocations {
			if matchedComponent.Evidence != nil && expectedComponent.Evidence != nil {
				assertOccurrencesEquals(t, *expectedComponent.Evidence.Occurrences, *matchedComponent.Evidence.Occurrences)
			} else if expectedComponent.Evidence != nil {
				assert.Fail(t, "matched component evidence is nil where it expected to be set", expectedComponent)
			}
		}
	}
}

func assertBaseBomEquals(t *testing.T, expected, actual cyclonedx.BOM) {
	t.Helper()
	assert.EqualValues(t, expected.JSONSchema, actual.JSONSchema)
	assert.EqualValues(t, expected.Version, actual.Version)
	assert.EqualValues(t, expected.BOMFormat, actual.BOMFormat)
	assert.EqualValues(t, expected.SpecVersion, actual.SpecVersion)
	assert.Len(t, *actual.Components, len(*expected.Components))
}

func assertComponentsContains(t *testing.T, expected cyclonedx.Component, actual []cyclonedx.Component) *cyclonedx.Component {
	t.Helper()

	for _, component := range actual {
		if component.PackageURL != expected.PackageURL {
			continue
		}
		assert.EqualValues(t, expected.Name, component.Name)
		assert.EqualValues(t, expected.Version, component.Version)
		assert.EqualValues(t, expected.BOMRef, component.BOMRef)
		assert.EqualValues(t, expected.PackageURL, component.PackageURL)
		assert.EqualValues(t, expected.Type, component.Type)

		return &component
	}
	assert.FailNowf(t, "Received component array does not contains expected component", "%v", expected)

	return nil
}

func assertOccurrencesEquals(t *testing.T, expected []cyclonedx.EvidenceOccurrence, actual []cyclonedx.EvidenceOccurrence) {
	t.Helper()

	assert.Len(t, actual, len(expected), "Length of occurrences differs from expected. expected = %v ; actual = %v", len(expected), len(actual))
	groupedLocations, err := groupLocationsByBlockFilePath(actual, expected)
	require.NoError(t, err)
	for _, occurrences := range groupedLocations {
		if len(occurrences) < 2 {
			// If there is less than 2 occurrences, it means the arrays are not equals
			expectedStr := strings.Builder{}
			actualStr := strings.Builder{}
			require.NoError(t, json.NewEncoder(&expectedStr).Encode(expected))
			require.NoError(t, json.NewEncoder(&actualStr).Encode(actual))
			assert.Fail(t, "Expected and actual locations does not contain the same paths. expected = %v ; actual = %v", expectedStr.String(), actualStr.String())
		}
		reference := occurrences[0] // If we have location to compare, then we take the first one as a reference
		for _, location := range occurrences[1:] {
			assert.JSONEq(t, reference.Location, location.Location)
		}
	}
}

func groupLocationsByBlockFilePath(occurrences ...[]cyclonedx.EvidenceOccurrence) (map[string][]cyclonedx.EvidenceOccurrence, error) {
	result := make(map[string][]cyclonedx.EvidenceOccurrence)

	for _, currentOccurences := range occurrences {
		for _, occurrence := range currentOccurences {
			decodedLocation := models.PackageLocations{}
			err := json.NewDecoder(strings.NewReader(occurrence.Location)).Decode(&decodedLocation)

			if err != nil {
				return nil, err
			}

			groupResult, exists := result[decodedLocation.Block.Filename]
			if !exists {
				groupResult = make([]cyclonedx.EvidenceOccurrence, 0)
			}
			groupResult = append(groupResult, occurrence)
			result[decodedLocation.Block.Filename] = groupResult
		}
	}

	return result, nil
}
