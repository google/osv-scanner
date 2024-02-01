package scan

import (
	"reflect"
	"testing"
)

func TestCreateCallAnalysisStates(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		enabledCallAnalysis        []string
		disabledCallAnalysis       []string
		expectedCallAnalysisStates map[string]bool
	}{
		{
			enabledCallAnalysis:  []string{"go", "rust"},
			disabledCallAnalysis: []string{},
			expectedCallAnalysisStates: map[string]bool{
				"go":   true,
				"rust": true,
			},
		},
		{
			enabledCallAnalysis:  []string{"all"},
			disabledCallAnalysis: []string{"rust"},
			expectedCallAnalysisStates: map[string]bool{
				"go":   true,
				"rust": false,
			},
		},
		{
			enabledCallAnalysis:  []string{},
			disabledCallAnalysis: []string{"all"},
			expectedCallAnalysisStates: map[string]bool{
				"go":   false,
				"rust": false,
			},
		},
		{
			enabledCallAnalysis:  []string{},
			disabledCallAnalysis: []string{"rust"},
			expectedCallAnalysisStates: map[string]bool{
				"go":   true,
				"rust": false,
			},
		},
		{
			enabledCallAnalysis:  []string{"all", "rust"},
			disabledCallAnalysis: []string{"go"},
			expectedCallAnalysisStates: map[string]bool{
				"go":   false,
				"rust": true,
			},
		},
	}

	for _, testCase := range testCases {
		actualCallAnalysisStates := createCallAnalysisStates(testCase.enabledCallAnalysis, testCase.disabledCallAnalysis)

		if !reflect.DeepEqual(actualCallAnalysisStates, testCase.expectedCallAnalysisStates) {
			t.Errorf("expected call analysis states to be %v, but got %v", testCase.expectedCallAnalysisStates, actualCallAnalysisStates)
		}
	}
}
