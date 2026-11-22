package helper

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
				"jar":  false,
			},
		},
		{
			enabledCallAnalysis:  []string{"all"},
			disabledCallAnalysis: []string{"rust"},
			expectedCallAnalysisStates: map[string]bool{
				"go":   true,
				"rust": false,
				"jar":  true,
			},
		},
		{
			enabledCallAnalysis:  []string{},
			disabledCallAnalysis: []string{"all"},
			expectedCallAnalysisStates: map[string]bool{
				"go":   false,
				"rust": false,
				"jar":  false,
			},
		},
		{
			enabledCallAnalysis:  []string{},
			disabledCallAnalysis: []string{"rust"},
			expectedCallAnalysisStates: map[string]bool{
				"go":   true,
				"rust": false,
				"jar":  false,
			},
		},
		{
			enabledCallAnalysis:  []string{"all", "rust"},
			disabledCallAnalysis: []string{"go"},
			expectedCallAnalysisStates: map[string]bool{
				"go":   false,
				"rust": true,
				"jar":  true,
			},
		},
	}

	for _, testCase := range testCases {
		actualCallAnalysisStates, err := CreateCallAnalysisStates(testCase.enabledCallAnalysis, testCase.disabledCallAnalysis)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !reflect.DeepEqual(actualCallAnalysisStates, testCase.expectedCallAnalysisStates) {
			t.Errorf("expected call analysis states to be %v, but got %v", testCase.expectedCallAnalysisStates, actualCallAnalysisStates)
		}
	}
}

func TestCreateCallAnalysisStatesRejectsUnknownLanguages(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name                       string
		enabledCallAnalysis        []string
		disabledCallAnalysis       []string
		expectedCallAnalysisStates map[string]bool
		expectedErr                string
	}{
		{
			name:                       "misspelled enabled language",
			enabledCallAnalysis:        []string{"goo"},
			expectedCallAnalysisStates: nil,
			expectedErr:                `unsupported call-analysis language "goo" - must be one of: all, go, jar, rust`,
		},
		{
			name:                       "misspelled disabled language",
			disabledCallAnalysis:       []string{"jarr"},
			expectedCallAnalysisStates: nil,
			expectedErr:                `unsupported call-analysis language "jarr" - must be one of: all, go, jar, rust`,
		},
		{
			name:                "language names are case insensitive",
			enabledCallAnalysis: []string{"Rust"},
			expectedCallAnalysisStates: map[string]bool{
				"go":   true,
				"rust": true,
				"jar":  false,
			},
		},
		{
			name:                 "all is accepted in both lists",
			enabledCallAnalysis:  []string{"ALL"},
			disabledCallAnalysis: []string{"all"},
			expectedCallAnalysisStates: map[string]bool{
				"go":   false,
				"rust": false,
				"jar":  false,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			actualCallAnalysisStates, err := CreateCallAnalysisStates(testCase.enabledCallAnalysis, testCase.disabledCallAnalysis)

			if testCase.expectedErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, but got none", testCase.expectedErr)
				}
				if err.Error() != testCase.expectedErr {
					t.Fatalf("expected error %q, but got %q", testCase.expectedErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(actualCallAnalysisStates, testCase.expectedCallAnalysisStates) {
				t.Errorf("expected call analysis states to be %v, but got %v", testCase.expectedCallAnalysisStates, actualCallAnalysisStates)
			}
		})
	}
}
