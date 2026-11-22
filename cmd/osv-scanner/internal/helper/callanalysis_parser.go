package helper

import (
	"fmt"
	"slices"
	"strings"
)

var stableCallAnalysisStates = map[string]bool{
	"go":   true,
	"rust": false,
	"jar":  false,
}

// supportedCallAnalysisLanguages returns every language name that may be given to
// --call-analysis and --no-call-analysis.
func supportedCallAnalysisLanguages() []string {
	languages := make([]string, 0, len(stableCallAnalysisStates)+1)
	languages = append(languages, "all")
	for language := range stableCallAnalysisStates {
		languages = append(languages, language)
	}
	slices.Sort(languages)
	return languages
}

// validateCallAnalysisLanguages rejects language names that call analysis does not know about. A
// misspelled name used to be stored under its own key and never consulted, so asking for call
// analysis silently did nothing.
func validateCallAnalysisLanguages(languages []string) error {
	for _, language := range languages {
		if language == "all" {
			continue
		}
		if _, ok := stableCallAnalysisStates[language]; !ok {
			return fmt.Errorf("unsupported call-analysis language %q - must be one of: %s",
				language, strings.Join(supportedCallAnalysisLanguages(), ", "))
		}
	}
	return nil
}

// CreateCallAnalysisStates creates a map to record if languages are enabled or disabled for call analysis
func CreateCallAnalysisStates(enabledCallAnalysis []string, disabledCallAnalysis []string) (map[string]bool, error) {
	for i, language := range enabledCallAnalysis {
		enabledCallAnalysis[i] = strings.ToLower(language)
	}
	for i, language := range disabledCallAnalysis {
		disabledCallAnalysis[i] = strings.ToLower(language)
	}

	if err := validateCallAnalysisLanguages(enabledCallAnalysis); err != nil {
		return nil, err
	}
	if err := validateCallAnalysisLanguages(disabledCallAnalysis); err != nil {
		return nil, err
	}

	callAnalysisStates := make(map[string]bool)

	for _, language := range enabledCallAnalysis {
		callAnalysisStates[language] = true
	}

	for _, language := range disabledCallAnalysis {
		callAnalysisStates[language] = false
	}

	enableAll, containsAll := callAnalysisStates["all"]
	for language, isStable := range stableCallAnalysisStates {
		if _, exists := callAnalysisStates[language]; !exists {
			callAnalysisStates[language] = isStable || enableAll
		}
		if containsAll && !enableAll {
			callAnalysisStates[language] = false
		}
	}
	delete(callAnalysisStates, "all")

	return callAnalysisStates, nil
}
