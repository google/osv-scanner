package scan

var stableCallAnalysisStates = map[string]bool{
	"go":   true,
	"rust": false,
}

// Creates a map to record if languages are enabled or disabled for call analysis.
func createCallAnalysisStates(enabledCallAnalysis []string, disabledCallAnalysis []string) map[string]bool {
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

	return callAnalysisStates
}
