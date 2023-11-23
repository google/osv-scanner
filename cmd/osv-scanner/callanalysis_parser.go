package main

var stableCallAnalysisStates = map[string]bool{
	"go":   true,
	"rust": false,
}

// Creates a map to record if languages are enabled or disabled for call analysis.
func createCallAnalysisStates(enabledCallAnalysis []string, disabledCallAnalysis []string) map[string]bool {
	enableAll, disableAll := false, false
	callAnalysisStates := make(map[string]bool)

	for _, language := range enabledCallAnalysis {
		if language == "all" {
			enableAll = true
			break
		}
		callAnalysisStates[language] = true
	}

	for _, language := range disabledCallAnalysis {
		if language == "all" {
			disableAll = true
			break
		}
		callAnalysisStates[language] = false
	}

	for language, isStable := range stableCallAnalysisStates {
		if disableAll {
			callAnalysisStates[language] = false
			continue
		}
		if _, exists := callAnalysisStates[language]; !exists {
			callAnalysisStates[language] = isStable
			if enableAll {
				callAnalysisStates[language] = true
			}
		}
	}

	return callAnalysisStates
}
