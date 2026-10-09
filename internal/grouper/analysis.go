package grouper

import (
	"slices"

	"github.com/google/osv-scanner/v2/pkg/models"
)

// CopyAnalysis copies the experimental analysis of each vulnerability in from
// onto the group in to that contains that vulnerability, overwriting any
// existing analysis for it.
//
// This is useful when regrouping, as some analysis (such as call analysis)
// cannot be derived from the vulnerabilities alone.
//
// Vulnerabilities are expected to be in exactly one group
func CopyAnalysis(from, to []models.GroupInfo) {
	for _, group := range from {
		for vulnID, analysis := range group.ExperimentalAnalysis {
			i := slices.IndexFunc(to, func(g models.GroupInfo) bool {
				return slices.Contains(g.IDs, vulnID)
			})

			if i == -1 {
				continue
			}

			if to[i].ExperimentalAnalysis == nil {
				to[i].ExperimentalAnalysis = make(map[string]models.AnalysisInfo)
			}

			to[i].ExperimentalAnalysis[vulnID] = analysis
		}
	}
}
