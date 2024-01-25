package remediation

import (
	"slices"

	"github.com/google/osv-scanner/internal/resolution"
	"github.com/google/osv-scanner/internal/utility/severity"
)

type RemediationOptions struct {
	IgnoreVulns   []string // Vulnerability IDs to ignore
	ExplicitVulns []string // If set, only consider these vulnerability IDs & ignore all others

	DevDeps     bool    // Whether to consider vulnerabilities in dev dependencies
	MinSeverity float64 // Minimum vulnerability CVSS score to consider
	MaxDepth    int     // Maximum depth of dependency to consider vulnerabilities for (e.g. 1 for direct only)

	AvoidPkgs  []string // Names of direct dependencies to avoid upgrading
	AllowMajor bool     // Whether to allow changes to major versions of direct dependencies
}

func (opts RemediationOptions) MatchVuln(v resolution.ResolutionVuln) bool {
	if slices.Contains(opts.IgnoreVulns, v.Vulnerability.ID) {
		return false
	}

	if len(opts.ExplicitVulns) > 0 && !slices.Contains(opts.ExplicitVulns, v.Vulnerability.ID) {
		return false
	}

	if !opts.DevDeps && v.DevOnly {
		return false
	}

	return opts.matchSeverity(v) && opts.matchDepth(v)
}

func (opts RemediationOptions) matchSeverity(v resolution.ResolutionVuln) bool {
	maxScore := -1.0
	// TODO: also check Vulnerability.Affected[].Severity
	for _, sev := range v.Vulnerability.Severity {
		if score, _, _ := severity.CalculateScore(sev); score > maxScore {
			maxScore = score
		}
	}

	return maxScore < 0 || // Always include vulns with unknown severities
		int(10*maxScore) >= int(10*opts.MinSeverity) // CVSS scores are only to 1 decimal place
}

func (opts RemediationOptions) matchDepth(v resolution.ResolutionVuln) bool {
	if opts.MaxDepth <= 0 {
		return true
	}

	if len(v.ProblemChains)+len(v.NonProblemChains) == 0 {
		panic("vulnerability with no dependency chains")
	}

	for _, ch := range v.ProblemChains {
		if len(ch.Edges) <= opts.MaxDepth {
			return true
		}
	}

	for _, ch := range v.NonProblemChains {
		if len(ch.Edges) <= opts.MaxDepth {
			return true
		}
	}

	return false
}
