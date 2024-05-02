package remediation

import (
	"math"
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

	AvoidPkgs  []string // Names of dependencies to avoid upgrading
	AllowMajor bool     // Whether to allow changes to major versions of direct dependencies
}

func (opts RemediationOptions) MatchVuln(v resolution.ResolutionVuln) bool {
	if opts.matchID(v, opts.IgnoreVulns) {
		return false
	}

	if len(opts.ExplicitVulns) > 0 && !opts.matchID(v, opts.ExplicitVulns) {
		return false
	}

	if !opts.DevDeps && v.DevOnly {
		return false
	}

	return opts.matchSeverity(v) && opts.matchDepth(v)
}

func (opts RemediationOptions) matchID(v resolution.ResolutionVuln, ids []string) bool {
	if slices.Contains(ids, v.Vulnerability.ID) {
		return true
	}

	for _, id := range v.Vulnerability.Aliases {
		if slices.Contains(ids, id) {
			return true
		}
	}

	return false
}

func (opts RemediationOptions) matchSeverity(v resolution.ResolutionVuln) bool {
	maxScore := -1.0
	// TODO: also check Vulnerability.Affected[].Severity
	for _, sev := range v.Vulnerability.Severity {
		if score, _, _ := severity.CalculateScore(sev); score > maxScore {
			maxScore = score
		}
	}

	// CVSS scores are meant to only be to 1 decimal place
	// and we want to avoid something being falsely rejected/included due to floating point precision.
	// Multiply and round to only consider relevant parts of the score.
	return math.Round(10*maxScore) >= math.Round(10*opts.MinSeverity) ||
		maxScore < 0 // Always include vulns with unknown severities
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
