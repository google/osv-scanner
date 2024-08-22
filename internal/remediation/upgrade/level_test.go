package upgrade_test

import (
	"slices"
	"testing"

	"deps.dev/util/semver"
	"github.com/google/osv-scanner/internal/remediation/upgrade"
)

func TestLevelAllows(t *testing.T) {
	t.Parallel()
	// Check every combination of Level + Diff
	allDiffs := [...]semver.Diff{
		semver.Same,
		semver.DiffOther,
		semver.DiffMajor,
		semver.DiffMinor,
		semver.DiffPatch,
		semver.DiffPrerelease,
		semver.DiffBuild,
	}

	levelDisallowed := map[upgrade.Level][]semver.Diff{
		upgrade.Major: {},
		upgrade.Minor: {semver.DiffMajor},
		upgrade.Patch: {semver.DiffMajor, semver.DiffMinor},
		upgrade.None:  allDiffs[1:], // everything but semver.Same
	}

	for level, disallowed := range levelDisallowed {
		for _, diff := range allDiffs {
			want := !slices.Contains(disallowed, diff)
			got := level.Allows(diff)
			if want != got {
				t.Errorf("(Level: %v, Diff: %v) Allows() = %v, want %v", level, diff, got, want)
			}
		}
	}
}
