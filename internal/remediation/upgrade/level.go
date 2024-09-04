package upgrade

import (
	"deps.dev/util/semver"
)

type Level int

const (
	Major Level = iota
	Minor
	Patch
	None
)

// Allows returns if the semver.Diff is allowable for this upgrade level constraint.
func (level Level) Allows(diff semver.Diff) bool {
	if diff == semver.Same {
		return true
	}

	switch level {
	case Major:
		return true
	case Minor:
		return diff != semver.DiffMajor
	case Patch:
		return (diff != semver.DiffMajor) && (diff != semver.DiffMinor)
	case None:
		return false
	default: // Invalid level
		return false
	}
}
