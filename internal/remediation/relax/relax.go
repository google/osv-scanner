package relax

import (
	"context"
	"errors"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/remediation/upgrade"
)

// A RequirementRelaxer provides an ecosystem-specific method for 'relaxing' the
// specified versions of dependencies for vulnerability remediation.
// Relaxing involves incrementally widening and bumping the version specifiers
// of the requirement to allow more recent versions to be selected during
// dependency resolution.
// It has access to the available versions of a package via a resolve client.
//
// e.g. in a semver-like ecosystem, relaxation could follow the sequence:
// 1.2.3 -> 1.2.* -> 1.*.* -> 2.*.* -> 3.*.* -> ...
type RequirementRelaxer interface {
	// Relax attempts to relax import requirement.
	// Returns the newly relaxed import and true it was successful.
	// If unsuccessful, it returns the original import and false.
	Relax(ctx context.Context, cl resolve.Client, req resolve.RequirementVersion, config upgrade.Config) (resolve.RequirementVersion, bool)
}

func GetRelaxer(ecosystem resolve.System) (RequirementRelaxer, error) {
	// TODO: is using ecosystem fine, or should this be per manifest?
	switch ecosystem { //nolint:exhaustive
	case resolve.NPM:
		return NpmRelaxer{}, nil
	default:
		return nil, errors.New("unsupported ecosystem")
	}
}
