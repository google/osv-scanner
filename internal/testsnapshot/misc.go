package testsnapshot

import (
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
)

// Clean ensures that snapshots are relevant and sorted for consistency
func Clean(m *testing.M) {
	snaps.Clean(m, snaps.CleanOpts{Sort: true})
}

// Skip is equivalent to t.Log followed by t.SkipNow, but allows tracking of
// what snapshots are skipped so that they're not marked as obsolete
func Skip(t *testing.T, args ...any) {
	t.Helper()

	snaps.Skip(t, args...)
}
