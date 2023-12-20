package testsnapshot

import (
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
)

// Clean ensures that snapshots are relevant and sorted for consistency
func Clean(m *testing.M) {
	snaps.Clean(m, snaps.CleanOpts{Sort: true})
}
