package output

import (
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// TuxCare advisories carry a "TuxCare:<Distro>:<Version>" ecosystem while the
// scanned package keeps its base ecosystem ("AlmaLinux:9.6"). The fix-version
// reconciliation must normalize the advisory's vendor prefix down to the base,
// analogous to how Ubuntu Pro/LTS variant suffixes are stripped.
func TestGetNextFixVersion_TuxCareOverlayReconcilesToBase(t *testing.T) {
	t.Parallel()

	affected := []*osvschema.Affected{
		{
			Package: &osvschema.Package{
				Name:      "binutils",
				Ecosystem: "TuxCare:AlmaLinux:9.6",
			},
			Ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "2.35.2-63.el9.tuxcare.els10"},
					},
				},
			},
		},
	}

	fixable, fixedVersion := getNextFixVersion(
		affected,
		"2.35.2-63.el9.tuxcare.els2", // installed TuxCare-rebuilt version
		"binutils",
		"AlmaLinux:9.6", // the package's base ecosystem
	)

	if !fixable {
		t.Fatalf("expected a fix to be available for a TuxCare advisory against an AlmaLinux package, got fixable=false (%q)", fixedVersion)
	}
	if want := "2.35.2-63.el9.tuxcare.els10"; fixedVersion != want {
		t.Errorf("fixedVersion = %q, want %q", fixedVersion, want)
	}
}
