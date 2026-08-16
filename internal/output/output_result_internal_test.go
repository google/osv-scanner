package output

import (
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// A `fixed` value the ecosystem's parser rejects must not abort the scan. Advisory
// data is third-party input, and result building runs after matching has already
// succeeded, so a panic here loses an otherwise complete scan.
func TestGetNextFixVersion_UnparsableFixedVersion(t *testing.T) {
	t.Parallel()

	affected := []*osvschema.Affected{
		{
			Package: &osvschema.Package{Ecosystem: "CRAN", Name: "mypkg"},
			Versions: []string{"1.0.0"},
			Ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "notaversion"},
					},
				},
			},
		},
	}

	hasFix, fixVersion := getNextFixVersion(affected, "1.0.0", "mypkg", "CRAN")

	if hasFix {
		t.Errorf("getNextFixVersion() reported a fix from an unparsable version, got %q", fixVersion)
	}
	if fixVersion != UnfixedDescription {
		t.Errorf("getNextFixVersion() = %q, want %q", fixVersion, UnfixedDescription)
	}
}

// An unparsable entry must not hide a valid fix that appears alongside it.
func TestGetNextFixVersion_UnparsableAlongsideValid(t *testing.T) {
	t.Parallel()

	affected := []*osvschema.Affected{
		{
			Package: &osvschema.Package{Ecosystem: "CRAN", Name: "mypkg"},
			Versions: []string{"1.0.0"},
			Ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "notaversion"},
						{Fixed: "2.0.0"},
					},
				},
			},
		},
	}

	hasFix, fixVersion := getNextFixVersion(affected, "1.0.0", "mypkg", "CRAN")

	if !hasFix {
		t.Fatal("getNextFixVersion() found no fix, want the valid one alongside the unparsable entry")
	}
	if fixVersion != "2.0.0" {
		t.Errorf("getNextFixVersion() = %q, want %q", fixVersion, "2.0.0")
	}
}
