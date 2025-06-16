package scalibrextract

import (
	"cmp"
	"fmt"

	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/extractor"
)

// InventorySort is a comparator function for Inventories, to be used in
// tests with cmp.Diff to disregard the order in which the Inventories
// are reported.
func inventorySort(a, b *extractor.Package) int {
	aLoc := fmt.Sprintf("%v", a.Locations)
	bLoc := fmt.Sprintf("%v", b.Locations)

	var aExtr, bExtr string
	var aPURL, bPURL string

	aPURLStruct := converter.ToPURL(a)
	bPURLStruct := converter.ToPURL(b)

	if aPURLStruct != nil {
		aPURL = aPURLStruct.String()
	}

	if bPURLStruct != nil {
		bPURL = bPURLStruct.String()
	}

	aSourceCode := fmt.Sprintf("%v", a.SourceCode)
	bSourceCode := fmt.Sprintf("%v", b.SourceCode)

	return cmp.Or(
		cmp.Compare(aLoc, bLoc),
		cmp.Compare(a.Name, b.Name),
		cmp.Compare(a.Version, b.Version),
		cmp.Compare(aSourceCode, bSourceCode),
		cmp.Compare(aExtr, bExtr),
		cmp.Compare(aPURL, bPURL),
	)
}
