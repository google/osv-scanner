package semantic

import (
	"math/big"
	"strings"
)

// CRANVersion is the representation of a version of a package that is held
// in the CRAN ecosystem (https://cran.r-project.org/).
//
// A version is a sequence of at least two non-negative integers separated by
// either a period or a dash.
//
// See https://astrostatistics.psu.edu/su07/R/html/base/html/package_version.html
type CRANVersion struct {
	components Components
}

func (v CRANVersion) Compare(w CRANVersion) int {
	if diff := v.components.Cmp(w.components); diff != 0 {
		return diff
	}

	// versions are only equal if they also have the same number of components,
	// otherwise the longer one is considered greater
	if len(v.components) == len(w.components) {
		return 0
	}

	if len(v.components) > len(w.components) {
		return 1
	}

	return -1
}

func (v CRANVersion) CompareStr(str string) int {
	return v.Compare(parseCRANVersion(str))
}

func parseCRANVersion(str string) CRANVersion {
	// dashes and periods have the same weight, so we can just normalize to periods
	parts := strings.Split(strings.ReplaceAll(str, "-", "."), ".")

	components := make(Components, 0, len(parts))

	for _, s := range parts {
		v, _ := new(big.Int).SetString(s, 10)

		components = append(components, v)
	}

	return CRANVersion{components}
}
