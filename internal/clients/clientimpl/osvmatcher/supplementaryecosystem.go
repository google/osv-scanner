package osvmatcher

import (
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/tuxcare"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// supplementaryEcosystemRule routes the osv.dev query for a vendor-rebuilt package
// (detected by a version marker) to the vendor's advisory ecosystem instead of the
// package's base ecosystem.
type supplementaryEcosystemRule struct {
	matches        func(version string) bool
	overlayPackage func(pkg *extractor.Package) *osvschema.Package
}

// supplementaryEcosystemRules is the built-in registry. TuxCare is the first entry;
// all its logic lives in internal/tuxcare.
var supplementaryEcosystemRules = []supplementaryEcosystemRule{
	{matches: tuxcare.Marker.MatchString, overlayPackage: tuxcare.OverlayPackage},
}

// routedQueryPackage returns the vendor package coordinates to query for pkg, or
// nil if no rule applies. Only OSVMatcher.pkgToQuery consults this; CachedOSVMatcher
// deliberately does not route (local matching has no TuxCare version ordering).
func routedQueryPackage(pkg *extractor.Package) *osvschema.Package {
	version := imodels.Version(pkg)
	if version == "" {
		return nil
	}
	for _, rule := range supplementaryEcosystemRules {
		if !rule.matches(version) {
			continue
		}
		if overlay := rule.overlayPackage(pkg); overlay != nil &&
			overlay.GetName() != "" && overlay.GetEcosystem() != "" {
			return overlay
		}
	}

	return nil
}
