package depgroups

import "github.com/ossf/osv-schema/bindings/go/osvschema"

// IsDevGroup returns if any string in groups indicates the development dependency group for the specified ecosystem.
func IsDevGroup(sys osvschema.Ecosystem, groups []string) bool {
	dev := ""
	switch sys {
	case osvschema.EcosystemPackagist, osvschema.EcosystemNPM, osvschema.EcosystemPyPI, osvschema.EcosystemPub:
		// Also PnpmEcosystem(=NpmEcosystem) and PipenvEcosystem(=PipEcosystem).
		dev = "dev"
	case osvschema.EcosystemConanCenter:
		dev = "build-requires"
	case osvschema.EcosystemMaven:
		dev = "test"
	case osvschema.EcosystemAlpine, osvschema.EcosystemRubyGems, osvschema.EcosystemCratesIO, osvschema.EcosystemCRAN,
		osvschema.EcosystemDebian, osvschema.EcosystemGo, osvschema.EcosystemHex, osvschema.EcosystemNuGet:
		// We are not able to report development dependencies for these ecosystems.
		return false
	}

	for _, g := range groups {
		if g == dev {
			return true
		}
	}

	return false
}
