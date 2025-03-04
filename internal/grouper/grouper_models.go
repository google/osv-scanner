package grouper

import (
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type IDAliases struct {
	ID      string
	Aliases []string
}

func ConvertVulnerabilityToIDAliases(c []osvschema.Vulnerability) []IDAliases {
	output := []IDAliases{}
	for _, v := range c {
		idAliases := IDAliases{
			ID:      v.ID,
			Aliases: v.Aliases,
		}

		// For Debian Security Advisory data,
		// all related CVEs should be bundled together, as they are part of this DSA.
		// TODO(gongh@): Revisit and provide a universal way to handle all Linux distro advisories.
		if strings.Split(v.ID, "-")[0] == "DSA" {
			idAliases.Aliases = append(idAliases.Aliases, v.Related...)
		}

		// For Ubuntu Security Advisory data,
		// all related CVEs should be bundled together, as they are part of this USN.
		if strings.Split(v.ID, "-")[0] == "USN" {
			idAliases.Aliases = append(idAliases.Aliases, v.Related...)
		}

		output = append(output, idAliases)
	}

	return output
}
