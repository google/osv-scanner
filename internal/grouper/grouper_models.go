package grouper

import (
	"slices"
	"strings"

	"github.com/google/osv-scanner/v2/internal/identifiers"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type IDAliases struct {
	ID      string
	Aliases []string
}

func ConvertVulnerabilityToIDAliases(c []osvschema.Vulnerability) []IDAliases {
	output := []IDAliases{}

	slices.SortFunc(c, identifiers.MostUpstreamsOrder)

	for _, v := range c {
		idAliases := IDAliases{
			ID:      v.ID,
			Aliases: v.Aliases,
		}

		idAliases.Aliases = append(idAliases.Aliases, v.Upstream...)

		// For Ubuntu Security Advisory data,
		// all related CVEs should be bundled together, as they are part of this USN.
		// TODO(jesslowe): remove after all USNs are migrated.
		if strings.Split(v.ID, "-")[0] == "USN" {
			idAliases.Aliases = append(idAliases.Aliases, v.Related...)
		}

		output = append(output, idAliases)
	}

	return output
}
