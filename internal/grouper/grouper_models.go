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

func ConvertVulnerabilityToIDAliases(c []*osvschema.Vulnerability) []IDAliases {
	output := make([]IDAliases, 0, len(c))

	slices.SortFunc(c, identifiers.MostUpstreamsOrder)

	for _, v := range c {
		idAliases := IDAliases{
			ID:      v.GetId(),
			Aliases: v.GetAliases(),
		}

		idAliases.Aliases = append(idAliases.Aliases, v.GetUpstream()...)

		// For Ubuntu Security Advisory data,
		// all related CVEs should be bundled together, as they are part of this USN.
		// TODO(jesslowe): remove after all USNs are migrated.
		if strings.Split(v.GetId(), "-")[0] == "USN" {
			idAliases.Aliases = append(idAliases.Aliases, v.GetRelated()...)
		}

		output = append(output, idAliases)
	}

	return output
}
