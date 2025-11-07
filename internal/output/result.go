package output

import (
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/google/osv-scanner/v2/internal/identifiers"
	"github.com/google/osv-scanner/v2/internal/utility/vulns"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

type pkgWithSource struct {
	Package models.PackageInfo `json:"Package"`
	Source  models.SourceInfo  `json:"Source"`
}

// Custom implementation of this unique set map to allow it to serialize to JSON
type pkgSourceSet map[pkgWithSource]struct{}

// StableKeys returns the pkgWithSource keys in a deterministic order
func (pss *pkgSourceSet) StableKeys() []pkgWithSource {
	pkgWithSrcKeys := slices.AppendSeq(make([]pkgWithSource, 0, len(*pss)), maps.Keys(*pss))

	slices.SortFunc(pkgWithSrcKeys, func(a, b pkgWithSource) int {
		// compare based on each field in descending priority
		for _, fn := range []func() int{
			func() int { return strings.Compare(a.Source.Path, b.Source.Path) },
			func() int { return strings.Compare(a.Package.Name, b.Package.Name) },
			func() int { return strings.Compare(a.Package.Version, b.Package.Version) },
		} {
			if r := fn(); r != 0 {
				return r
			}
		}

		return 0
	})

	return pkgWithSrcKeys
}

func (pss *pkgSourceSet) MarshalJSON() ([]byte, error) {
	res := []pkgWithSource{}

	for v := range *pss {
		res = append(res, v)
	}

	return json.Marshal(res)
}

func (pss *pkgSourceSet) UnmarshalJSON(data []byte) error {
	aux := []pkgWithSource{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	*pss = make(pkgSourceSet)
	for _, pws := range aux {
		(*pss)[pws] = struct{}{}
	}

	return nil
}

// mustGetWorkingDirectory panics if it can't get the working directory
func mustGetWorkingDirectory() string {
	dir, err := os.Getwd()
	if err != nil {
		log.Panicf("can't get working dir: %v", err)
	}

	return dir
}

// groupFixedVersions builds the fixed versions for each ID Group, with keys formatted like so:
// `Source:ID`
func groupFixedVersions(flattened []models.VulnerabilityFlattened) map[string][]string {
	groupedFixedVersions := map[string][]string{}

	// Get the fixed versions indexed by each group of vulnerabilities
	// Prepend source path as same vulnerability in two projects should be counted twice
	// Remember to sort and compact before displaying later
	for _, vf := range flattened {
		if vf.Vulnerability == nil {
			continue
		}
		groupIdx := vf.Source.String() + ":" + vf.GroupInfo.IndexString()
		pkg := vulns.PackageKey{
			Ecosystem: vf.Package.Ecosystem,
			Name:      vf.Package.Name,
		}
		groupedFixedVersions[groupIdx] =
			append(groupedFixedVersions[groupIdx], vulns.GetFixedVersions(vf.Vulnerability)[pkg]...)
	}

	// Remove duplicates
	for k := range groupedFixedVersions {
		fixedVersions := groupedFixedVersions[k]
		slices.Sort(fixedVersions)
		groupedFixedVersions[k] = slices.Compact(fixedVersions)
	}

	return groupedFixedVersions
}

// groupedSARIFFinding groups vulnerabilities by aliases
type groupedSARIFFinding struct {
	DisplayID string
	PkgSource pkgSourceSet
	// AliasedVulns contains vulns that are OSV vulnerabilities
	AliasedVulns map[string]*osvschema.Vulnerability
	// AliasedIDList contains all aliased IDs, including ones that are not OSV (e.g. CVE IDs)
	// Sorted by idSortFunc, therefore the first element will be the display ID
	AliasedIDList []string
}

// UnmarshalJSON implements the json.unmarshaler interface.
// It is required because the AliasedVulns field is a proto message,
// which requires protojson to unmarshal, while the rest of the struct uses
// the standard encoding/json library.
func (g *groupedSARIFFinding) UnmarshalJSON(data []byte) error {
	// Use alias to avoid recursion.
	type alias groupedSARIFFinding

	// Use temporary struct to combine standard fields (via alias)
	// and the manually processed field (via shadowing).
	tmp := &struct {
		*alias

		AliasedVulns map[string]json.RawMessage `json:"AliasedVulns"`
	}{
		alias: (*alias)(g),
	}

	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	// Manually process the custom field from RawMessage format.
	if tmp.AliasedVulns != nil {
		g.AliasedVulns = make(map[string]*osvschema.Vulnerability, len(tmp.AliasedVulns))
		for id, rawVuln := range tmp.AliasedVulns {
			var vuln osvschema.Vulnerability
			if err := protojson.Unmarshal(rawVuln, &vuln); err != nil {
				return fmt.Errorf("failed to protojson unmarshal vuln %q: %w", id, err)
			}
			g.AliasedVulns[id] = &vuln
		}
	}

	return nil
}

// MarshalJSON implements the json.Marshaler interface.
// It is required because the AliasedVulns field is a proto message,
// which requires protojson to marshal, while the rest of the struct uses
// the standard encoding/json library.
func (g *groupedSARIFFinding) MarshalJSON() ([]byte, error) {
	// Use alias to avoid recursion.
	type alias groupedSARIFFinding

	// Pre-process the custom field into standardized RawMessage format.
	var rawVulns map[string]json.RawMessage
	if g.AliasedVulns != nil {
		rawVulns = make(map[string]json.RawMessage, len(g.AliasedVulns))
		for id, vuln := range g.AliasedVulns {
			marshaler := protojson.MarshalOptions{Indent: "  "}
			b, err := marshaler.Marshal(vuln)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal vuln %q: %w", id, err)
			}
			rawVulns[id] = b
		}
	}

	// Use temporary struct to combine standard fields (via alias)
	// and the manually processed field (via shadowing).
	return json.Marshal(&struct {
		*alias

		AliasedVulns map[string]json.RawMessage `json:"AliasedVulns"`
	}{
		alias:        (*alias)(g),
		AliasedVulns: rawVulns,
	})
}

// mapIDsToGroupedSARIFFinding creates a map over all vulnerability IDs, with aliased vuln IDs
// pointing to the same groupedSARIFFinding object
func mapIDsToGroupedSARIFFinding(vulnResults *models.VulnerabilityResults) map[string]*groupedSARIFFinding {
	// Map of vuln IDs to their respective groupedSARIFFinding
	results := map[string]*groupedSARIFFinding{}

	for _, res := range vulnResults.Results {
		for _, pkg := range res.Packages {
			for _, gi := range pkg.Groups {
				var data *groupedSARIFFinding
				// See if this vulnerability group already exists (from another package or source)
				for _, id := range gi.IDs {
					existingData, ok := results[id]
					if ok {
						data = existingData
						break
					}
				}
				// If not create this group
				if data == nil {
					data = &groupedSARIFFinding{
						PkgSource:    make(pkgSourceSet),
						AliasedVulns: make(map[string]*osvschema.Vulnerability),
					}
				}
				// Point all the IDs of the same group to the same data, either newly created or existing
				for _, id := range gi.IDs {
					results[id] = data
				}
			}
			for _, v := range pkg.Vulnerabilities {
				newPkgSource := pkgWithSource{
					Package: pkg.Package,
					Source:  res.Source,
				}
				entry := results[v.GetId()]
				entry.PkgSource[newPkgSource] = struct{}{}
				entry.AliasedVulns[v.GetId()] = v
				entry.AliasedIDList = append(entry.AliasedIDList, v.GetId())
				entry.AliasedIDList = append(entry.AliasedIDList, v.GetAliases()...)
			}
		}
	}

	for _, gs := range results {
		slices.SortFunc(gs.AliasedIDList, identifiers.IDSortFunc)
		gs.AliasedIDList = slices.Compact(gs.AliasedIDList)
		gs.DisplayID = gs.AliasedIDList[0]
	}

	return results
}
