package output

import (
	"encoding/json"
	"io"
	"log"

	"github.com/google/osv.dev/tools/osv-scanner/internal/osv"
)

type Output struct {
	Results []Result `json:"results"`
}

type Result struct {
	PackageSource osv.Source `json:"packageSource"`
	Packages      []Package  `json:"packages"`
}

type Package struct {
	Name            string              `json:"name"`
	Version         string              `json:"version"`
	Ecosystem       string              `json:"ecosystem"`
	Vulnerabilities []osv.Vulnerability `json:"vulnerabilities"`
}

// PrintJSONResults writes results to the provided writer in JSON format
func PrintJSONResults(query osv.BatchedQuery, resp *osv.HydratedBatchedResponse, outputWriter io.Writer) error {
	output := Output{
		Results: []Result{},
	}
	groupedBySource := map[osv.Source][]Package{}

	for i, query := range query.Queries {
		response := resp.Results[i]
		if len(response.Vulns) == 0 {
			continue
		}
		var pkg Package
		if query.Commit != "" {
			pkg.Version = query.Commit
		} else if query.Package.PURL != "" {
			var err error
			pkg, err = PURLToPackage(query.Package.PURL)
			if err != nil {
				log.Printf("Failed to parse purl: %s, with error: %s",
					query.Package.PURL, err)
				continue
			}
			pkg.Vulnerabilities = response.Vulns
		} else {
			pkg = Package{
				Name:            query.Package.Name,
				Version:         query.Version,
				Ecosystem:       query.Package.Ecosystem,
				Vulnerabilities: response.Vulns,
			}
		}

		groupedBySource[query.Source] = append(groupedBySource[query.Source], pkg)
	}

	for source, packages := range groupedBySource {
		output.Results = append(output.Results, Result{
			PackageSource: source,
			Packages:      packages,
		})
	}

	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}
