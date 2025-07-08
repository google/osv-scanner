package source

import (
	"net/http"

	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this enricher.
	Name = "enricher/reachability/govulncheck/source"
)

// Enricher is the Go source reachability enricher.
type Enricher struct {
	client *http.Client
}

// Name returns the name of the enricher.
func (Enricher) Name() string {
	return Name
}

// Version returns the version of the enricher.
func (Enricher) Version() int {
	return 0
}

// Requirements returns the requirements of the enricher.
func (Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network:  plugin.NetworkOnline,
		DirectFS: true,
	}
}

// RequiredPlugins returns the names of the plugins required by the enricher.
func (Enricher) RequiredPlugins() []string {
	return []string{gomod.Name}
}

// Enrich enriches the inventory with Java Reach data.
// func (enr Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
// 	goProjects := make(map[string]struct{})
// 	for i := range inv.Packages {
// 		for _, extractorName := range inv.Packages[i].Plugins {
// 			if extractorName == gomod.Name {
// 				goProjects[inv.Packages[i].Locations[0]] = struct{}{}
// 				break
// 			}
// 		}
// 	}

// 	// for project := range goProjects {
// 	// 	sourceInfo = models.SourceInfo{
// 	// 		Path: project,
// 	// 		Type: "lockfile",
// 	// 	}
// 	// 	err := goAnalysis()
// 	// 	if err != nil {
// 	// 		return err
// 	// 	}
// 	// }
// }
