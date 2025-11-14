// Package imagepackagefilter filters language packages from the output result if they are
// located in common OS install areas
package imagepackagefilter

import (
	"context"
	"strings"

	"github.com/google/osv-scalibr/annotator"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

const (
	// Name of the Annotator.
	Name = "misc/imagepackagefilter"
)

// Annotator filters out language packages that are installed as OS packages
// by adding a `ComponentNotPresent` exploitability signal. This prevents them
// from being reported as language package vulnerabilities.
type Annotator struct{}

// New returns a new Annotator.
func New(_ *cpb.PluginConfig) annotator.Annotator { return &Annotator{} }

// Name of the annotator.
func (*Annotator) Name() string { return Name }

// Version of the annotator.
func (*Annotator) Version() int { return 1 }

// Requirements of the annotator.
func (*Annotator) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// Annotate adds explotability signals to packages that exist within OS packages.
func (a *Annotator) Annotate(_ context.Context, _ *annotator.ScanInput, results *inventory.Inventory) error {
	// TODO: This is a set of heuristics,
	//    - Assume that packages under /usr/ might be a OS package depending on ecosystem
	//    - Assume python packages under dist-packages is a OS package
	// Move this into OSV-Scalibr (potentially via full filesystem accountability).
	for i, psr := range results.Packages {
		if (strings.HasPrefix(psr.Locations[0], "usr/") && psr.Ecosystem().Ecosystem == osvconstants.EcosystemGo) ||
			strings.Contains(psr.Locations[0], "dist-packages/") && psr.Ecosystem().Ecosystem == osvconstants.EcosystemPyPI {
			results.Packages[i].ExploitabilitySignals = append(results.Packages[i].ExploitabilitySignals,
				&vex.PackageExploitabilitySignal{
					Plugin:          Name,
					Justification:   vex.ComponentNotPresent,
					VulnIdentifiers: nil,
					MatchesAllVulns: true,
				})
		}
	}

	return nil
}
