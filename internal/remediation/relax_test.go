package remediation_test

import (
	"testing"

	"github.com/google/osv-scanner/v2/internal/remediation"
	"github.com/google/osv-scanner/v2/internal/remediation/upgrade"
)

func TestComputeRelaxPatches(t *testing.T) {
	t.Parallel()

	basicOpts := remediation.Options{
		DevDeps:       true,
		MaxDepth:      -1,
		UpgradeConfig: upgrade.NewConfig(),
	}

	tests := []struct {
		name         string
		universePath string
		manifestPath string
		opts         remediation.Options
	}{
		{
			name:         "npm-santatracker",
			universePath: "./testdata/santatracker/universe.yaml",
			manifestPath: "./testdata/santatracker/package.json",
			opts:         basicOpts,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, cl := parseRemediationFixture(t, tt.universePath, tt.manifestPath, tt.opts.ResolveOpts)
			res.FilterVulns(tt.opts.MatchVuln)
			p, err := remediation.ComputeRelaxPatches(t.Context(), cl, res, tt.opts)
			if err != nil {
				t.Fatalf("Failed to compute relaxation patches: %v", err)
			}
			checkRemediationResults(t, p)
		})
	}
}
