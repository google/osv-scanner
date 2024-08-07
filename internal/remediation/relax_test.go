package remediation_test

import (
	"context"
	"testing"

	"github.com/google/osv-scanner/internal/remediation"
)

func TestComputeRelaxPatches(t *testing.T) {
	t.Parallel()

	basicOpts := remediation.RemediationOptions{
		DevDeps:    true,
		MaxDepth:   -1,
		AllowMajor: true,
	}

	tests := []struct {
		name         string
		universePath string
		manifestPath string
		opts         remediation.RemediationOptions
	}{
		{
			name:         "npm-santatracker",
			universePath: "./fixtures/santatracker/universe.yaml",
			manifestPath: "./fixtures/santatracker/package.json",
			opts:         basicOpts,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, cl := parseRemediationFixture(t, tt.universePath, tt.manifestPath)
			res.FilterVulns(tt.opts.MatchVuln)
			p, err := remediation.ComputeRelaxPatches(context.Background(), cl, res, tt.opts)
			if err != nil {
				t.Fatalf("Failed to compute relaxation patches: %v", err)
			}
			checkRemediationResults(t, p)
		})
	}
}
