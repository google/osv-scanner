package remediation_test

import (
	"context"
	"testing"

	"github.com/google/osv-scanner/internal/remediation"
	"github.com/google/osv-scanner/internal/remediation/upgrade"
)

func TestComputeOverridePatches(t *testing.T) {
	t.Parallel()

	basicOpts := remediation.RemediationOptions{
		DevDeps:       true,
		MaxDepth:      -1,
		UpgradeConfig: upgrade.NewConfig(),
	}

	tests := []struct {
		name         string
		universePath string
		manifestPath string
		opts         remediation.RemediationOptions
	}{
		{
			name:         "maven-zeppelin-server",
			universePath: "./fixtures/zeppelin-server/universe.yaml",
			manifestPath: "./fixtures/zeppelin-server/pom.xml",
			opts:         basicOpts,
		},
		{
			name:         "maven-classifier",
			universePath: "./fixtures/maven-classifier/universe.yaml",
			manifestPath: "./fixtures/maven-classifier/pom.xml",
			opts:         basicOpts,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, cl := parseRemediationFixture(t, tt.universePath, tt.manifestPath)
			res.FilterVulns(tt.opts.MatchVuln)
			p, err := remediation.ComputeOverridePatches(context.Background(), cl, res, tt.opts)
			if err != nil {
				t.Fatalf("Failed to compute override patches: %v", err)
			}
			checkRemediationResults(t, p)
		})
	}
}
