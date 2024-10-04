package remediation_test

import (
	"context"
	"testing"

	"github.com/google/osv-scanner/internal/remediation"
	"github.com/google/osv-scanner/internal/remediation/upgrade"
	"github.com/google/osv-scanner/internal/resolution"
)

func TestComputeOverridePatches(t *testing.T) {
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
		{
			name:         "maven-management-only",
			universePath: "./fixtures/zeppelin-server/universe.yaml",
			manifestPath: "./fixtures/zeppelin-server/parent/pom.xml",
			opts: remediation.Options{
				ResolveOpts: resolution.ResolveOpts{
					MavenManagement: true,
				},
				DevDeps:       true,
				MaxDepth:      -1,
				UpgradeConfig: upgrade.NewConfig(),
			},
		},
		{
			name:         "workaround-maven-guava-none-to-jre",
			universePath: "./fixtures/override-workaround/universe.yaml",
			manifestPath: "./fixtures/override-workaround/guava/none-to-jre/pom.xml",
			opts:         basicOpts,
		},
		{
			name:         "workaround-maven-guava-jre-to-jre",
			universePath: "./fixtures/override-workaround/universe.yaml",
			manifestPath: "./fixtures/override-workaround/guava/jre-to-jre/pom.xml",
			opts:         basicOpts,
		},
		{
			name:         "workaround-maven-guava-android-to-android",
			universePath: "./fixtures/override-workaround/universe.yaml",
			manifestPath: "./fixtures/override-workaround/guava/android-to-android/pom.xml",
			opts:         basicOpts,
		},
		{
			name:         "workaround-commons",
			universePath: "./fixtures/override-workaround/universe.yaml",
			manifestPath: "./fixtures/override-workaround/commons/pom.xml",
			opts:         basicOpts,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, cl := parseRemediationFixture(t, tt.universePath, tt.manifestPath, tt.opts.ResolveOpts)
			res.FilterVulns(tt.opts.MatchVuln)
			p, err := remediation.ComputeOverridePatches(context.Background(), cl, res, tt.opts)
			if err != nil {
				t.Fatalf("Failed to compute override patches: %v", err)
			}
			checkRemediationResults(t, p)
		})
	}
}
