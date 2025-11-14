package remediation_test

import (
	"testing"

	"github.com/google/osv-scanner/v2/internal/remediation"
	"github.com/google/osv-scanner/v2/internal/remediation/upgrade"
	"github.com/google/osv-scanner/v2/internal/resolution"
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
		vulnPath     string
		manifestPath string
		opts         remediation.Options
	}{
		{
			name:         "maven-zeppelin-server",
			universePath: "./testdata/zeppelin-server/universe.yaml",
			vulnPath:     "./testdata/zeppelin-server/vulns.json",
			manifestPath: "./testdata/zeppelin-server/pom.xml",
			opts:         basicOpts,
		},
		{
			name:         "maven-classifier",
			universePath: "./testdata/maven-classifier/universe.yaml",
			vulnPath:     "./testdata/maven-classifier/vulns.json",
			manifestPath: "./testdata/maven-classifier/pom.xml",
			opts:         basicOpts,
		},
		{
			name:         "maven-management-only",
			universePath: "./testdata/zeppelin-server/universe.yaml",
			vulnPath:     "./testdata/zeppelin-server/vulns.json",
			manifestPath: "./testdata/zeppelin-server/parent/pom.xml",
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
			universePath: "./testdata/override-workaround/universe.yaml",
			vulnPath:     "./testdata/override-workaround/vulns.json",
			manifestPath: "./testdata/override-workaround/guava/none-to-jre/pom.xml",
			opts:         basicOpts,
		},
		{
			name:         "workaround-maven-guava-jre-to-jre",
			universePath: "./testdata/override-workaround/universe.yaml",
			vulnPath:     "./testdata/override-workaround/vulns.json",
			manifestPath: "./testdata/override-workaround/guava/jre-to-jre/pom.xml",
			opts:         basicOpts,
		},
		{
			name:         "workaround-maven-guava-android-to-android",
			universePath: "./testdata/override-workaround/universe.yaml",
			vulnPath:     "./testdata/override-workaround/vulns.json",
			manifestPath: "./testdata/override-workaround/guava/android-to-android/pom.xml",
			opts:         basicOpts,
		},
		{
			name:         "workaround-commons",
			universePath: "./testdata/override-workaround/universe.yaml",
			vulnPath:     "./testdata/override-workaround/vulns.json",
			manifestPath: "./testdata/override-workaround/commons/pom.xml",
			opts:         basicOpts,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, cl := parseRemediationFixture(t, tt.universePath, tt.vulnPath, tt.manifestPath, tt.opts.ResolveOpts)
			res.FilterVulns(tt.opts.MatchVuln)
			p, err := remediation.ComputeOverridePatches(t.Context(), cl, res, tt.opts)
			if err != nil {
				t.Fatalf("Failed to compute override patches: %v", err)
			}
			checkRemediationResults(t, p)
		})
	}
}
