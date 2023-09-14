package output

import (
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
)

func Test_groupFixedVersions(t *testing.T) {
	t.Parallel()

	type args struct {
		flattened []models.VulnerabilityFlattened
	}
	tests := []struct {
		name     string
		args     args
		wantPath string
	}{
		{
			name: "",
			args: args{
				flattened: testutility.LoadJSONFixture[[]models.VulnerabilityFlattened](t, "fixtures/flattened_vulns.json"),
			},
			wantPath: "fixtures/group_fixed_version_output.json",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := groupFixedVersions(tt.args.flattened)
			testutility.AssertMatchFixtureJSON(t, tt.wantPath, got)
		})
	}
}

func Test_groupByVulnGroups(t *testing.T) {
	tests := []struct {
		name     string
		args     models.VulnerabilityResults
		wantPath string
	}{
		{
			args:     testutility.LoadJSONFixture[models.VulnerabilityResults](t, "fixtures/test-vuln-results-a.json"),
			wantPath: "fixtures/test-vuln-results-a-grouped.json",
		},
	}
	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := groupByVulnGroups(&tt.args)
			testutility.CreateJSONFixture(t, tt.wantPath, got)
			// if got := groupByVulnGroups(&tt.args); !reflect.DeepEqual(got, tt.want) {
			// 	t.Errorf("groupByVulnGroups() = %v, want %v", got, tt.want)
			// }
		})
	}
}
