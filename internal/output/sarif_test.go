package output

import (
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
)

func TestGroupFixedVersions(t *testing.T) {
	t.Parallel()

	type args struct {
		flattened []models.VulnerabilityFlattened
	}
	tests := []struct {
		name string
		args args
		want map[string][]string
	}{
		{
			name: "",
			args: args{
				flattened: testutility.LoadJSONFixture[[]models.VulnerabilityFlattened](t, "fixtures/flattened_vulns.json"),
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GroupFixedVersions(tt.args.flattened)
			testutility.AssertMatchFixtureJSON(t, "fixtures/group_fixed_version_output.json", got)
		})
	}
}
