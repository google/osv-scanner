package vulns_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/utility/vulns"
	"github.com/google/osv-scanner/pkg/models"
)

func TestVulnerabilities_Includes(t *testing.T) {
	t.Parallel()

	type args struct {
		osv models.Vulnerability
	}
	tests := []struct {
		name string
		vs   models.Vulnerabilities
		args args
		want bool
	}{
		{
			name: "",
			vs: models.Vulnerabilities{
				models.Vulnerability{
					ID:      "GHSA-1",
					Aliases: []string{},
				},
			},
			args: args{
				osv: models.Vulnerability{
					ID:      "GHSA-2",
					Aliases: []string{},
				},
			},
			want: false,
		},
		{
			name: "",
			vs: models.Vulnerabilities{
				models.Vulnerability{
					ID:      "GHSA-1",
					Aliases: []string{},
				},
			},
			args: args{
				osv: models.Vulnerability{
					ID:      "GHSA-1",
					Aliases: []string{},
				},
			},
			want: true,
		},
		{
			name: "",
			vs: models.Vulnerabilities{
				models.Vulnerability{
					ID:      "GHSA-1",
					Aliases: []string{"GHSA-2"},
				},
			},
			args: args{
				osv: models.Vulnerability{
					ID:      "GHSA-2",
					Aliases: []string{},
				},
			},
			want: true,
		},
		{
			name: "",
			vs: models.Vulnerabilities{
				models.Vulnerability{
					ID:      "GHSA-1",
					Aliases: []string{},
				},
			},
			args: args{
				osv: models.Vulnerability{
					ID:      "GHSA-2",
					Aliases: []string{"GHSA-1"},
				},
			},
			want: true,
		},
		{
			name: "",
			vs: models.Vulnerabilities{
				models.Vulnerability{
					ID:      "GHSA-1",
					Aliases: []string{"CVE-1"},
				},
			},
			args: args{
				osv: models.Vulnerability{
					ID:      "GHSA-2",
					Aliases: []string{"CVE-1"},
				},
			},
			want: true,
		},
		{
			name: "",
			vs: models.Vulnerabilities{
				models.Vulnerability{
					ID:      "GHSA-1",
					Aliases: []string{"CVE-2"},
				},
			},
			args: args{
				osv: models.Vulnerability{
					ID:      "GHSA-2",
					Aliases: []string{"CVE-2"},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := vulns.Include(tt.vs, tt.args.osv); got != tt.want {
				t.Errorf("Includes() = %v, want %v", got, tt.want)
			}
		})
	}
}
