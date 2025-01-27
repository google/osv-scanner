package severity_test

import (
	"math"
	"testing"

	"github.com/google/osv-scanner/internal/utility/severity"
	"github.com/google/osv-scanner/pkg/models"
)

func TestSeverity_CalculateScore(t *testing.T) {
	t.Parallel()

	type result struct {
		score  float64
		rating string
	}
	tests := []struct {
		name string
		sev  models.Severity
		want result
	}{
		{
			name: "Empty Severity Type",
			sev:  models.Severity{},
			want: result{
				score:  -1,
				rating: "UNKNOWN",
			},
		},
		{
			name: "CVSS v2.0",
			sev: models.Severity{
				Type:  models.SeverityCVSSV2,
				Score: "AV:L/AC:M/Au:N/C:N/I:P/A:C/E:H/RL:U/RC:C/CDP:LM/TD:M/CR:L/IR:M/AR:H",
			},
			want: result{
				score:  5.4,
				rating: "MEDIUM",
			},
		},
		{
			name: "CVSS v3.0",
			sev: models.Severity{
				Type:  models.SeverityCVSSV3,
				Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
			},
			want: result{
				score:  10.0,
				rating: "CRITICAL",
			},
		},
		{
			name: "CVSS v3.1",
			sev: models.Severity{
				Type:  models.SeverityCVSSV3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
			},
			want: result{
				score:  10.0,
				rating: "CRITICAL",
			},
		},
		{
			name: "CVSS v4.0",
			sev: models.Severity{
				Type:  models.SeverityCVSSV4,
				Score: "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear",
			},
			want: result{
				score:  0.0,
				rating: "NONE",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotScore, gotRating, err := severity.CalculateScore(tt.sev)
			if err != nil {
				t.Errorf("CalculateScore() error: %v", err)
			}
			// CVSS scores are only supposed to be to 1 decimal place.
			// Multiply and round to get around potential precision issues.
			if math.Round(10*gotScore) != math.Round(10*tt.want.score) || gotRating != tt.want.rating {
				t.Errorf("CalculateScore() = (%.1f, %s), want (%.1f, %s)", gotScore, gotRating, tt.want.score, tt.want.rating)
			}
		})
	}
}
