package severity_test

import (
	"math"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/utility/severity"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestSeverity_CalculateScore(t *testing.T) {
	t.Parallel()

	type result struct {
		score  float64
		rating string
	}
	tests := []struct {
		name string
		sev  *osvschema.Severity
		want result
	}{
		{
			name: "Empty_Severity_Type",
			sev:  &osvschema.Severity{},
			want: result{
				score:  -1,
				rating: "UNKNOWN",
			},
		},
		{
			name: "CVSS_v2.0",
			sev: &osvschema.Severity{
				Type:  osvschema.Severity_CVSS_V2,
				Score: "AV:L/AC:M/Au:N/C:N/I:P/A:C/E:H/RL:U/RC:C/CDP:LM/TD:M/CR:L/IR:M/AR:H",
			},
			want: result{
				score:  5.4,
				rating: "MEDIUM",
			},
		},
		{
			name: "CVSS_v3.0",
			sev: &osvschema.Severity{
				Type:  osvschema.Severity_CVSS_V3,
				Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
			},
			want: result{
				score:  10.0,
				rating: "CRITICAL",
			},
		},
		{
			name: "CVSS_v3.1",
			sev: &osvschema.Severity{
				Type:  osvschema.Severity_CVSS_V3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
			},
			want: result{
				score:  10.0,
				rating: "CRITICAL",
			},
		},
		{
			name: "CVSS_v4.0",
			sev: &osvschema.Severity{
				Type:  osvschema.Severity_CVSS_V4,
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

func TestCalculateScoreBasedOnMostRecentCvssVersionAvailable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		severities []*osvschema.Severity
		wantScore  float64
		wantRating string
		wantErr    bool
	}{
		{
			name:       "Empty severities",
			severities: []*osvschema.Severity{},
			wantScore:  -1,
			wantRating: "UNKNOWN",
			wantErr:    true,
		},
		{
			name: "Only CVSS v4.0",
			severities: []*osvschema.Severity{
				{
					Type:  osvschema.Severity_CVSS_V4,
					Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				},
			},
			wantScore:  9.3,
			wantRating: "CRITICAL",
			wantErr:    false,
		},
		{
			name: "Only CVSS v3.1",
			severities: []*osvschema.Severity{
				{
					Type:  osvschema.Severity_CVSS_V3,
					Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				},
			},
			wantScore:  9.8,
			wantRating: "CRITICAL",
			wantErr:    false,
		},
		{
			name: "Only CVSS v2.0",
			severities: []*osvschema.Severity{
				{
					Type:  osvschema.Severity_CVSS_V2,
					Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
				},
			},
			wantScore:  7.5,
			wantRating: "HIGH",
			wantErr:    false,
		},
		{
			name: "CVSS v4.0 and v3.1 - prefers v4.0",
			severities: []*osvschema.Severity{
				{
					Type:  osvschema.Severity_CVSS_V3,
					Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				},
				{
					Type:  osvschema.Severity_CVSS_V4,
					Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
				},
			},
			wantScore:  6.9,
			wantRating: "MEDIUM",
			wantErr:    false,
		},
		{
			name: "CVSS v3.1 and v2.0 - prefers v3.1",
			severities: []*osvschema.Severity{
				{
					Type:  osvschema.Severity_CVSS_V2,
					Score: "AV:N/AC:L/Au:N/C:C/I:C/A:C",
				},
				{
					Type:  osvschema.Severity_CVSS_V3,
					Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
				},
			},
			wantScore:  7.3,
			wantRating: "HIGH",
			wantErr:    false,
		},
		{
			name: "All versions - prefers v4.0",
			severities: []*osvschema.Severity{
				{
					Type:  osvschema.Severity_CVSS_V2,
					Score: "AV:N/AC:L/Au:N/C:C/I:C/A:C",
				},
				{
					Type:  osvschema.Severity_CVSS_V3,
					Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				},
				{
					Type:  osvschema.Severity_CVSS_V4,
					Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				},
			},
			wantScore:  9.3,
			wantRating: "CRITICAL",
			wantErr:    false,
		},
		{
			name: "Duplicate CVSS versions - uses first occurrence",
			severities: []*osvschema.Severity{
				{
					Type:  osvschema.Severity_CVSS_V3,
					Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
				},
				{
					Type:  osvschema.Severity_CVSS_V3,
					Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				},
			},
			wantScore:  7.3,
			wantRating: "HIGH",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotScore, gotRating, err := severity.CalculateScoreBasedOnMostRecentCvssVersionAvailable(tt.severities)

			if (err != nil) != tt.wantErr {
				t.Errorf("CalculateScoreBasedOnMostRecentCvssVersionAvailable() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if !strings.Contains(err.Error(), "no CVSS severity found") {
					t.Errorf("Expected 'no CVSS severity found' error, got: %v", err)
				}
				return
			}

			if math.Round(10*gotScore) != math.Round(10*tt.wantScore) {
				t.Errorf("CalculateScoreBasedOnMostRecentCvssVersionAvailable() score = %.1f, want %.1f", gotScore, tt.wantScore)
			}

			if gotRating != tt.wantRating {
				t.Errorf("CalculateScoreBasedOnMostRecentCvssVersionAvailable() rating = %v, want %v", gotRating, tt.wantRating)
			}
		})
	}
}
