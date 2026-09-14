package depgroups_test

import (
	"testing"

	"github.com/google/osv-scanner/v2/pkg/depgroups"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

func TestIsDevGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ecosystem osvconstants.Ecosystem
		groups    []string
		expected  bool
	}{
		{
			name:      "NPM with dev group",
			ecosystem: osvconstants.EcosystemNPM,
			groups:    []string{"dev", "production"},
			expected:  true,
		},
		{
			name:      "NPM without dev group",
			ecosystem: osvconstants.EcosystemNPM,
			groups:    []string{"production"},
			expected:  false,
		},
		{
			name:      "PyPI with dev group",
			ecosystem: osvconstants.EcosystemPyPI,
			groups:    []string{"dev"},
			expected:  true,
		},
		{
			name:      "Packagist with dev group",
			ecosystem: osvconstants.EcosystemPackagist,
			groups:    []string{"dev"},
			expected:  true,
		},
		{
			name:      "Pub with dev group",
			ecosystem: osvconstants.EcosystemPub,
			groups:    []string{"dev"},
			expected:  true,
		},
		{
			name:      "ConanCenter with build-requires group",
			ecosystem: osvconstants.EcosystemConanCenter,
			groups:    []string{"build-requires"},
			expected:  true,
		},
		{
			name:      "ConanCenter with wrong group",
			ecosystem: osvconstants.EcosystemConanCenter,
			groups:    []string{"dev"},
			expected:  false,
		},
		{
			name:      "Maven with test group",
			ecosystem: osvconstants.EcosystemMaven,
			groups:    []string{"test"},
			expected:  true,
		},
		{
			name:      "Maven with compile group",
			ecosystem: osvconstants.EcosystemMaven,
			groups:    []string{"compile"},
			expected:  false,
		},
		{
			name:      "Unsupported ecosystem",
			ecosystem: osvconstants.EcosystemGo,
			groups:    []string{"dev", "test"},
			expected:  false,
		},
		{
			name:      "Empty groups slice",
			ecosystem: osvconstants.EcosystemNPM,
			groups:    []string{},
			expected:  false,
		},
		{
			name:      "Nil groups slice",
			ecosystem: osvconstants.EcosystemNPM,
			groups:    nil,
			expected:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			actual := depgroups.IsDevGroup(tc.ecosystem, tc.groups)
			if actual != tc.expected {
				t.Errorf("IsDevGroup(%v, %v) = %v; want %v", tc.ecosystem, tc.groups, actual, tc.expected)
			}
		})
	}
}
