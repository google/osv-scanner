package fileposition

import (
	"testing"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestInTOML(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		groupKey     string
		otherKey     string
		dependencies []*models.FilePosition
		lines        []string
		expected     []*models.FilePosition
	}{
		{
			groupKey: "[pkg]",
			otherKey: "[other-section]",
			dependencies: []*models.FilePosition{
				{},
			},
			lines: []string{
				`[pkg]`,
				`name = "pkg-1"`,
				``,
				`[other-section]`,
				`version = "1.1"`,
			},
			expected: []*models.FilePosition{
				{
					Line:   models.Position{Start: 1, End: 2},
					Column: models.Position{Start: 1, End: 15},
				},
			},
		},
		{
			groupKey: "[pkg]",
			otherKey: "[other-section]",
			dependencies: []*models.FilePosition{
				{},
			},
			lines: []string{
				`[pkg]`,
				`name = "pkg-1"`,
			},
			expected: []*models.FilePosition{
				{
					Line:   models.Position{Start: 1, End: 2},
					Column: models.Position{Start: 1, End: 15},
				},
			},
		},
		{
			groupKey: "[pkg]",
			otherKey: "[other-section]",
			dependencies: []*models.FilePosition{
				{},
				{},
			},
			lines: []string{
				`[pkg]`,
				`name = "pkg-1"`,
				`[pkg]`,
				`name = "pkg-2"`,
			},
			expected: []*models.FilePosition{
				{
					Line:   models.Position{Start: 1, End: 2},
					Column: models.Position{Start: 1, End: 15},
				},
				{
					Line:   models.Position{Start: 3, End: 4},
					Column: models.Position{Start: 1, End: 15},
				},
			},
		},
	}

	for _, tt := range testCases {
		InTOML(tt.groupKey, tt.otherKey, tt.dependencies, tt.lines)
		for index, dep := range tt.dependencies {
			assert.Equal(t, dep, tt.expected[index])
		}
	}
}
