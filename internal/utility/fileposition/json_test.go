package fileposition

import (
	"testing"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/stretchr/testify/assert"
)

type Dependency struct {
	Dependencies map[string]*Dependency
	models.FilePosition
}

func (d *Dependency) GetNestedDependencies() map[string]*models.FilePosition {
	result := make(map[string]*models.FilePosition)
	for key, value := range d.Dependencies {
		result[key] = &value.FilePosition
	}

	return result
}

func TestInJSON(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		groupKey     string
		dependencies map[string]*Dependency
		lines        []string
		offset       int
		expected     map[string]*Dependency
	}{
		{
			groupKey: "groupKey",
			dependencies: map[string]*Dependency{
				"dep-1": {},
			},
			lines: []string{
				`{`,
				` "groupKey": {`,
				`  "dep-1": {`,
				`   "some-key": "some-value"`,
				`  }`,
				` }`,
				`}`,
			},
			offset: 0,
			expected: map[string]*Dependency{
				"dep-1": {
					FilePosition: models.FilePosition{
						Line:   models.Position{Start: 3, End: 5},
						Column: models.Position{Start: 3, End: 4},
					},
				},
			},
		},
		{
			groupKey: "groupKey",
			dependencies: map[string]*Dependency{
				"dep-1": {
					Dependencies: map[string]*Dependency{
						"nested-dep": {},
					},
				},
			},
			lines: []string{
				`{`,
				` "groupKey": {`,
				`  "dep-1": {`,
				`   "some-key": "some-value"`,
				`   "nested-dep": {`,
				`    "some-nested-key": "some-nested-value"`,
				`   }`,
				`  }`,
				` }`,
				`}`,
			},
			offset: 0,
			expected: map[string]*Dependency{
				"dep-1": {
					FilePosition: models.FilePosition{
						Line:   models.Position{Start: 3, End: 8},
						Column: models.Position{Start: 3, End: 4},
					},
				},
				"nested-dep": {
					FilePosition: models.FilePosition{
						Line:   models.Position{Start: 5, End: 7},
						Column: models.Position{Start: 3, End: 4},
					},
				},
			},
		},
		{
			groupKey: "groupKey",
			dependencies: map[string]*Dependency{
				"dep-1": {
					Dependencies: map[string]*Dependency{
						"nested-dep": {
							Dependencies: map[string]*Dependency{
								"very-nested-dep": {},
							},
						},
					},
				},
			},
			lines: []string{
				`{`,
				` "groupKey": {`,
				`  "dep-1": {`,
				`   "some-key": "some-value"`,
				`   "nested-dep": {`,
				`    "some-nested-key": "some-nested-value"`,
				`    "very-nested-dep": {`,
				`     "some-very-nested-key": "some-very-nested-value"`,
				`    }`,
				`   }`,
				`  }`,
				` }`,
				`}`,
			},
			offset: 0,
			expected: map[string]*Dependency{
				"dep-1": {
					FilePosition: models.FilePosition{
						Line:   models.Position{Start: 3, End: 11},
						Column: models.Position{Start: 3, End: 4},
					},
				},
				"nested-dep": {
					FilePosition: models.FilePosition{
						Line:   models.Position{Start: 5, End: 10},
						Column: models.Position{Start: 3, End: 4},
					},
				},
				"very-nested-dep": {
					FilePosition: models.FilePosition{
						Line:   models.Position{Start: 7, End: 9},
						Column: models.Position{Start: 3, End: 4},
					},
				},
			},
		},
	}

	for _, tt := range testCases {
		InJSON(tt.groupKey, tt.dependencies, tt.lines, tt.offset)
		for key, dep := range tt.dependencies {
			assert.Equal(t, dep.FilePosition, tt.expected[key].FilePosition)
		}
	}
}
