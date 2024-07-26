package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
)

func TestPnpmLockExtractor_Extract_v9(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/no-packages.v9.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/one-package.v9.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "acorn",
					Version:    "8.11.3",
					Locations:  []string{"fixtures/pnpm/one-package.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "one package dev",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/one-package-dev.v9.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "acorn",
					Version:    "8.11.3",
					Locations:  []string{"fixtures/pnpm/one-package-dev.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "scoped packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/scoped-packages.v9.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.62.0",
					Locations:  []string{"fixtures/pnpm/scoped-packages.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "peer dependencies",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/peer-dependencies.v9.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "acorn-jsx",
					Version:    "5.3.2",
					Locations:  []string{"fixtures/pnpm/peer-dependencies.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					Version:    "8.11.3",
					Locations:  []string{"fixtures/pnpm/peer-dependencies.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "peer dependencies advanced",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/peer-dependencies-advanced.v9.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "@eslint-community/eslint-utils",
					Version:    "4.4.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@eslint/eslintrc",
					Version:    "2.1.4",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/eslint-plugin",
					Version:    "5.62.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/parser",
					Version:    "5.62.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/type-utils",
					Version:    "5.62.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/typescript-estree",
					Version:    "5.62.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/utils",
					Version:    "5.62.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "debug",
					Version:    "4.3.4",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "eslint",
					Version:    "8.57.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "4.0.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "7.2.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "tsutils",
					Version:    "3.21.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "typescript",
					Version:    "4.9.5",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "multiple versions",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/multiple-versions.v9.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "uuid",
					Version:    "8.0.0",
					Locations:  []string{"fixtures/pnpm/multiple-versions.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "8.3.2",
					Locations:  []string{"fixtures/pnpm/multiple-versions.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "xmlbuilder",
					Version:    "11.0.1",
					Locations:  []string{"fixtures/pnpm/multiple-versions.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "commits",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/commits.v9.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "ansi-regex",
					Version:   "6.0.1",
					Locations: []string{"fixtures/pnpm/commits.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "02fa893d619d3da85411acc8fd4e2eea0e95a9d9",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "is-number",
					Version:   "7.0.0",
					Locations: []string{"fixtures/pnpm/commits.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "98e8ff1da1a89f93d1397a24d7413ed15421c139",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "mixed groups",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/mixed-groups.v9.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "ansi-regex",
					Version:    "5.0.1",
					Locations:  []string{"fixtures/pnpm/mixed-groups.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "8.3.2",
					Locations:  []string{"fixtures/pnpm/mixed-groups.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "is-number",
					Version:    "7.0.0",
					Locations:  []string{"fixtures/pnpm/mixed-groups.v9.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PnpmLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
