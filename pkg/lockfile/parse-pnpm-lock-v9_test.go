package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestPnpmLockExtractor_Extract_v9(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "v9_ no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/no-packages.v9.yaml",
			},
			wantInventory: []*lockfile.Inventory{},
		},
		{
			name: "v9_ one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/one-package.v9.yaml",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:       "acorn",
					Version:    "8.11.3",
					Locations:  []string{"fixtures/pnpm/one-package.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "v9_ one package dev",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/one-package-dev.v9.yaml",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:       "acorn",
					Version:    "8.11.3",
					Locations:  []string{"fixtures/pnpm/one-package-dev.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "v9_ scoped packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/scoped-packages.v9.yaml",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.62.0",
					Locations:  []string{"fixtures/pnpm/scoped-packages.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "v9_ peer dependencies",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/peer-dependencies.v9.yaml",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:       "acorn-jsx",
					Version:    "5.3.2",
					Locations:  []string{"fixtures/pnpm/peer-dependencies.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					Version:    "8.11.3",
					Locations:  []string{"fixtures/pnpm/peer-dependencies.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "v9_ peer dependencies advanced",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/peer-dependencies-advanced.v9.yaml",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:       "@eslint-community/eslint-utils",
					Version:    "4.4.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@eslint/eslintrc",
					Version:    "2.1.4",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/eslint-plugin",
					Version:    "5.62.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/parser",
					Version:    "5.62.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/type-utils",
					Version:    "5.62.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/typescript-estree",
					Version:    "5.62.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/utils",
					Version:    "5.62.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "debug",
					Version:    "4.3.4",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "eslint",
					Version:    "8.57.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "4.0.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "7.2.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "tsutils",
					Version:    "3.21.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "typescript",
					Version:    "4.9.5",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "v9_ multiple versions",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/multiple-versions.v9.yaml",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:       "uuid",
					Version:    "8.0.0",
					Locations:  []string{"fixtures/pnpm/multiple-versions.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "8.3.2",
					Locations:  []string{"fixtures/pnpm/multiple-versions.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "xmlbuilder",
					Version:    "11.0.1",
					Locations:  []string{"fixtures/pnpm/multiple-versions.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "v9_ commits",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/commits.v9.yaml",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "ansi-regex",
					Version:   "6.0.1",
					Locations: []string{"fixtures/pnpm/commits.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "02fa893d619d3da85411acc8fd4e2eea0e95a9d9",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "is-number",
					Version:   "7.0.0",
					Locations: []string{"fixtures/pnpm/commits.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "98e8ff1da1a89f93d1397a24d7413ed15421c139",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "v9_ mixed groups",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/mixed-groups.v9.yaml",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:       "ansi-regex",
					Version:    "5.0.1",
					Locations:  []string{"fixtures/pnpm/mixed-groups.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "8.3.2",
					Locations:  []string{"fixtures/pnpm/mixed-groups.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "is-number",
					Version:    "7.0.0",
					Locations:  []string{"fixtures/pnpm/mixed-groups.v9.yaml"},
					SourceCode: &lockfile.SourceCodeIdentifier{},
					Metadata: lockfile.DepGroupMetadata{
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
			e := lockfile.PnpmLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
