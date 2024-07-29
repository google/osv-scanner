package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
)

func TestYarnLockExtractor_Extract_v1(t *testing.T) {
	t.Parallel()

	tests := []TestTableEntry{
		{
			Name: "no packages",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/yarn/empty.v1.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/yarn/one-package.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "balanced-match",
					Version:   "1.0.2",
					Locations: []string{"fixtures/yarn/one-package.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/yarn/two-packages.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "concat-stream",
					Version:   "1.6.2",
					Locations: []string{"fixtures/yarn/two-packages.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "concat-map",
					Version:   "0.0.1",
					Locations: []string{"fixtures/yarn/two-packages.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "with quotes",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/yarn/with-quotes.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "concat-stream",
					Version:   "1.6.2",
					Locations: []string{"fixtures/yarn/with-quotes.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "concat-map",
					Version:   "0.0.1",
					Locations: []string{"fixtures/yarn/with-quotes.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "multiple versions",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/yarn/multiple-versions.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "define-properties",
					Version:   "1.1.3",
					Locations: []string{"fixtures/yarn/multiple-versions.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "define-property",
					Version:   "0.2.5",
					Locations: []string{"fixtures/yarn/multiple-versions.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "define-property",
					Version:   "1.0.0",
					Locations: []string{"fixtures/yarn/multiple-versions.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "define-property",
					Version:   "2.0.2",
					Locations: []string{"fixtures/yarn/multiple-versions.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "multiple constraints",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/yarn/multiple-constraints.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "@babel/code-frame",
					Version:   "7.12.13",
					Locations: []string{"fixtures/yarn/multiple-constraints.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "domelementtype",
					Version:   "1.3.1",
					Locations: []string{"fixtures/yarn/multiple-constraints.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "scoped packages",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/yarn/scoped-packages.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "@babel/code-frame",
					Version:   "7.12.11",
					Locations: []string{"fixtures/yarn/scoped-packages.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "@babel/compat-data",
					Version:   "7.14.0",
					Locations: []string{"fixtures/yarn/scoped-packages.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "with prerelease",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/yarn/with-prerelease.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "css-tree",
					Version:   "1.0.0-alpha.37",
					Locations: []string{"fixtures/yarn/with-prerelease.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "gensync",
					Version:   "1.0.0-beta.2",
					Locations: []string{"fixtures/yarn/with-prerelease.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "node-fetch",
					Version:   "3.0.0-beta.9",
					Locations: []string{"fixtures/yarn/with-prerelease.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "resolve",
					Version:   "1.20.0",
					Locations: []string{"fixtures/yarn/with-prerelease.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "resolve",
					Version:   "2.0.0-next.3",
					Locations: []string{"fixtures/yarn/with-prerelease.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "with build string",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/yarn/with-build-string.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "domino",
					Version:   "2.1.6+git",
					Locations: []string{"fixtures/yarn/with-build-string.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "tslib",
					Version:   "2.6.2",
					Locations: []string{"fixtures/yarn/with-build-string.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "commits",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/yarn/commits.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "mine1",
					Version:   "1.0.0-alpha.37",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "0a2d2506c1fe299691fc5db53a2097db3bd615bc",
					},
				},
				{
					Name:      "mine2",
					Version:   "0.0.1",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "0a2d2506c1fe299691fc5db53a2097db3bd615bc",
					},
				},
				{
					Name:      "mine3",
					Version:   "1.2.3",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "094e581aaf927d010e4b61d706ba584551dac502",
					},
				},
				{
					Name:      "mine4",
					Version:   "0.0.2",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "aa3bdfcb1d845c79f14abb66f60d35b8a3ee5998",
					},
				},
				{
					Name:      "mine4",
					Version:   "0.0.4",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "aa3bdfcb1d845c79f14abb66f60d35b8a3ee5998",
					},
				},
				{
					Name:      "my-package",
					Version:   "1.8.3",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "b3bd3f1b3dad036e671251f5258beaae398f983a",
					},
				},
				{
					Name:      "@bower_components/angular-animate",
					Version:   "1.4.14",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "e7f778fc054a086ba3326d898a00fa1bc78650a8",
					},
				},
				{
					Name:      "@bower_components/alertify",
					Version:   "0.0.0",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "e7b6c46d76604d297c389d830817b611c9a8f17c",
					},
				},
				{
					Name:      "minimist",
					Version:   "0.0.8",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "3754568bfd43a841d2d72d7fb54598635aea8fa4",
					},
				},
				{
					Name:      "bats-assert",
					Version:   "2.0.0",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4bdd58d3fbcdce3209033d44d884e87add1d8405",
					},
				},
				{
					Name:      "bats-support",
					Version:   "0.3.0",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d140a65044b2d6810381935ae7f0c94c7023c8c3",
					},
				},
				{
					Name:      "bats",
					Version:   "1.5.0",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "172580d2ce19ee33780b5f1df817bbddced43789",
					},
				},
				{
					Name:      "vue",
					Version:   "2.6.12",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "bb253db0b3e17124b6d1fe93fbf2db35470a1347",
					},
				},
				{
					Name:      "kit",
					Version:   "1.0.0",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "5b6830c0252eb73c6024d40a8ff5106d3023a2a6",
					},
				},
				{
					Name:      "casadistance",
					Version:   "1.0.0",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "f0308391f0c50104182bfb2332a53e4e523a4603",
					},
				},
				{
					Name:      "babel-preset-php",
					Version:   "1.1.1",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
					},
				},
				{
					Name:      "is-number",
					Version:   "2.0.0",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
					},
				},
				{
					Name:      "is-number",
					Version:   "5.0.0",
					Locations: []string{"fixtures/yarn/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
					},
				},
			},
		},
		{
			Name: "files",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/yarn/files.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "etag",
					Version:   "1.8.1",
					Locations: []string{"fixtures/yarn/files.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "filedep",
					Version:   "1.2.0",
					Locations: []string{"fixtures/yarn/files.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "lodash",
					Version:   "1.3.1",
					Locations: []string{"fixtures/yarn/files.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "other_package",
					Version:   "0.0.2",
					Locations: []string{"fixtures/yarn/files.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "sprintf-js",
					Version:   "0.0.0",
					Locations: []string{"fixtures/yarn/files.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "etag",
					Version:   "1.8.0",
					Locations: []string{"fixtures/yarn/files.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "with aliases",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/yarn/with-aliases.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "@babel/helper-validator-identifier",
					Version:   "7.22.20",
					Locations: []string{"fixtures/yarn/with-aliases.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "ansi-regex",
					Version:   "6.0.1",
					Locations: []string{"fixtures/yarn/with-aliases.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "ansi-regex",
					Version:   "5.0.1",
					Locations: []string{"fixtures/yarn/with-aliases.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.YarnLockExtractor{}
			_, _ = ExtractionTester(t, e, tt)
		})
	}
}
