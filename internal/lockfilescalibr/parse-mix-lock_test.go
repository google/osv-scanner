package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestMixLockExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig sharedtesthelpers.ScanInputMockConfig
		want        bool
	}{
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "mix.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/mix.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/mix.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/mix.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path.to.my.mix.lock",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.MixLockExtractor{}
			got := e.FileRequired(tt.inputConfig.Path, sharedtesthelpers.GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.Path, got, tt.want)
			}
		})
	}
}

func TestMixLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		// TODO: Add invalid test case here
		{
			Name: "no packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/mix/empty.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/mix/one-package.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "plug",
					Version:   "1.11.1",
					Locations: []string{"fixtures/mix/one-package.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "f2992bac66fdae679453c9e86134a4201f6f43a687d8ff1cd1b2862d53c80259",
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/mix/two-packages.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "plug",
					Version:   "1.11.1",
					Locations: []string{"fixtures/mix/two-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "f2992bac66fdae679453c9e86134a4201f6f43a687d8ff1cd1b2862d53c80259",
					},
				},
				{
					Name:      "plug_crypto",
					Version:   "1.2.2",
					Locations: []string{"fixtures/mix/two-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "05654514ac717ff3a1843204b424477d9e60c143406aa94daf2274fdd280794d",
					},
				},
			},
		},
		{
			Name: "many",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/mix/many.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "backoff",
					Version:   "1.1.6",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "83b72ed2108ba1ee8f7d1c22e0b4a00cfe3593a67dbc792799e8cce9f42f796b",
					},
				},
				{
					Name:      "decimal",
					Version:   "2.0.0",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "a78296e617b0f5dd4c6caf57c714431347912ffb1d0842e998e9792b5642d697",
					},
				},
				{
					Name:      "dialyxir",
					Version:   "1.1.0",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "c5aab0d6e71e5522e77beff7ba9e08f8e02bad90dfbeffae60eaf0cb47e29488",
					},
				},
				{
					Name:      "earmark",
					Version:   "1.4.3",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "364ca2e9710f6bff494117dbbd53880d84bebb692dafc3a78eb50aa3183f2bfd",
					},
				},
				{
					Name:      "earmark_parser",
					Version:   "1.4.10",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "6603d7a603b9c18d3d20db69921527f82ef09990885ed7525003c7fe7dc86c56",
					},
				},
				{
					Name:      "ecto",
					Version:   "3.5.5",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "48219a991bb86daba6e38a1e64f8cea540cded58950ff38fbc8163e062281a07",
					},
				},
				{
					Name:      "erlex",
					Version:   "0.2.6",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "c7987d15e899c7a2f34f5420d2a2ea0d659682c06ac607572df55a43753aa12e",
					},
				},
				{
					Name:      "ex_doc",
					Version:   "0.23.0",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "a069bc9b0bf8efe323ecde8c0d62afc13d308b1fa3d228b65bca5cf8703a529d",
					},
				},
				{
					Name:      "makeup",
					Version:   "1.0.5",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d5a830bc42c9800ce07dd97fa94669dfb93d3bf5fcf6ea7a0c67b2e0e4a7f26c",
					},
				},
				{
					Name:      "makeup_elixir",
					Version:   "0.15.0",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "98312c9f0d3730fde4049985a1105da5155bfe5c11e47bdc7406d88e01e4219b",
					},
				},
				{
					Name:      "meck",
					Version:   "0.9.2",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "85ccbab053f1db86c7ca240e9fc718170ee5bda03810a6292b5306bf31bae5f5",
					},
				},
				{
					Name:      "mime",
					Version:   "1.5.0",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "203ef35ef3389aae6d361918bf3f952fa17a09e8e43b5aa592b93eba05d0fb8d",
					},
				},
				{
					Name:      "nimble_parsec",
					Version:   "1.1.0",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "3a6fca1550363552e54c216debb6a9e95bd8d32348938e13de5eda962c0d7f89",
					},
				},
				{
					Name:      "phoenix",
					Version:   "1.4.17",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "1b1bd4cff7cfc87c94deaa7d60dd8c22e04368ab95499483c50640ef3bd838d8",
					},
				},
				{
					Name:      "phoenix_html",
					Version:   "2.14.3",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "51f720d0d543e4e157ff06b65de38e13303d5778a7919bcc696599e5934271b8",
					},
				},
				{
					Name:      "phoenix_pubsub",
					Version:   "1.1.2",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "496c303bdf1b2e98a9d26e89af5bba3ab487ba3a3735f74bf1f4064d2a845a3e",
					},
				},
				{
					Name:      "plug",
					Version:   "1.11.1",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "f2992bac66fdae679453c9e86134a4201f6f43a687d8ff1cd1b2862d53c80259",
					},
				},
				{
					Name:      "plug_crypto",
					Version:   "1.2.2",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "05654514ac717ff3a1843204b424477d9e60c143406aa94daf2274fdd280794d",
					},
				},
				{
					Name:      "poolboy",
					Version:   "1.5.2",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "392b007a1693a64540cead79830443abf5762f5d30cf50bc95cb2c1aaafa006b",
					},
				},
				{
					Name:      "pow",
					Version:   "1.0.15",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "9267b5c75df2d59968585c042e2a0ec6217b1959d3afd629817461f0a20e903c",
					},
				},
				{
					Name:      "telemetry",
					Version:   "0.4.2",
					Locations: []string{"fixtures/mix/many.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "2808c992455e08d6177322f14d3bdb6b625fbcfd233a73505870d8738a2f4599",
					},
				},
			},
		},
		{
			Name: "git packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/mix/git.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "foe",
					Version:   "",
					Locations: []string{"fixtures/mix/git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "a9574ab75d6ed01e1288c453ae1d943d7a964595",
					},
				},
				{
					Name:      "foo",
					Version:   "",
					Locations: []string{"fixtures/mix/git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "fc94cce7830fa4dc455024bc2a83720afe244531",
					},
				},
				{
					Name:      "bar",
					Version:   "",
					Locations: []string{"fixtures/mix/git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "bef3ee1d3618017061498b96c75043e8449ef9b5",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.MixLockExtractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
