package requirementstxt_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/python/requirementstxt"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestExtractor_FileRequired(t *testing.T) {
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
				Path: "requirements.txt",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/requirements.txt",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/requirements.txt/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/requirements.txt.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path.to.my.requirements.txt",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := requirementstxt.Extractor{}
			got := e.FileRequired(tt.inputConfig.Path, sharedtesthelpers.GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.Path, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "empty",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/empty.txt",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "comments only",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/only-comments.txt",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one requirement unconstrained",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/one-package-unconstrained.txt",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "flask",
					Version:   "0.0.0",
					Locations: []string{"testdata/one-package-unconstrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"one-package-unconstrained"},
					},
				},
			},
		},
		{
			Name: "one requirement constrained",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/one-package-constrained.txt",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "django",
					Version:   "2.2.24",
					Locations: []string{"testdata/one-package-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"one-package-constrained"},
					},
				},
			},
		},
		{
			Name: "multiple requirements constrained",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/multiple-packages-constrained.txt",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "astroid",
					Version:   "2.5.1",
					Locations: []string{"testdata/multiple-packages-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "beautifulsoup4",
					Version:   "4.9.3",
					Locations: []string{"testdata/multiple-packages-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "boto3",
					Version:   "1.17.19",
					Locations: []string{"testdata/multiple-packages-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "botocore",
					Version:   "1.20.19",
					Locations: []string{"testdata/multiple-packages-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "certifi",
					Version:   "2020.12.5",
					Locations: []string{"testdata/multiple-packages-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "chardet",
					Version:   "4.0.0",
					Locations: []string{"testdata/multiple-packages-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "circus",
					Version:   "0.17.1",
					Locations: []string{"testdata/multiple-packages-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "click",
					Version:   "7.1.2",
					Locations: []string{"testdata/multiple-packages-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "django-debug-toolbar",
					Version:   "3.2.1",
					Locations: []string{"testdata/multiple-packages-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "django-filter",
					Version:   "2.4.0",
					Locations: []string{"testdata/multiple-packages-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "django-nose",
					Version:   "1.4.7",
					Locations: []string{"testdata/multiple-packages-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "django-storages",
					Version:   "1.11.1",
					Locations: []string{"testdata/multiple-packages-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "django",
					Version:   "2.2.24",
					Locations: []string{"testdata/multiple-packages-constrained.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
			},
		},
		{
			Name: "multiple requirements mixed",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/multiple-packages-mixed.txt",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "flask",
					Version:   "0.0.0",
					Locations: []string{"testdata/multiple-packages-mixed.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "flask-cors",
					Version:   "0.0.0",
					Locations: []string{"testdata/multiple-packages-mixed.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "pandas",
					Version:   "0.23.4",
					Locations: []string{"testdata/multiple-packages-mixed.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "numpy",
					Version:   "1.16.0",
					Locations: []string{"testdata/multiple-packages-mixed.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "scikit-learn",
					Version:   "0.20.1",
					Locations: []string{"testdata/multiple-packages-mixed.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "sklearn",
					Version:   "0.0.0",
					Locations: []string{"testdata/multiple-packages-mixed.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "requests",
					Version:   "0.0.0",
					Locations: []string{"testdata/multiple-packages-mixed.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "gevent",
					Version:   "0.0.0",
					Locations: []string{"testdata/multiple-packages-mixed.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
			},
		},
		{
			Name: "with added support",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/with-added-support.txt",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "twisted",
					Version:   "20.3.0",
					Locations: []string{"testdata/with-added-support.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"with-added-support"},
					},
				},
			},
		},
		{
			Name: "non normalized names",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/non-normalized-names.txt",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zope-interface",
					Version:   "5.4.0",
					Locations: []string{"testdata/non-normalized-names.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"non-normalized-names"},
					},
				},
				{
					Name:      "pillow",
					Version:   "1.0.0",
					Locations: []string{"testdata/non-normalized-names.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"non-normalized-names"},
					},
				},
				{
					Name:      "twisted",
					Version:   "20.3.0",
					Locations: []string{"testdata/non-normalized-names.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"non-normalized-names"},
					},
				},
			},
		},
		{
			Name: "with per requirement options",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/with-per-requirement-options.txt",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "boto3",
					Version:   "1.26.121",
					Locations: []string{"testdata/with-per-requirement-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"with-per-requirement-options"},
					},
				},
				{
					Name:      "foo",
					Version:   "1.0.0",
					Locations: []string{"testdata/with-per-requirement-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"with-per-requirement-options"},
					},
				},
				{
					Name:      "fooproject",
					Version:   "1.2",
					Locations: []string{"testdata/with-per-requirement-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"with-per-requirement-options"},
					},
				},
				{
					Name:      "barproject",
					Version:   "1.2",
					Locations: []string{"testdata/with-per-requirement-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"with-per-requirement-options"},
					},
				},
			},
		},
		{
			Name: "line continuation",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/line-continuation.txt",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "foo",
					Version:   "1.2.3",
					Locations: []string{"testdata/line-continuation.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"line-continuation"},
					},
				},
				{
					Name:      "bar",
					Version:   "4.5\\\\",
					Locations: []string{"testdata/line-continuation.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"line-continuation"},
					},
				},
				{
					Name:      "baz",
					Version:   "7.8.9",
					Locations: []string{"testdata/line-continuation.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"line-continuation"},
					},
				},
				{
					Name:      "qux",
					Version:   "10.11.12",
					Locations: []string{"testdata/line-continuation.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"line-continuation"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := requirementstxt.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}

func TestExtractor_Extract_WithRequirements(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "file format example",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/file-format-example.txt",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "pytest",
					Version:   "0.0.0",
					Locations: []string{"testdata/file-format-example.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "pytest-cov",
					Version:   "0.0.0",
					Locations: []string{"testdata/file-format-example.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "beautifulsoup4",
					Version:   "0.0.0",
					Locations: []string{"testdata/file-format-example.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "docopt",
					Version:   "0.6.1",
					Locations: []string{"testdata/file-format-example.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "keyring",
					Version:   "4.1.1",
					Locations: []string{"testdata/file-format-example.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "coverage",
					Version:   "0.0.0",
					Locations: []string{"testdata/file-format-example.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "mopidy-dirble",
					Version:   "1.1",
					Locations: []string{"testdata/file-format-example.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "rejected",
					Version:   "0.0.0",
					Locations: []string{"testdata/file-format-example.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "green",
					Version:   "0.0.0",
					Locations: []string{"testdata/file-format-example.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "django",
					Version:   "2.2.24",
					Locations: []string{"testdata/file-format-example.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"other-file"},
					},
				},
			},
		},
		{
			Name: "with multiple r options",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/with-multiple-r-options.txt",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "flask",
					Version:   "0.0.0",
					Locations: []string{"testdata/with-multiple-r-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "flask-cors",
					Version:   "0.0.0",
					Locations: []string{"testdata/with-multiple-r-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "pandas",
					Version:   "0.23.4",
					Locations: []string{"testdata/with-multiple-r-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed", "with-multiple-r-options"},
					},
				},
				{
					Name:      "numpy",
					Version:   "1.16.0",
					Locations: []string{"testdata/with-multiple-r-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "scikit-learn",
					Version:   "0.20.1",
					Locations: []string{"testdata/with-multiple-r-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "sklearn",
					Version:   "0.0.0",
					Locations: []string{"testdata/with-multiple-r-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "requests",
					Version:   "0.0.0",
					Locations: []string{"testdata/with-multiple-r-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "gevent",
					Version:   "0.0.0",
					Locations: []string{"testdata/with-multiple-r-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "requests",
					Version:   "1.2.3",
					Locations: []string{"testdata/with-multiple-r-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"with-multiple-r-options"},
					},
				},
				{
					Name:      "django",
					Version:   "2.2.24",
					Locations: []string{"testdata/with-multiple-r-options.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"one-package-constrained"},
					},
				},
			},
		},
		{
			Name: "with bad r option",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/with-bad-r-option.txt",
			},
			WantErrIs: fs.ErrNotExist},
		{
			Name: "duplicate r options",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/duplicate-r-dev.txt",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "django",
					Version:   "0.1.0",
					Locations: []string{"testdata/duplicate-r-dev.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"duplicate-r-base"},
					},
				},
				{
					Name:      "pandas",
					Version:   "0.23.4",
					Locations: []string{"testdata/duplicate-r-dev.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"duplicate-r-dev"},
					},
				},
				{
					Name:      "requests",
					Version:   "1.2.3",
					Locations: []string{"testdata/duplicate-r-dev.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"duplicate-r-test", "duplicate-r-dev"},
					},
				},
				{
					Name:      "unittest",
					Version:   "1.0.0",
					Locations: []string{"testdata/duplicate-r-dev.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"duplicate-r-test"},
					},
				},
			},
		},
		{
			Name: "cyclic r self",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/cyclic-r-self.txt",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "pandas",
					Version:   "0.23.4",
					Locations: []string{"testdata/cyclic-r-self.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"cyclic-r-self"},
					},
				},
				{
					Name:      "requests",
					Version:   "1.2.3",
					Locations: []string{"testdata/cyclic-r-self.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"cyclic-r-self"},
					},
				},
			},
		},
		{
			Name: "cyclic r complex",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/cyclic-r-complex-1.txt",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "cyclic-r-complex",
					Version:   "1",
					Locations: []string{"testdata/cyclic-r-complex-1.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"cyclic-r-complex-1"},
					},
				},
				{
					Name:      "cyclic-r-complex",
					Version:   "2",
					Locations: []string{"testdata/cyclic-r-complex-1.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"cyclic-r-complex-2"},
					},
				},
				{
					Name:      "cyclic-r-complex",
					Version:   "3",
					Locations: []string{"testdata/cyclic-r-complex-1.txt"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"cyclic-r-complex-3"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := requirementstxt.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
