package lockfilescalibr_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
)

func TestRequirementsTxtExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig ScanInputMockConfig
		want        bool
	}{
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "requirements.txt",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/requirements.txt",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/requirements.txt/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/requirements.txt.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.requirements.txt",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.RequirementsTxtExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestRequirementsTxtExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "empty",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/empty.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "comments only",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/only-comments.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "one requirement unconstrained",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/one-package-unconstrained.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "flask",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/one-package-unconstrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"one-package-unconstrained"},
					},
				},
			},
		},
		{
			name: "one requirement constrained",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/one-package-constrained.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "django",
					Version:   "2.2.24",
					Locations: []string{"fixtures/pip/one-package-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"one-package-constrained"},
					},
				},
			},
		},
		{
			name: "multiple requirements constrained",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/multiple-packages-constrained.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "astroid",
					Version:   "2.5.1",
					Locations: []string{"fixtures/pip/multiple-packages-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "beautifulsoup4",
					Version:   "4.9.3",
					Locations: []string{"fixtures/pip/multiple-packages-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "boto3",
					Version:   "1.17.19",
					Locations: []string{"fixtures/pip/multiple-packages-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "botocore",
					Version:   "1.20.19",
					Locations: []string{"fixtures/pip/multiple-packages-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "certifi",
					Version:   "2020.12.5",
					Locations: []string{"fixtures/pip/multiple-packages-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "chardet",
					Version:   "4.0.0",
					Locations: []string{"fixtures/pip/multiple-packages-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "circus",
					Version:   "0.17.1",
					Locations: []string{"fixtures/pip/multiple-packages-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "click",
					Version:   "7.1.2",
					Locations: []string{"fixtures/pip/multiple-packages-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "django-debug-toolbar",
					Version:   "3.2.1",
					Locations: []string{"fixtures/pip/multiple-packages-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "django-filter",
					Version:   "2.4.0",
					Locations: []string{"fixtures/pip/multiple-packages-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "django-nose",
					Version:   "1.4.7",
					Locations: []string{"fixtures/pip/multiple-packages-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "django-storages",
					Version:   "1.11.1",
					Locations: []string{"fixtures/pip/multiple-packages-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
				{
					Name:      "django",
					Version:   "2.2.24",
					Locations: []string{"fixtures/pip/multiple-packages-constrained.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-constrained"},
					},
				},
			},
		},
		{
			name: "multiple requirements mixed",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/multiple-packages-mixed.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "flask",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/multiple-packages-mixed.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "flask-cors",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/multiple-packages-mixed.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "pandas",
					Version:   "0.23.4",
					Locations: []string{"fixtures/pip/multiple-packages-mixed.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "numpy",
					Version:   "1.16.0",
					Locations: []string{"fixtures/pip/multiple-packages-mixed.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "scikit-learn",
					Version:   "0.20.1",
					Locations: []string{"fixtures/pip/multiple-packages-mixed.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "sklearn",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/multiple-packages-mixed.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "requests",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/multiple-packages-mixed.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "gevent",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/multiple-packages-mixed.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
			},
		},
		{
			name: "with added support",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/with-added-support.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "twisted",
					Version:   "20.3.0",
					Locations: []string{"fixtures/pip/with-added-support.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"with-added-support"},
					},
				},
			},
		},
		{
			name: "non normalized names",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/non-normalized-names.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "zope-interface",
					Version:   "5.4.0",
					Locations: []string{"fixtures/pip/non-normalized-names.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"non-normalized-names"},
					},
				},
				{
					Name:      "pillow",
					Version:   "1.0.0",
					Locations: []string{"fixtures/pip/non-normalized-names.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"non-normalized-names"},
					},
				},
				{
					Name:      "twisted",
					Version:   "20.3.0",
					Locations: []string{"fixtures/pip/non-normalized-names.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"non-normalized-names"},
					},
				},
			},
		},
		{
			name: "with per requirement options",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/with-per-requirement-options.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "boto3",
					Version:   "1.26.121",
					Locations: []string{"fixtures/pip/with-per-requirement-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"with-per-requirement-options"},
					},
				},
				{
					Name:      "foo",
					Version:   "1.0.0",
					Locations: []string{"fixtures/pip/with-per-requirement-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"with-per-requirement-options"},
					},
				},
				{
					Name:      "fooproject",
					Version:   "1.2",
					Locations: []string{"fixtures/pip/with-per-requirement-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"with-per-requirement-options"},
					},
				},
				{
					Name:      "barproject",
					Version:   "1.2",
					Locations: []string{"fixtures/pip/with-per-requirement-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"with-per-requirement-options"},
					},
				},
			},
		},
		{
			name: "line continuation",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/line-continuation.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "foo",
					Version:   "1.2.3",
					Locations: []string{"fixtures/pip/line-continuation.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"line-continuation"},
					},
				},
				{
					Name:      "bar",
					Version:   "4.5\\\\",
					Locations: []string{"fixtures/pip/line-continuation.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"line-continuation"},
					},
				},
				{
					Name:      "baz",
					Version:   "7.8.9",
					Locations: []string{"fixtures/pip/line-continuation.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"line-continuation"},
					},
				},
				{
					Name:      "qux",
					Version:   "10.11.12",
					Locations: []string{"fixtures/pip/line-continuation.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"line-continuation"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.RequirementsTxtExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}

func TestRequirementsTxtExtractor_Extract_WithRequirements(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "file format example",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/file-format-example.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "pytest",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/file-format-example.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "pytest-cov",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/file-format-example.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "beautifulsoup4",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/file-format-example.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "docopt",
					Version:   "0.6.1",
					Locations: []string{"fixtures/pip/file-format-example.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "keyring",
					Version:   "4.1.1",
					Locations: []string{"fixtures/pip/file-format-example.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "coverage",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/file-format-example.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "mopidy-dirble",
					Version:   "1.1",
					Locations: []string{"fixtures/pip/file-format-example.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "rejected",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/file-format-example.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "green",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/file-format-example.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"file-format-example"},
					},
				},
				{
					Name:      "django",
					Version:   "2.2.24",
					Locations: []string{"fixtures/pip/file-format-example.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"other-file"},
					},
				},
			},
		},
		{
			name: "with multiple r options",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/with-multiple-r-options.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "flask",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/with-multiple-r-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "flask-cors",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/with-multiple-r-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "pandas",
					Version:   "0.23.4",
					Locations: []string{"fixtures/pip/with-multiple-r-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed", "with-multiple-r-options"},
					},
				},
				{
					Name:      "numpy",
					Version:   "1.16.0",
					Locations: []string{"fixtures/pip/with-multiple-r-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "scikit-learn",
					Version:   "0.20.1",
					Locations: []string{"fixtures/pip/with-multiple-r-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "sklearn",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/with-multiple-r-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "requests",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/with-multiple-r-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "gevent",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pip/with-multiple-r-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"multiple-packages-mixed"},
					},
				},
				{
					Name:      "requests",
					Version:   "1.2.3",
					Locations: []string{"fixtures/pip/with-multiple-r-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"with-multiple-r-options"},
					},
				},
				{
					Name:      "django",
					Version:   "2.2.24",
					Locations: []string{"fixtures/pip/with-multiple-r-options.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"one-package-constrained"},
					},
				},
			},
		},
		{
			name: "with bad r option",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/with-bad-r-option.txt",
			},
			wantErrIs: fs.ErrNotExist},
		{
			name: "duplicate r options",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/duplicate-r-dev.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "django",
					Version:   "0.1.0",
					Locations: []string{"fixtures/pip/duplicate-r-dev.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"duplicate-r-base"},
					},
				},
				{
					Name:      "pandas",
					Version:   "0.23.4",
					Locations: []string{"fixtures/pip/duplicate-r-dev.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"duplicate-r-dev"},
					},
				},
				{
					Name:      "requests",
					Version:   "1.2.3",
					Locations: []string{"fixtures/pip/duplicate-r-dev.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"duplicate-r-test", "duplicate-r-dev"},
					},
				},
				{
					Name:      "unittest",
					Version:   "1.0.0",
					Locations: []string{"fixtures/pip/duplicate-r-dev.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"duplicate-r-test"},
					},
				},
			},
		},
		{
			name: "cyclic r self",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/cyclic-r-self.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "pandas",
					Version:   "0.23.4",
					Locations: []string{"fixtures/pip/cyclic-r-self.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"cyclic-r-self"},
					},
				},
				{
					Name:      "requests",
					Version:   "1.2.3",
					Locations: []string{"fixtures/pip/cyclic-r-self.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"cyclic-r-self"},
					},
				},
			},
		},
		{
			name: "cyclic r complex",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pip/cyclic-r-complex-1.txt",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "cyclic-r-complex",
					Version:   "1",
					Locations: []string{"fixtures/pip/cyclic-r-complex-1.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"cyclic-r-complex-1"},
					},
				},
				{
					Name:      "cyclic-r-complex",
					Version:   "2",
					Locations: []string{"fixtures/pip/cyclic-r-complex-1.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"cyclic-r-complex-2"},
					},
				},
				{
					Name:      "cyclic-r-complex",
					Version:   "3",
					Locations: []string{"fixtures/pip/cyclic-r-complex-1.txt"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"cyclic-r-complex-3"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.RequirementsTxtExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
