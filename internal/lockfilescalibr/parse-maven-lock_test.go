package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
)

func TestMavenLockExtractor_FileRequired(t *testing.T) {
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
				path: "pom.xml",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/pom.xml",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/pom.xml/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/pom.xml.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.pom.xml",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.MavenLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestMavenLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "invalid",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/maven/not-pom.txt",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "invalid syntax",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/maven/invalid-syntax.xml",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/maven/empty.xml",
			},
			wantInventory: []*extractor.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/maven/one-package.xml",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "org.apache.maven:maven-artifact",
					Version:   "1.0.0",
					Locations: []string{"fixtures/maven/one-package.xml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/maven/two-packages.xml",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "io.netty:netty-all",
					Version:   "4.1.42.Final",
					Locations: []string{"fixtures/maven/two-packages.xml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.slf4j:slf4j-log4j12",
					Version:   "1.7.25",
					Locations: []string{"fixtures/maven/two-packages.xml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "with dependency management",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/maven/with-dependency-management.xml",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "io.netty:netty-all",
					Version:   "4.1.9",
					Locations: []string{"fixtures/maven/with-dependency-management.xml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.slf4j:slf4j-log4j12",
					Version:   "1.7.25",
					Locations: []string{"fixtures/maven/with-dependency-management.xml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "com.google.code.findbugs:jsr305",
					Version:   "3.0.2",
					Locations: []string{"fixtures/maven/with-dependency-management.xml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "interpolation",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/maven/interpolation.xml",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "org.mine:mypackage",
					Version:   "1.0.0",
					Locations: []string{"fixtures/maven/interpolation.xml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.mine:my.package",
					Version:   "2.3.4",
					Locations: []string{"fixtures/maven/interpolation.xml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.mine:ranged-package",
					Version:   "9.4.35.v20201120",
					Locations: []string{"fixtures/maven/interpolation.xml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "with scope",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/maven/with-scope.xml",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "abc:xyz",
					Version:   "1.2.3",
					Locations: []string{"fixtures/maven/with-scope.xml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "junit:junit",
					Version:   "4.12",
					Locations: []string{"fixtures/maven/with-scope.xml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"test"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.MavenLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
