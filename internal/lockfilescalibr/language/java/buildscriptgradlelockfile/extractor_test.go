package buildscriptgradlelockfile_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extracttest"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/java/buildscriptgradlelockfile"
)

func TestExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "",
			inputPath: "",
			want:      false,
		},
		{
			name:      "",
			inputPath: "buildscript-gradle.lockfile",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/buildscript-gradle.lockfile",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/buildscript-gradle.lockfile/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/buildscript-gradle.lockfile.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.buildscript-gradle.lockfile",
			want:      false,
		},
		{
			name:      "",
			inputPath: "gradle.lockfile",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/gradle.lockfile",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/gradle.lockfile/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/gradle.lockfile.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.gradle.lockfile",
			want:      false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := buildscriptgradlelockfile.Extractor{}
			got := e.FileRequired(tt.inputPath, nil)
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()
	tests := []extracttest.TestTableEntry{
		{
			Name: "only comments",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/only-comments",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "empty statement",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/only-empty",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-pkg",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.springframework.security:spring-security-crypto",
					Version:   "5.7.3",
					Locations: []string{"testdata/one-pkg"},
				},
			},
		},
		{
			Name: "multiple package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/5-pkg",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.springframework.boot:spring-boot-autoconfigure",
					Version:   "2.7.4",
					Locations: []string{"testdata/5-pkg"},
				},
				{
					Name:      "org.springframework.boot:spring-boot-configuration-processor",
					Version:   "2.7.5",
					Locations: []string{"testdata/5-pkg"},
				},
				{
					Name:      "org.springframework.boot:spring-boot-devtools",
					Version:   "2.7.6",
					Locations: []string{"testdata/5-pkg"},
				},
				{
					Name:      "org.springframework.boot:spring-boot-starter-aop",
					Version:   "2.7.7",
					Locations: []string{"testdata/5-pkg"},
				},
				{
					Name:      "org.springframework.boot:spring-boot-starter-data-jpa",
					Version:   "2.7.8",
					Locations: []string{"testdata/5-pkg"},
				},
			},
		},
		{
			Name: "with invalid lines",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-bad-pkg",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.springframework.boot:spring-boot-autoconfigure",
					Version:   "2.7.4",
					Locations: []string{"testdata/with-bad-pkg"},
				},
				{
					Name:      "org.springframework.boot:spring-boot-configuration-processor",
					Version:   "2.7.5",
					Locations: []string{"testdata/with-bad-pkg"},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			extr := buildscriptgradlelockfile.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantInventory, got, cmpopts.SortSlices(extracttest.InventoryCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
