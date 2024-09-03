package buildscriptgradlelockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/java/buildscriptgradlelockfile"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
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
	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name:          "only comments",
			inputPath:     "testdata/only-comments",
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name:          "empty statement",
			inputPath:     "testdata/only-empty",
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name:      "one package",
			inputPath: "testdata/one-pkg",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.springframework.security:spring-security-crypto",
					Version:   "5.7.3",
					Locations: []string{"testdata/one-pkg"},
				},
			},
		},
		{
			Name:      "multiple package",
			inputPath: "testdata/5-pkg",
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
			Name:      "with invalid lines",
			inputPath: "testdata/with-bad-pkg",
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
			e := buildscriptgradlelockfile.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
