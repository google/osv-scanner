package lockfilescalibr_test

import (
	"testing"

	lockfile "github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
)

func TestGradleLockExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig ScanInputMockConfig
		want        bool
	}{
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "buildscript-gradle.lockfile",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/buildscript-gradle.lockfile",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/buildscript-gradle.lockfile/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/buildscript-gradle.lockfile.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path.to.my.buildscript-gradle.lockfile",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "gradle.lockfile",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/gradle.lockfile",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/gradle.lockfile/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/gradle.lockfile.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path.to.my.gradle.lockfile",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.GradleLockExtractor{}
			got := e.FileRequired(tt.inputConfig.Path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.Path, got, tt.want)
			}
		})
	}
}

func TestGradleLockExtractor_Extract(t *testing.T) {
	t.Parallel()
	tests := []TestTableEntry{
		{
			Name: "only comments",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/gradle/only-comments",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "empty statement",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/gradle/only-empty",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/gradle/one-pkg",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.springframework.security:spring-security-crypto",
					Version:   "5.7.3",
					Locations: []string{"fixtures/gradle/one-pkg"},
				},
			},
		},
		{
			Name: "multiple package",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/gradle/5-pkg",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.springframework.boot:spring-boot-autoconfigure",
					Version:   "2.7.4",
					Locations: []string{"fixtures/gradle/5-pkg"},
				},
				{
					Name:      "org.springframework.boot:spring-boot-configuration-processor",
					Version:   "2.7.5",
					Locations: []string{"fixtures/gradle/5-pkg"},
				},
				{
					Name:      "org.springframework.boot:spring-boot-devtools",
					Version:   "2.7.6",
					Locations: []string{"fixtures/gradle/5-pkg"},
				},
				{
					Name:      "org.springframework.boot:spring-boot-starter-aop",
					Version:   "2.7.7",
					Locations: []string{"fixtures/gradle/5-pkg"},
				},
				{
					Name:      "org.springframework.boot:spring-boot-starter-data-jpa",
					Version:   "2.7.8",
					Locations: []string{"fixtures/gradle/5-pkg"},
				},
			},
		},
		{
			Name: "with invalid lines",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/gradle/with-bad-pkg",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.springframework.boot:spring-boot-autoconfigure",
					Version:   "2.7.4",
					Locations: []string{"fixtures/gradle/with-bad-pkg"},
				},
				{
					Name:      "org.springframework.boot:spring-boot-configuration-processor",
					Version:   "2.7.5",
					Locations: []string{"fixtures/gradle/with-bad-pkg"},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.GradleLockExtractor{}
			_, _ = ExtractionTester(t, e, tt)
		})
	}
}
