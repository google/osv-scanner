package lockfilescalibr_test

import (
	"testing"

	lockfile "github.com/google/osv-scanner/internal/lockfilescalibr"
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
				path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "buildscript-gradle.lockfile",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/buildscript-gradle.lockfile",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/buildscript-gradle.lockfile/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/buildscript-gradle.lockfile.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.buildscript-gradle.lockfile",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "gradle.lockfile",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/gradle.lockfile",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/gradle.lockfile/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/gradle.lockfile.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.gradle.lockfile",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.GradleLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestGradleLockExtractor_Extract(t *testing.T) {
	t.Parallel()
	tests := []testTableEntry{
		{
			name: "only comments",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/gradle/only-comments",
			},
			wantInventory: []*lockfile.Inventory{},
		},
		{
			name: "empty statement",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/gradle/only-empty",
			},
			wantInventory: []*lockfile.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/gradle/one-pkg",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "org.springframework.security:spring-security-crypto",
					Version:   "5.7.3",
					Locations: []string{"fixtures/gradle/one-pkg"},
				},
			},
		},
		{
			name: "multiple package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/gradle/5-pkg",
			},
			wantInventory: []*lockfile.Inventory{
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
			name: "with invalid lines",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/gradle/with-bad-pkg",
			},
			wantInventory: []*lockfile.Inventory{
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.GradleLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}

// func TestParseGradleLock_OnlyComments(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGradleLock("fixtures/gradle/only-comments")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseGradleLock_EmptyStatement(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGradleLock("fixtures/gradle/only-empty")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseGradleLock_OnePackage(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGradleLock("fixtures/gradle/one-pkg")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "org.springframework.security:spring-security-crypto",
// 			Version:   "5.7.3",
// 			Ecosystem: lockfile.MavenEcosystem,
// 			CompareAs: lockfile.MavenEcosystem,
// 		},
// 	})
// }

// func TestParseGradleLock_MultiplePackage(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGradleLock("fixtures/gradle/5-pkg")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "org.springframework.boot:spring-boot-autoconfigure",
// 			Version:   "2.7.4",
// 			Ecosystem: lockfile.MavenEcosystem,
// 			CompareAs: lockfile.MavenEcosystem,
// 		},
// 		{
// 			Name:      "org.springframework.boot:spring-boot-configuration-processor",
// 			Version:   "2.7.5",
// 			Ecosystem: lockfile.MavenEcosystem,
// 			CompareAs: lockfile.MavenEcosystem,
// 		},
// 		{
// 			Name:      "org.springframework.boot:spring-boot-devtools",
// 			Version:   "2.7.6",
// 			Ecosystem: lockfile.MavenEcosystem,
// 			CompareAs: lockfile.MavenEcosystem,
// 		},

// 		{
// 			Name:      "org.springframework.boot:spring-boot-starter-aop",
// 			Version:   "2.7.7",
// 			Ecosystem: lockfile.MavenEcosystem,
// 			CompareAs: lockfile.MavenEcosystem,
// 		},
// 		{
// 			Name:      "org.springframework.boot:spring-boot-starter-data-jpa",
// 			Version:   "2.7.8",
// 			Ecosystem: lockfile.MavenEcosystem,
// 			CompareAs: lockfile.MavenEcosystem,
// 		},
// 	})
// }

// func TestParseGradleLock_WithInvalidLines(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGradleLock("fixtures/gradle/with-bad-pkg")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "org.springframework.boot:spring-boot-autoconfigure",
// 			Version:   "2.7.4",
// 			Ecosystem: lockfile.MavenEcosystem,
// 			CompareAs: lockfile.MavenEcosystem,
// 		},
// 		{
// 			Name:      "org.springframework.boot:spring-boot-configuration-processor",
// 			Version:   "2.7.5",
// 			Ecosystem: lockfile.MavenEcosystem,
// 			CompareAs: lockfile.MavenEcosystem,
// 		},
// 	})
// }
