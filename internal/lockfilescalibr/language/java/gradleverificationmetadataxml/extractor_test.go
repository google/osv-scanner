package gradleverificationmetadataxml_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extracttest"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/java/gradleverificationmetadataxml"
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
			inputPath: "verification-metadata.xml",
			want:      false,
		},
		{
			name:      "",
			inputPath: "gradle/verification-metadata.xml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/verification-metadata.xml",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/verification-metadata.xml/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/verification-metadata.xml.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.verification-metadata.xml",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/gradle/verification-metadata.xml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/gradle/verification-metadata.xml/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/gradle/verification-metadata.xml.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.gradle.verification-metadata.xml",
			want:      false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := gradleverificationmetadataxml.Extractor{}
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
			Name: "invalid xml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-xml.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.xml",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.apache.pdfbox:pdfbox",
					Version:   "2.0.17",
					Locations: []string{"testdata/one-package.xml"},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.apache.pdfbox:pdfbox",
					Version:   "2.0.17",
					Locations: []string{"testdata/two-packages.xml"},
				},
				{
					Name:      "com.github.javaparser:javaparser-core",
					Version:   "3.6.11",
					Locations: []string{"testdata/two-packages.xml"},
				},
			},
		},
		{
			Name: "multiple versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-versions.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "androidx.activity:activity",
					Version:   "1.2.1",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "androidx.activity:activity",
					Version:   "1.2.3",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "androidx.activity:activity",
					Version:   "1.5.1",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "androidx.activity:activity",
					Version:   "1.6.0",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "androidx.activity:activity",
					Version:   "1.7.0",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "androidx.activity:activity",
					Version:   "1.7.2",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "androidx.activity:activity-compose",
					Version:   "1.5.0",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "androidx.activity:activity-compose",
					Version:   "1.7.0",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "androidx.activity:activity-compose",
					Version:   "1.7.2",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "androidx.activity:activity-ktx",
					Version:   "1.5.1",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "androidx.activity:activity-ktx",
					Version:   "1.7.0",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "androidx.activity:activity-ktx",
					Version:   "1.7.2",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "io.ktor:ktor-serialization-jvm",
					Version:   "2.0.0",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "io.ktor:ktor-serialization-jvm",
					Version:   "2.0.0-beta-1",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "io.ktor:ktor-serialization-jvm",
					Version:   "2.0.3",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "com.google.auto.service:auto-service",
					Version:   "1.0-rc4",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "com.google.auto.service:auto-service",
					Version:   "1.0.1",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
				{
					Name:      "com.google.auto.service:auto-service",
					Version:   "1.1.1",
					Locations: []string{"testdata/multiple-versions.xml"},
				},
			},
		},
		{
			Name: "complex",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/complex.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "com.google:google",
					Version:   "1",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.errorprone:javac",
					Version:   "9+181-r4173-1",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.android.tools:sdklib",
					Version:   "31.3.0",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.android.tools.build:aapt2",
					Version:   "8.3.0-10880808",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.android.tools.build:aapt2-proto",
					Version:   "8.3.0-10880808",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.android.tools.build:transform-api",
					Version:   "2.0.0-deprecated-use-gradle-api",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.android.tools.build.jetifier:jetifier-core",
					Version:   "1.0.0-beta10",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.android.tools.build.jetifier:jetifier-processor",
					Version:   "1.0.0-beta10",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.android.tools.emulator:proto",
					Version:   "31.3.0",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.android.tools.external.com-intellij:intellij-core",
					Version:   "31.3.0",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.android.tools.external.com-intellij:kotlin-compiler",
					Version:   "31.3.0",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.android.tools.external.org-jetbrains:uast",
					Version:   "31.3.0",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.facebook:ktfmt",
					Version:   "0.47",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.github.ben-manes:gradle-versions-plugin",
					Version:   "0.51.0",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.github.spullara.mustache.java:compiler",
					Version:   "0.9.6",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.android:annotations",
					Version:   "4.1.1.4",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.apis:google-api-services-androidpublisher",
					Version:   "v3-rev20231115-2.0.0",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.devtools.ksp:symbol-processing",
					Version:   "1.9.22-1.0.17",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.devtools.ksp:symbol-processing-api",
					Version:   "1.9.22-1.0.17",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.devtools.ksp:symbol-processing-gradle-plugin",
					Version:   "1.9.22-1.0.17",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.googlejavaformat:google-java-format",
					Version:   "1.8",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.guava:guava",
					Version:   "32.0.0-jre",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.guava:guava",
					Version:   "32.0.1-jre",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.guava:guava",
					Version:   "32.1.3-jre",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.guava:listenablefuture",
					Version:   "1.0",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.guava:listenablefuture",
					Version:   "9999.0-empty-to-avoid-conflict-with-guava",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.j2objc:j2objc-annotations",
					Version:   "2.8",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.jimfs:jimfs",
					Version:   "1.1",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.testing.platform:core",
					Version:   "0.0.9-alpha02",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.testing.platform:core-proto",
					Version:   "0.0.9-alpha02",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.google.testing.platform:launcher",
					Version:   "0.0.9-alpha02",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.h2database:h2",
					Version:   "2.1.214",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.hankcs:aho-corasick-double-array-trie",
					Version:   "1.2.3",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.jakewharton.android.repackaged:dalvik-dx",
					Version:   "9.0.0_r3",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.samskivert:jmustache",
					Version:   "1.15",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.squareup.curtains:curtains",
					Version:   "1.2.4",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.vaadin.external.google:android-json",
					Version:   "0.0.20131108.vaadin1",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "commons-logging:commons-logging",
					Version:   "1.2",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "commons-logging:commons-logging",
					Version:   "1.3.0",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "commons-validator:commons-validator",
					Version:   "1.7",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "commons-validator:commons-validator",
					Version:   "1.8.0",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "de.mannodermaus.gradle.plugins:android-junit5",
					Version:   "1.10.0.0",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "io.netty:netty-codec-http",
					Version:   "4.1.93.Final",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "io.netty:netty-codec-http2",
					Version:   "4.1.93.Final",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "javax.inject:javax.inject",
					Version:   "1",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.jetbrains.intellij.deps:trove4j",
					Version:   "1.0.20200330",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.sonatype.ossindex:ossindex-service-client",
					Version:   "1.8.2",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.tensorflow:tensorflow-lite-metadata",
					Version:   "0.1.0-rc2",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.tukaani:xz",
					Version:   "1.9",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.whitesource:pecoff4j",
					Version:   "0.0.2.1",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.yaml:snakeyaml",
					Version:   "2.2",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "us.springett:cpe-parser",
					Version:   "2.0.3",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.json:json",
					Version:   "20180813",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.json:json",
					Version:   "20211205",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.json:json",
					Version:   "20220320",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "junit:junit",
					Version:   "4.12",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "junit:junit",
					Version:   "4.13",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "junit:junit",
					Version:   "4.13.1",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "junit:junit",
					Version:   "4.13.2",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.almworks.sqlite4java:sqlite4java",
					Version:   "0.282",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "com.almworks.sqlite4java:sqlite4java",
					Version:   "1.0.392",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.apache:apache",
					Version:   "13",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.apache:apache",
					Version:   "15",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.apache:apache",
					Version:   "16",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.apache:apache",
					Version:   "5",
					Locations: []string{"testdata/complex.xml"},
				},
				{
					Name:      "org.apache:apache",
					Version:   "9",
					Locations: []string{"testdata/complex.xml"},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			extr := gradleverificationmetadataxml.Extractor{}

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
