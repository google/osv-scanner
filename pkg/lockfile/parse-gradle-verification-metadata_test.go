package lockfile_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/stretchr/testify/assert"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestGradleVerificationMetadataExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "",
			path: "",
			want: false,
		},
		{
			name: "",
			path: "verification-metadata.xml",
			want: false,
		},
		{
			name: "",
			path: "gradle/verification-metadata.xml",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/verification-metadata.xml",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/verification-metadata.xml/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/verification-metadata.xml.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.verification-metadata.xml",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/gradle/verification-metadata.xml",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/gradle/verification-metadata.xml/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/gradle/verification-metadata.xml.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.gradle.verification-metadata.xml",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.GradleVerificationMetadataExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseGradleVerificationMetadata_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleVerificationMetadata("fixtures/gradle-verification-metadata/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGradleVerificationMetadata_InvalidXml(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleVerificationMetadata("fixtures/gradle-verification-metadata/not-xml.txt")

	expectErrContaining(t, err, "could not extract from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGradleVerificationMetadata_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleVerificationMetadata("fixtures/gradle-verification-metadata/empty.xml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGradleVerificationMetadata_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleVerificationMetadata("fixtures/gradle-verification-metadata/one-package.xml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.apache.pdfbox:pdfbox",
			Version:        "2.0.17",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
	})
}

//nolint:paralleltest
func TestParseGradleVerificationMetadata_OnePackage_MatcherFailed(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	stderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	os.Stderr = w

	// Mock buildGradleMatcher to fail
	matcherError := errors.New("buildGradleMatcher failed")
	lockfile.GradleVerificationExtractor.Matchers = []lockfile.Matcher{FailingMatcher{Error: matcherError}}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/gradle-verification-metadata/one-package.xml"))
	packages, err := lockfile.ParseGradleVerificationMetadata(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Capture stderr
	_ = w.Close()
	os.Stderr = stderr
	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, r)
	if err != nil {
		t.Errorf("failed to copy stderr output: %v", err)
	}
	_ = r.Close()

	assert.Contains(t, buffer.String(), matcherError.Error())
	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.apache.pdfbox:pdfbox",
			Version:        "2.0.17",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
	})

	// Reset buildGradleMatcher mock
	MockAllMatchers()
}

func TestParseGradleVerificationMetadata_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleVerificationMetadata("fixtures/gradle-verification-metadata/two-packages.xml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.apache.pdfbox:pdfbox",
			Version:        "2.0.17",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.github.javaparser:javaparser-core",
			Version:        "3.6.11",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
	})
}

func TestParseGradleVerificationMetadata_MultipleVersions(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleVerificationMetadata("fixtures/gradle-verification-metadata/multiple-versions.xml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "androidx.activity:activity",
			Version:        "1.2.1",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "androidx.activity:activity",
			Version:        "1.2.3",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "androidx.activity:activity",
			Version:        "1.5.1",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "androidx.activity:activity",
			Version:        "1.6.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "androidx.activity:activity",
			Version:        "1.7.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "androidx.activity:activity",
			Version:        "1.7.2",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "androidx.activity:activity-compose",
			Version:        "1.5.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "androidx.activity:activity-compose",
			Version:        "1.7.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "androidx.activity:activity-compose",
			Version:        "1.7.2",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "androidx.activity:activity-ktx",
			Version:        "1.5.1",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "androidx.activity:activity-ktx",
			Version:        "1.7.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "androidx.activity:activity-ktx",
			Version:        "1.7.2",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "io.ktor:ktor-serialization-jvm",
			Version:        "2.0.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "io.ktor:ktor-serialization-jvm",
			Version:        "2.0.0-beta-1",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "io.ktor:ktor-serialization-jvm",
			Version:        "2.0.3",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.auto.service:auto-service",
			Version:        "1.0-rc4",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.auto.service:auto-service",
			Version:        "1.0.1",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.auto.service:auto-service",
			Version:        "1.1.1",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
	})
}

func TestParseGradleVerificationMetadata_Complex(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleVerificationMetadata("fixtures/gradle-verification-metadata/complex.xml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.google:google",
			Version:        "1",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.errorprone:javac",
			Version:        "9+181-r4173-1",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.android.tools:sdklib",
			Version:        "31.3.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.android.tools.build:aapt2",
			Version:        "8.3.0-10880808",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.android.tools.build:aapt2-proto",
			Version:        "8.3.0-10880808",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.android.tools.build:transform-api",
			Version:        "2.0.0-deprecated-use-gradle-api",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.android.tools.build.jetifier:jetifier-core",
			Version:        "1.0.0-beta10",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.android.tools.build.jetifier:jetifier-processor",
			Version:        "1.0.0-beta10",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.android.tools.emulator:proto",
			Version:        "31.3.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.android.tools.external.com-intellij:intellij-core",
			Version:        "31.3.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.android.tools.external.com-intellij:kotlin-compiler",
			Version:        "31.3.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.android.tools.external.org-jetbrains:uast",
			Version:        "31.3.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.facebook:ktfmt",
			Version:        "0.47",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.github.ben-manes:gradle-versions-plugin",
			Version:        "0.51.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.github.spullara.mustache.java:compiler",
			Version:        "0.9.6",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.android:annotations",
			Version:        "4.1.1.4",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.apis:google-api-services-androidpublisher",
			Version:        "v3-rev20231115-2.0.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.devtools.ksp:symbol-processing",
			Version:        "1.9.22-1.0.17",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.devtools.ksp:symbol-processing-api",
			Version:        "1.9.22-1.0.17",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.devtools.ksp:symbol-processing-gradle-plugin",
			Version:        "1.9.22-1.0.17",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.googlejavaformat:google-java-format",
			Version:        "1.8",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.guava:guava",
			Version:        "32.0.0-jre",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.guava:guava",
			Version:        "32.0.1-jre",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.guava:guava",
			Version:        "32.1.3-jre",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.guava:listenablefuture",
			Version:        "1.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.guava:listenablefuture",
			Version:        "9999.0-empty-to-avoid-conflict-with-guava",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.j2objc:j2objc-annotations",
			Version:        "2.8",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.jimfs:jimfs",
			Version:        "1.1",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.testing.platform:core",
			Version:        "0.0.9-alpha02",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.testing.platform:core-proto",
			Version:        "0.0.9-alpha02",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.google.testing.platform:launcher",
			Version:        "0.0.9-alpha02",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.h2database:h2",
			Version:        "2.1.214",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.hankcs:aho-corasick-double-array-trie",
			Version:        "1.2.3",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.jakewharton.android.repackaged:dalvik-dx",
			Version:        "9.0.0_r3",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.samskivert:jmustache",
			Version:        "1.15",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.squareup.curtains:curtains",
			Version:        "1.2.4",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.vaadin.external.google:android-json",
			Version:        "0.0.20131108.vaadin1",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "commons-logging:commons-logging",
			Version:        "1.2",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "commons-logging:commons-logging",
			Version:        "1.3.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "commons-validator:commons-validator",
			Version:        "1.7",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "commons-validator:commons-validator",
			Version:        "1.8.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "de.mannodermaus.gradle.plugins:android-junit5",
			Version:        "1.10.0.0",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "io.netty:netty-codec-http",
			Version:        "4.1.93.Final",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "io.netty:netty-codec-http2",
			Version:        "4.1.93.Final",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "javax.inject:javax.inject",
			Version:        "1",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.jetbrains.intellij.deps:trove4j",
			Version:        "1.0.20200330",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.sonatype.ossindex:ossindex-service-client",
			Version:        "1.8.2",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.tensorflow:tensorflow-lite-metadata",
			Version:        "0.1.0-rc2",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.tukaani:xz",
			Version:        "1.9",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.whitesource:pecoff4j",
			Version:        "0.0.2.1",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.yaml:snakeyaml",
			Version:        "2.2",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "us.springett:cpe-parser",
			Version:        "2.0.3",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.json:json",
			Version:        "20180813",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.json:json",
			Version:        "20211205",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.json:json",
			Version:        "20220320",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "junit:junit",
			Version:        "4.12",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "junit:junit",
			Version:        "4.13",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "junit:junit",
			Version:        "4.13.1",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "junit:junit",
			Version:        "4.13.2",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.almworks.sqlite4java:sqlite4java",
			Version:        "0.282",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "com.almworks.sqlite4java:sqlite4java",
			Version:        "1.0.392",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.apache:apache",
			Version:        "13",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.apache:apache",
			Version:        "15",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.apache:apache",
			Version:        "16",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.apache:apache",
			Version:        "5",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.apache:apache",
			Version:        "9",
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
	})
}
