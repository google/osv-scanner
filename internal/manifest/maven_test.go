package manifest_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/internal/manifest"
	"github.com/google/osv-scanner/internal/resolution/clienttest"
	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestMavenResolverExtractor_ShouldExtract(t *testing.T) {
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
			path: "pom.xml",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/pom.xml",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/pom.xml/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/pom.xml.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.pom.xml",
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := manifest.MavenResolverExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseMavenWithResolver_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := manifest.ParseMavenWithResolver(nil, "fixtures/maven/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenWithResolver_Invalid(t *testing.T) {
	t.Parallel()

	packages, err := manifest.ParseMavenWithResolver(nil, "fixtures/maven/not-pom.txt")

	expectErrContaining(t, err, "could not extract from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenWithResolver_InvalidSyntax(t *testing.T) {
	t.Parallel()

	packages, err := manifest.ParseMavenWithResolver(nil, "fixtures/maven/invalid-syntax.xml")

	expectErrContaining(t, err, "XML syntax error")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenWithResolver_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := manifest.ParseMavenWithResolver(nil, "fixtures/maven/empty.xml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenWithResolver_OnePackage(t *testing.T) {
	t.Parallel()

	resolutionClient := clienttest.NewMockResolutionClient(t, "fixtures/universe/basic-universe.yaml")
	packages, err := manifest.ParseMavenWithResolver(resolutionClient, "fixtures/maven/one-package.xml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "org.apache.maven:maven-artifact",
			Version:   "1.0.0",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
	})
}

func TestParseMavenWithResolver_TwoPackages(t *testing.T) {
	t.Parallel()

	resolutionClient := clienttest.NewMockResolutionClient(t, "fixtures/universe/basic-universe.yaml")
	packages, err := manifest.ParseMavenWithResolver(resolutionClient, "fixtures/maven/two-packages.xml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "io.netty:netty-all",
			Version:   "4.1.42.Final",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
		{
			Name:      "org.slf4j:slf4j-log4j12",
			Version:   "1.7.25",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
	})
}

func TestParseMavenWithResolver_WithDependencyManagement(t *testing.T) {
	t.Parallel()

	resolutionClient := clienttest.NewMockResolutionClient(t, "fixtures/universe/basic-universe.yaml")
	packages, err := manifest.ParseMavenWithResolver(resolutionClient, "fixtures/maven/with-dependency-management.xml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "io.netty:netty-all",
			Version:   "4.1.9",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
		{
			Name:      "org.slf4j:slf4j-log4j12",
			Version:   "1.7.25",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
	})
}

func TestParseMavenWithResolver_Interpolation(t *testing.T) {
	t.Parallel()

	resolutionClient := clienttest.NewMockResolutionClient(t, "fixtures/universe/basic-universe.yaml")
	packages, err := manifest.ParseMavenWithResolver(resolutionClient, "fixtures/maven/interpolation.xml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "org.mine:mypackage",
			Version:   "1.0.0",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
		{
			Name:      "org.mine:my.package",
			Version:   "2.3.4",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
		{
			Name:      "org.mine:ranged-package",
			Version:   "9.4.37",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
	})
}

func TestParseMavenWithResolver_WithScope(t *testing.T) {
	t.Parallel()

	resolutionClient := clienttest.NewMockResolutionClient(t, "fixtures/universe/basic-universe.yaml")
	packages, err := manifest.ParseMavenWithResolver(resolutionClient, "fixtures/maven/with-scope.xml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "junit:junit",
			Version:   "4.12",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
			DepGroups: []string{"runtime"},
		},
	})
}

func TestParseMavenWithResolver_Transitive(t *testing.T) {
	t.Parallel()

	resolutionClient := clienttest.NewMockResolutionClient(t, "fixtures/universe/basic-universe.yaml")
	packages, err := manifest.ParseMavenWithResolver(resolutionClient, "fixtures/maven/transitive.xml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "org.direct:alice",
			Version:   "1.0.0",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
		{
			Name:      "org.direct:bob",
			Version:   "2.0.0",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
		{
			Name:      "org.transitive:chuck",
			Version:   "1.1.1",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
		{
			Name:      "org.transitive:dave",
			Version:   "2.2.2",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
		{
			Name:      "org.transitive:eve",
			Version:   "3.3.3",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
	})
}
