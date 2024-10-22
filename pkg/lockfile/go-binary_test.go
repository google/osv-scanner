package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestGoBinaryExtractor_ShouldExtract(t *testing.T) {
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
			path: testutility.ValueIfOnWindows("path\\to\\dir\\", "path/to/dir/"),
			want: false,
		},
		{
			name: "",
			path: "binary.json",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/binary.json",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/binary-lock.json/file",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/binary",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/binary.exe",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/.hidden-binary",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/binary.exe.1",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.GoBinaryExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract(%v) got = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractGoBinary_NoPackages(t *testing.T) {
	t.Parallel()

	file, err := lockfile.OpenLocalDepFile("fixtures/go/binaries/just-go")
	if err != nil {
		t.Fatalf("could not open file %v", err)
	}

	packages, err := lockfile.GoBinaryExtractor{}.Extract(file)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "stdlib",
			Version:   "1.21.10",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
		},
	})
}

func TestExtractGoBinary_OnePackage(t *testing.T) {
	t.Parallel()

	file, err := lockfile.OpenLocalDepFile("fixtures/go/binaries/has-one-dep")
	if err != nil {
		t.Fatalf("could not open file %v", err)
	}

	packages, err := lockfile.GoBinaryExtractor{}.Extract(file)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "stdlib",
			Version:   "1.21.10",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
		},
		{
			Name:      "github.com/BurntSushi/toml",
			Version:   "1.4.0",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
		},
	})
}

func TestExtractGoBinary_NotAGoBinary(t *testing.T) {
	t.Parallel()

	file, err := lockfile.OpenLocalDepFile("fixtures/go/one-package.mod")
	if err != nil {
		t.Fatalf("could not open file %v", err)
	}

	packages, err := lockfile.GoBinaryExtractor{}.Extract(file)
	if err == nil {
		t.Errorf("did not get expected error when extracting")
	}

	if len(packages) != 0 {
		t.Errorf("packages not empty")
	}
}
