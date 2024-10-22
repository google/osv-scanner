package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestPubspecLockExtractor_ShouldExtract(t *testing.T) {
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
			path: "pubspec.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/pubspec.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/pubspec.lock/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/pubspec.lock.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.pubspec.lock",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.PubspecLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePubspecLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePubspecLock("fixtures/pub/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePubspecLock_InvalidYaml(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePubspecLock("fixtures/pub/not-yaml.txt")

	expectErrContaining(t, err, "could not extract from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePubspecLock_Empty(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePubspecLock("fixtures/pub/empty.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePubspecLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePubspecLock("fixtures/pub/no-packages.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePubspecLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePubspecLock("fixtures/pub/one-package.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "back_button_interceptor",
			Version:   "6.0.1",
			Ecosystem: lockfile.PubEcosystem,
		},
	})
}

func TestParsePubspecLock_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePubspecLock("fixtures/pub/one-package-dev.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "build_runner",
			Version:   "2.2.1",
			Ecosystem: lockfile.PubEcosystem,
			DepGroups: []string{"dev"},
		},
	})
}

func TestParsePubspecLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePubspecLock("fixtures/pub/two-packages.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "shelf",
			Version:   "1.3.2",
			Ecosystem: lockfile.PubEcosystem,
		},
		{
			Name:      "shelf_web_socket",
			Version:   "1.0.2",
			Ecosystem: lockfile.PubEcosystem,
		},
	})
}

func TestParsePubspecLock_MixedPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePubspecLock("fixtures/pub/mixed-packages.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "back_button_interceptor",
			Version:   "6.0.1",
			Ecosystem: lockfile.PubEcosystem,
		},
		{
			Name:      "build_runner",
			Version:   "2.2.1",
			Ecosystem: lockfile.PubEcosystem,
			DepGroups: []string{"dev"},
		},
		{
			Name:      "shelf",
			Version:   "1.3.2",
			Ecosystem: lockfile.PubEcosystem,
		},
		{
			Name:      "shelf_web_socket",
			Version:   "1.0.2",
			Ecosystem: lockfile.PubEcosystem,
		},
	})
}

func TestParsePubspecLock_PackageWithGitSource(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePubspecLock("fixtures/pub/source-git.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "flutter_rust_bridge",
			Version:   "1.32.0",
			Ecosystem: lockfile.PubEcosystem,
			Commit:    "e5adce55eea0b74d3680e66a2c5252edf17b07e1",
		},
		{
			Name:      "screen_retriever",
			Version:   "0.1.2",
			Ecosystem: lockfile.PubEcosystem,
			Commit:    "406b9b038b2c1d779f1e7bf609c8c248be247372",
		},
		{
			Name:      "tray_manager",
			Version:   "0.1.8",
			Ecosystem: lockfile.PubEcosystem,
			Commit:    "3aa37c86e47ea748e7b5507cbe59f2c54ebdb23a",
		},
		{
			Name:      "window_manager",
			Version:   "0.2.7",
			Ecosystem: lockfile.PubEcosystem,
			Commit:    "88487257cbafc501599ab4f82ec343b46acec020",
		},
		{
			Name:      "toggle_switch",
			Version:   "1.4.0",
			Ecosystem: lockfile.PubEcosystem,
			Commit:    "",
		},
	})
}

func TestParsePubspecLock_PackageWithSdkSource(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePubspecLock("fixtures/pub/source-sdk.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "flutter_web_plugins",
			Version:   "0.0.0",
			Ecosystem: lockfile.PubEcosystem,
			Commit:    "",
		},
	})
}

func TestParsePubspecLock_PackageWithPathSource(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePubspecLock("fixtures/pub/source-path.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "maa_core",
			Version:   "0.0.1",
			Ecosystem: lockfile.PubEcosystem,
			Commit:    "",
		},
	})
}
