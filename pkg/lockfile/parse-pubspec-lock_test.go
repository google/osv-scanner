package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParsePubspecLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePubspecLock("fixtures/pub/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePubspecLock_InvalidYaml(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePubspecLock("fixtures/pub/not-yaml.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePubspecLockWithDiagnostics(t *testing.T) {
	t.Parallel()

	testParserWithDiagnostics(t, lockfile.ParsePubspecLockWithDiagnostics, []testParserWithDiagnosticsTest{
		// empty
		{
			name: "",
			file: "fixtures/pub/empty.lock",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{},
		},
		// no packages
		{
			name: "",
			file: "fixtures/pub/no-packages.lock",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{},
		},
		// one package
		{
			name: "",
			file: "fixtures/pub/one-package.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "back_button_interceptor",
					Version:   "6.0.1",
					Ecosystem: lockfile.PubEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// one package, dev
		{
			name: "",
			file: "fixtures/pub/one-package-dev.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "build_runner",
					Version:   "2.2.1",
					Ecosystem: lockfile.PubEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// two packages
		{
			name: "",
			file: "fixtures/pub/two-packages.lock",
			want: []lockfile.PackageDetails{
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
			},
			diag: lockfile.Diagnostics{},
		},
		// mixed packages
		{
			name: "",
			file: "fixtures/pub/mixed-packages.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "back_button_interceptor",
					Version:   "6.0.1",
					Ecosystem: lockfile.PubEcosystem,
				},
				{
					Name:      "build_runner",
					Version:   "2.2.1",
					Ecosystem: lockfile.PubEcosystem,
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
			},
			diag: lockfile.Diagnostics{},
		},
		// package with git source
		{
			name: "",
			file: "fixtures/pub/source-git.lock",
			want: []lockfile.PackageDetails{
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
			},
			diag: lockfile.Diagnostics{},
		},
		// package with sdk source
		{
			name: "",
			file: "fixtures/pub/source-sdk.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "flutter_web_plugins",
					Version:   "0.0.0",
					Ecosystem: lockfile.PubEcosystem,
					Commit:    "",
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// package with path source
		{
			name: "",
			file: "fixtures/pub/source-path.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "maa_core",
					Version:   "0.0.1",
					Ecosystem: lockfile.PubEcosystem,
					Commit:    "",
				},
			},
			diag: lockfile.Diagnostics{},
		},
	})
}
