package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParseYarnLock_v1_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/does-not-exist")

	expectErrContaining(t, err, "could not open")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseYarnLock_v1_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/empty.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseYarnLock_v1_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/one-package.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "balanced-match",
			Version:   "1.0.2",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/two-packages.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "concat-stream",
			Version:   "1.6.2",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "concat-map",
			Version:   "0.0.1",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_MultipleVersions(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/multiple-versions.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "define-properties",
			Version:   "1.1.3",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "define-property",
			Version:   "0.2.5",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "define-property",
			Version:   "1.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "define-property",
			Version:   "2.0.2",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_MultipleConstraints(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/multiple-constraints.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@babel/code-frame",
			Version:   "7.12.13",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "domelementtype",
			Version:   "1.3.1",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_ScopedPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/scoped-packages.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@babel/code-frame",
			Version:   "7.12.11",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "@babel/compat-data",
			Version:   "7.14.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_VersionsWithBuildString(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/versions-with-build-strings.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "css-tree",
			Version:   "1.0.0-alpha.37",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "gensync",
			Version:   "1.0.0-beta.2",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "node-fetch",
			Version:   "3.0.0-beta.9",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "resolve",
			Version:   "1.20.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "resolve",
			Version:   "2.0.0-next.3",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_Commits(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/commits.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "mine1",
			Version:   "1.0.0-alpha.37",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "0a2d2506c1fe299691fc5db53a2097db3bd615bc",
		},
		{
			Name:      "mine2",
			Version:   "0.0.1",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "0a2d2506c1fe299691fc5db53a2097db3bd615bc",
		},
		{
			Name:      "mine3",
			Version:   "1.2.3",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "094e581aaf927d010e4b61d706ba584551dac502",
		},
		{
			Name:      "mine4",
			Version:   "0.0.2",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "aa3bdfcb1d845c79f14abb66f60d35b8a3ee5998",
		},
		{
			Name:      "mine4",
			Version:   "0.0.4",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "aa3bdfcb1d845c79f14abb66f60d35b8a3ee5998",
		},
		{
			Name:      "my-package",
			Version:   "1.8.3",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "b3bd3f1b3dad036e671251f5258beaae398f983a",
		},
		{
			Name:      "@bower_components/angular-animate",
			Version:   "1.4.14",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "e7f778fc054a086ba3326d898a00fa1bc78650a8",
		},
		{
			Name:      "@bower_components/alertify",
			Version:   "0.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "e7b6c46d76604d297c389d830817b611c9a8f17c",
		},
		{
			Name:      "minimist",
			Version:   "0.0.8",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "3754568bfd43a841d2d72d7fb54598635aea8fa4",
		},
		{
			Name:      "bats-assert",
			Version:   "2.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "4bdd58d3fbcdce3209033d44d884e87add1d8405",
		},
		{
			Name:      "bats-support",
			Version:   "0.3.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "d140a65044b2d6810381935ae7f0c94c7023c8c3",
		},
		{
			Name:      "bats",
			Version:   "1.5.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "172580d2ce19ee33780b5f1df817bbddced43789",
		},
		{
			Name:      "vue",
			Version:   "2.6.12",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "bb253db0b3e17124b6d1fe93fbf2db35470a1347",
		},
		{
			Name:      "kit",
			Version:   "1.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "5b6830c0252eb73c6024d40a8ff5106d3023a2a6",
		},
		{
			Name:      "casadistance",
			Version:   "1.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "f0308391f0c50104182bfb2332a53e4e523a4603",
		},
		{
			Name:      "babel-preset-php",
			Version:   "1.1.1",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
		},
		{
			Name:      "is-number",
			Version:   "2.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
		},
		{
			Name:      "is-number",
			Version:   "5.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
		},
	})
}

func TestParseYarnLock_v1_Files(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/files.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "etag",
			Version:   "1.8.1",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "",
		},
		{
			Name:      "filedep",
			Version:   "1.2.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "",
		},
		{
			Name:      "lodash",
			Version:   "1.3.1",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "",
		},
		{
			Name:      "other_package",
			Version:   "0.0.2",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "",
		},
		{
			Name:      "sprintf-js",
			Version:   "0.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "",
		},
		{
			Name:      "etag",
			Version:   "1.8.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "",
		},
	})
}
