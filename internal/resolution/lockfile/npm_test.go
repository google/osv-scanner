package lockfile_test

import (
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/internal/resolution/lockfile"
	lf "github.com/google/osv-scanner/pkg/lockfile"
)

func npmVK(t *testing.T, name, version string) resolve.VersionKey {
	t.Helper()
	return resolve.VersionKey{
		PackageKey: resolve.PackageKey{
			System: resolve.NPM,
			Name:   name,
		},
		Version:     version,
		VersionType: resolve.Concrete,
	}
}

func TestNpmReadV2(t *testing.T) {
	t.Parallel()

	// This lockfile was generated using a private registry with https://verdaccio.org/
	// Mock packages were published to it and installed with npm.
	df, err := lf.OpenLocalDepFile("./fixtures/npm_v2/package-lock.json")
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer df.Close()

	npmIO := lockfile.NpmLockfileIO{}
	got, err := npmIO.Read(df)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	if err := got.Canon(); err != nil {
		t.Fatalf("failed canonicalizing got graph: %v", err)
	}

	want := new(resolve.Graph)
	//nolint:errcheck // AddEdge only errors if the nodes do not exist
	{
		root := want.AddNode(npmVK(t, "r", "1.0.0"))
		workspace := want.AddNode(npmVK(t, "w", "1.0.0"))
		a1 := want.AddNode(npmVK(t, "@fake-registry/a", "1.2.3"))
		a2 := want.AddNode(npmVK(t, "@fake-registry/a", "2.3.4"))
		a2A := want.AddNode(npmVK(t, "@fake-registry/a", "2.3.4"))
		b1 := want.AddNode(npmVK(t, "@fake-registry/b", "1.0.1"))
		b2 := want.AddNode(npmVK(t, "@fake-registry/b", "2.0.0"))
		b2A := want.AddNode(npmVK(t, "@fake-registry/b", "2.0.0"))
		c := want.AddNode(npmVK(t, "@fake-registry/c", "1.1.1"))
		d := want.AddNode(npmVK(t, "@fake-registry/d", "2.2.2"))

		want.AddEdge(root, a1, "^1.2.3", dep.NewType())
		want.AddEdge(root, b1, "^1.0.1", dep.NewType())

		aliasType := dep.NewType(dep.Dev)
		aliasType.AddAttr(dep.KnownAs, "a-dev")
		want.AddEdge(root, a2A, "^2.3.4", aliasType)

		want.AddEdge(root, workspace, "*", dep.NewType())
		want.AddEdge(a1, b1, "^1.0.0", dep.NewType(dep.Opt))
		want.AddEdge(a2A, b2A, "^2.0.0", dep.NewType())
		want.AddEdge(workspace, a2, "^2.3.4", dep.NewType(dep.Dev))
		want.AddEdge(a2, b2, "^2.0.0", dep.NewType())
		want.AddEdge(b2, c, "^1.0.0", dep.NewType())
		want.AddEdge(b2A, c, "^1.0.0", dep.NewType())
		want.AddEdge(b2, d, "^2.0.0", dep.NewType())
		want.AddEdge(b2A, d, "^2.0.0", dep.NewType())
		want.AddEdge(c, d, "^2.0.0", dep.NewType(dep.Opt)) // peerDependency becomes optional
	}

	if err := want.Canon(); err != nil {
		t.Fatalf("failed canonicalizing want graph: %v", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("npm lockfile mismatch (-want/+got):\n%s", diff)
	}
}

func TestNpmReadV1(t *testing.T) {
	t.Parallel()

	// This lockfile was generated using a private registry with https://verdaccio.org/
	// Mock packages were published to it and installed with npm.
	df, err := lf.OpenLocalDepFile("./fixtures/npm_v1/package-lock.json")
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer df.Close()

	npmIO := lockfile.NpmLockfileIO{}
	got, err := npmIO.Read(df)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	if err := got.Canon(); err != nil {
		t.Fatalf("failed canonicalizing got graph: %v", err)
	}

	want := new(resolve.Graph)
	//nolint:errcheck // AddEdge only errors if the nodes do not exist
	{
		root := want.AddNode(npmVK(t, "r", "1.0.0"))
		a1 := want.AddNode(npmVK(t, "@fake-registry/a", "1.2.3"))
		a2 := want.AddNode(npmVK(t, "@fake-registry/a", "2.3.4"))
		b1 := want.AddNode(npmVK(t, "@fake-registry/b", "1.0.1"))
		b2 := want.AddNode(npmVK(t, "@fake-registry/b", "2.0.0"))
		c := want.AddNode(npmVK(t, "@fake-registry/c", "1.1.1"))
		d := want.AddNode(npmVK(t, "@fake-registry/d", "2.2.2"))
		// v1 does not support workspaces

		want.AddEdge(root, a1, "^1.2.3", dep.NewType())
		want.AddEdge(root, b1, "^1.0.1", dep.NewType())

		aliasType := dep.NewType(dep.Dev)
		aliasType.AddAttr(dep.KnownAs, "a-dev")
		want.AddEdge(root, a2, "^2.3.4", aliasType)

		// all indirect dependencies are optional because it's impossible to tell in v1
		optType := dep.NewType(dep.Opt)
		want.AddEdge(a1, b1, "^1.0.0", optType)
		want.AddEdge(a2, b2, "^2.0.0", optType)
		want.AddEdge(b2, c, "^1.0.0", optType)
		want.AddEdge(b2, d, "^2.0.0", optType)
		// peerDependencies are not in v1
	}

	if err := want.Canon(); err != nil {
		t.Fatalf("failed canonicalizing want graph: %v", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("npm lockfile mismatch (-want/+got):\n%s", diff)
	}
}
