package lockfile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Old-style (npm < 7 / lockfileVersion 1) dependencies structure
// https://docs.npmjs.com/cli/v6/configuring-npm/package-lock-json
// Installed packages stored in recursive "dependencies" object
// with "requires" field listing direct dependencies, and each possibly having their own "dependencies"
// No dependency information package-lock.json for the root node, so we must also have the package.json
func (rw NpmReadWriter) nodesFromDependencies(lockJSON lockfile.NpmLockfile, manifestFile io.Reader) (*resolve.Graph, *npmNodeModule, error) {
	// Need to grab the root requirements from the package.json, since it's not in the lockfile
	var manifestJSON manifest.PackageJSON
	if err := json.NewDecoder(manifestFile).Decode(&manifestJSON); err != nil {
		return nil, nil, err
	}

	nodeModuleTree := &npmNodeModule{
		Children: make(map[string]*npmNodeModule),
		Deps:     make(map[string]npmDependencyVersionSpec),
	}

	// The order we process dependency types here is to match npm's behavior.
	for name, version := range manifestJSON.PeerDependencies {
		var typ dep.Type
		typ.AddAttr(dep.Scope, "peer")
		// TODO: check peerDependenciesMeta for optional peer dependencies
		nodeModuleTree.Deps[name] = npmDependencyVersionSpec{Version: version, DepType: typ}
	}
	for name, version := range manifestJSON.Dependencies {
		nodeModuleTree.Deps[name] = npmDependencyVersionSpec{Version: version}
	}
	for name, version := range manifestJSON.OptionalDependencies {
		nodeModuleTree.Deps[name] = npmDependencyVersionSpec{Version: version, DepType: dep.NewType(dep.Opt)}
	}
	for name, version := range manifestJSON.DevDependencies {
		nodeModuleTree.Deps[name] = npmDependencyVersionSpec{Version: version, DepType: dep.NewType(dep.Dev)}
	}
	rw.reVersionAliasedDeps(nodeModuleTree.Deps)

	var g resolve.Graph
	nodeModuleTree.NodeID = g.AddNode(resolve.VersionKey{
		PackageKey: resolve.PackageKey{
			System: resolve.NPM,
			Name:   manifestJSON.Name,
		},
		VersionType: resolve.Concrete,
		Version:     manifestJSON.Version,
	})

	err := rw.computeDependenciesRecursive(&g, nodeModuleTree, lockJSON.Dependencies)

	return &g, nodeModuleTree, err
}

func (rw NpmReadWriter) computeDependenciesRecursive(g *resolve.Graph, parent *npmNodeModule, deps map[string]lockfile.NpmLockDependency) error {
	for name, d := range deps {
		actualName, version := manifest.SplitNPMAlias(d.Version)
		nID := g.AddNode(resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				System: resolve.NPM,
				Name:   name,
			},
			VersionType: resolve.Concrete,
			Version:     version,
		})
		nm := &npmNodeModule{
			Parent:     parent,
			NodeID:     nID,
			Children:   make(map[string]*npmNodeModule),
			Deps:       make(map[string]npmDependencyVersionSpec),
			ActualName: actualName,
		}

		// The requires map includes regular dependencies AND optionalDependencies
		// but it does not include peerDependencies or devDependencies.
		// The generated graphs will lack the edges between peers
		for name, version := range d.Requires {
			nm.Deps[name] = npmDependencyVersionSpec{Version: version}
		}
		rw.reVersionAliasedDeps(nm.Deps)

		parent.Children[name] = nm
		if d.Dependencies != nil {
			if err := rw.computeDependenciesRecursive(g, nm, d.Dependencies); err != nil {
				return err
			}
		}
	}

	return nil
}

func (rw NpmReadWriter) modifyPackageLockDependencies(lockJSON string, patches map[string]map[string]string, api *datasource.NpmRegistryAPIClient) (string, error) {
	if !gjson.Get(lockJSON, "dependencies").Exists() {
		return lockJSON, nil
	}

	return rw.modifyPackageLockDependenciesRecurse(lockJSON, "dependencies", 1, patches, api)
}

func (rw NpmReadWriter) modifyPackageLockDependenciesRecurse(lockJSON, path string, depth int, patches map[string]map[string]string, api *datasource.NpmRegistryAPIClient) (string, error) {
	for pkg, data := range gjson.Get(lockJSON, path).Map() {
		pkgPath := fmt.Sprintf("%s.%s", path, gjson.Escape(pkg))
		if data.Get("dependencies").Exists() {
			var err error
			lockJSON, err = rw.modifyPackageLockDependenciesRecurse(lockJSON, pkgPath+".dependencies", depth+1, patches, api)
			if err != nil {
				return lockJSON, err
			}
		}
		isAlias := false
		realPkg, version := manifest.SplitNPMAlias(data.Get("version").String())
		if realPkg != "" {
			isAlias = true
			pkg = realPkg
		}

		if upgrades, ok := patches[pkg]; ok {
			if newVer, ok := upgrades[version]; ok {
				// update dependency in place
				npmData, err := api.FullJSON(context.Background(), pkg, newVer)
				if err != nil {
					return lockJSON, err
				}
				// From what I can tell, the only fields to update are "version" "resolved" "integrity" and "requires"
				newVersion := npmData.Get("version").String()
				if isAlias {
					newVersion = fmt.Sprintf("npm:%s@%s", pkg, newVersion)
				}
				lockJSON, _ = sjson.Set(lockJSON, pkgPath+".version", newVersion)
				lockJSON, _ = sjson.Set(lockJSON, pkgPath+".resolved", npmData.Get("dist.tarball").String())
				lockJSON, _ = sjson.Set(lockJSON, pkgPath+".integrity", npmData.Get("dist.integrity").String())
				// formatting & padding to output for the correct level at this depth
				pretty := fmt.Sprintf("|@pretty:{\"prefix\": %q}", strings.Repeat(" ", 4*depth+2))
				reqs := npmData.Get("dependencies" + pretty)
				if !reqs.Exists() {
					lockJSON, _ = sjson.Delete(lockJSON, pkgPath+".requires")
				} else {
					text := reqs.Raw
					// remove trailing newlines that @pretty creates for objects
					text = strings.TrimSuffix(text, "\n")
					lockJSON, _ = sjson.SetRaw(lockJSON, pkgPath+".requires", text)
				}
			}
		}
	}

	return lockJSON, nil
}
