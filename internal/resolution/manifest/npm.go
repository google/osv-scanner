package manifest

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func npmRequirementKey(requirement resolve.RequirementVersion) RequirementKey {
	// Npm requirements are the uniquely identified by the key in the dependencies fields (which ends up being the path in node_modules)
	// Declaring a dependency in multiple places (dependencies, devDependencies, optionalDependencies) only installs it once at one version.
	// Aliases & non-registry dependencies are keyed on their 'KnownAs' attribute.
	knownAs, _ := requirement.Type.GetAttr(dep.KnownAs)
	return RequirementKey{
		PackageKey:        requirement.PackageKey,
		EcosystemSpecific: knownAs,
	}
}

type NpmReadWriter struct{}

func (NpmReadWriter) System() resolve.System { return resolve.NPM }

type PackageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// TODO: yarn allows workspaces to be a object OR a list:
	// https://classic.yarnpkg.com/blog/2018/02/15/nohoist/
	Workspaces           []string          `json:"workspaces"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`

	// These fields are currently only used when parsing package-lock.json
	PeerDependencies map[string]string `json:"peerDependencies"`
	// BundleDependencies   []string          `json:"bundleDependencies"`
}

func (rw NpmReadWriter) Read(f lockfile.DepFile) (Manifest, error) {
	dec := json.NewDecoder(f)
	var packagejson PackageJSON
	if err := dec.Decode(&packagejson); err != nil {
		return Manifest{}, err
	}

	// Create the root node.
	manif := newManifest()
	manif.FilePath = f.Path()
	manif.Root = resolve.Version{
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				Name:   packagejson.Name,
				System: resolve.NPM,
			},
			Version:     packagejson.Version,
			VersionType: resolve.Concrete,
		}}

	// Find all package.json files in the workspaces & parse those too.
	var workspaces []string
	for _, pattern := range packagejson.Workspaces {
		match, err := filepath.Glob(filepath.Join(filepath.Dir(f.Path()), pattern, "package.json"))
		if err != nil {
			return Manifest{}, err
		}
		workspaces = append(workspaces, match...)
	}

	// workspaces seem to be evaluated in sorted path order
	slices.Sort(workspaces)
	workspaceNames := make(map[string]struct{})
	for _, path := range workspaces {
		wsFile, err := f.Open(path)
		if err != nil {
			return Manifest{}, err
		}
		defer wsFile.Close()
		// TODO: Workspaces can't have workspaces of their own.
		// Avoid attempting to resolve them recursively.
		m, err := rw.Read(wsFile)
		if err != nil {
			return Manifest{}, err
		}
		manif.LocalManifests = append(manif.LocalManifests, m)
		workspaceNames[m.Root.Name] = struct{}{}
	}

	isWorkspace := func(req resolve.RequirementVersion) bool {
		if req.Type.HasAttr(dep.KnownAs) {
			// "alias": "npm:pkg@*" seems to always take the real 'pkg',
			// even if there's a workspace with the same name.
			return false
		}
		_, ok := workspaceNames[req.Name]

		return ok
	}

	workspaceReqVers := make(map[resolve.PackageKey]resolve.RequirementVersion)

	// empirically, the dev version takes precedence over optional, which takes precedence over regular, if they conflict.
	for pkg, ver := range packagejson.Dependencies {
		req := rw.makeNPMReqVer(pkg, ver)
		if isWorkspace(req) {
			// workspaces seem to always be evaluated separately
			workspaceReqVers[req.PackageKey] = req
			continue
		}
		manif.Requirements = append(manif.Requirements, req)
	}

	for pkg, ver := range packagejson.OptionalDependencies {
		req := rw.makeNPMReqVer(pkg, ver)
		req.Type.AddAttr(dep.Opt, "")
		if isWorkspace(req) {
			// workspaces seem to always be evaluated separately
			workspaceReqVers[req.PackageKey] = req
			continue
		}
		idx := slices.IndexFunc(manif.Requirements, func(imp resolve.RequirementVersion) bool {
			return imp.PackageKey == req.PackageKey
		})
		if idx != -1 {
			manif.Requirements[idx] = req
		} else {
			manif.Requirements = append(manif.Requirements, req)
		}
		manif.Groups[npmRequirementKey(req)] = []string{"optional"}
	}

	for pkg, ver := range packagejson.DevDependencies {
		req := rw.makeNPMReqVer(pkg, ver)
		if isWorkspace(req) {
			// workspaces seem to always be evaluated separately
			workspaceReqVers[req.PackageKey] = req
			continue
		}
		idx := slices.IndexFunc(manif.Requirements, func(imp resolve.RequirementVersion) bool {
			return imp.PackageKey == req.PackageKey
		})
		if idx != -1 {
			// In newer versions of npm, having a package in both the `dependencies` and `devDependencies`
			// makes it treated as ONLY a devDependency (using the devDependency version)
			// npm v6 and below seems to do the opposite and there's no easy way of seeing the npm version :/
			manif.Requirements[idx] = req
		} else {
			manif.Requirements = append(manif.Requirements, req)
		}
		manif.Groups[npmRequirementKey(req)] = []string{"dev"}
	}

	resolve.SortDependencies(manif.Requirements)

	// resolve workspaces after regular requirements
	for i, m := range manif.LocalManifests {
		imp, ok := workspaceReqVers[m.Root.PackageKey]
		if !ok { // The workspace isn't directly used by the root package, add it as a 'requirement' anyway so it's resolved
			imp = resolve.RequirementVersion{
				Type: dep.NewType(),
				VersionKey: resolve.VersionKey{
					PackageKey:  m.Root.PackageKey,
					Version:     "*", // use the 'any' specifier so we always match the sub-package version
					VersionType: resolve.Requirement,
				},
			}
		}
		// Add an extra identifier to the workspace package names so name collisions don't overwrite indirect dependencies
		imp.Name += ":workspace"
		manif.LocalManifests[i].Root.Name = imp.Name
		manif.Requirements = append(manif.Requirements, imp)
		// replace the workspace's sibling requirements
		for j, req := range m.Requirements {
			if isWorkspace(req) {
				manif.LocalManifests[i].Requirements[j].Name = req.Name + ":workspace"
				reqKey := npmRequirementKey(req)
				if g, ok := m.Groups[reqKey]; ok {
					newKey := npmRequirementKey(manif.LocalManifests[i].Requirements[j])
					manif.LocalManifests[i].Groups[newKey] = g
					delete(manif.LocalManifests[i].Groups, reqKey)
				}
			}
		}
	}

	return manif, nil
}

func (rw NpmReadWriter) makeNPMReqVer(pkg, ver string) resolve.RequirementVersion {
	// TODO: URLs, Git, GitHub, `file:`
	typ := dep.NewType() // don't use dep.NewType(dep.Dev) for devDeps to force the resolver to resolve them
	realPkg, realVer := SplitNPMAlias(ver)
	if realPkg != "" {
		// This dependency is aliased, add it as a
		// dependency on the actual name, with the
		// KnownAs attribute set to the alias.
		typ.AddAttr(dep.KnownAs, pkg)
		pkg = realPkg
		ver = realVer
	}
	if strings.Contains(ver, ":") {
		// TODO: Also check for GitHub URLs - https://docs.npmjs.com/cli/v10/configuring-npm/package-json#github-urls
		// Unhandled version prefix
		// e.g. `git+https://...`, `file:...`
		// TODO: Do a proper match for possibilities:
		// https://docs.npmjs.com/cli/v10/configuring-npm/package-json#urls-as-dependencies
		// TODO: resolve the package.json from the file/repo into a local Manifest (and uniquely refer to it somehow)

		// For now we want to avoid fatal resolution errors.
		// The resolver fatally errors if the package is not found, but not if the version is not found.
		// As a hack, assign the name as an alias of a real package, but keep the version invalid/non-existent.
		typ.AddAttr(dep.KnownAs, pkg)
		pkg = "-" // This is a real npm package!
		// TODO: don't add this to the manifest, return some non-fatal errors to surface instead of relying on resolution errors
	}

	return resolve.RequirementVersion{
		Type: typ,
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				Name:   pkg,
				System: resolve.NPM,
			},
			Version:     ver,
			VersionType: resolve.Requirement,
		},
	}
}

func (NpmReadWriter) Write(r lockfile.DepFile, w io.Writer, patch Patch) error {
	// Read the whole package.json into a string so we can use sjson to write in-place.
	var buf strings.Builder
	_, err := io.Copy(&buf, r)
	if err != nil {
		return err
	}
	manif := buf.String()

	for _, changedDep := range patch.Deps {
		name := changedDep.Pkg.Name
		origVer := changedDep.OrigRequire
		newVer := changedDep.NewRequire
		if knownAs, ok := changedDep.Type.GetAttr(dep.KnownAs); ok {
			// reconstruct alias versioning
			origVer = fmt.Sprintf("npm:%s@%s", name, origVer)
			newVer = fmt.Sprintf("npm:%s@%s", name, newVer)
			name = knownAs
		}
		// Don't know what kind of dependency this is, so check them all.
		// Check them in dev -> optional -> prod because that's the order npm seems to use when they conflict.
		// Check devDependency first because npm>=7 uses only the devDependency if it exists in both.
		alreadyMatched := false
		depStr := "devDependencies." + name
		if res := gjson.Get(manif, depStr); res.Exists() {
			if res.Str != origVer {
				panic("original dependency version does not match what is in package.json")
			}
			alreadyMatched = true
			manif, err = sjson.Set(manif, depStr, newVer)
			if err != nil {
				return err
			}
		}

		depStr = "optionalDependencies." + name
		if res := gjson.Get(manif, depStr); res.Exists() {
			if res.Str != origVer {
				if alreadyMatched {
					continue
				}
				panic("original dependency version does not match what is in package.json")
			}
			alreadyMatched = true
			manif, err = sjson.Set(manif, depStr, newVer)
			if err != nil {
				return err
			}
		}

		depStr = "dependencies." + name
		if res := gjson.Get(manif, depStr); res.Exists() {
			if res.Str != origVer {
				if alreadyMatched {
					continue
				}
				panic("original dependency version does not match what is in package.json")
			}
			manif, err = sjson.Set(manif, depStr, newVer)
			if err != nil {
				return err
			}
		}
	}

	// Write out modified package.json
	_, err = io.WriteString(w, manif)

	return err
}

// extract the real package name & version from an alias-specified version
// e.g. "npm:pkg@^1.2.3" -> name: "pkg", version: "^1.2.3"
// name is empty and version is unchanged if not an alias specifier
func SplitNPMAlias(v string) (name, version string) {
	if r, ok := strings.CutPrefix(v, "npm:"); ok {
		if i := strings.LastIndex(r, "@"); i > 0 {
			return r[:i], r[i+1:]
		}

		return r, "" // alias with no version specified
	}

	return "", v // not an alias
}
