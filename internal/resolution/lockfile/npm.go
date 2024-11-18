package lockfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/pkg/lockfile"
)

type NpmReadWriter struct{}

func (NpmReadWriter) System() resolve.System { return resolve.NPM }

type npmDependencyVersionSpec struct {
	Version string
	DepType dep.Type
}

type npmNodeModule struct {
	NodeID     resolve.NodeID
	Parent     *npmNodeModule
	Children   map[string]*npmNodeModule // keyed on package name
	Deps       map[string]npmDependencyVersionSpec
	ActualName string // set if the node is an alias, the real package name this refers to
}

func (n npmNodeModule) IsAliased() bool {
	return len(n.ActualName) > 0
}

func (rw NpmReadWriter) Read(file lockfile.DepFile) (*resolve.Graph, error) {
	dec := json.NewDecoder(file)
	var lockJSON lockfile.NpmLockfile
	if err := dec.Decode(&lockJSON); err != nil {
		return nil, err
	}

	// Build the node_modules directory tree in memory & add unconnected nodes into graph
	var g *resolve.Graph
	var nodeModuleTree *npmNodeModule
	var err error
	switch {
	case lockJSON.Packages != nil:
		g, nodeModuleTree, err = rw.nodesFromPackages(lockJSON)
	case lockJSON.Dependencies != nil:
		manifestFile, ferr := file.Open("package.json")
		if ferr != nil {
			return nil, fmt.Errorf("failed to open package.json (required for parsing lockfileVersion 1): %w", err)
		}
		defer manifestFile.Close()
		g, nodeModuleTree, err = rw.nodesFromDependencies(lockJSON, manifestFile)
	default:
		return nil, errors.New("no dependencies in package-lock.json")
	}
	if err != nil {
		return nil, fmt.Errorf("error when parsing package-lock.json: %w", err)
	}

	// Traverse the graph (somewhat inefficiently) to add edges between nodes
	aliasNodes := make(map[resolve.NodeID]string)
	todo := []*npmNodeModule{nodeModuleTree}
	seen := make(map[*npmNodeModule]struct{})
	seen[nodeModuleTree] = struct{}{}

	for len(todo) > 0 {
		node := todo[0]
		todo = todo[1:]
		if node.IsAliased() {
			// Note which nodes that have to be renamed because of aliasing
			// Don't rename them now because we rely on the names for working out edges
			aliasNodes[node.NodeID] = node.ActualName
		}

		// Add the directory's children to the queue
		for _, child := range node.Children {
			if _, ok := seen[child]; !ok {
				todo = append(todo, child)
				seen[child] = struct{}{}
			}
		}

		// Add edges to the correct dependency nodes
		for depName, depSpec := range node.Deps {
			depNode := rw.findDependencyNode(node, depName)
			if depNode == -1 {
				// The dependency is apparently not in the package-lock.json.
				// This probably means the lockfile is malformed, and npm would usually error installing this.
				// But there are some cases (with workspaces) that npm doesn't error.
				// We just always ignore the error to make it work.
				// TODO: g.AddError(...)
				continue
			}
			if err := g.AddEdge(node.NodeID, depNode, depSpec.Version, depSpec.DepType); err != nil {
				return nil, err
			}
		}
	}

	// Add alias KnownAs attribute and rename them correctly
	for i, e := range g.Edges {
		if _, ok := aliasNodes[e.To]; ok {
			name := g.Nodes[e.To].Version.Name
			g.Edges[i].Type.AddAttr(dep.KnownAs, name)
		}
	}
	for i := range g.Nodes {
		if name, ok := aliasNodes[resolve.NodeID(i)]; ok {
			g.Nodes[i].Version.Name = name
		}
	}

	return g, nil
}

func (rw NpmReadWriter) findDependencyNode(node *npmNodeModule, depName string) resolve.NodeID {
	// Walk up the node_modules to find which node would be used as the requirement
	for node != nil {
		if child, ok := node.Children[depName]; ok {
			return child.NodeID
		}
		node = node.Parent
	}

	return resolve.NodeID(-1)
}

func (rw NpmReadWriter) reVersionAliasedDeps(deps map[string]npmDependencyVersionSpec) {
	// for the dependency maps, change versions from "npm:pkg@version" to "version"
	for k, v := range deps {
		_, v.Version = manifest.SplitNPMAlias(v.Version)
		deps[k] = v
	}
}

func (rw NpmReadWriter) Write(original lockfile.DepFile, output io.Writer, patches []DependencyPatch) error {
	var buf strings.Builder
	_, err := io.Copy(&buf, original)
	if err != nil {
		return err
	}
	lock := buf.String()

	patchMap := make(map[string]map[string]string) // name -> old -> new
	for _, p := range patches {
		if _, ok := patchMap[p.Pkg.Name]; !ok {
			patchMap[p.Pkg.Name] = make(map[string]string)
		}
		patchMap[p.Pkg.Name][p.OrigVersion] = p.NewVersion
	}

	api, err := datasource.NewNpmRegistryAPIClient(filepath.Dir(original.Path()))
	if err != nil {
		return err
	}

	if lock, err = rw.modifyPackageLockPackages(lock, patchMap, api); err != nil {
		return err
	}

	if lock, err = rw.modifyPackageLockDependencies(lock, patchMap, api); err != nil {
		return err
	}

	// Write out modified package-lock.json
	_, err = io.WriteString(output, lock)

	return err
}
