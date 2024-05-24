package manifest

import (
	"context"
	"encoding/xml"
	"fmt"
	"path/filepath"

	depsdevpb "deps.dev/api/v3"
	"deps.dev/util/maven"
	"deps.dev/util/semver"
	"github.com/google/osv-scanner/pkg/lockfile"
	"golang.org/x/exp/maps"
)

type MavenResolverExtractor struct {
	Client depsdevpb.InsightsClient
}

func (e MavenResolverExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "pom.xml"
}

func (e MavenResolverExtractor) Extract(f lockfile.DepFile) ([]lockfile.PackageDetails, error) {
	ctx := context.Background()

	var project maven.Project
	if err := xml.NewDecoder(f).Decode(&project); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}
	if err := project.Interpolate(); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not interpolate Maven project %s: %w", project.ProjectKey.Name(), err)
	}

	details := map[string]lockfile.PackageDetails{}

	for _, dep := range project.Dependencies {
		name := dep.Name()
		v, err := e.resolveVersion(ctx, dep)
		if err != nil {
			return []lockfile.PackageDetails{}, err
		}
		pkgDetails := lockfile.PackageDetails{
			Name:      name,
			Version:   v,
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		}
		if dep.Scope != "" {
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, string(dep.Scope))
		}
		// A dependency may be declared more than one times, we keep the details
		// from the last declared one as what `mvn` does.
		details[name] = pkgDetails
	}

	// managed dependencies take precedent over standard dependencies
	for _, dep := range project.DependencyManagement.Dependencies {
		name := dep.Name()
		v, err := e.resolveVersion(ctx, dep)
		if err != nil {
			return []lockfile.PackageDetails{}, err
		}
		pkgDetails := lockfile.PackageDetails{
			Name:      name,
			Version:   v,
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		}
		if dep.Scope != "" {
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, string(dep.Scope))
		}
		// A dependency may be declared more than one times, we keep the details
		// from the last declared one as what `mvn` does.
		details[name] = pkgDetails
	}

	return maps.Values(details), nil
}

func (e MavenResolverExtractor) resolveVersion(ctx context.Context, dep maven.Dependency) (string, error) {
	constraint, err := semver.Maven.ParseConstraint(string(dep.Version))
	if err != nil {
		return "", fmt.Errorf("failed parsing Maven constraint %s: %w", dep.Version, err)
	}
	if constraint.IsSimple() {
		// Return the constraint if it is a simple version string.
		return constraint.String(), nil
	}

	// Otherwise return the greatest version matching the constraint.
	// TODO: invoke Maven resolver to decide the exact version.
	resp, err := e.Client.GetPackage(ctx, &depsdevpb.GetPackageRequest{
		PackageKey: &depsdevpb.PackageKey{
			System: depsdevpb.System_MAVEN,
			Name:   dep.Name(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("requesting versions of Maven package %s: %w", dep.Name(), err)
	}

	var result *semver.Version
	for _, ver := range resp.GetVersions() {
		v, _ := semver.Maven.Parse(ver.GetVersionKey().GetVersion())
		if constraint.MatchVersion(v) && result.Compare(v) < 0 {
			result = v
		}
	}

	return result.String(), nil
}

func ParseMavenWithResolver(depsdev depsdevpb.InsightsClient, pathToLockfile string) ([]lockfile.PackageDetails, error) {
	f, err := lockfile.OpenLocalDepFile(pathToLockfile)
	if err != nil {
		return []lockfile.PackageDetails{}, err
	}
	defer f.Close()

	return MavenResolverExtractor{Client: depsdev}.Extract(f)
}
