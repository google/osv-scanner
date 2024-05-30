package datasource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/tidwall/gjson"
	"golang.org/x/exp/maps"
)

type NpmRegistryAPIClient struct {
	// Registries from the npmrc config
	// This should only be written to when the client is first being created.
	// Other functions should not modify it & it is not covered by the mutex.
	registries NpmRegistryConfig

	// cache fields
	mu             sync.Mutex
	cacheTimestamp *time.Time // If set, this means we loaded from a cache
	details        map[string]npmRegistryPackageDetails
}

type npmRegistryPackageDetails struct {
	// Only cache the info needed for the DependencyClient
	Versions map[string]npmRegistryDependencies
	Tags     map[string]string
}

func NewNpmRegistryAPIClient(workdir string) (*NpmRegistryAPIClient, error) {
	registries, err := LoadNpmRegistryConfig(workdir)
	if err != nil {
		return nil, err
	}

	return &NpmRegistryAPIClient{
		registries: registries,
		details:    make(map[string]npmRegistryPackageDetails),
	}, nil
}

type npmRegistryVersions struct {
	Versions []string
	Tags     map[string]string
}

func (c *NpmRegistryAPIClient) Versions(ctx context.Context, pkg string) (npmRegistryVersions, error) {
	pkgDetails, err := c.getPackageDetails(ctx, pkg)
	if err != nil {
		return npmRegistryVersions{}, err
	}

	return npmRegistryVersions{
		Versions: maps.Keys(pkgDetails.Versions),
		Tags:     pkgDetails.Tags,
	}, nil
}

type npmRegistryDependencies struct {
	// TODO: These maps should preserve ordering from JSON response
	Dependencies         map[string]string
	DevDependencies      map[string]string
	PeerDependencies     map[string]string
	OptionalDependencies map[string]string
	BundleDependencies   []string
}

func (c *NpmRegistryAPIClient) Dependencies(ctx context.Context, pkg, version string) (npmRegistryDependencies, error) {
	pkgDetails, err := c.getPackageDetails(ctx, pkg)
	if err != nil {
		return npmRegistryDependencies{}, err
	}

	if deps, ok := pkgDetails.Versions[version]; ok {
		return deps, nil
	}

	return npmRegistryDependencies{}, fmt.Errorf("no version %s for package %s", version, pkg)
}

func (c *NpmRegistryAPIClient) FullJSON(ctx context.Context, pkg, version string) (gjson.Result, error) {
	return c.get(ctx, pkg, version)
}

func (c *NpmRegistryAPIClient) get(ctx context.Context, urlComponents ...string) (gjson.Result, error) {
	req, err := c.registries.BuildRequest(ctx, urlComponents...)
	if err != nil {
		return gjson.Result{}, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return gjson.Result{}, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return gjson.Result{}, errors.New(resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return gjson.Result{}, err
	}

	res := gjson.ParseBytes(body)

	return res, nil
}

func (c *NpmRegistryAPIClient) getPackageDetails(ctx context.Context, pkg string) (npmRegistryPackageDetails, error) {
	c.mu.Lock()
	pkgData, ok := c.details[pkg]
	c.mu.Unlock()
	if ok {
		return pkgData, nil
	}

	// Not cached, make the network request
	jsonData, err := c.get(ctx, pkg)
	if err != nil {
		return npmRegistryPackageDetails{}, err
	}

	versions := make(map[string]npmRegistryDependencies)
	for v, data := range jsonData.Get("versions").Map() {
		versions[v] = npmRegistryDependencies{
			Dependencies:         jsonToStringMap(data.Get("dependencies")),
			DevDependencies:      jsonToStringMap(data.Get("devDependencies")),
			PeerDependencies:     jsonToStringMap(data.Get("peerDependencies")),
			OptionalDependencies: jsonToStringMap(data.Get("optionalDependencies")),
			BundleDependencies:   jsonToStringSlice(data.Get("bundleDependencies")),
		}
	}
	pkgData = npmRegistryPackageDetails{
		Versions: versions,
		Tags:     jsonToStringMap(jsonData.Get("dist-tags")),
	}

	c.mu.Lock()
	c.details[pkg] = pkgData
	c.mu.Unlock()

	return pkgData, nil
}

func jsonToStringSlice(v gjson.Result) []string {
	arr := v.Array()
	if len(arr) == 0 {
		return nil
	}
	strs := make([]string, len(arr))
	for i, s := range arr {
		strs[i] = s.String()
	}

	return strs
}

func jsonToStringMap(v gjson.Result) map[string]string {
	mp := v.Map()
	if len(mp) == 0 {
		return nil
	}
	strs := make(map[string]string)
	for k, s := range mp {
		strs[k] = s.String()
	}

	return strs
}
