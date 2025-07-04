package client

import (
	"encoding/gob"
	"os"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/v2/internal/datasource"
)

const depsDevCacheExt = ".resolve.deps"

// DepsDevClient is a ResolutionClient wrapping the official resolve.APIClient
type DepsDevClient struct {
	resolve.APIClient

	c *datasource.CachedInsightsClient
}

func NewDepsDevClient(addr string, userAgent string) (*DepsDevClient, error) {
	c, err := datasource.NewCachedInsightsClient(addr, userAgent)
	if err != nil {
		return nil, err
	}

	return &DepsDevClient{APIClient: *resolve.NewAPIClient(c), c: c}, nil
}

func (d *DepsDevClient) AddRegistries(_ []Registry) error { return nil }

func (d *DepsDevClient) WriteCache(path string) error {
	f, err := os.Create(path + depsDevCacheExt)
	if err != nil {
		return err
	}
	defer f.Close()

	return gob.NewEncoder(f).Encode(d.c)
}

func (d *DepsDevClient) LoadCache(path string) error {
	f, err := os.Open(path + depsDevCacheExt)
	if err != nil {
		return err
	}
	defer f.Close()

	return gob.NewDecoder(f).Decode(&d.c)
}
