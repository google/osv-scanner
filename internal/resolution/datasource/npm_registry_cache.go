package datasource

import (
	"strings"
	"time"

	"golang.org/x/exp/maps"
)

type npmRegistryCache struct {
	Timestamp *time.Time                           // Timestamp of when this cache was made
	Details   map[string]npmRegistryPackageDetails // For a package name, the versions & their dependencies, and the list of tags
	ScopeURLs map[string]string                    // The URL of the registry used for a given package @scope. Used to invalidate cache if registry has changed.
}

func (c *NpmRegistryAPIClient) GobEncode() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cacheTimestamp == nil {
		now := time.Now().UTC()
		c.cacheTimestamp = &now
	}

	cache := npmRegistryCache{
		Timestamp: c.cacheTimestamp,
		Details:   c.details,
		ScopeURLs: make(map[string]string),
	}

	// store the registry URL for each scope (but not the auth info)
	cache.ScopeURLs = c.registries.ScopeURLs

	return gobMarshal(&cache)
}

func (c *NpmRegistryAPIClient) GobDecode(b []byte) error {
	// decode the cached data
	var cache npmRegistryCache
	if err := gobUnmarshal(b, &cache); err != nil {
		return err
	}

	if cache.Timestamp != nil && time.Since(*cache.Timestamp) >= cacheExpiry {
		// Cache expired
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// remove any cache entries whose registry has changed
	maps.DeleteFunc(cache.Details, func(pkg string, _ npmRegistryPackageDetails) bool {
		scope := ""
		if strings.HasPrefix(pkg, "@") {
			scope, _, _ = strings.Cut(pkg, "/")
		}

		return cache.ScopeURLs[scope] != c.registries.ScopeURLs[scope]
	})

	c.cacheTimestamp = cache.Timestamp
	c.details = cache.Details

	return nil
}
