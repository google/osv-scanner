package datasource

import (
	"strings"
	"time"

	"golang.org/x/exp/maps"
)

type npmRegistryCache struct {
	Timestamp    *time.Time
	Details      map[string]npmRegistryPackageDetails
	RegistryURLs map[string]string
}

func (c *NpmRegistryAPIClient) GobEncode() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cacheTimestamp == nil {
		now := time.Now().UTC()
		c.cacheTimestamp = &now
	}

	cache := npmRegistryCache{
		Timestamp:    c.cacheTimestamp,
		Details:      c.details,
		RegistryURLs: make(map[string]string),
	}

	// store the registry URL for each scope (but not the auth info)
	for scope, reg := range c.registries {
		cache.RegistryURLs[scope] = reg.URL
	}

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

		return cache.RegistryURLs[scope] != c.registries[scope].URL
	})

	c.cacheTimestamp = cache.Timestamp
	c.details = cache.Details

	return nil
}
