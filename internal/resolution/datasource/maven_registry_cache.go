package datasource

import (
	"time"

	"deps.dev/util/maven"
)

type mavenRegistryCache struct {
	Timestamp *time.Time
	Projects  map[string]maven.Project  // url -> project
	Metadata  map[string]maven.Metadata // url -> metadata
}

func (m *MavenRegistryAPIClient) GobEncode() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cacheTimestamp == nil {
		now := time.Now().UTC()
		m.cacheTimestamp = &now
	}

	cache := mavenRegistryCache{
		Timestamp: m.cacheTimestamp,
		Projects:  m.projects.GetMap(),
		Metadata:  m.metadata.GetMap(),
	}

	return gobMarshal(&cache)
}

func (m *MavenRegistryAPIClient) GobDecode(b []byte) error {
	var cache mavenRegistryCache
	if err := gobUnmarshal(b, &cache); err != nil {
		return err
	}

	if cache.Timestamp != nil && time.Since(*cache.Timestamp) >= cacheExpiry {
		// Cache expired
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.cacheTimestamp = cache.Timestamp
	m.projects.SetMap(cache.Projects)
	m.metadata.SetMap(cache.Metadata)

	return nil
}
