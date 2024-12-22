package datasource

import (
	"time"
)

type mavenRegistryCache struct {
	Timestamp *time.Time
	Responses map[string]response // url -> response
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
		Responses: m.responses.GetMap(),
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
	m.responses.SetMap(cache.Responses)

	return nil
}
