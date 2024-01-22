package datasource

import (
	"time"

	"google.golang.org/protobuf/proto"
)

type depsdevAPICache struct {
	Timestamp         *time.Time
	PackageCache      map[packageKey][]byte
	VersionCache      map[versionKey][]byte
	RequirementsCache map[versionKey][]byte
}

func protoMarshalCache[K comparable, V proto.Message](protoMap map[K]V) (map[K][]byte, error) {
	byteMap := make(map[K][]byte)
	for k, v := range protoMap {
		b, err := proto.Marshal(v)
		if err != nil {
			return nil, err
		}
		byteMap[k] = b
	}

	return byteMap, nil
}

func protoUnmarshalCache[K comparable, V any, PV interface {
	proto.Message
	*V
}](byteMap map[K][]byte, protoMap *map[K]PV) error {
	*protoMap = make(map[K]PV)
	for k, b := range byteMap {
		v := PV(new(V))
		if err := proto.Unmarshal(b, v); err != nil {
			return err
		}
		(*protoMap)[k] = v
	}

	return nil
}

func (c *DepsDevAPIClient) GobEncode() ([]byte, error) {
	var cache depsdevAPICache
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cacheTimestamp == nil {
		now := time.Now().UTC()
		c.cacheTimestamp = &now
	}

	cache.Timestamp = c.cacheTimestamp
	var err error
	cache.PackageCache, err = protoMarshalCache(c.packageCache)
	if err != nil {
		return nil, err
	}
	cache.VersionCache, err = protoMarshalCache(c.versionCache)
	if err != nil {
		return nil, err
	}
	cache.RequirementsCache, err = protoMarshalCache(c.requirementsCache)
	if err != nil {
		return nil, err
	}

	return gobMarshal(cache)
}

func (c *DepsDevAPIClient) GobDecode(b []byte) error {
	var cache depsdevAPICache
	if err := gobUnmarshal(b, &cache); err != nil {
		return err
	}

	if cache.Timestamp != nil && time.Since(*cache.Timestamp) >= cacheExpiry {
		// Cache expired
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.cacheTimestamp = cache.Timestamp
	if err := protoUnmarshalCache(cache.PackageCache, &c.packageCache); err != nil {
		return err
	}
	if err := protoUnmarshalCache(cache.VersionCache, &c.versionCache); err != nil {
		return err
	}
	if err := protoUnmarshalCache(cache.RequirementsCache, &c.requirementsCache); err != nil {
		return err
	}

	return nil
}
