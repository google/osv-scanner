package datasource

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const cacheExpiry = 6 * time.Hour

func gobMarshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)

	err := enc.Encode(v)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func gobUnmarshal(b []byte, v any) error {
	dec := gob.NewDecoder(bytes.NewReader(b))
	return dec.Decode(v)
}

// requestCache is a map to cache the results of expensive functions that are called concurrently.
type requestCache[K comparable, V any] struct {
	Map     map[K]V
	mu      *sync.Mutex
	sfGroup *singleflight.Group
}

func newRequestCache[K comparable, V any](mu *sync.Mutex) requestCache[K, V] {
	return requestCache[K, V]{
		Map:     make(map[K]V),
		mu:      mu,
		sfGroup: &singleflight.Group{},
	}
}

// Get gets the value from the cache map if it's cached, otherwise it will call fn to get the value and cache it.
// fn will only ever be called once for a key, even if there are multiple simultaneous calls to Get before the first call is finished.
func (rq requestCache[K, V]) Get(key K, fn func() (V, error)) (V, error) {
	// Try get it from cache
	rq.mu.Lock()
	v, ok := rq.Map[key]
	rq.mu.Unlock()
	if ok {
		return v, nil
	}

	// Not in cache, use singleflight.Group to call the function a single time.

	// singleflight requires the key to be a string, but K is a generic comparable.
	// I *think* %#v is enough to preserve equality of basic types and comparable structs.
	groupKey := fmt.Sprintf("%#v", key)
	val, err, _ := rq.sfGroup.Do(groupKey, func() (interface{}, error) {
		v, err := fn()

		// If we successfully got the value, store it in the cache for future calls.
		if err == nil {
			rq.mu.Lock()
			rq.Map[key] = v
			rq.mu.Unlock()
		}

		return v, err
	})
	// Remove the cached value from the singleflight group so we don't store everything twice.
	defer rq.sfGroup.Forget(groupKey)

	return val.(V), err
}
