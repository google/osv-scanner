package datasource

import (
	"bytes"
	"encoding/gob"
	"maps"
	"sync"
	"time"
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

type requestCacheCall[V any] struct {
	wg  sync.WaitGroup
	val V
	err error
}

// RequestCache is a map to cache the results of expensive functions that are called concurrently.
type RequestCache[K comparable, V any] struct {
	cache map[K]V
	calls map[K]*requestCacheCall[V]
	mu    sync.Mutex
}

func NewRequestCache[K comparable, V any]() *RequestCache[K, V] {
	return &RequestCache[K, V]{
		cache: make(map[K]V),
		calls: make(map[K]*requestCacheCall[V]),
	}
}

// Get gets the value from the cache map if it's cached, otherwise it will call fn to get the value and cache it.
// fn will only ever be called once for a key, even if there are multiple simultaneous calls to Get before the first call is finished.
func (rq *RequestCache[K, V]) Get(key K, fn func() (V, error)) (V, error) {
	// Try get it from regular cache.
	rq.mu.Lock()
	if v, ok := rq.cache[key]; ok {
		rq.mu.Unlock()
		return v, nil
	}

	// See if there is already a pending request for this key.
	if c, ok := rq.calls[key]; ok {
		rq.mu.Unlock()
		c.wg.Wait()

		return c.val, c.err
	}

	// Cache miss - create the call.
	c := new(requestCacheCall[V])
	c.wg.Add(1)
	rq.calls[key] = c
	rq.mu.Unlock()

	c.val, c.err = fn()
	rq.mu.Lock()
	defer rq.mu.Unlock()

	// Allow other waiting goroutines to return
	c.wg.Done()

	// Store value in regular cache.
	if c.err == nil {
		rq.cache[key] = c.val
	}

	// Remove the completed call now that it's cached.
	if rq.calls[key] == c {
		delete(rq.calls, key)
	}

	return c.val, c.err
}

// GetMap gets a shallow clone of the stored cache map.
func (rq *RequestCache[K, V]) GetMap() map[K]V {
	rq.mu.Lock()
	defer rq.mu.Unlock()

	return maps.Clone(rq.cache)
}

// SetMap loads (a shallow clone of) the provided map into the cache map.
func (rq *RequestCache[K, V]) SetMap(m map[K]V) {
	rq.mu.Lock()
	defer rq.mu.Unlock()
	rq.cache = maps.Clone(m)
}
