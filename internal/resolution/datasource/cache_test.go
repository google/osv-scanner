package datasource_test

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/osv-scanner/internal/resolution/datasource"
)

func TestRequestCache(t *testing.T) {
	t.Parallel()
	// Test that RequestCache calls each function exactly once per key.
	requestCache := datasource.NewRequestCache[int, int]()

	const numKeys = 20
	const numConcurrent = 50

	calls := make([]int32, numKeys)

	var wg sync.WaitGroup

	for i := range numKeys {
		for range numConcurrent {
			wg.Add(1)
			go func() {
				t.Helper()
				//nolint:errcheck
				requestCache.Get(i, func() (int, error) {
					atomic.AddInt32(&calls[i], 1)
					return i, nil
				})
				wg.Done()
			}()
		}
	}

	wg.Wait()

	for i, c := range calls {
		if c != 1 {
			t.Errorf("RequestCache Get(%d) function called %d times", i, c)
		}
	}

	cacheMap := requestCache.GetMap()
	if len(cacheMap) != numKeys {
		t.Errorf("RequestCache GetMap length was %d, expected %d", len(cacheMap), numKeys)
	}

	for k, v := range cacheMap {
		if k != v {
			t.Errorf("RequestCache GetMap key %d has unexpected value %d", k, v)
		}
	}
}
