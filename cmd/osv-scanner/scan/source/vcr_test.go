package source_test

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/dnaeon/go-vcr.v4/pkg/recorder"
)

func TestHelloWorld(t *testing.T) {
	t.Parallel()

	// Create our recorder
	r, err := recorder.New(filepath.Join("testdata", strings.ReplaceAll(t.Name(), "/", "_")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Make sure recorder is stopped once done with it.
		if err := r.Stop(); err != nil {
			t.Error(err)
		}
	})

	client := r.GetDefaultClient()
	url := "https://go.dev/VERSION?m=text"

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Failed to get url %s: %s", url, err)
	}

	t.Logf("GET %s: %d\n", url, resp.StatusCode)
}
