package testcmd

import (
	"bytes"
	"cmp"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tidwall/pretty"
	"go.yaml.in/yaml/v4"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/recorder"
)

func determineRecorderMode() recorder.Mode {
	switch strings.ToLower(os.Getenv("TEST_VCR_MODE")) {
	case "recordonly", "0":
		return recorder.ModeRecordOnly
	case "replayonly", "1":
		return recorder.ModeReplayOnly
	case "replaywithnewepisodes", "2":
		return recorder.ModeReplayWithNewEpisodes
	case "recordonce", "3":
		return recorder.ModeRecordOnce
	case "passthrough", "4":
		return recorder.ModePassthrough
	}

	if _, inCI := os.LookupEnv("CI"); inCI {
		return recorder.ModeReplayOnly
	}

	return recorder.ModeReplayWithNewEpisodes
}

// withHeadersTripper adds extra headers to requests before they're done by the wrapped http.Client
type withHeadersTripper struct {
	wrapper http.Client
	headers map[string]string
}

func (wht withHeadersTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	for key, value := range wht.headers {
		request.Header.Set(key, value)
	}

	return wht.wrapper.Do(request)
}

var _ http.RoundTripper = withHeadersTripper{}

// WithTestNameHeader wraps the given http.Client with an http.RoundTripper that
// adds a custom header to every request with the name of the test being run
func WithTestNameHeader(t *testing.T, client http.Client) *http.Client {
	t.Helper()

	return &http.Client{Transport: withHeadersTripper{
		wrapper: client,
		headers: map[string]string{"X-Test-Name": t.Name()},
	}}
}

// InsertCassette returns an http.Client backed by a [recorder.Recorder] which
// will record and (re)play responses from a cassette based on the tests name
func InsertCassette(t *testing.T) *http.Client {
	t.Helper()

	path := filepath.Join("testdata/cassettes", strings.ReplaceAll(t.Name(), "/", "_"))

	r, err := recorder.New(
		path,
		recorder.WithSkipRequestLatency(true),
		recorder.WithMode(determineRecorderMode()),
		recorder.WithPassthrough(func(req *http.Request) bool {
			// exclude requests for info on a specific vuln since they can be quite large
			// and their changes should be less impactful to our snapshots than the query
			// endpoint, as those reqs are what results in specific vulns being looked up
			return strings.HasPrefix(req.URL.Path, "/v1/vulns/")
		}),
		recorder.WithMatcher(matcher),
		recorder.WithHook(func(i *cassette.Interaction) error {
			// remove headers that are not important to reduce cassette size and noise
			for _, header := range []string{
				"Alt-Svc",
				"Grpc-Accept-Encoding",
				"Grpc-Message",
				"Grpc-Status",
				"Server",
				"Traceparent",
				"X-Cloud-Trace-Context",
				"X-Envoy-Decorator-Operation",
				"Date",
			} {
				delete(i.Response.Headers, header)
			}

			delete(i.Request.Headers, "User-Agent")

			body, err := normalizeBody([]byte(i.Request.Body))
			if err != nil {
				return err
			}
			i.Request.Body = string(body)
			i.Request.ContentLength = int64(len(i.Request.Body))

			// use a static duration since we don't care about replicating latency
			i.Response.Duration = 0
			i.Response.Body = string(pretty.Pretty([]byte(i.Response.Body)))

			return nil
		}, recorder.AfterCaptureHook),
	)

	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Stop(); err != nil {
			t.Error(err)
		}

		sortCassetteInteractions(t, path)
	})

	return r.GetDefaultClient()
}

// sortCassetteInteractions reorders the interactions in the given cassette, based
// on the X-Test-Name header to help reduce the diff when interactions are changed
func sortCassetteInteractions(t *testing.T, path string) {
	t.Helper()

	cass, err := cassette.Load(strings.TrimSuffix(path, ".yaml"))
	if err != nil {
		t.Fatalf("failed to load %s: %v", path, err)
	}

	cass.MarshalFunc = func(input any) ([]byte, error) {
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(input); err != nil {
			return nil, err
		}

		return buf.Bytes(), nil
	}

	// we don't need to worry about the interaction ids as they get updated as part of saving
	slices.SortFunc(cass.Interactions, func(a, b *cassette.Interaction) int {
		return cmp.Compare(a.Request.Headers.Get("X-Test-Name"), b.Request.Headers.Get("X-Test-Name"))
	})

	if err = cass.Save(); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

// Simplified matcher, which only looks at:
// - Method
// - URL
// - Headers
// - Body
func matcher(r *http.Request, i cassette.Request) bool {
	if r.Method != i.Method {
		return false
	}

	if r.URL.String() != i.URL {
		return false
	}

	requestHeader := r.Header.Clone()
	cassetteRequestHeaders := i.Headers.Clone()

	for _, header := range []string{
		"User-Agent",
		"Content-Length",
	} {
		delete(requestHeader, header)
		delete(cassetteRequestHeaders, header)
	}

	if !reflect.DeepEqual(requestHeader, cassetteRequestHeaders) {
		return false
	}

	if !matchBody(r, i) {
		return false
	}

	return true
}

func matchBody(r *http.Request, i cassette.Request) bool {
	if r.Body != nil {
		var buffer bytes.Buffer
		if _, err := buffer.ReadFrom(r.Body); err != nil {
			return false
		}

		r.Body = io.NopCloser(bytes.NewBuffer(buffer.Bytes()))

		body2, err := normalizeBody(buffer.Bytes())
		if err != nil {
			// This file will only run in tests, and this should be very unlikely
			panic(err)
		}

		if !bytes.Equal(body2, []byte(i.Body)) {
			return false
		}
	} else if len(i.Body) != 0 {
		return false
	}

	return true
}

func normalizeBody(body []byte) ([]byte, error) {
	var intermediate any
	if err := json.Unmarshal(body, &intermediate); err != nil {
		return nil, err
	}

	buffer2, err := json.Marshal(intermediate)
	if err != nil {
		return nil, err
	}

	return buffer2, nil
}
