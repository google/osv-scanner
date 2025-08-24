package testcmd

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	return recorder.ModeRecordOnce
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

	r, err := recorder.New(
		filepath.Join("testdata/cassettes", strings.ReplaceAll(t.Name(), "/", "_")),
		recorder.WithSkipRequestLatency(true),
		recorder.WithMode(determineRecorderMode()),
		recorder.WithPassthrough(func(req *http.Request) bool {
			// exclude requests for info on a specific vuln since they can be quite large
			// and their changes should be less impactful to our snapshots than the query
			// endpoint, as those reqs are what results in specific vulns being looked up
			return strings.HasPrefix(req.URL.Path, "/v1/vulns/")
		}),
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
			} {
				delete(i.Response.Headers, header)
			}

			// use a static duration since we don't care about replicating latency
			i.Response.Duration = 0

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
	})

	return r.GetDefaultClient()
}
