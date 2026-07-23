package testcmd

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
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

	return wht.wrapper.Do(request) //nolint:gosec // Safe in tests
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

// this is cassette.Interaction without its ID field
type withoutID struct {
	Request  cassette.Request  `yaml:"request"`
	Response cassette.Response `yaml:"response"`
}

// custom marshaller to make cassettes pretty and to omit the "id" field from interactions
// for a smaller diff since we don't care about their order
func marshalCassettes(in any) (out []byte, err error) {
	cass, ok := in.(*cassette.Cassette)
	if !ok {
		return nil, fmt.Errorf("expected *cassette.Cassette, got %T", in)
	}

	interactions := make([]withoutID, len(cass.Interactions))
	for i, interaction := range cass.Interactions {
		interactions[i] = withoutID{
			Request:  interaction.Request,
			Response: interaction.Response,
		}
	}

	input := struct {
		Version      int         `yaml:"version"`
		Interactions []withoutID `yaml:"interactions"`
	}{Version: cass.Version, Interactions: interactions}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(input); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// InsertCassette returns an http.Client backed by a [recorder.Recorder] which
// will record and (re)play responses from a cassette based on the tests name
func InsertCassette(t *testing.T) *http.Client {
	t.Helper()

	path := filepath.Join("testdata/cassettes", strings.ReplaceAll(t.Name(), "/", "_"))

	r, err := recorder.New(
		path,
		recorder.WithMarshalFunc(marshalCassettes),
		recorder.WithSkipRequestLatency(true),
		recorder.WithMode(determineRecorderMode()),
		recorder.WithPassthrough(func(req *http.Request) bool {
			// exclude requests for info on a specific vuln since they can be quite large
			// and their changes should be less impactful to our snapshots than the query
			// endpoint, as those reqs are what results in specific vulns being looked up
			if strings.HasPrefix(req.URL.Path, "/v1/vulns/") {
				return true
			}
			// exclude requests for binary file downloads from cassettes (e.g. zip databases, jar files)
			ext := strings.ToLower(filepath.Ext(req.URL.Path))
			binaryExts := []string{".zip", ".gz", ".bin", ".db", ".tar", ".tgz", ".jar", ".aar", ".whl"}

			return slices.Contains(binaryExts, ext)
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
				"Etag",
				"X-Cache",
				"X-Cache-Hits",
				"X-Served-By",
				"X-Timer",
				"X-Pypi-Last-Serial",
				"Age",
			} {
				delete(i.Response.Headers, header)
			}

			for header := range i.Response.Headers {
				if strings.HasPrefix(header, "X-Google-") {
					delete(i.Response.Headers, header)
				}
			}

			delete(i.Request.Headers, "User-Agent")

			// Force copy of default options, as we don't want to change the global variable
			prettyOptions := *pretty.DefaultOptions
			prettyOptions.SortKeys = true

			if strings.Contains(strings.ToLower(i.Request.Headers.Get("Content-Type")), "json") {
				i.Request.Body = string(pretty.PrettyOptions([]byte(i.Request.Body), &prettyOptions))
				i.Request.ContentLength = int64(len(i.Request.Body))
			}

			// use a static duration since we don't care about replicating latency
			i.Response.Duration = 0
			if strings.Contains(strings.ToLower(i.Response.Headers.Get("Content-Type")), "json") {
				i.Response.Body = string(pretty.PrettyOptions([]byte(i.Response.Body), &prettyOptions))
			}

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

	client := r.GetDefaultClient()
	client.Transport = &vcrErrorWrappingTransport{
		t:            t,
		wrapper:      client.Transport,
		cassettePath: path,
	}

	return client
}

// sortCassetteInteractions reorders the interactions in the given cassette, based
// on the X-Test-Name header to help reduce the diff when interactions are changed
func sortCassetteInteractions(t *testing.T, path string) {
	t.Helper()

	cass, err := cassette.Load(strings.TrimSuffix(path, ".yaml"))
	if err != nil {
		t.Fatalf("failed to load %s: %v", path, err)
	}

	cass.MarshalFunc = marshalCassettes

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

		if !bytes.Equal(
			pretty.PrettyOptions(buffer.Bytes(), &pretty.Options{SortKeys: true}),
			pretty.PrettyOptions([]byte(i.Body), &pretty.Options{SortKeys: true}),
		) {
			return false
		}
	} else if len(i.Body) != 0 {
		return false
	}

	return true
}

type vcrErrorWrappingTransport struct {
	t            *testing.T
	wrapper      http.RoundTripper
	cassettePath string
}

func (t *vcrErrorWrappingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.wrapper.RoundTrip(req)
	if err != nil && errors.Is(err, cassette.ErrInteractionNotFound) {
		t.logRequestMismatch(req)

		// Convert VCR error to a 404 response to avoid retries by the client
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Status:     "404 Not Found (VCR: requested interaction not found)",
			Body:       io.NopCloser(strings.NewReader("VCR: requested interaction not found")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}

	return resp, err
}

type comparableRequest struct {
	Method  string      `yaml:"method"`
	URL     string      `yaml:"url"`
	Headers http.Header `yaml:"headers"`
	Body    string      `yaml:"body"`
}

func toComparableRequest(r *http.Request) (comparableRequest, error) {
	var body string
	if r.Body != nil {
		var buffer bytes.Buffer
		if _, err := buffer.ReadFrom(r.Body); err != nil {
			return comparableRequest{}, err
		}
		r.Body = io.NopCloser(bytes.NewBuffer(buffer.Bytes()))
		prettyOptions := *pretty.DefaultOptions
		prettyOptions.SortKeys = true
		body = string(pretty.PrettyOptions(buffer.Bytes(), &prettyOptions))
	}

	headers := r.Header.Clone()
	for _, header := range []string{"User-Agent", "Content-Length"} {
		headers.Del(header)
	}

	return comparableRequest{
		Method:  r.Method,
		URL:     r.URL.String(),
		Headers: headers,
		Body:    body,
	}, nil
}

func cassetteToComparableRequest(i cassette.Request) comparableRequest {
	headers := i.Headers.Clone()
	for _, header := range []string{"User-Agent", "Content-Length"} {
		headers.Del(header)
	}
	prettyOptions := *pretty.DefaultOptions
	prettyOptions.SortKeys = true
	body := string(pretty.PrettyOptions([]byte(i.Body), &prettyOptions))

	return comparableRequest{
		Method:  i.Method,
		URL:     i.URL,
		Headers: headers,
		Body:    body,
	}
}

func (t *vcrErrorWrappingTransport) logRequestMismatch(req *http.Request) {
	t.t.Helper()

	cass, err := cassette.Load(strings.TrimSuffix(t.cassettePath, ".yaml"))
	if err != nil {
		t.t.Logf("VCR Miss: failed to load cassette %s: %v", t.cassettePath, err)
		return
	}

	actual, err := toComparableRequest(req)
	if err != nil {
		t.t.Logf("VCR Miss: failed to parse incoming request: %v", err)
		return
	}

	testName := req.Header.Get("X-Test-Name")
	var candidates []*cassette.Interaction
	for _, inter := range cass.Interactions {
		if inter.Request.Headers.Get("X-Test-Name") == testName {
			candidates = append(candidates, inter)
		}
	}

	var sb strings.Builder
	sb.WriteString("\n=================== VCR CASSETTE REQUEST MISMATCH ===================\n")
	fmt.Fprintf(&sb, "Incoming request did not match any stored cassette interaction in %s.yaml\n", t.cassettePath)
	fmt.Fprintf(&sb, "Incoming Request URL:    %s %s\n", actual.Method, actual.URL)
	fmt.Fprintf(&sb, "Incoming Test Name:      %s\n", testName)

	if len(candidates) > 0 {
		fmt.Fprintf(&sb, "\nFound %d candidate(s) in the cassette matching this test name:\n", len(candidates))
		for i, cand := range candidates {
			fmt.Fprintf(&sb, "\n--- Candidate %d ---\n", i+1)
			fmt.Fprintf(&sb, "Recorded URL:       %s %s\n", cand.Request.Method, cand.Request.URL)

			candComparable := cassetteToComparableRequest(cand.Request)
			diff := gocmp.Diff(candComparable, actual)
			sb.WriteString("Diff (-recorded +actual):\n")
			sb.WriteString(diff)
		}
	} else {
		fmt.Fprintf(&sb, "\nNo candidate requests found matching the test name: %s\n", testName)
		sb.WriteString("Recorded interactions in this cassette:\n")
		seen := make(map[string]bool)
		for _, inter := range cass.Interactions {
			name := inter.Request.Headers.Get("X-Test-Name")
			key := fmt.Sprintf("%s %s (Test: %s)", inter.Request.Method, inter.Request.URL, name)
			if !seen[key] {
				seen[key] = true
				fmt.Fprintf(&sb, "  - %s\n", key)
			}
		}
	}
	sb.WriteString("=====================================================================\n")

	t.t.Errorf("%s", sb.String())
}
