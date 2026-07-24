package testcmd

import (
	"archive/zip"
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	scalibrconfig "github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/internal/grpcvcr"
	localscalibr "github.com/google/osv-scanner/v2/internal/scalibr"
	"github.com/tidwall/gjson"
	"github.com/tidwall/pretty"
	"github.com/tidwall/sjson"
	"go.yaml.in/yaml/v4"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/recorder"
)

const (
	gcsBucketHost         = "osv-vulnerabilities.storage.googleapis.com"
	offlineDBRelativePath = "cmd/osv-scanner/internal/testcmd/testdata/offline-dbs"
)

var globalPassthroughGRPCMethods = []string{
	"/QueryContainerImages",
}

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

// determineGRPCRecorderMode maps the HTTP recorder mode to grpcvcr mode.
func determineGRPCRecorderMode() grpcvcr.Mode {
	// Re-use determineRecorderMode which reads TEST_VCR_MODE env var
	switch determineRecorderMode() {
	case recorder.ModeRecordOnly:
		return grpcvcr.ModeRecordOnly
	case recorder.ModeReplayOnly:
		return grpcvcr.ModeReplayOnly
	case recorder.ModeReplayWithNewEpisodes:
		return grpcvcr.ModeReplayWithNewEpisodes
	case recorder.ModePassthrough:
		return grpcvcr.ModePassthrough
	default:
		return grpcvcr.ModeReplayWithNewEpisodes
	}
}

// InsertGRPCRecorder returns a grpcvcr.Recorder which will record and replay gRPC responses.
func InsertGRPCRecorder(t *testing.T) *grpcvcr.Recorder {
	t.Helper()

	path := filepath.Join("testdata/cassettes", strings.ReplaceAll(t.Name(), "/", "_")+"_grpc.yaml")

	rec, err := grpcvcr.NewRecorder(path, determineGRPCRecorderMode(), t.Name())
	if err != nil {
		t.Fatalf("failed to initialize gRPC recorder: %v", err)
	}

	rec.Passthrough = func(method string, _ proto.Message) bool {
		for _, passthroughMethod := range globalPassthroughGRPCMethods {
			if strings.HasSuffix(method, passthroughMethod) {
				return true
			}
		}

		return false
	}

	rec.OnMiss = func(method string, req proto.Message, cassette *grpcvcr.Cassette) {
		logGRPCRequestMismatch(t, path, method, req, cassette)
	}

	t.Cleanup(func() {
		if err := rec.Close(); err != nil {
			t.Errorf("failed to close gRPC recorder: %v", err)
		}
	})

	return rec
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
		recorder.WithRealTransport(&vcrResponseNormalizingTransport{
			underlying:   http.DefaultTransport,
			cassettePath: path + ".yaml",
		}),
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
		if c := cmp.Compare(a.Request.Headers.Get("X-Test-Name"), b.Request.Headers.Get("X-Test-Name")); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Request.Method, b.Request.Method); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Request.URL, b.Request.URL); c != 0 {
			return c
		}

		return cmp.Compare(a.Request.Body, b.Request.Body)
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

// SharedClientFactories is a package-level ClientFactories used by tests to reuse connections.
var SharedClientFactories scalibrconfig.ClientFactories

// TestClientFactories wraps a shared ClientFactories but overrides the HTTPClient and GRPC connection.
type TestClientFactories struct {
	scalibrconfig.ClientFactories

	HTTPClientOverride   *http.Client
	GRPCRecorderOverride *grpcvcr.Recorder
}

func (t *TestClientFactories) HTTPClient() *http.Client {
	if t.HTTPClientOverride != nil {
		return t.HTTPClientOverride
	}

	return t.ClientFactories.HTTPClient()
}

func (t *TestClientFactories) GRPCClientConn(url string, dialOpts ...grpc.DialOption) (grpc.ClientConnInterface, error) {
	conn, err := t.ClientFactories.GRPCClientConn(url, dialOpts...)
	if err != nil {
		return nil, err
	}
	if t.GRPCRecorderOverride != nil {
		return grpcvcr.NewClientConn(conn, t.GRPCRecorderOverride), nil
	}

	return conn, nil
}

// NewClientFactories returns a new ClientFactories instance for testing.
func NewClientFactories(client *http.Client) *localscalibr.ClientFactories {
	return localscalibr.NewClientFactories(client, "")
}

func logGRPCRequestMismatch(t *testing.T, cassettePath string, method string, req proto.Message, cass *grpcvcr.Cassette) {
	t.Helper()

	marshalOptions := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}
	actualJSON, err := marshalOptions.Marshal(req)
	if err != nil {
		t.Logf("gRPC VCR Miss: failed to marshal incoming request: %v", err)
		return
	}

	cleanJSON, err := grpcvcr.CleanJSON(string(actualJSON))
	if err != nil {
		t.Logf("gRPC VCR Miss: failed to clean incoming request: %v", err)
		return
	}

	var candidates []grpcvcr.Interaction
	if cass != nil {
		for _, inter := range cass.Interactions {
			if inter.Method == method {
				candidates = append(candidates, inter)
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("\n=================== gRPC VCR CASSETTE REQUEST MISMATCH ===================\n")
	fmt.Fprintf(&sb, "Incoming gRPC request did not match any stored cassette interaction in %s\n", cassettePath)
	fmt.Fprintf(&sb, "Incoming Method: %s\n", method)
	fmt.Fprintf(&sb, "Incoming Request JSON:\n%s\n", cleanJSON)

	if len(candidates) > 0 {
		fmt.Fprintf(&sb, "\nFound %d candidate(s) in the cassette matching this method:\n", len(candidates))
		for i, cand := range candidates {
			fmt.Fprintf(&sb, "\n--- Candidate %d ---\n", i+1)
			diff := gocmp.Diff(cand.Request, cleanJSON)
			sb.WriteString("Diff (-recorded +actual):\n")
			sb.WriteString(diff)
		}
	} else {
		fmt.Fprintf(&sb, "\nNo candidate requests found matching the method: %s\n", method)
		if cass != nil && len(cass.Interactions) > 0 {
			sb.WriteString("Recorded interactions in this cassette:\n")
			seen := make(map[string]bool)
			for _, inter := range cass.Interactions {
				key := inter.Method
				if !seen[key] {
					seen[key] = true
					fmt.Fprintf(&sb, "  - %s\n", key)
				}
			}
		} else {
			sb.WriteString("Cassette is empty.\n")
		}
	}
	sb.WriteString("==========================================================================\n")

	t.Errorf("%s", sb.String())
}

type vcrResponseNormalizingTransport struct {
	underlying   http.RoundTripper
	cassettePath string
}

func (t *vcrResponseNormalizingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Intercept OSV database zip downloads
	if req.Method == http.MethodGet && strings.HasPrefix(req.URL.Host, gcsBucketHost) && strings.HasSuffix(req.URL.Path, "/all.zip") {
		return t.handleOfflineDBDownload(req)
	}
	if req.Method == http.MethodHead && strings.HasPrefix(req.URL.Host, gcsBucketHost) && strings.HasSuffix(req.URL.Path, "/all.zip") {
		return t.handleOfflineDBHead(req)
	}

	var reqBodyBytes []byte
	var err error
	if req.Body != nil && req.Body != http.NoBody {
		reqBodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		// Restore body
		req.Body = io.NopCloser(bytes.NewBuffer(reqBodyBytes))
	}

	resp, err := t.underlying.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		path := req.URL.Path
		if path == "/v1/querybatch" {
			resp, err = t.normalizeQueryBatchResponse(req, reqBodyBytes, resp)
		}
	}

	return resp, err
}

type minimalVcrCassette struct {
	Interactions []struct {
		Request struct {
			Method string `yaml:"method"`
			URL    string `yaml:"url"`
			Body   string `yaml:"body"`
		} `yaml:"request"`
		Response struct {
			Body string `yaml:"body"`
		} `yaml:"response"`
	} `yaml:"interactions"`
}

func (t *vcrResponseNormalizingTransport) normalizeQueryBatchResponse(req *http.Request, reqBodyBytes []byte, resp *http.Response) (*http.Response, error) {
	if os.Getenv("VCR_UPDATE_MODIFIED") == "true" {
		return resp, nil
	}

	// Read new response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	// Load existing cassette
	cassetteBytes, err := os.ReadFile(t.cassettePath) //nolint:gosec
	if err != nil {
		// Cassette doesn't exist yet, just return original
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		return resp, nil //nolint:nilerr
	}

	var cass minimalVcrCassette
	if err := yaml.Unmarshal(cassetteBytes, &cass); err != nil {
		// Failed to parse cassette, return original
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		return resp, nil //nolint:nilerr
	}

	// Canonicalize new request JSON using the same pretty-printing options (SortKeys: true)
	// so we can compare it directly with the already formatted cassette request body.
	prettyOptions := *pretty.DefaultOptions
	prettyOptions.SortKeys = true
	newReqPretty := string(pretty.PrettyOptions(reqBodyBytes, &prettyOptions))

	// Find matching interaction in existing cassette
	var matchedResponseStr string
	for _, inter := range cass.Interactions {
		if inter.Request.Method == req.Method && inter.Request.URL == req.URL.String() {
			if inter.Request.Body == newReqPretty {
				matchedResponseStr = inter.Response.Body
				break
			}
		}
	}

	if matchedResponseStr == "" {
		// No matching interaction found, return original
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		return resp, nil
	}

	// Parse recorded response to extract original modified dates
	recordedModified := make(map[string]string)
	for _, resVal := range gjson.Get(matchedResponseStr, "results").Array() {
		for _, vulnVal := range resVal.Get("vulns").Array() {
			id := vulnVal.Get("id").String()
			mod := vulnVal.Get("modified").String()
			if id != "" && mod != "" {
				recordedModified[id] = mod
			}
		}
	}

	// Parse new response and replace modified dates in-place using sjson
	finalRespBytes := bodyBytes
	var setErr error
	for resIdx, resVal := range gjson.ParseBytes(bodyBytes).Get("results").Array() {
		for vulnIdx, vulnVal := range resVal.Get("vulns").Array() {
			id := vulnVal.Get("id").String()
			if oldMod, exists := recordedModified[id]; exists {
				path := fmt.Sprintf("results.%d.vulns.%d.modified", resIdx, vulnIdx)
				finalRespBytes, setErr = sjson.SetBytes(finalRespBytes, path, oldMod)
				if setErr != nil {
					break
				}
			}
		}
		if setErr != nil {
			break
		}
	}

	if setErr != nil {
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		return resp, nil //nolint:nilerr
	}

	resp.Body = io.NopCloser(bytes.NewBuffer(finalRespBytes))
	resp.ContentLength = int64(len(finalRespBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(finalRespBytes)))

	return resp, nil
}

// Find the git repository root by looking for go.mod
func findRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return ""
}

func (t *vcrResponseNormalizingTransport) handleOfflineDBDownload(req *http.Request) (*http.Response, error) {
	repoRoot := findRepoRoot()
	ecosystem := filepath.Base(filepath.Dir(req.URL.Path)) // e.g. "Alpine", "Packagist"
	localDBPath := filepath.Join(repoRoot, offlineDBRelativePath, ecosystem)

	if os.Getenv("VCR_UPDATE_OFFLINE_DBS") == "true" {
		if err := t.updateOfflineDB(req.URL.String(), localDBPath, ecosystem); err != nil {
			return nil, err
		}
	}

	zipBytes, err := buildZipInMemory(ecosystem)
	if err != nil {
		return nil, fmt.Errorf("failed to build local offline database zip for %s: %w", ecosystem, err)
	}

	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(bytes.NewBuffer(zipBytes)),
		ContentLength: int64(len(zipBytes)),
		Header:        make(http.Header),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "application/zip")
	resp.Header.Set("Content-Length", strconv.Itoa(len(zipBytes)))

	return resp, nil
}

func (t *vcrResponseNormalizingTransport) handleOfflineDBHead(req *http.Request) (*http.Response, error) {
	ecosystem := filepath.Base(filepath.Dir(req.URL.Path))

	if os.Getenv("VCR_UPDATE_OFFLINE_DBS") == "true" {
		return t.underlying.RoundTrip(req)
	}

	zipBytes, err := buildZipInMemory(ecosystem)
	if err != nil {
		return nil, fmt.Errorf("local offline database not found for %s: %w", ecosystem, err)
	}

	checksum := crc32.Checksum(zipBytes, crc32.MakeTable(crc32.Castagnoli))
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, checksum)
	base64Hash := base64.StdEncoding.EncodeToString(buf)

	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          http.NoBody,
		ContentLength: 0,
		Header:        make(http.Header),
		Request:       req,
	}
	resp.Header.Set("X-Goog-Hash", "crc32c="+base64Hash)

	return resp, nil
}

var (
	dbUpdateMutexes   sync.Map
	updatedEcosystems sync.Map
)

func getDBUpdateMutex(ecosystem string) *sync.Mutex {
	val, _ := dbUpdateMutexes.LoadOrStore(ecosystem, &sync.Mutex{})
	return val.(*sync.Mutex)
}

func (t *vcrResponseNormalizingTransport) updateOfflineDB(url string, localDBPath string, ecosystem string) error {
	mu := getDBUpdateMutex(ecosystem)
	mu.Lock()
	defer mu.Unlock()

	if _, alreadyUpdated := updatedEcosystems.Load(ecosystem); alreadyUpdated {
		return nil
	}

	println("Updating offline database for:", ecosystem)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil) //nolint:gosec
	if err != nil {
		return err
	}
	resp, err := t.underlying.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download live db from %s: %s", url, resp.Status)
	}

	fullZipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	zipReader, err := zip.NewReader(bytes.NewReader(fullZipBytes), int64(len(fullZipBytes)))
	if err != nil {
		return err
	}

	// Delete existing directory to start clean
	if err := os.RemoveAll(localDBPath); err != nil {
		return err
	}
	if err := os.MkdirAll(localDBPath, 0750); err != nil {
		return err
	}

	for _, file := range zipReader.File {
		if !strings.HasSuffix(file.Name, ".json") {
			continue
		}

		vulnID := strings.TrimSuffix(file.Name, ".json")
		if !shouldKeepVuln(vulnID) {
			continue
		}

		f, err := file.Open()
		if err != nil {
			return err
		}
		content, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return err
		}

		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, content, "", "  "); err != nil {
			return err
		}

		targetFilePath := filepath.Join(localDBPath, vulnID+".json")
		if err := os.WriteFile(targetFilePath, prettyJSON.Bytes(), 0644); err != nil { //nolint:gosec
			return err
		}
	}

	updatedEcosystems.Store(ecosystem, true)

	return nil
}

func buildZipInMemory(ecosystem string) ([]byte, error) {
	repoRoot := findRepoRoot()
	localDBPath := filepath.Join(repoRoot, offlineDBRelativePath, ecosystem)

	files, err := os.ReadDir(localDBPath)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(localDBPath, file.Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			zipWriter.Close()
			return nil, err
		}

		w, err := zipWriter.Create(file.Name())
		if err != nil {
			zipWriter.Close()
			return nil, err
		}
		if _, err := w.Write(content); err != nil {
			zipWriter.Close()
			return nil, err
		}
	}

	if err := zipWriter.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// allowedVulnIDs defines a small subset of vulnerabilities we want to match in offline local database tests.
var allowedVulnIDs = map[string]bool{
	"ALPINE-CVE-2025-26519":   true, // Alpine - musl @ 1.2.3-r4 in testdata/locks-many-with-insecure/alpine.cdx.xml
	"CVE-2024-51757":          true, // GIT - github.com/capricorn86/happy-dom @ v11.1.0 in testdata/locks-git/osv-scanner.json
	"CVE-2025-11187":          true, // GIT - github.com/openssl/openssl @ openssl-3.5.0 in testdata/locks-git/osv-scanner.json
	"DLA-3008-1":              true, // Debian - openssl @ 1.1.0l-1~deb9u5 in testdata/sbom-insecure/postgres-stretch.cdx.xml
	"DLA-3012-1":              true, // Debian - libxml2 @ 2.9.4+dfsg1-2.2+deb9u6 in testdata/sbom-insecure/postgres-stretch.cdx.xml
	"DLA-3022-1":              true, // Debian - dpkg @ 1.18.25 in testdata/sbom-insecure/postgres-stretch.cdx.xml
	"DLA-3051-1":              true, // Debian - tzdata @ 2021a-0+deb9u3 in testdata/sbom-insecure/postgres-stretch.cdx.xml
	"DRUPAL-CONTRIB-2025-083": true, // Packagist - drupal/simple_sitemap @ 4.2.1 in testdata/locks-many-with-insecure/composer.lock
	"DRUPAL-CORE-2025-005":    true, // Packagist - drupal/core @ 10.4.5 in testdata/locks-many-with-insecure/composer.lock
	"DRUPAL-CORE-2026-001":    true, // Packagist - drupal/core @ 10.4.5 in testdata/locks-many-with-insecure/composer.lock
	"GHSA-269g-pwp5-87pp":     true, // Maven - junit:junit @ 4.12 in testdata/maven-transitive/encoding.xml
	"GHSA-3pxv-7cmr-fjr4":     true, // Maven - org.apache.logging.log4j:log4j-core @ 2.14.1 in testdata/maven-transitive/registry.xml
	"GHSA-9f46-5r25-5wfm":     true, // Packagist - league/flysystem @ 1.0.8 in testdata/locks-many-with-insecure/composer.lock
	"GHSA-cm6r-892j-jv2g":     true, // Maven - com.google.android.gms:play-services-basement @ 10.0.0 in testdata/maven-transitive/registry.xml
	"GHSA-whgm-jr23-g3j9":     true, // npm - ansi-html @ 0.0.1 in testdata/locks-many-with-insecure/package-lock.json
	"GO-2022-0274":            true, // Go - github.com/opencontainers/runc @ v1.0.1 in testdata/sbom-insecure/postgres-stretch.cdx.xml
	"GO-2022-0493":            true, // Go - golang.org/x/sys @ v0.0.0-20210817142637-7d9622a276b7 in testdata/sbom-insecure/postgres-stretch.cdx.xml
	"OSV-2018-389":            true, // GIT - github.com/boostorg/boost @ boost-1.67.0 in testdata/locks-git/osv-scanner.json
	"OSV-2023-1161":           true, // GIT - github.com/Exiv2/exiv2 @ v0.28.0 in testdata/locks-git/osv-scanner.json
	"PYSEC-2020-148":          true, // PyPI - urllib3 @ 1.24.3 in testdata/locks-requirements/requirements.txt
	"PYSEC-2020-43":           true, // PyPI - flask-cors @ 1.0.0 in testdata/locks-requirements/unresolvable-requirements.txt
	"PYSEC-2020-73":           true, // PyPI - pandas @ 0.23.4 in testdata/locks-requirements/unresolvable-requirements.txt
	"PYSEC-2021-98":           true, // PyPI - django @ 1.11.29 in testdata/locks-requirements/requirements.txt
	"PYSEC-2023-62":           true, // PyPI - flask @ 1.0.0 in testdata/locks-requirements/requirements.txt
	"PYSEC-2023-74":           true, // PyPI - requests @ 2.20.0 in testdata/locks-requirements/requirements.txt
}

func shouldKeepVuln(vulnID string) bool {
	return allowedVulnIDs[vulnID]
}
