package osvmatcher

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/osvdev"
)

func TestOSVMatcher_MatchVulnerabilities(t *testing.T) {
	t.Parallel()

	type fields struct {
		Client              osvdev.OSVClient
		InitialQueryTimeout time.Duration
	}

	type args struct {
		pkgs []*extractor.Package
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    [][]*osvschema.Vulnerability
		wantErr error
	}{
		{
			name: "Timeout_returns_deadline_exceeded_error_(http.Client_code)",
			fields: fields{
				Client: *osvdev.DefaultClient(),
				// Long enough to not timeout until we enter the http client code
				InitialQueryTimeout: 1 * time.Millisecond,
			},
			args: args{
				pkgs: []*extractor.Package{
					{
						Name:     "stdlib",
						Version:  "1.22.0",
						PURLType: purl.TypeGolang,
					},
				},
			},
			want:    nil,
			wantErr: context.DeadlineExceeded,
		},
		{
			name: "Timeout_returns_deadline_exceeded_error_(osv.dev_code)",
			fields: fields{
				Client: *osvdev.DefaultClient(),
				// Short enough to test timeouts before reaching the http client
				InitialQueryTimeout: 100 * time.Nanosecond,
			},
			args: args{
				pkgs: []*extractor.Package{
					{
						Name:     "stdlib",
						Version:  "1.22.0",
						PURLType: purl.TypeGolang,
					},
				},
			},
			want:    nil,
			wantErr: context.DeadlineExceeded,
		},
	}

	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			matcher := &OSVMatcher{
				Client:              tt.fields.Client,
				InitialQueryTimeout: tt.fields.InitialQueryTimeout,
			}

			got, err := matcher.MatchVulnerabilities(t.Context(), tt.args.pkgs)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("OSVMatcher.MatchVulnerabilities() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("OSVMatcher.MatchVulnerabilities() = %v, want %v", got, tt.want)
			}
		})
	}
}

func mustReadAll(t *testing.T, r *http.Request) []byte {
	t.Helper()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("failed to read request body: %v", err)
	}

	return body
}

func writeProtoJSON(t *testing.T, w http.ResponseWriter, msg proto.Message) {
	t.Helper()

	body, err := protojson.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to encode response: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(body); err != nil {
		t.Fatalf("failed to write response: %v", err)
	}
}

func TestOSVMatcher_MatchVulnerabilitiesDeduplicatesBulkQueries(t *testing.T) {
	t.Parallel()

	queryCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case osvdev.QueryBatchEndpoint:
			var req api.BatchQuery
			if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(mustReadAll(t, r), &req); err != nil {
				t.Fatalf("failed to decode query batch: %v", err)
			}
			queryCount = len(req.GetQueries())
			writeProtoJSON(t, w, &api.BatchVulnerabilityList{
				Results: []*api.VulnerabilityList{
					{Vulns: []*osvschema.Vulnerability{{Id: "OSV-1"}}},
					{Vulns: []*osvschema.Vulnerability{{Id: "OSV-2"}}},
				},
			})
		case osvdev.GetEndpoint + "/OSV-1":
			writeProtoJSON(t, w, &osvschema.Vulnerability{Id: "OSV-1"})
		case osvdev.GetEndpoint + "/OSV-2":
			writeProtoJSON(t, w, &osvschema.Vulnerability{Id: "OSV-2"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	matcher := &OSVMatcher{
		Client: osvdev.OSVClient{
			HTTPClient:  ts.Client(),
			Config:      osvdev.DefaultConfig(),
			BaseHostURL: ts.URL,
		},
	}

	got, err := matcher.MatchVulnerabilities(t.Context(), []*extractor.Package{
		{Name: "a", Version: "1.0.0", PURLType: purl.TypeNPM},
		{Name: "a", Version: "1.0.0", PURLType: purl.TypeNPM},
		{Name: "b", Version: "2.0.0", PURLType: purl.TypeNPM},
	})
	if err != nil {
		t.Fatalf("MatchVulnerabilities() error = %v", err)
	}

	if queryCount != 2 {
		t.Fatalf("query count = %d, want 2", queryCount)
	}
	if len(got) != 3 {
		t.Fatalf("result count = %d, want 3", len(got))
	}
	if got[0][0].GetId() != "OSV-1" || got[1][0].GetId() != "OSV-1" || got[2][0].GetId() != "OSV-2" {
		t.Fatalf("unexpected vulnerabilities: got %#v", got)
	}
}
