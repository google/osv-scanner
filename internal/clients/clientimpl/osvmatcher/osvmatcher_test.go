package osvmatcher

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/osvdev"

	"github.com/google/osv-scanner/v2/internal/imodels"
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

func TestOSVMatcher_RoutesTuxCarePackageToTuxCareEcosystem(t *testing.T) {
	t.Parallel()

	var gotEcosystem, gotName, gotVersion string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case osvdev.QueryBatchEndpoint:
			var req api.BatchQuery
			if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(mustReadAll(t, r), &req); err != nil {
				t.Fatalf("failed to decode query batch: %v", err)
			}
			q := req.GetQueries()[0]
			gotEcosystem = q.GetPackage().GetEcosystem()
			gotName = q.GetPackage().GetName()
			gotVersion = q.GetVersion()
			writeProtoJSON(t, w, &api.BatchVulnerabilityList{
				Results: []*api.VulnerabilityList{
					{Vulns: []*osvschema.Vulnerability{{Id: "CLSA-2023-1703184336"}}},
				},
			})
		case osvdev.GetEndpoint + "/CLSA-2023-1703184336":
			writeProtoJSON(t, w, &osvschema.Vulnerability{Id: "CLSA-2023-1703184336"})
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
		dpkgPkg("squid-cgi", "squid", "3.5.27-1ubuntu1.14+tuxcare.els3", "ubuntu", "18.04"),
	})
	if err != nil {
		t.Fatalf("MatchVulnerabilities() error = %v", err)
	}

	if gotEcosystem != "TuxCare:Ubuntu:18.04" {
		t.Errorf("query ecosystem = %q, want %q", gotEcosystem, "TuxCare:Ubuntu:18.04")
	}
	if gotName != "squid-cgi" {
		t.Errorf("query name = %q, want %q", gotName, "squid-cgi")
	}
	if gotVersion != "3.5.27-1ubuntu1.14+tuxcare.els3" {
		t.Errorf("query version = %q, want %q", gotVersion, "3.5.27-1ubuntu1.14+tuxcare.els3")
	}
	if len(got) != 1 || len(got[0]) != 1 || got[0][0].GetId() != "CLSA-2023-1703184336" {
		t.Fatalf("unexpected vulnerabilities: got %#v", got)
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

func TestOSVMatcher_UnmarkedDpkgPackageUsesBaseEcosystem(t *testing.T) {
	t.Parallel()

	pkg := dpkgPkg("squid", "squid", "3.5.27-1ubuntu1.14", "ubuntu", "16.04")

	var gotEcosystem, gotName string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case osvdev.QueryBatchEndpoint:
			var req api.BatchQuery
			if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(mustReadAll(t, r), &req); err != nil {
				t.Fatalf("failed to decode query batch: %v", err)
			}
			q := req.GetQueries()[0]
			gotEcosystem = q.GetPackage().GetEcosystem()
			gotName = q.GetPackage().GetName()
			writeProtoJSON(t, w, &api.BatchVulnerabilityList{
				Results: []*api.VulnerabilityList{
					{Vulns: []*osvschema.Vulnerability{{Id: "USN-TEST"}}},
				},
			})
		case osvdev.GetEndpoint + "/USN-TEST":
			writeProtoJSON(t, w, &osvschema.Vulnerability{Id: "USN-TEST"})
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

	_, err := matcher.MatchVulnerabilities(t.Context(), []*extractor.Package{pkg})
	if err != nil {
		t.Fatalf("MatchVulnerabilities() error = %v", err)
	}

	if strings.HasPrefix(gotEcosystem, "TuxCare") {
		t.Errorf("query ecosystem = %q, must not be TuxCare-routed for unmarked package", gotEcosystem)
	}
	wantEcosystem := imodels.Ecosystem(pkg).String()
	if gotEcosystem != wantEcosystem {
		t.Errorf("query ecosystem = %q, want base ecosystem %q", gotEcosystem, wantEcosystem)
	}
	wantName := imodels.Name(pkg)
	if gotName != wantName {
		t.Errorf("query name = %q, want source name %q", gotName, wantName)
	}
}

func TestOSVMatcher_RoutesTuxCareDebianPackageToTuxCareEcosystem(t *testing.T) {
	t.Parallel()

	var gotEcosystem, gotName, gotVersion string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case osvdev.QueryBatchEndpoint:
			var req api.BatchQuery
			if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(mustReadAll(t, r), &req); err != nil {
				t.Fatalf("failed to decode query batch: %v", err)
			}
			q := req.GetQueries()[0]
			gotEcosystem = q.GetPackage().GetEcosystem()
			gotName = q.GetPackage().GetName()
			gotVersion = q.GetVersion()
			writeProtoJSON(t, w, &api.BatchVulnerabilityList{
				Results: []*api.VulnerabilityList{
					{Vulns: []*osvschema.Vulnerability{{Id: "CLSA-DEBIAN-TEST"}}},
				},
			})
		case osvdev.GetEndpoint + "/CLSA-DEBIAN-TEST":
			writeProtoJSON(t, w, &osvschema.Vulnerability{Id: "CLSA-DEBIAN-TEST"})
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

	_, err := matcher.MatchVulnerabilities(t.Context(), []*extractor.Package{
		dpkgPkg("binutils", "binutils", "2.31.1-16+tuxcare.els11", "debian", "10"),
	})
	if err != nil {
		t.Fatalf("MatchVulnerabilities() error = %v", err)
	}

	if gotEcosystem != "TuxCare:Debian:10" {
		t.Errorf("query ecosystem = %q, want %q", gotEcosystem, "TuxCare:Debian:10")
	}
	if gotName != "binutils" {
		t.Errorf("query name = %q, want %q", gotName, "binutils")
	}
	if gotVersion != "2.31.1-16+tuxcare.els11" {
		t.Errorf("query version = %q, want %q", gotVersion, "2.31.1-16+tuxcare.els11")
	}
}

func TestOSVMatcher_RoutedQueryPreservesEpoch(t *testing.T) {
	t.Parallel()

	var gotVersion, gotEcosystem string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case osvdev.QueryBatchEndpoint:
			var req api.BatchQuery
			if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(mustReadAll(t, r), &req); err != nil {
				t.Fatalf("failed to decode query batch: %v", err)
			}
			q := req.GetQueries()[0]
			gotVersion = q.GetVersion()
			gotEcosystem = q.GetPackage().GetEcosystem()
			writeProtoJSON(t, w, &api.BatchVulnerabilityList{
				Results: []*api.VulnerabilityList{
					{Vulns: []*osvschema.Vulnerability{{Id: "CLSA-EPOCH-TEST"}}},
				},
			})
		case osvdev.GetEndpoint + "/CLSA-EPOCH-TEST":
			writeProtoJSON(t, w, &osvschema.Vulnerability{Id: "CLSA-EPOCH-TEST"})
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

	_, err := matcher.MatchVulnerabilities(t.Context(), []*extractor.Package{
		dpkgPkg("dbus", "dbus", "2:1.10.6-1ubuntu3.6+tuxcare.els2", "ubuntu", "16.04"),
	})
	if err != nil {
		t.Fatalf("MatchVulnerabilities() error = %v", err)
	}

	if gotVersion != "2:1.10.6-1ubuntu3.6+tuxcare.els2" {
		t.Errorf("query version = %q, want epoch-intact version %q", gotVersion, "2:1.10.6-1ubuntu3.6+tuxcare.els2")
	}
	if gotEcosystem != "TuxCare:Ubuntu:16.04" {
		t.Errorf("query ecosystem = %q, want %q", gotEcosystem, "TuxCare:Ubuntu:16.04")
	}
}

func TestOSVMatcher_RoutesCentOS7RpmWithEmptyBaseEcosystem(t *testing.T) {
	t.Parallel()

	// Precondition: scalibr gives CentOS RPMs no base ecosystem, so the pkgToQuery
	// base-ecosystem gate would drop them without the routing-first fix.
	pkg := rpmPkg("glibc", "2.17-326.el7.tuxcare.els2", "centos", "7", "CentOS Linux", "cpe:/o:centos:centos:7")
	if !imodels.Ecosystem(pkg).IsEmpty() {
		t.Fatalf("precondition: expected empty base ecosystem for CentOS rpm, got %q", imodels.Ecosystem(pkg).String())
	}

	var gotEcosystem, gotName, gotVersion string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case osvdev.QueryBatchEndpoint:
			var req api.BatchQuery
			if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(mustReadAll(t, r), &req); err != nil {
				t.Fatalf("failed to decode query batch: %v", err)
			}
			q := req.GetQueries()[0]
			gotEcosystem = q.GetPackage().GetEcosystem()
			gotName = q.GetPackage().GetName()
			gotVersion = q.GetVersion()
			writeProtoJSON(t, w, &api.BatchVulnerabilityList{
				Results: []*api.VulnerabilityList{
					{Vulns: []*osvschema.Vulnerability{{Id: "CLSA-2024-1700000000"}}},
				},
			})
		case osvdev.GetEndpoint + "/CLSA-2024-1700000000":
			writeProtoJSON(t, w, &osvschema.Vulnerability{Id: "CLSA-2024-1700000000"})
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

	got, err := matcher.MatchVulnerabilities(t.Context(), []*extractor.Package{pkg})
	if err != nil {
		t.Fatalf("MatchVulnerabilities() error = %v", err)
	}

	if gotEcosystem != "TuxCare:CentOS:7" {
		t.Errorf("query ecosystem = %q, want %q", gotEcosystem, "TuxCare:CentOS:7")
	}
	if gotName != "glibc" {
		t.Errorf("query name = %q, want %q", gotName, "glibc")
	}
	if gotVersion != "2.17-326.el7.tuxcare.els2" {
		t.Errorf("query version = %q, want %q", gotVersion, "2.17-326.el7.tuxcare.els2")
	}
	if len(got) != 1 || len(got[0]) != 1 || got[0][0].GetId() != "CLSA-2024-1700000000" {
		t.Fatalf("unexpected vulnerabilities: got %#v", got)
	}
}

func TestOSVMatcher_RoutesStampedCentOS8Rpm(t *testing.T) {
	t.Parallel()
	pkg := rpmPkg("openssl", "1.1.1g-15.el8.tuxcare.els8", "centos", "8.5", "CentOS Linux", "cpe:/o:centos:centos:8")
	if !imodels.Ecosystem(pkg).IsEmpty() {
		t.Fatalf("precondition: expected empty base ecosystem for CentOS rpm")
	}
	var gotEcosystem, gotName string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case osvdev.QueryBatchEndpoint:
			var req api.BatchQuery
			_ = (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(mustReadAll(t, r), &req)
			gotEcosystem = req.GetQueries()[0].GetPackage().GetEcosystem()
			gotName = req.GetQueries()[0].GetPackage().GetName()
			writeProtoJSON(t, w, &api.BatchVulnerabilityList{Results: []*api.VulnerabilityList{{Vulns: []*osvschema.Vulnerability{{Id: "CLSA-2022-1643747494"}}}}})
		case osvdev.GetEndpoint + "/CLSA-2022-1643747494":
			writeProtoJSON(t, w, &osvschema.Vulnerability{Id: "CLSA-2022-1643747494"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	matcher := &OSVMatcher{Client: osvdev.OSVClient{HTTPClient: ts.Client(), Config: osvdev.DefaultConfig(), BaseHostURL: ts.URL}}
	got, err := matcher.MatchVulnerabilities(t.Context(), []*extractor.Package{pkg})
	if err != nil {
		t.Fatalf("MatchVulnerabilities() error = %v", err)
	}
	if gotEcosystem != "TuxCare:CentOS:8.5" || gotName != "openssl" {
		t.Errorf("query = {%q,%q}, want {TuxCare:CentOS:8.5, openssl}", gotEcosystem, gotName)
	}
	if len(got) != 1 || len(got[0]) != 1 {
		t.Fatalf("unexpected vulns: %#v", got)
	}
}

func TestOSVMatcher_MixedRoutingMapsResultsToCorrectPackage(t *testing.T) {
	t.Parallel()

	// [0] marked  → routes to TuxCare:Ubuntu:16.04  (CLSA-TEST)
	// [1] unmarked → stays at base ecosystem         (USN-TEST)
	pkgMarked := dpkgPkg("linux-modules-4.4.0-283-generic", "linux-modules-4.4.0-283-generic",
		"4.4.0-283.317+tuxcare.els1", "ubuntu", "16.04")
	pkgUnmarked := dpkgPkg("squid", "squid", "3.5.27-1ubuntu1.14", "ubuntu", "16.04")

	var queryCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case osvdev.QueryBatchEndpoint:
			var req api.BatchQuery
			if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(mustReadAll(t, r), &req); err != nil {
				t.Fatalf("failed to decode query batch: %v", err)
			}
			queryCount = len(req.GetQueries())
			results := make([]*api.VulnerabilityList, len(req.GetQueries()))
			for i, q := range req.GetQueries() {
				if strings.HasPrefix(q.GetPackage().GetEcosystem(), "TuxCare") {
					results[i] = &api.VulnerabilityList{Vulns: []*osvschema.Vulnerability{{Id: "CLSA-TEST"}}}
				} else {
					results[i] = &api.VulnerabilityList{Vulns: []*osvschema.Vulnerability{{Id: "USN-TEST"}}}
				}
			}
			writeProtoJSON(t, w, &api.BatchVulnerabilityList{Results: results})
		case osvdev.GetEndpoint + "/CLSA-TEST":
			writeProtoJSON(t, w, &osvschema.Vulnerability{Id: "CLSA-TEST"})
		case osvdev.GetEndpoint + "/USN-TEST":
			writeProtoJSON(t, w, &osvschema.Vulnerability{Id: "USN-TEST"})
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

	got, err := matcher.MatchVulnerabilities(t.Context(), []*extractor.Package{pkgMarked, pkgUnmarked})
	if err != nil {
		t.Fatalf("MatchVulnerabilities() error = %v", err)
	}

	if queryCount != 2 {
		t.Fatalf("query count = %d, want 2", queryCount)
	}
	if len(got) != 2 {
		t.Fatalf("result count = %d, want 2", len(got))
	}
	if len(got[0]) == 0 || got[0][0].GetId() != "CLSA-TEST" {
		t.Errorf("got[0] (marked package) vulns = %v, want [CLSA-TEST]", got[0])
	}
	if len(got[1]) == 0 || got[1][0].GetId() != "USN-TEST" {
		t.Errorf("got[1] (unmarked package) vulns = %v, want [USN-TEST]", got[1])
	}
}
