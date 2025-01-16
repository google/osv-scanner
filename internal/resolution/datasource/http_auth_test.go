package datasource_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/osv-scanner/internal/resolution/datasource"
)

// mockTransport is used to inspect the requests being made by HTTPAuthentications
type mockTransport struct {
	Requests         []*http.Request // All requests made to this transport
	UnauthedResponse *http.Response  // Response sent when request does not have an 'Authorization' header.
	AuthedReponse    *http.Response  // Response to sent when request does include 'Authorization' (not checked).
}

func (mt *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	mt.Requests = append(mt.Requests, req)
	var resp *http.Response
	if req.Header.Get("Authorization") == "" {
		resp = mt.UnauthedResponse
	} else {
		resp = mt.AuthedReponse
	}
	if resp == nil {
		resp = &http.Response{StatusCode: http.StatusOK}
	}

	return resp, nil
}

func TestHTTPAuthentication(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                  string
		httpAuth              *datasource.HTTPAuthentication
		requestURL            string
		wwwAuth               []string
		expectedAuths         []string // expected Authentication headers received.
		expectedResponseCodes []int    // expected final response codes received (length may be less than expectedAuths)
	}{
		{
			name:                  "nil auth",
			httpAuth:              nil,
			requestURL:            "http://127.0.0.1/",
			wwwAuth:               []string{"Basic"},
			expectedAuths:         []string{""},
			expectedResponseCodes: []int{http.StatusUnauthorized},
		},
		{
			name:                  "default auth",
			httpAuth:              &datasource.HTTPAuthentication{},
			requestURL:            "http://127.0.0.1/",
			wwwAuth:               []string{"Basic"},
			expectedAuths:         []string{""},
			expectedResponseCodes: []int{http.StatusUnauthorized},
		},
		{
			name: "basic auth",
			httpAuth: &datasource.HTTPAuthentication{
				SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthBasic},
				AlwaysAuth:       true,
				Username:         "Aladdin",
				Password:         "open sesame",
			},
			requestURL:            "http://127.0.0.1/",
			expectedAuths:         []string{"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
			expectedResponseCodes: []int{http.StatusOK},
		},
		{
			name: "basic auth from token",
			httpAuth: &datasource.HTTPAuthentication{
				SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthBasic},
				AlwaysAuth:       true,
				Username:         "ignored",
				Password:         "ignored",
				BasicAuth:        "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
			},
			requestURL:            "http://127.0.0.1/",
			expectedAuths:         []string{"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
			expectedResponseCodes: []int{http.StatusOK},
		},
		{
			name: "basic auth missing username",
			httpAuth: &datasource.HTTPAuthentication{
				SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthBasic},
				AlwaysAuth:       true,
				Username:         "",
				Password:         "ignored",
			},
			requestURL:            "http://127.0.0.1/",
			expectedAuths:         []string{""},
			expectedResponseCodes: []int{http.StatusOK},
		},
		{
			name: "basic auth missing password",
			httpAuth: &datasource.HTTPAuthentication{
				SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthBasic},
				AlwaysAuth:       true,
				Username:         "ignored",
				Password:         "",
			},
			requestURL:            "http://127.0.0.1/",
			expectedAuths:         []string{""},
			expectedResponseCodes: []int{http.StatusOK},
		},
		{
			name: "basic auth not always",
			httpAuth: &datasource.HTTPAuthentication{
				SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthBasic},
				AlwaysAuth:       false,
				BasicAuth:        "YTph",
			},
			requestURL:            "http://127.0.0.1/",
			wwwAuth:               []string{"Basic realm=\"User Visible Realm\""},
			expectedAuths:         []string{"", "Basic YTph"},
			expectedResponseCodes: []int{http.StatusOK},
		},
		{
			name: "bearer auth",
			httpAuth: &datasource.HTTPAuthentication{
				SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthBearer},
				AlwaysAuth:       true,
				BearerToken:      "abcdefgh",
			},
			requestURL:            "http://127.0.0.1/",
			expectedAuths:         []string{"Bearer abcdefgh"},
			expectedResponseCodes: []int{http.StatusOK},
		},
		{
			name: "bearer auth not always",
			httpAuth: &datasource.HTTPAuthentication{
				SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthBearer},
				AlwaysAuth:       false,
				BearerToken:      "abcdefgh",
			},
			requestURL:            "http://127.0.0.1/",
			wwwAuth:               []string{"Bearer"},
			expectedAuths:         []string{"", "Bearer abcdefgh"},
			expectedResponseCodes: []int{http.StatusOK},
		},
		{
			name: "always auth priority",
			httpAuth: &datasource.HTTPAuthentication{
				SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthBasic, datasource.AuthBearer},
				AlwaysAuth:       true,
				BasicAuth:        "UseThisOne",
				BearerToken:      "NotThisOne",
			},
			requestURL:            "http://127.0.0.1/",
			expectedAuths:         []string{"Basic UseThisOne"},
			expectedResponseCodes: []int{http.StatusOK},
		},
		{
			name: "not always auth priority",
			httpAuth: &datasource.HTTPAuthentication{
				SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthBearer, datasource.AuthDigest, datasource.AuthBasic},
				AlwaysAuth:       false,
				Username:         "DoNotUse",
				Password:         "ThisField",
				BearerToken:      "PleaseUseThis",
			},
			requestURL:            "http://127.0.0.1/",
			wwwAuth:               []string{"Basic", "Bearer"},
			expectedAuths:         []string{"", "Bearer PleaseUseThis"},
			expectedResponseCodes: []int{http.StatusOK},
		},
		{
			name: "digest auth",
			// Example from https://en.wikipedia.org/wiki/Digest_access_authentication#Example_with_explanation
			httpAuth: &datasource.HTTPAuthentication{
				SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthDigest},
				AlwaysAuth:       false,
				Username:         "Mufasa",
				Password:         "Circle Of Life",
				CnonceFunc:       func() string { return "0a4f113b" },
			},
			requestURL: "https://127.0.0.1/dir/index.html",
			wwwAuth: []string{
				"Digest realm=\"testrealm@host.com\", " +
					"qop=\"auth,auth-int\", " +
					"nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
					"opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
			},
			expectedAuths: []string{
				"",
				// The order of these fields shouldn't actually matter
				"Digest username=\"Mufasa\", " +
					"realm=\"testrealm@host.com\", " +
					"nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
					"uri=\"/dir/index.html\", " +
					"qop=auth, " +
					"nc=00000001, " +
					"cnonce=\"0a4f113b\", " +
					"response=\"6629fae49393a05397450978507c4ef1\", " +
					"opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
			},
			expectedResponseCodes: []int{http.StatusOK},
		},
		{
			name: "digest auth rfc2069", // old spec, without qop header
			httpAuth: &datasource.HTTPAuthentication{
				SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthDigest},
				AlwaysAuth:       false,
				Username:         "Mufasa",
				Password:         "Circle Of Life",
			},
			requestURL: "https://127.0.0.1/dir/index.html",
			wwwAuth: []string{
				"Digest realm=\"testrealm@host.com\", " +
					"nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
					"opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
			},
			expectedAuths: []string{
				"",
				// The order of these fields shouldn't actually matter
				"Digest username=\"Mufasa\", " +
					"realm=\"testrealm@host.com\", " +
					"nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", " +
					"uri=\"/dir/index.html\", " +
					"response=\"670fd8c2df070c60b045671b8b24ff02\", " +
					"opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
			},
			expectedResponseCodes: []int{http.StatusOK},
		},
		{
			name: "digest auth mvn",
			// From what mvn sends.
			httpAuth: &datasource.HTTPAuthentication{
				SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthDigest},
				AlwaysAuth:       false,
				Username:         "my-username",
				Password:         "cool-password",
				CnonceFunc:       func() string { return "f7ef2d457dabcd54" },
			},
			requestURL: "https://127.0.0.1:41565/commons-io/commons-io/1.0/commons-io-1.0.pom",
			wwwAuth: []string{
				"Digest realm=\"test@osv.dev\"," +
					"qop=\"auth\"," +
					"nonce=\"deadbeef\"," +
					"opaque=\"aaaa\"," +
					"algorithm=\"MD5-sess\"," +
					"domain=\"/test\"",
			},
			expectedAuths: []string{
				"",
				// The order of these fields shouldn't actually matter
				"Digest username=\"my-username\", " +
					"realm=\"test@osv.dev\", " +
					"nonce=\"deadbeef\", " +
					"uri=\"/commons-io/commons-io/1.0/commons-io-1.0.pom\", " +
					"qop=auth, " +
					"nc=00000001, " +
					"cnonce=\"f7ef2d457dabcd54\", " +
					"algorithm=MD5-sess, " +
					"response=\"15a35e7018a0fc7db05d31185e0d2c9e\", " +
					"opaque=\"aaaa\"",
			},
			expectedResponseCodes: []int{http.StatusOK},
		},
		{
			name: "basic auth reuse on subsequent",
			httpAuth: &datasource.HTTPAuthentication{
				SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthDigest, datasource.AuthBasic},
				AlwaysAuth:       false,
				Username:         "user",
				Password:         "pass",
			},
			requestURL:            "http://127.0.0.1/",
			wwwAuth:               []string{"Basic realm=\"Realm\""},
			expectedAuths:         []string{"", "Basic dXNlcjpwYXNz", "Basic dXNlcjpwYXNz"},
			expectedResponseCodes: []int{http.StatusOK, http.StatusOK},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mt := &mockTransport{}
			if len(tt.wwwAuth) > 0 {
				mt.UnauthedResponse = &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     make(http.Header),
				}
				for _, v := range tt.wwwAuth {
					mt.UnauthedResponse.Header.Add("WWW-Authenticate", v)
				}
			}
			httpClient := &http.Client{Transport: mt}
			for _, want := range tt.expectedResponseCodes {
				resp, err := tt.httpAuth.Get(context.Background(), httpClient, tt.requestURL)
				if err != nil {
					t.Fatalf("error making request: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != want {
					t.Errorf("authorization response status code got = %d, want %d", resp.StatusCode, want)
				}
			}
			if len(mt.Requests) != len(tt.expectedAuths) {
				t.Fatalf("unexpected number of requests got = %d, want %d", len(mt.Requests), len(tt.expectedAuths))
			}
			for i, want := range tt.expectedAuths {
				got := mt.Requests[i].Header.Get("Authorization")
				if got != want {
					t.Errorf("authorization header got = \"%s\", want \"%s\"", got, want)
				}
			}
		})
	}
}
