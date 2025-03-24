package datasource

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // used in Digest access authentication algorithm
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
)

type HTTPAuthMethod int

const (
	AuthBasic HTTPAuthMethod = iota
	AuthBearer
	AuthDigest
)

// HTTPAuthentication holds the information needed for general HTTP Authentication support.
// Requests made through this will automatically populate the relevant info in the Authorization headers.
// This is a general implementation and should be suitable for use with any ecosystem.
type HTTPAuthentication struct {
	SupportedMethods []HTTPAuthMethod // In order of preference, only one method will be attempted.

	// AlwaysAuth determines whether to always send auth headers.
	// If false, the server must respond with a WWW-Authenticate header which will be checked for supported methods.
	// Must be set to false to use Digest authentication.
	AlwaysAuth bool

	// Shared
	Username string // Basic & Digest, plain text.
	Password string // Basic & Digest, plain text.
	// Basic
	BasicAuth string // Base64-encoded username:password. Overrides Username & Password fields if set.
	// Bearer
	BearerToken string
	// Digest
	CnonceFunc func() string // Function used to generate cnonce string for Digest. OK to leave unassigned. Mostly for use in tests.

	lastUsed atomic.Value // The last-used authentication method - used when AlwaysAuth is false to automatically send Basic auth.
}

// Get makes an http GET request with the given http.Client.
// The Authorization Header will automatically be populated according to the fields in the HTTPAuthentication.
func (auth *HTTPAuthentication) Get(ctx context.Context, httpClient *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// For convenience, have the nil HTTPAuthentication just make an unauthenticated request.
	if auth == nil {
		return httpClient.Do(req)
	}

	if auth.AlwaysAuth {
		for _, method := range auth.SupportedMethods {
			ok := false
			switch method {
			case AuthBasic:
				ok = auth.addBasic(req)
			case AuthBearer:
				ok = auth.addBearer(req)
			case AuthDigest:
				// AuthDigest needs a challenge from WWW-Authenticate, so we cannot always add the auth.
			}
			if ok {
				break
			}
		}

		return httpClient.Do(req)
	}

	// If the last request we made to this server used Basic or Bearer auth, send the header with this request
	if lastUsed, ok := auth.lastUsed.Load().(HTTPAuthMethod); ok {
		switch lastUsed {
		case AuthBasic:
			auth.addBasic(req)
		case AuthBearer:
			auth.addBearer(req)
		case AuthDigest:
			// Cannot add AuthDigest without the challenge from the initial request.
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	wwwAuth := resp.Header.Values("WWW-Authenticate")

	ok := false
	var usedMethod HTTPAuthMethod
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for _, method := range auth.SupportedMethods {
		switch method {
		case AuthBasic:
			if auth.authIndex(wwwAuth, "Basic") >= 0 {
				ok = auth.addBasic(req)
			}
		case AuthBearer:
			if auth.authIndex(wwwAuth, "Bearer") >= 0 {
				ok = auth.addBearer(req)
			}
		case AuthDigest:
			if idx := auth.authIndex(wwwAuth, "Digest"); idx >= 0 {
				ok = auth.addDigest(req, wwwAuth[idx])
			}
		}
		if ok {
			usedMethod = method
			break
		}
	}

	if ok {
		defer resp.Body.Close() // Close the original request before we discard it.
		resp, err = httpClient.Do(req)
	}
	if resp.StatusCode == http.StatusOK {
		auth.lastUsed.Store(usedMethod)
	}
	// The original request's response will be returned if there is no matching methods.
	return resp, err
}

func (auth *HTTPAuthentication) authIndex(wwwAuth []string, authScheme string) int {
	return slices.IndexFunc(wwwAuth, func(s string) bool {
		scheme, _, _ := strings.Cut(s, " ")
		return scheme == authScheme
	})
}

func (auth *HTTPAuthentication) addBasic(req *http.Request) bool {
	if auth.BasicAuth != "" {
		req.Header.Set("Authorization", "Basic "+auth.BasicAuth)

		return true
	}

	if auth.Username != "" && auth.Password != "" {
		authStr := base64.StdEncoding.EncodeToString([]byte(auth.Username + ":" + auth.Password))
		req.Header.Set("Authorization", "Basic "+authStr)

		return true
	}

	return false
}

func (auth *HTTPAuthentication) addBearer(req *http.Request) bool {
	if auth.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+auth.BearerToken)

		return true
	}

	return false
}

func (auth *HTTPAuthentication) addDigest(req *http.Request, challenge string) bool {
	// Mostly following the algorithm as outlined in https://en.wikipedia.org/wiki/Digest_access_authentication
	// And also https://datatracker.ietf.org/doc/html/rfc2617
	if auth.Username == "" || auth.Password == "" {
		return false
	}
	params := auth.parseChallenge(challenge)
	realm, ok := params["realm"]
	if !ok {
		return false
	}

	nonce, ok := params["nonce"]
	if !ok {
		return false
	}
	var cnonce string

	ha1 := md5.Sum([]byte(auth.Username + ":" + realm + ":" + auth.Password)) //nolint:gosec
	switch params["algorithm"] {
	case "MD5-sess":
		cnonce = auth.cnonce()
		if cnonce == "" {
			return false
		}
		var b bytes.Buffer
		fmt.Fprintf(&b, "%x:%s:%s", ha1, nonce, cnonce)
		ha1 = md5.Sum(b.Bytes()) //nolint:gosec
	case "MD5":
	case "":
	default:
		return false
	}

	// Only support "auth" qop
	if qop, ok := params["qop"]; ok && !slices.Contains(strings.Split(qop, ","), "auth") {
		return false
	}

	uri := req.URL.Path // is this sufficient?

	ha2 := md5.Sum([]byte(req.Method + ":" + uri)) //nolint:gosec

	// hard-coding nonceCount to 1 since we don't make a request more than once
	nonceCount := "00000001"

	var b bytes.Buffer
	if _, ok := params["qop"]; ok {
		if cnonce == "" {
			cnonce = auth.cnonce()
			if cnonce == "" {
				return false
			}
		}
		fmt.Fprintf(&b, "%x:%s:%s:%s:%s:%x", ha1, nonce, nonceCount, cnonce, "auth", ha2)
	} else {
		fmt.Fprintf(&b, "%x:%s:%x", ha1, nonce, ha2)
	}
	response := md5.Sum(b.Bytes()) //nolint:gosec

	var sb strings.Builder
	fmt.Fprintf(&sb, "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\"",
		auth.Username, realm, nonce, uri)
	if _, ok := params["qop"]; ok {
		fmt.Fprintf(&sb, ", qop=auth, nc=%s, cnonce=\"%s\"", nonceCount, cnonce)
	}
	if alg, ok := params["algorithm"]; ok {
		fmt.Fprintf(&sb, ", algorithm=%s", alg)
	}
	fmt.Fprintf(&sb, ", response=\"%x\", opaque=\"%s\"", response, params["opaque"])

	req.Header.Add("Authorization", sb.String())

	return true
}

func (auth *HTTPAuthentication) parseChallenge(challenge string) map[string]string {
	// Parse the params out of the auth challenge header.
	// e.g. Digest realm="testrealm@host.com", qop="auth,auth-int" ->
	// {"realm": "testrealm@host.com", "qop", "auth,auth-int"}
	//
	// This isn't perfectly robust - some edge cases / weird headers may parse incorrectly.

	// Get rid of "Digest" prefix
	_, challenge, _ = strings.Cut(challenge, " ")

	parts := strings.Split(challenge, ",")
	// parts may have had a quoted comma, recombine if there's an unclosed quote.

	for i := 0; i < len(parts); {
		if strings.Count(parts[i], "\"")%2 == 1 && len(parts) > i+1 {
			parts[i] = parts[i] + "," + parts[i+1]
			parts = append(parts[:i+1], parts[i+2:]...)

			continue
		}
		i++
	}

	m := make(map[string]string)
	for _, part := range parts {
		key, val, _ := strings.Cut(part, "=")
		key = strings.Trim(key, " ")
		val = strings.Trim(val, " ")
		// remove quotes from quoted string
		val = strings.Trim(val, "\"")
		m[key] = val
	}

	return m
}

func (auth *HTTPAuthentication) cnonce() string {
	if auth.CnonceFunc != nil {
		return auth.CnonceFunc()
	}

	// for a default nonce use a random 8 bytes
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return ""
	}

	return hex.EncodeToString(b)
}
