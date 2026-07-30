// Package scalibr provides custom client factories and integrations for the osv-scalibr engine.
package scalibr

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/google/osv-scalibr/plugin/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type grpcClientConnCloser interface {
	grpc.ClientConnInterface
	Close() error
}

// ClientFactories implements scalibrconfig.ClientFactories for osv-scanner.
type ClientFactories struct {
	mu               sync.Mutex
	baseHTTPClient   *http.Client
	grpcClientConns  map[string]grpcClientConnCloser
	defaultUserAgent string
}

var _ config.ClientFactories = (*ClientFactories)(nil)

// NewClientFactories returns a new ClientFactories instance.
func NewClientFactories(baseHTTPClient *http.Client, defaultUserAgent string) *ClientFactories {
	if baseHTTPClient == nil {
		baseHTTPClient = &http.Client{}
	}

	return &ClientFactories{
		baseHTTPClient:   baseHTTPClient,
		grpcClientConns:  make(map[string]grpcClientConnCloser),
		defaultUserAgent: defaultUserAgent,
	}
}

type userAgentRoundTripper struct {
	underlying http.RoundTripper
	userAgent  string
}

// RoundTrip implements http.RoundTripper to inject a default User-Agent header
// if one is not already set.
func (rt *userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" && rt.userAgent != "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", rt.userAgent)
	}

	return rt.underlying.RoundTrip(req)
}

// HTTPClient returns a copy of the base HTTP client configured with User-Agent injection.
func (c *ClientFactories) HTTPClient() *http.Client {
	transport := c.baseHTTPClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	clientCopy := *c.baseHTTPClient
	clientCopy.Transport = &userAgentRoundTripper{
		underlying: transport,
		userAgent:  c.defaultUserAgent,
	}

	return &clientCopy
}

func (c *ClientFactories) GoogleHTTPClient(_ context.Context, _ ...string) (*http.Client, error) {
	return nil, errors.New("unimplemented, this should not be used from osv-scanner")
}

// GRPCClientConn returns a cached gRPC client connection from a package-level connection cache.
func (c *ClientFactories) GRPCClientConn(url string, dialOpts ...grpc.DialOption) (grpc.ClientConnInterface, error) {
	c.mu.Lock()
	if conn, ok := c.grpcClientConns[url]; ok {
		c.mu.Unlock()
		return conn, nil
	}
	c.mu.Unlock()

	// Perform system cert pool loading and gRPC client creation outside the critical section
	// to avoid lock contention across concurrent callers while dialing external endpoints.
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system cert pool: %w", err)
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")

	ourDialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if c.defaultUserAgent != "" {
		ourDialOpts = append(ourDialOpts, grpc.WithUserAgent(c.defaultUserAgent))
	}
	ourDialOpts = append(ourDialOpts, dialOpts...)

	realConn, err := grpc.NewClient(url, ourDialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial gRPC endpoint %s: %w", url, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check if another goroutine created and stored a connection for this URL in the meantime.
	if conn, ok := c.grpcClientConns[url]; ok {
		_ = realConn.Close()
		return conn, nil
	}

	c.grpcClientConns[url] = realConn

	return realConn, nil
}

// Close closes all open cached gRPC connections.
func (c *ClientFactories) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error
	for url, conn := range c.grpcClientConns {
		if err := conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close connection to %s: %w", url, err))
		}
		delete(c.grpcClientConns, url)
	}

	return errors.Join(errs...)
}
