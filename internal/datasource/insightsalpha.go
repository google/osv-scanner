package datasource

import (
	"crypto/x509"
	"fmt"

	pb "deps.dev/api/v3alpha"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// NewInsightsAlphaClient creates a deps.dev v3alpha InsightsClient with a custom address and userAgent.
func NewInsightsAlphaClient(addr string, userAgent string) (pb.InsightsClient, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("getting system cert pool: %w", err)
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	if userAgent != "" {
		dialOpts = append(dialOpts, grpc.WithUserAgent(userAgent))
	}

	conn, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dialling %q: %w", addr, err)
	}

	return pb.NewInsightsClient(conn), nil
}
