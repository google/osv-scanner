package datasource

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	pb "deps.dev/api/v3"
	"github.com/google/osv-scanner/pkg/osv"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// DepsDevAPIClient is a wrapper for InsightsClient that caches requests.
type DepsDevAPIClient struct {
	pb.InsightsClient

	// cache fields
	mu                sync.Mutex
	cacheTimestamp    *time.Time
	packageCache      map[packageKey]*pb.Package
	versionCache      map[versionKey]*pb.Version
	requirementsCache map[versionKey]*pb.Requirements

	group *singleflight.Group
}

// Comparable types to use as map keys for cache.
type packageKey struct {
	System pb.System
	Name   string
}

func makePackageKey(k *pb.PackageKey) packageKey {
	return packageKey{
		System: k.GetSystem(),
		Name:   k.GetName(),
	}
}

type versionKey struct {
	System  pb.System
	Name    string
	Version string
}

func makeVersionKey(k *pb.VersionKey) versionKey {
	return versionKey{
		System:  k.GetSystem(),
		Name:    k.GetName(),
		Version: k.GetVersion(),
	}
}

func NewDepsDevAPIClient(addr string) (*DepsDevAPIClient, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("getting system cert pool: %w", err)
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	if osv.RequestUserAgent != "" {
		dialOpts = append(dialOpts, grpc.WithUserAgent(osv.RequestUserAgent))
	}

	conn, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dialling %q: %w", addr, err)
	}
	c := pb.NewInsightsClient(conn)

	return &DepsDevAPIClient{
		InsightsClient:    c,
		packageCache:      make(map[packageKey]*pb.Package),
		versionCache:      make(map[versionKey]*pb.Version),
		requirementsCache: make(map[versionKey]*pb.Requirements),
		group:             &singleflight.Group{},
	}, nil
}

//nolint:dupl
func (c *DepsDevAPIClient) GetPackage(ctx context.Context, in *pb.GetPackageRequest, opts ...grpc.CallOption) (*pb.Package, error) {
	key := makePackageKey(in.GetPackageKey())
	c.mu.Lock()
	pkg, ok := c.packageCache[key]
	c.mu.Unlock()
	if ok {
		return pkg, nil
	}

	groupKey := fmt.Sprintf("GetPackage%v", key)
	res, err, _ := c.group.Do(groupKey, func() (interface{}, error) {
		pkg, err := c.InsightsClient.GetPackage(ctx, in, opts...)
		if err == nil {
			c.mu.Lock()
			c.packageCache[key] = pkg
			c.mu.Unlock()
		}

		return pkg, err
	})

	c.group.Forget(groupKey)

	return res.(*pb.Package), err
}

//nolint:dupl
func (c *DepsDevAPIClient) GetVersion(ctx context.Context, in *pb.GetVersionRequest, opts ...grpc.CallOption) (*pb.Version, error) {
	key := makeVersionKey(in.GetVersionKey())
	c.mu.Lock()
	ver, ok := c.versionCache[key]
	c.mu.Unlock()
	if ok {
		return ver, nil
	}

	groupKey := fmt.Sprintf("GetVersion%v", key)
	res, err, _ := c.group.Do(groupKey, func() (interface{}, error) {
		ver, err := c.InsightsClient.GetVersion(ctx, in, opts...)
		if err == nil {
			c.mu.Lock()
			c.versionCache[key] = ver
			c.mu.Unlock()
		}

		return ver, err
	})

	c.group.Forget(groupKey)

	return res.(*pb.Version), err
}

//nolint:dupl
func (c *DepsDevAPIClient) GetRequirements(ctx context.Context, in *pb.GetRequirementsRequest, opts ...grpc.CallOption) (*pb.Requirements, error) {
	key := makeVersionKey(in.GetVersionKey())
	c.mu.Lock()
	req, ok := c.requirementsCache[key]
	c.mu.Unlock()
	if ok {
		return req, nil
	}

	groupKey := fmt.Sprintf("GetRequirement%v", key)
	res, err, _ := c.group.Do(groupKey, func() (interface{}, error) {
		req, err := c.InsightsClient.GetRequirements(ctx, in, opts...)
		if err == nil {
			c.mu.Lock()
			c.requirementsCache[key] = req
			c.mu.Unlock()
		}

		return req, err
	})

	c.group.Forget(groupKey)

	return res.(*pb.Requirements), err
}
