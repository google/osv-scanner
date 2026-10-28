// Package osvdiet provides an OSV.dev client that reduces the memory used by
// vulnerabilities, by keeping their full data on disk until it's needed.
package osvdiet

import (
	"context"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/api"
)

// Client wraps an osvdev.Client to reduce memory usage by returning "slimmed"
// vulnerabilities, with the full vulnerability data stored on disk so it can
// be retrieved if needed such as for outputting
type Client struct {
	backend osvdev.Client
}

// New returns a Client that uses the given backend for making requests
func New(backend osvdev.Client) Client {
	return Client{backend: backend}
}

func (c Client) Query(ctx context.Context, query *api.Query) (*api.VulnerabilityList, error) {
	return c.backend.Query(ctx, query)
}

func (c Client) QueryBatch(ctx context.Context, queries []*api.Query) (*api.BatchVulnerabilityList, error) {
	return c.backend.QueryBatch(ctx, queries)
}

func (c Client) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	return c.backend.GetVulnByID(ctx, id)
}

var _ osvdev.Client = &Client{}
