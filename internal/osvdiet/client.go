// Package osvdiet provides an OSV.dev client that reduces the memory used by
// vulnerabilities, by keeping their full data on disk until it's needed.
package osvdiet

import (
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"osv.dev/bindings/go/api"
)

var global *Client

// Client wraps an osvdev.Client to reduce memory usage by returning "slimmed"
// vulnerabilities, with the full vulnerability data stored on disk so it can
// be retrieved if needed such as for outputting
type Client struct {
	backend osvdev.Client
	mu      sync.Mutex
	dir     string
}

// New returns a Client that uses the given backend for making requests.
//
// The same client will be used until Cleanup is called, after which
// the next New will return a new Client instance
func New(backend osvdev.Client) *Client {
	if global == nil {
		global = &Client{backend: backend}
	}

	return global
}

// Cleanup removes the global Client after clearing its storage directory.
//
// Subsequent calls to Fatten will fail unless a New Client is initialized.
func Cleanup() error {
	if global == nil {
		return nil
	}

	// todo: return, or ignore?
	err := os.RemoveAll(global.dir)

	global = nil

	return err
}

// getDirectory returns the temporary directory to store vulnerabilities in,
// creating it if it does not already exist
func (c *Client) getDirectory() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.dir != "" {
		return c.dir, nil
	}

	var err error

	c.dir, err = os.MkdirTemp("", "osv-scanner-vulnerabilities-")

	if err != nil {
		return "", err
	}

	return c.dir, nil
}

func (c *Client) Query(ctx context.Context, query *api.Query) (*api.VulnerabilityList, error) {
	return c.backend.Query(ctx, query)
}

func (c *Client) QueryBatch(ctx context.Context, queries []*api.Query) (*api.BatchVulnerabilityList, error) {
	return c.backend.QueryBatch(ctx, queries)
}

func (c *Client) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	// fetch the vuln data from the api...
	vuln, err := c.backend.GetVulnByID(ctx, id)

	if err != nil {
		return nil, err
	}

	// ...store the full data on disk...
	err = c.store(vuln)

	// todo: maybe we warn instead...?
	if err != nil {
		return nil, err
	}

	// ...and then return a slimmed version of the advisory
	return slim(vuln), nil
}

var _ osvdev.Client = &Client{}

// store writes the vulnerability to disk
func (c *Client) store(vuln *osvschema.Vulnerability) error {
	content, err := protojson.Marshal(vuln)

	if err != nil {
		return err
	}

	dir, err := c.getDirectory()

	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, vuln.GetId()+".json"), content, 0600)
}

// slim returns a version of the vulnerability with a subset of the available data
func slim(vuln *osvschema.Vulnerability) *osvschema.Vulnerability {
	vuln.References = nil
	vuln.DatabaseSpecific = nil
	vuln.Credits = nil
	vuln.Related = nil

	for _, affected := range vuln.GetAffected() {
		affected.DatabaseSpecific = nil
		affected.EcosystemSpecific = nil

		for _, rang := range affected.GetRanges() {
			rang.DatabaseSpecific = nil
		}

		affected.Versions = nil
	}

	return vuln
}

// Fatten returns a version of the vulnerability with all the available data
func Fatten(vuln *osvschema.Vulnerability) (*osvschema.Vulnerability, error) {
	dir, err := global.getDirectory()

	if err != nil {
		return nil, err
	}

	// todo: it's possible for other plugins to add vulns...
	content, err := os.ReadFile(filepath.Join(dir, vuln.GetId()+".json"))

	if err != nil {
		return nil, err
	}

	vulnerability := &osvschema.Vulnerability{}
	if err := protojson.Unmarshal(content, vulnerability); err != nil {
		return nil, err
	}

	return vulnerability, nil
}
