// Package osvdiet provides an OSV.dev client that reduces the memory used by
// vulnerabilities, by keeping their full data on disk until it's needed.
package osvdiet

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"weak"

	scalibrosvdev "github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/osvdev"
)

// ErrFullDataUnavailable is returned by Fatten when a vulnerability was
// slimmed but its full data is no longer available, e.g. after Cleanup
var ErrFullDataUnavailable = errors.New("full vulnerability data is not available")

// Client wraps an osvdev.Client to reduce memory usage by returning "slimmed"
// vulnerabilities, with the full vulnerability data stored on disk so it can
// be retrieved if needed such as for outputting
type Client struct {
	backend scalibrosvdev.Client
	mu      sync.Mutex

	// root is the directory vulnerabilities are stored in
	root *os.Root

	// slimmed tracks (weak) pointers to osvschema.Vulnerability that have been slimmed
	slimmed sync.Map
}

// New returns a Client that can be used by osvdev.Enricher to make requests
func New(httpClient *http.Client, userAgent string) *Client {
	cfg := osvdev.DefaultConfig()
	cfg.UserAgent = userAgent

	return &Client{
		backend: &osvdev.OSVClient{
			HTTPClient:  httpClient,
			Config:      cfg,
			BaseHostURL: osvdev.DefaultBaseURL,
		},
	}
}

// Cleanup removes any vulnerabilities this Client has saved to disk
func (c *Client) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.root == nil {
		return
	}

	dir := c.root.Name()

	if err := c.root.Close(); err != nil {
		cmdlogger.Warnf("failed to close %s: %v", dir, err)
	}

	if err := os.RemoveAll(dir); err != nil {
		cmdlogger.Warnf("failed to remove %s: %v", dir, err)
	}

	c.root = nil
}

// getRoot returns the temporary directory to store vulnerabilities in,
// creating it if it does not already exist
func (c *Client) getRoot() (*os.Root, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.root != nil {
		return c.root, nil
	}

	dir, err := os.MkdirTemp("", "osv-scanner-vulnerabilities-")

	if err != nil {
		return nil, err
	}

	c.root, err = os.OpenRoot(dir)

	if err != nil {
		_ = os.RemoveAll(dir)

		return nil, err
	}

	return c.root, nil
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

	// ...attempt to store the full vulnerability on disk,
	// returning it in full if we can't for some reason...
	if err = c.store(vuln); err != nil {
		cmdlogger.Warnf("Failed to store full data for %s, so it will be kept in memory: %v", id, err)

		return vuln, nil
	}

	// ...otherwise, return a slimmed version of the vulnerability
	c.slim(vuln)

	return vuln, nil
}

var _ scalibrosvdev.Client = &Client{}

// store writes the vulnerability to disk
func (c *Client) store(vuln *osvschema.Vulnerability) error {
	content, err := protojson.Marshal(vuln)

	if err != nil {
		return err
	}

	root, err := c.getRoot()

	if err != nil {
		return err
	}

	return root.WriteFile(vuln.GetId()+".json", content, 0600)
}

// slim trims the data of the vulnerability to only what the scanner needs
func (c *Client) slim(vuln *osvschema.Vulnerability) {
	c.slimmed.Store(weak.Make(vuln), c)

	// vuln.References = nil
	vuln.DatabaseSpecific = nil
	// vuln.Credits = nil
	// vuln.Related = nil

	for _, affected := range vuln.GetAffected() {
		affected.DatabaseSpecific = nil
		affected.EcosystemSpecific = only(affected.GetEcosystemSpecific(), []string{
			"urgency",
			"ubuntu_priority",
			"affects",
			"imports",
		})

		for _, rang := range affected.GetRanges() {
			rang.DatabaseSpecific = nil
		}

		affected.Versions = nil
	}
}

func only(currentStruct *structpb.Struct, fields []string) *structpb.Struct {
	currentFields := currentStruct.GetFields()

	if len(currentFields) == 0 {
		return nil
	}

	newStruct := &structpb.Struct{Fields: make(map[string]*structpb.Value, len(fields))}

	for _, field := range fields {
		if currentValue, ok := currentFields[field]; ok {
			newStruct.Fields[field] = currentValue
		}
	}

	if len(newStruct.GetFields()) == 0 {
		return nil
	}

	return newStruct
}

// Fatten returns a version of the vulnerability with all the available data
func (c *Client) Fatten(vuln *osvschema.Vulnerability) (*osvschema.Vulnerability, error) {
	_, ok := c.slimmed.Load(weak.Make(vuln))

	// if the vuln isn't slim, return it immediately
	if !ok {
		return vuln, nil
	}

	c.mu.Lock()
	root := c.root
	c.mu.Unlock()

	if root == nil {
		return nil, fmt.Errorf("%w: %s", ErrFullDataUnavailable, vuln.GetId())
	}

	content, err := root.ReadFile(vuln.GetId() + ".json")

	if err != nil {
		return nil, fmt.Errorf("reading full data for %s: %w", vuln.GetId(), err)
	}

	vulnerability := &osvschema.Vulnerability{}
	err = protojson.Unmarshal(content, vulnerability)

	if err != nil {
		return nil, fmt.Errorf("parsing full data for %s: %w", vuln.GetId(), err)
	}

	return vulnerability, nil
}
