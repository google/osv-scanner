// Package osvdiet provides an OSV.dev client that reduces the memory used by
// vulnerabilities, by keeping their full data on disk until it's needed.
package osvdiet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"weak"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"osv.dev/bindings/go/api"
)

// ErrFullDataUnavailable is returned by Fatten when a vulnerability was
// slimmed but its full data is no longer available, e.g. after Cleanup
var ErrFullDataUnavailable = errors.New("full vulnerability data is not available")

// slimmed tracks (weak) pointers to osvschema.Vulnerability that have been slimmed
var slimmed sync.Map

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
	return &Client{backend: backend}
}

// Cleanup removes the global Client after clearing its storage directory.
//
// Subsequent calls to Fatten will fail unless a New Client is initialized.
func Cleanup() {
	seen := map[any]bool{}

	// todo: it might be more efficient to store the "slimmed" map on the client
	//  and have a global slice of clients...
	slimmed.Range(func(_, value any) bool {
		if !seen[value] {
			seen[value] = true
			client := value.(*Client)

			// todo: return, or ignore?
			err := os.RemoveAll(client.dir)

			if err != nil {
				cmdlogger.Warnf("failed to remove %s: %v", client.dir, err)
			}
		}

		return true
	})
	slimmed.Clear()
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

// slim trims the data of the vulnerability to only what the scanner needs
func (c *Client) slim(vuln *osvschema.Vulnerability) {
	slimmed.Store(weak.Make(vuln), c)

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
func Fatten(vuln *osvschema.Vulnerability) (*osvschema.Vulnerability, error) {
	key, ok := slimmed.Load(weak.Make(vuln))

	// if the vuln isn't slim, return it immediately
	if !ok {
		return vuln, nil
	}

	var client *Client

	if key != nil {
		client = key.(*Client)
	}

	if client == nil || client.dir == "" {
		return nil, fmt.Errorf("%w: %s", ErrFullDataUnavailable, vuln.GetId())
	}

	content, err := os.ReadFile(filepath.Join(client.dir, vuln.GetId()+".json"))

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
