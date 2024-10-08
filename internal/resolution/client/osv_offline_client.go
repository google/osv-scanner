package client

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/local"
	"github.com/google/osv-scanner/internal/resolution/util"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
)

type OSVOfflineClient struct {
	// TODO: OSV-Scanner v2 plans to make vulnerability clients that can be used here.
	offline     bool
	localDBPath string
	mu          sync.Mutex
}

func NewOSVOfflineClient(downloadDBs bool, localDBPath string) *OSVOfflineClient {
	return &OSVOfflineClient{
		offline:     !downloadDBs,
		localDBPath: localDBPath,
	}
}

func (c *OSVOfflineClient) FindVulns(g *resolve.Graph) ([]models.Vulnerabilities, error) {
	var query osv.BatchedQuery
	query.Queries = make([]*osv.Query, len(g.Nodes)-1)
	for i, node := range g.Nodes[1:] {
		query.Queries[i] = &osv.Query{
			Package: osv.Package{
				Name:      node.Version.Name,
				Ecosystem: string(util.OSVEcosystem[node.Version.System]),
			},
			Version: node.Version.Version,
		}
	}

	// local.MakeRequest only logs an error if the database cannot be found.
	// For guided remediation this should be a fatal error, since there's only the one ecosystem.
	// Set up a reporter to capture error logs and return the logs as an error.
	r := &errorReporter{}

	// Not entirely sure if the local database is thread safe.
	// Chucking it in a mutex just in case.
	c.mu.Lock()
	hydrated, err := local.MakeRequest(r, query, c.offline, c.localDBPath)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}

	if r.HasErrored() {
		return nil, r.GetError()
	}

	nodeVulns := make([]models.Vulnerabilities, len(g.Nodes))
	for i, res := range hydrated.Results {
		nodeVulns[i+1] = res.Vulns
	}

	return nodeVulns, nil
}

// errorReporter is a reporter.Reporter to capture error logs and pack them into an error.
type errorReporter struct {
	s strings.Builder
}

func (r *errorReporter) Errorf(format string, a ...any) {
	fmt.Fprintf(&r.s, format, a...)
}

func (r *errorReporter) HasErrored() bool {
	return r.s.Len() > 0
}

func (r *errorReporter) GetError() error {
	str := strings.TrimSpace(r.s.String())
	if str == "" {
		return nil
	}

	return errors.New(str)
}

func (r *errorReporter) Warnf(string, ...any)                           {}
func (r *errorReporter) Infof(string, ...any)                           {}
func (r *errorReporter) Verbosef(string, ...any)                        {}
func (r *errorReporter) PrintResult(*models.VulnerabilityResults) error { return nil }
