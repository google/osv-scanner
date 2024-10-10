package client

import (
	"errors"
	"fmt"
	"strings"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/local"
	"github.com/google/osv-scanner/internal/resolution/util"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
	"github.com/google/osv-scanner/pkg/reporter"
)

type OSVOfflineClient struct {
	// TODO: OSV-Scanner v2 plans to make vulnerability clients that can be used here.
	localDBPath string
}

func NewOSVOfflineClient(r reporter.Reporter, system resolve.System, downloadDBs bool, localDBPath string) (*OSVOfflineClient, error) {
	if system == resolve.UnknownSystem {
		return nil, errors.New("osv offline client created with unknown ecosystem")
	}
	// Make a dummy request to the local client to log and make sure the database is downloaded without error.
	q := osv.BatchedQuery{Queries: []*osv.Query{{
		Package: osv.Package{
			Name:      "foo",
			Ecosystem: string(util.OSVEcosystem[system]),
		},
		Version: "1.0.0",
	}}}
	_, err := local.MakeRequest(r, q, !downloadDBs, localDBPath)
	if err != nil {
		return nil, err
	}

	if r.HasErrored() {
		return nil, errors.New("error creating osv offline client")
	}

	return &OSVOfflineClient{localDBPath: localDBPath}, nil
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

	// If local.MakeRequest logs an error, it's probably fatal for guided remediation.
	// Set up a reporter to capture error logs and return the logs as an error.
	r := &errorReporter{}
	// DB should already be downloaded, set offline to true.
	hydrated, err := local.MakeRequest(r, query, true, c.localDBPath)

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
