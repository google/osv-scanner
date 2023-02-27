package govulncheckshim

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/vuln/client"
	gvcOSV "golang.org/x/vuln/osv"

	"github.com/google/osv-scanner/pkg/models"
)

type localSource struct {
	vulnList         []models.Vulnerability
	vulnsByID        map[string]*models.Vulnerability
	vulnsByAlias     map[string][]*models.Vulnerability
	vulnsByModule    map[string][]*models.Vulnerability
	lastModifiedTime time.Time
	client.Client
}

func newClient(vulns []models.Vulnerability) *localSource {
	client := localSource{
		vulnList:         vulns,
		vulnsByID:        make(map[string]*models.Vulnerability),
		vulnsByAlias:     make(map[string][]*models.Vulnerability),
		vulnsByModule:    make(map[string][]*models.Vulnerability),
		lastModifiedTime: time.Unix(0, 0),
	}
	for idx := range vulns {
		// Iterate on reference to avoid copying entire data structure
		v := &client.vulnList[idx]
		client.vulnsByID[v.ID] = v
		for _, alias := range v.Aliases {
			client.vulnsByAlias[alias] = append(client.vulnsByAlias[alias], v)
		}
		for _, affected := range v.Affected {
			client.vulnsByModule[affected.Package.Name] = append(client.vulnsByModule[affected.Package.Name], v)
		}
		if client.lastModifiedTime.Before(v.Modified) {
			client.lastModifiedTime = v.Modified
		}
	}

	return &client
}

func convertToGvcOSV(osv models.Vulnerability) (gvcOSV.Entry, error) {
	val, err := json.Marshal(osv)
	if err != nil {
		return gvcOSV.Entry{}, fmt.Errorf("failed to convert vuln to JSON: %w", err)
	}
	response := gvcOSV.Entry{}
	err = json.Unmarshal(val, &response)
	if err != nil {
		return gvcOSV.Entry{}, fmt.Errorf("gvc format is no longer compatible with osv format: %w", err)
	}

	return response, nil
}

func (ls *localSource) GetByModule(ctx context.Context, modulePath string) ([]*gvcOSV.Entry, error) {
	//nolint:prealloc // Need to be nil if none exists
	var entries []*gvcOSV.Entry
	for _, v := range ls.vulnsByModule[modulePath] {
		res, err := convertToGvcOSV(*v)
		if err != nil {
			return nil, err
		}
		entries = append(entries, &res)
	}

	return entries, nil
}

func (ls *localSource) GetByID(ctx context.Context, id string) (*gvcOSV.Entry, error) {
	entry, ok := ls.vulnsByID[id]
	if !ok {
		//nolint:nilnil // This follows govulncheck's client implementation
		// See: https://github.com/golang/vuln/blob/master/client/client.go
		return nil, nil
	}
	response, err := convertToGvcOSV(*entry)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (ls *localSource) GetByAlias(ctx context.Context, alias string) ([]*gvcOSV.Entry, error) {
	//nolint:prealloc // Need to be nil if none exists
	var entries []*gvcOSV.Entry

	for _, v := range ls.vulnsByAlias[alias] {
		res, err := convertToGvcOSV(*v)
		if err != nil {
			return nil, err
		}
		entries = append(entries, &res)
	}

	return entries, nil
}

func (ls *localSource) ListIDs(ctx context.Context) ([]string, error) {
	//nolint:prealloc // Need to be nil if none exists
	var ids []string
	for i := range ls.vulnList {
		ids = append(ids, ls.vulnList[i].ID)
	}

	return ids, nil
}

func (ls *localSource) LastModifiedTime(context.Context) (time.Time, error) {
	// Assume that if anything changes, the index does.
	return ls.lastModifiedTime, nil
}
