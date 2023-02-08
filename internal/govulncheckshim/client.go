package govulncheckshim

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/vuln/client"
	gvcOSV "golang.org/x/vuln/osv"
)

type localSource struct {
	vulnList         []models.Vulnerability
	response         map[string]*models.Vulnerability
	aliasToIDs       map[string][]*models.Vulnerability
	moduleToIDs      map[string][]*models.Vulnerability
	lastModifiedTime time.Time
	client.Client
}

func newClient(vulns []models.Vulnerability) *localSource {
	outLs := localSource{
		vulnList:         vulns,
		response:         make(map[string]*models.Vulnerability),
		aliasToIDs:       make(map[string][]*models.Vulnerability),
		moduleToIDs:      make(map[string][]*models.Vulnerability),
		lastModifiedTime: time.Unix(0, 0),
	}
	for idx := range vulns {
		// Iterate on reference to avoid copying entire data structure
		v := &outLs.vulnList[idx]
		outLs.response[v.ID] = v
		for _, alias := range v.Aliases {
			outLs.aliasToIDs[alias] = append(outLs.aliasToIDs[alias], v)
		}
		for _, affected := range v.Affected {
			outLs.moduleToIDs[affected.Package.Name] = append(outLs.moduleToIDs[affected.Package.Name], v)
		}
		if outLs.lastModifiedTime.Before(v.Modified) {
			outLs.lastModifiedTime = v.Modified
		}
	}

	return &outLs
}

func convertToGvcOSV(osv models.Vulnerability) gvcOSV.Entry {
	val, err := json.Marshal(osv)
	if err != nil {
		panic("failed to convert vulnerability")
	}
	response := gvcOSV.Entry{}
	err = json.Unmarshal(val, &response)
	if err != nil {
		panic("gvc format is no longer compatible with osv format")
	}

	return response
}

func (ls *localSource) GetByModule(ctx context.Context, modulePath string) ([]*gvcOSV.Entry, error) {
	//nolint:prealloc // Need to be nil if none exists
	var entries []*gvcOSV.Entry = nil
	for _, v := range ls.moduleToIDs[modulePath] {
		res := convertToGvcOSV(*v)
		entries = append(entries, &res)
	}

	return entries, nil
}

func (ls *localSource) GetByID(ctx context.Context, id string) (*gvcOSV.Entry, error) {
	entry, ok := ls.response[id]
	if !ok {
		//nolint:nilnil // This follows govulncheck's client implementation
		// See: https://github.com/golang/vuln/blob/master/client/client.go
		return nil, nil
	}
	response := convertToGvcOSV(*entry)

	return &response, nil
}

func (ls *localSource) GetByAlias(ctx context.Context, alias string) ([]*gvcOSV.Entry, error) {
	//nolint:prealloc // Need to be nil if none exists
	var entries []*gvcOSV.Entry = nil

	for _, v := range ls.aliasToIDs[alias] {
		res := convertToGvcOSV(*v)
		entries = append(entries, &res)
	}

	return entries, nil
}

func (ls *localSource) ListIDs(ctx context.Context) ([]string, error) {
	//nolint:prealloc // Need to be nil if none exists
	var ids []string = nil
	for i := range ls.vulnList {
		ids = append(ids, ls.vulnList[i].ID)
	}

	return ids, nil
}

func (ls *localSource) LastModifiedTime(context.Context) (time.Time, error) {
	// Assume that if anything changes, the index does.
	return ls.lastModifiedTime, nil
}
