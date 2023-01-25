package govulncheckshim

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/exp/govulncheck"
	gvcOSV "golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

type packageError struct {
	Errors []packages.Error
}

func (e *packageError) Error() string {
	var b strings.Builder
	fmt.Fprintln(&b, "Packages contain errors:")
	for _, e := range e.Errors {
		fmt.Fprintln(&b, e)
	}

	return b.String()
}

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
	json.Unmarshal(val, &response)

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

func RunVulnCheck(path string, vulns []models.Vulnerability) (*govulncheck.Result, error) {
	scanPath := filepath.Join(path, "...")
	client := newClient(vulns)
	cfg := &govulncheck.Config{Client: client}
	var res *govulncheck.Result
	var pkgs []*vulncheck.Package
	pkgs, err := loadPackages([]string{scanPath}, filepath.Dir(scanPath))
	if err != nil {
		panic(err)
	}
	res, err = govulncheck.Source(context.Background(), cfg, pkgs)

	return res, err
}

// loadPackages loads the packages matching patterns at dir using build tags
// provided by tagsFlag. Uses load mode needed for vulncheck analysis. If the
// packages contain errors, a packageError is returned containing a list of
// the errors, along with the packages themselves.
func loadPackages(patterns []string, dir string) ([]*vulncheck.Package, error) {
	var buildFlags []string
	// if tagsFlag != nil {
	// 	buildFlags = []string{fmt.Sprintf("-tags=%s", strings.Join(tagsFlag, ","))}
	// }

	cfg := &packages.Config{Dir: dir, Tests: true}
	cfg.Mode |= packages.NeedName | packages.NeedImports | packages.NeedTypes |
		packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
		packages.NeedModule
	cfg.BuildFlags = buildFlags

	pkgs, err := packages.Load(cfg, patterns...)
	vpkgs := vulncheck.Convert(pkgs)
	if err != nil {
		return nil, err
	}
	var perrs []packages.Error
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		perrs = append(perrs, p.Errors...)
	})
	if len(perrs) > 0 {
		err = &packageError{perrs}
	}

	return vpkgs, err
}
