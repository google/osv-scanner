package govulncheckshim

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/exp/govulncheck"
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

// RunVulnCheck runs govulncheck with a subset of vulnerabilities identified by osv-scanner
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
