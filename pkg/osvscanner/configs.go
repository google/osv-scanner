package osvscanner

import (
	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func addVulnConfigIgnores(vulnResults *models.VulnerabilityResults, manager *config.Manager) {
	configVulns := make(map[string][]*osvschema.Vulnerability)
	configPaths := make(map[string]config.Config)

	for _, pkgSrc := range vulnResults.Results {
		c := manager.Get(pkgSrc.Source.Path)

		// skip the default config
		if c.LoadPath == "" {
			continue
		}

		configPaths[c.LoadPath] = c

		for _, pkgVulns := range pkgSrc.Packages {
			configVulns[c.LoadPath] = append(configVulns[c.LoadPath], pkgVulns.Vulnerabilities...)
		}
	}

	// update each config to ignore all the vulnerabilities
	// found across all packages that are using that config
	for p, vulns := range configVulns {
		c := configPaths[p]

		c.IgnoreVulns(vulns)
	}
}

func removeAllUnusedConfigIgnores(manager *config.Manager) {
	if manager.OverrideConfig != nil {
		manager.OverrideConfig.RemoveUnusedIgnores()
	}

	for _, c := range manager.ConfigMap {
		// skip the default config
		if c.LoadPath == "" {
			continue
		}

		c.RemoveUnusedIgnores()
	}
}

func saveAllConfigs(manager *config.Manager) error {
	if manager.OverrideConfig != nil {
		err := manager.OverrideConfig.Save()
		if err != nil {
			return err
		}
	}

	for _, c := range manager.ConfigMap {
		// skip the default config
		if c.LoadPath == "" {
			continue
		}

		err := c.Save()
		if err != nil {
			return err
		}
	}

	return nil
}
