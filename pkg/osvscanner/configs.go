package osvscanner

import (
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func addVulnConfigIgnoresAndSave(vulnResults *models.VulnerabilityResults, manager *config.Manager) error {
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

		err := c.Save()
		if err != nil {
			return err
		}
	}

	return nil
}

func removeUnusedConfigIgnoresAndSave(conf *config.Config) error {
	ignoredVulnsCount := len(conf.IgnoredVulns)
	conf.RemoveUnusedIgnores()

	// don't bother saving if nothing was removed
	if ignoredVulnsCount == len(conf.IgnoredVulns) {
		return nil
	}

	err := conf.Save()
	if err != nil {
		return err
	}

	removed := ignoredVulnsCount-len(conf.IgnoredVulns)

	// todo: might be nice to log what was removed?
	cmdlogger.Infof(
		"Removed %d unused ignore %s from %s",
		removed,
		output.Form(removed, "entry", "entries"),
		conf.LoadPath,
	)

	return nil
}

func removeAllUnusedConfigIgnoresAndSave(manager *config.Manager) error {
	if manager.OverrideConfig != nil {
		err := removeUnusedConfigIgnoresAndSave(manager.OverrideConfig)

		if err != nil {
			return err
		}
	}

	for _, c := range manager.ConfigMap {
		// skip the default config
		if c.LoadPath == "" {
			continue
		}

		err := removeUnusedConfigIgnoresAndSave(c)

		if err != nil {
			return err
		}
	}

	return nil
}
