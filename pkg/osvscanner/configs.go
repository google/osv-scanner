package osvscanner

import (
	"maps"
	"slices"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func addVulnConfigIgnoresAndSave(vulnResults *models.VulnerabilityResults, manager *config.Manager) (map[string]int, error) {
	configVulns := make(map[string][]*osvschema.Vulnerability)
	configPaths := make(map[string]config.Config)

	counts := make(map[string]int)

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
			return counts, err
		}

		counts[c.LoadPath] = len(c.IgnoredVulns)
	}

	return counts, nil
}

func removeUnusedConfigIgnoresAndSave(conf *config.Config) ([]*config.IgnoreEntry, error) {
	ignoredVulnsCount := len(conf.IgnoredVulns)
	removed := conf.RemoveUnusedIgnores()

	// don't bother saving if nothing was removed
	if ignoredVulnsCount == len(conf.IgnoredVulns) {
		return nil, nil
	}

	err := conf.Save()
	if err != nil {
		return nil, err
	}

	return removed, nil
}

func removeAllUnusedConfigIgnoresAndSave(manager *config.Manager) (map[string][]*config.IgnoreEntry, error) {
	entries := make(map[string][]*config.IgnoreEntry)

	if manager.OverrideConfig != nil {
		removed, err := removeUnusedConfigIgnoresAndSave(manager.OverrideConfig)

		if err != nil {
			return entries, err
		}

		if len(removed) > 0 {
			entries[manager.OverrideConfig.LoadPath] = removed
		}
	}

	for _, c := range manager.ConfigMap {
		// skip the default config
		if c.LoadPath == "" {
			continue
		}

		removed, err := removeUnusedConfigIgnoresAndSave(c)

		if err != nil {
			return entries, err
		}

		if len(removed) > 0 {
			entries[c.LoadPath] = removed
		}
	}

	return entries, nil
}

func reportOnUnusedIgnoreActions(unusedIgnoreEntries map[string][]*config.IgnoreEntry, action string) {
	configFiles := slices.Collect(maps.Keys(unusedIgnoreEntries))
	slices.Sort(configFiles)

	for _, configFile := range configFiles {
		cmdlogger.Warnf("%s %s:", configFile, action)

		for _, iv := range unusedIgnoreEntries[configFile] {
			cmdlogger.Warnf(" - %s", iv.ID)
		}
	}
}

func handleUnusedIgnoreEntries(manager *config.Manager, remove bool) error {
	if remove {
		removedIgnoreEntries, err := removeAllUnusedConfigIgnoresAndSave(manager)

		// for once, we do this before checking the error as we might have successfully
		// updated some configs before hitting an error saving, if running recursively
		if len(removedIgnoreEntries) != 0 {
			reportOnUnusedIgnoreActions(removedIgnoreEntries, "had unused ignores that were removed")
		}

		if err != nil {
			return err
		}

		return nil
	}

	if unusedIgnoredEntries := manager.GetUnusedIgnoreEntries(); len(unusedIgnoredEntries) != 0 {
		reportOnUnusedIgnoreActions(unusedIgnoredEntries, "has unused ignores")
	}

	return nil
}
