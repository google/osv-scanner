package config

// OmitUnexpiredLicenseOverrides removes any overrides that relate only to licenses
func OmitUnexpiredLicenseOverrides(overrides []*PackageOverrideEntry) []*PackageOverrideEntry {
	var collected []*PackageOverrideEntry

	for _, override := range overrides {
		hasLicenseOverride := override.License.Ignore || len(override.License.Override) > 0

		if shouldIgnoreTimestamp(override.EffectiveUntil) && hasLicenseOverride && !override.Ignore && !override.Vulnerability.Ignore {
			continue
		}

		collected = append(collected, override)
	}

	return collected
}
