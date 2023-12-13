package lockfile

// Returns a slice of all known ecosystems, matching the results in pkg/models.
func KnownEcosystems() []Ecosystem {
	return []Ecosystem{
		NpmEcosystem,
		NuGetEcosystem,
		CargoEcosystem,
		BundlerEcosystem,
		ComposerEcosystem,
		GoEcosystem,
		MixEcosystem,
		MavenEcosystem,
		PipEcosystem,
		PubEcosystem,
		ConanEcosystem,
		CRANEcosystem,
		// Disabled temporarily,
		// see https://github.com/google/osv-scanner/pull/128 discussion for additional context
		// AlpineEcosystem,
	}
}
