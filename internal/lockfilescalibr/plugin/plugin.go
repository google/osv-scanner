package plugin

// Plugin is the part of the plugin interface that's shared between extractors and detectors.
type Plugin interface {
	// A unique name used to identify this plugin.
	Name() string
	// Plugin version, should get bumped whenever major changes are made.
	Version() int
}

// Requirements lists requirements that the plugin has about the environment its running on.
// Plugins that don't satisfy the scanning environments's requirements can't be enabled.
type Requirements struct {
	// Whether this extractor requires network access.
	Network bool

	// Whether this extractor requires a real filesystem. If true, extractors
	// may access the ScanInput file paths directly, bypassing the fs.FS.
	RealFS bool
}
