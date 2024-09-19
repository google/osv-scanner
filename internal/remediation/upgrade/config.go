package upgrade

type Config map[string]Level

func NewConfig() Config {
	return make(Config)
}

// Set the allowed upgrade level for a given pkg name.
// If level for pkg was previously set, sets the package to the new level and returns true.
// Otherwise, sets the package's level and returns false.
func (c Config) Set(pkg string, level Level) bool {
	_, alreadySet := c[pkg]
	c[pkg] = level

	return alreadySet
}

// SetDefault sets the default allowed upgrade level packages that weren't explicitly set.
// If default was previously set, sets the default to the new level and returns true.
// Otherwise, sets the default and returns false.
func (c Config) SetDefault(level Level) bool {
	// Empty package name is used as the default level.
	return c.Set("", level)
}

// Get the allowed Level for the given pkg name.
func (c Config) Get(pkg string) Level {
	if lvl, ok := c[pkg]; ok {
		return lvl
	}

	// Empty package name is used as the default level.
	return c[""]
}
