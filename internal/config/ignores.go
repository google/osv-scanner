package config

import "time"

type IgnoreEntry struct {
	ID             string    `toml:"id"`
	EffectiveUntil time.Time `toml:"effectiveUntil"`
	Reason         string    `toml:"reason"`

	Used bool `toml:"-"`

	// Deprecated: use EffectiveUntil
	IgnoreUntil time.Time `toml:"ignoreUntil"`
}

func (ie *IgnoreEntry) MarkAsUsed() {
	ie.Used = true
}
