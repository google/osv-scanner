package config

import "time"

type IgnoreEntry struct {
	ID             string    `toml:"id"`
	EffectiveUntil time.Time `toml:"effectiveUntil,omitempty"`
	Reason         string    `toml:"reason,omitempty"`

	Used bool `toml:"-"`

	// Deprecated: use EffectiveUntil
	IgnoreUntil time.Time `toml:"ignoreUntil,omitempty"`
}

func (ie *IgnoreEntry) MarkAsUsed() {
	ie.Used = true
}
