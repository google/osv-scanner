package config

import "time"

type IgnoreEntry struct {
	ID          string    `toml:"id"`
	IgnoreUntil time.Time `toml:"ignoreUntil"`
	Reason      string    `toml:"reason"`

	Used bool `toml:"-"`
}

func (ie *IgnoreEntry) MarkAsUsed() {
	ie.Used = true
}
