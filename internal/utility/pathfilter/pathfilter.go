// Package pathfilter provides utilities for filtering and sanitizing file paths to prevent path traversal.
package pathfilter

import (
	"path/filepath"
	"strings"
)

// FilterPath removes any ".." components from the path to prevent path traversal.
// It cleans the path first, then removes any ".." components.
// If the path becomes empty or only contains "." after filtering, it returns ".".
func FilterPath(p string) string {
	if p == "" {
		return ""
	}

	cleaned := filepath.Clean(p)

	// Split into volume and path (for Windows compatibility)
	vol := filepath.VolumeName(cleaned)
	rel := cleaned[len(vol):]

	components := strings.Split(rel, string(filepath.Separator))
	var filtered []string
	for _, c := range components {
		if c == ".." || c == "." || c == "" {
			continue
		}
		filtered = append(filtered, c)
	}

	rejoined := filepath.Join(filtered...)
	if rejoined == "" {
		return "."
	}

	return vol + rejoined
}
