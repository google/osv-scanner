package spdx_test

import (
	"strings"
	"testing"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/spdx"
)

func namer(t *testing.T, license models.License, licenses []string, expected bool) string {
	t.Helper()

	name := string(license) + " is"

	if !expected {
		name += " not"
	}

	return name + " satisfied by " + strings.Join(licenses, ", ")
}

func TestSatisfies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		license models.License
		pass    [][]string
		fail    [][]string
	}{
		// simple
		{
			license: "MIT",
			pass:    [][]string{{"MIT"}, {"MIT", "Apache-2.0"}},
			fail:    [][]string{{"Apache-2.0"}},
		},
		{
			license: "Apache-2.0",
			pass:    [][]string{{"Apache-2.0"}, {"MIT", "Apache-2.0"}},
			fail:    [][]string{{"MIT"}},
		},
		// WITH expressions (ignored)
		{
			license: "GPL-2.0-or-later WITH Bison-exception-2.2",
			pass: [][]string{
				{"GPL-2.0-or-later"},
				{"GPL-2.0-or-later", "Bison-exception-2.2"},
			},
			fail: [][]string{
				{"Bison-exception-2.2"},
				{"GPL-2.0-or-later WITH Bison-exception-2.2"},
				{"GPL-1.0"},
			},
		},
		// OR expressions
		{
			license: "MIT OR Apache-2.0",
			pass: [][]string{
				{"MIT"},
				{"Apache-2.0"},
				{"Apache-2.0", "MIT"},
				{"Apache-1.0", "MIT"},
			},
			fail: [][]string{
				{"Apache-1.0"},
			},
		},
		{
			license: "LGPL-2.1-only OR MIT OR BSD-3-Clause",
			pass: [][]string{
				{"LGPL-2.1-only"},
				{"MIT"},
				{"BSD-3-Clause"},
				{"Apache-2.0", "MIT"},
				{"LGPL-2.1-only", "MIT", "BSD-3-Clause"},
				{"LGPL-2.1-only", "BSD-3-Clause"},
			},
			fail: [][]string{
				{"Apache-2.0"},
			},
		},
		// AND expressions
		{
			license: "MIT AND Apache-2.0",
			pass: [][]string{
				{"Apache-2.0", "MIT"},
				{"Apache-2.0", "Apache-1.0", "MIT"},
			},
			fail: [][]string{
				{"MIT"},
				{"Apache-2.0"},
				{"Apache-1.0"},
				{"Apache-1.0", "MIT"},
			},
		},
		// AND & OR expressions
		{
			license: "LGPL-2.1-only OR BSD-3-Clause AND MIT",
			pass: [][]string{
				{"LGPL-2.1-only"},
				{"BSD-3-Clause", "MIT"},
				{"LGPL-2.1-only", "BSD-3-Clause", "MIT"},
				{"LGPL-2.1-only", "BSD-3-Clause"},
				{"LGPL-2.1-only", "MIT"},
			},
			fail: [][]string{
				{"Apache-2.0"},
				{"BSD-3-Clause"},
				{"MIT"},
			},
		},
		{
			license: "MIT AND LGPL-2.1-only OR BSD-3-Clause",
			pass: [][]string{
				{"BSD-3-Clause"},
				{"BSD-3-Clause", "MIT"},
				{"LGPL-2.1-only", "BSD-3-Clause", "MIT"},
				{"LGPL-2.1-only", "BSD-3-Clause"},
				{"LGPL-2.1-only", "MIT"},
				{"MIT", "LGPL-2.1-only"},
			},
			fail: [][]string{
				{"Apache-2.0"},
				{"LGPL-2.1-only"},
				{"MIT"},
			},
		},
		{
			license: "A OR B AND C OR D",
			pass: [][]string{
				{"A"},
				{"B", "C"},
				{"D"},
				{"A", "B", "C"},
				{"B", "C", "D"},
				{"A", "D"},
				{"A", "B", "C", "D"},
			},
			fail: [][]string{
				{"B"},
				{"C"},
				{"E"},
			},
		},
		// parentheses
		{
			license: "MIT AND (LGPL-2.1-or-later OR BSD-3-Clause)",
			pass: [][]string{
				{"MIT", "LGPL-2.1-or-later"},
				{"MIT", "BSD-3-Clause"},
				{"MIT", "LGPL-2.1-or-later", "BSD-3-Clause"},
			},
			fail: [][]string{
				{"Apache-2.0"},
				{"MIT"},
				{"LGPL-2.1-or-later"},
				{"BSD-3-Clause"},
				{"LGPL-2.1-or-later", "BSD-3-Clause"},
			},
		},
		{
			license: "(A OR B) AND (C OR D)",
			pass: [][]string{
				{"A", "C"},
				{"A", "D"},
				{"B", "C"},
				{"B", "D"},
				{"A", "C", "D"},
				{"B", "C", "D"},
				{"A", "B", "C"},
				{"A", "B", "D"},
				{"A", "B", "C", "D"},
			},
			fail: [][]string{
				{"A"},
				{"B"},
				{"C"},
				{"D"},
				{"A", "B"},
				{"C", "D"},
				{"E"},
			},
		},
		{
			license: "A AND (B OR C AND D)",
			pass: [][]string{
				{"A", "B"},
				{"A", "C", "D"},
				{"A", "B", "C", "D"},
			},
			fail: [][]string{
				{"A"},
				{"B"},
				{"C"},
				{"D"},
				{"A", "C"},
				{"A", "D"},
				{"C", "D"},
				{"B", "C", "D"},
				{"E"},
			},
		},
		{
			license: "A AND ((B OR C) AND D)",
			pass: [][]string{
				{"A", "B", "D"},
				{"A", "C", "D"},
				{"A", "B", "C", "D"},
			},
			fail: [][]string{
				{"A"},
				{"B"},
				{"C"},
				{"D"},
				{"A", "B"},
				{"A", "C"},
				{"A", "D"},
				{"C", "D"},
				{"B", "C", "D"},
				{"E"},
			},
		},
	}
	for _, tt := range tests {
		for _, variant := range tt.pass {
			t.Run(namer(t, tt.license, variant, true), func(t *testing.T) {
				t.Parallel()

				if got := spdx.Satisfies(tt.license, variant); !got {
					t.Errorf("Satisfies() = %v, want %v", got, true)
				}
			})
		}

		for _, variant := range tt.fail {
			t.Run(namer(t, tt.license, variant, false), func(t *testing.T) {
				t.Parallel()

				if got := spdx.Satisfies(tt.license, variant); got {
					t.Errorf("Satisfies() = %v, want %v", got, false)
				}
			})
		}
	}
}
