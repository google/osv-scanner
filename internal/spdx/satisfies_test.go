package spdx_test

import (
	"strings"
	"testing"

	"github.com/google/osv-scanner/internal/spdx"
	"github.com/google/osv-scanner/pkg/models"
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
				{"GPL-2.0-or-later WITH Bison-exception-2.2"},
			},
			fail: [][]string{
				{"Bison-exception-2.2"},
				{"GPL-2.0-or-later"},
				{"GPL-2.0-or-later", "Bison-exception-2.2"},
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
		{
			license: "MIT AND LGPL-2.1-or-later OR BSD-3-Clause",
			pass: [][]string{
				{"BSD-3-Clause"},
				{"MIT", "LGPL-2.1-or-later"},
				{"MIT", "BSD-3-Clause"},
				{"LGPL-2.1-or-later", "BSD-3-Clause"},
				{"MIT", "LGPL-2.1-or-later", "BSD-3-Clause"},
			},
			fail: [][]string{
				{"Apache-2.0"},
				{"MIT"},
				{"LGPL-2.1-or-later"},
			},
		},
		{
			license: "BSD-3-Clause OR MIT AND LGPL-2.1-or-later",
			pass: [][]string{
				{"BSD-3-Clause"},
				{"MIT", "LGPL-2.1-or-later"},
				{"MIT", "BSD-3-Clause"},
				{"LGPL-2.1-or-later", "BSD-3-Clause"},
				{"MIT", "LGPL-2.1-or-later", "BSD-3-Clause"},
			},
			fail: [][]string{
				{"Apache-2.0"},
				{"MIT"},
				{"LGPL-2.1-or-later"},
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
			license: "(BSD-3-Clause OR LGPL-2.1-or-later) AND MIT",
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
		{
			license: "A AND B AND C OR D AND E OR F",
			pass: [][]string{
				{"A", "B", "C", "D", "E", "F"},
				{"A", "B", "C", "D", "E"},
				{"A", "B", "C"},
				{"D", "E"},
				{"F"},
			},
			fail: [][]string{
				{"A"},
				{"B"},
				{"C"},
				{"D"},
				{"E"},
				{"A", "C"},
				{"A", "D"},
				{"A", "E"},
				{"B", "C"},
				{"B", "D"},
				{"B", "E"},
				{"C", "C"},
				{"C", "D"},
				{"C", "E"},
			},
		},
	}
	for _, tt := range tests {
		for _, variant := range tt.pass {
			t.Run(namer(t, tt.license, variant, true), func(t *testing.T) {
				t.Parallel()

				got, err := spdx.Satisfies(tt.license, variant)

				if err != nil {
					t.Errorf("Satisfies(\"%s\") = %v, want %v", tt.license, err, nil)
				}

				if !got {
					t.Errorf("Satisfies(\"%s\") = %v, want %v", tt.license, got, true)
				}
			})
		}

		for _, variant := range tt.fail {
			t.Run(namer(t, tt.license, variant, false), func(t *testing.T) {
				t.Parallel()

				got, err := spdx.Satisfies(tt.license, variant)

				if err != nil {
					t.Errorf("Satisfies(\"%s\") = %v, want %v", tt.license, err, nil)
				}

				if got {
					t.Errorf("Satisfies(\"%s\") = %v, want %v", tt.license, got, false)
				}
			})
		}
	}
}

func TestSatisfies_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		license models.License
		wantErr string
	}{
		// brackets must be paired
		{"(A AND B", "missing closing bracket"},
		{"(((A AND B))", "missing closing bracket"},
		{"(A AND B OR (A AND C)", "missing closing bracket"},
		// "WITH" must only be followed by a license expression
		{"A WITH(", "unexpected ( after WITH"},
		{"A WITH (", "unexpected ( after WITH"},
		{"A WITH WITH", "unexpected WITH after WITH"}, //nolint:dupword
		{"A WITH AND", "unexpected AND after WITH"},
		{"A WITH OR", "unexpected OR after WITH"},
		{"A WITH)", "unexpected ) after WITH"},
		{"A WITH )", "unexpected ) after WITH"},
		{"A WITH", "unexpected END after WITH"},
		{"A WITH ", "unexpected END after WITH"},
		// "AND" must only be followed by a license expression or "("
		{"A AND WITH", "unexpected WITH after AND"},
		{"A AND AND", "unexpected AND after AND"}, //nolint:dupword
		{"A AND OR", "unexpected OR after AND"},
		{"A AND )", "unexpected ) after AND"},
		{"A AND)", "unexpected ) after AND"},
		{"A AND", "unexpected END after AND"},
		{"A AND ", "unexpected END after AND"},
		// "OR" must only be followed by a license expression or "("
		{"A OR WITH", "unexpected WITH after OR"},
		{"A OR AND", "unexpected AND after OR"},
		{"A OR OR", "unexpected OR after OR"}, //nolint:dupword
		{"A OR )", "unexpected ) after OR"},
		{"A OR)", "unexpected ) after OR"},
		{"A OR", "unexpected END after OR"},
		{"A OR ", "unexpected END after OR"},
		// "(" must only be followed by a license expression or "("
		{"(WITH", "unexpected WITH after ("},
		{"( WITH", "unexpected WITH after ("},
		{"(AND", "unexpected AND after ("},
		{"( AND", "unexpected AND after ("},
		{"(OR", "unexpected OR after ("},
		{"( OR", "unexpected OR after ("},
		{"()", "unexpected ) after ("},
		{"( )", "unexpected ) after ("},
		{"(", "unexpected END after ("},
		{"( ", "unexpected END after ("},
		// ")" must only be followed by a license expression, ")", "WITH", "AND", or "OR"
		{"(A)(", "unexpected ( after )"},
		{"(A) (", "unexpected ( after )"},
		{"( A ) (", "unexpected ( after )"},
		{"(A)Apache-2.0", "unexpected EXP after )"},
		{"(A)MIT", "unexpected EXP after )"},
		{"(A) MIT", "unexpected EXP after )"},
		{"( A ) MIT", "unexpected EXP after )"},
		{"(A)WITH", "unexpected WITH after )"},
		{"(A) WITH", "unexpected WITH after )"},
		{"( A ) WITH", "unexpected WITH after )"},
		// a license expression must only be followed by "WITH", "AND", "OR", or nothing
		{"MIT (", "unexpected ( after EXP"},
		{"MIT(", "unexpected ( after EXP"},
		{"Apache2.0(", "unexpected ( after EXP"},
		{"MIT Apache2.0", "unexpected EXP after EXP"},
		// nested errors
		{"A AND (OR", "unexpected OR after ("},
		{"A OR (AND", "unexpected AND after ("},
		{"A OR AND (()", "unexpected AND after OR"},
		{"A OR (()", "unexpected ) after ("},
		{"A OR (B AND A OR (OR)", "unexpected OR after ("},
	}
	for _, tt := range tests {
		t.Run(string(tt.license), func(t *testing.T) {
			t.Parallel()

			got, err := spdx.Satisfies(tt.license, []string{})

			if got {
				t.Errorf("Satisfies(\"%s\") = %v, want %v", tt.license, got, false)
			}

			if err == nil {
				t.Fatalf("Satisfies(\"%s\") = %v, want %v", tt.license, err, tt.wantErr)
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Satisfies(\"%s\") = %v, want %v", tt.license, err, tt.wantErr)
			}
		})
	}
}
