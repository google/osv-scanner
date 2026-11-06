package spdx_test

import (
	"reflect"
	"testing"

	"github.com/google/osv-scanner/v2/internal/spdx"
)

func TestUnrecognized(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		licenses []string
		want     []string
	}{
		{
			name:     "all_recognized_licenses",
			licenses: []string{"agpl-1.0", "MIT", "apache-1.0", "UNKNOWN"},
			want:     nil,
		}, {
			name:     "all_unrecognized_licenses",
			licenses: []string{"agpl1.0", "unrecognized license", "apache1.0"},
			want:     []string{"agpl1.0", "unrecognized license", "apache1.0"},
		}, {
			name:     "some_recognized,_some_unrecognized_licenses",
			licenses: []string{"agpl-1.0", "unrecognized license", "apache-1.0"},
			want:     []string{"unrecognized license"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := spdx.Unrecognized(tt.licenses); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Unrecognized() = %v,\nwant %v", got, tt.want)
			}
		})
	}
}

func TestIsSPDX(t *testing.T) {
	t.Parallel()
	tests := []struct {
		license string
		want    bool
	}{
		{"MIT", true},
		{"mit", true},
		{"Apache-2.0", true},
		{"ISC", true},
		{"gpl-2.0-with-classpath-exception", true},
		{"non-standard", false},
		{"UNKNOWN", false},
		{"MIT AND Zlib", false},
	}
	for _, tt := range tests {
		if got := spdx.IsSPDX(tt.license); got != tt.want {
			t.Errorf("IsSPDX(%q) = %v, want %v", tt.license, got, tt.want)
		}
	}
}

func TestIsExpression(t *testing.T) {
	t.Parallel()
	tests := []struct {
		license string
		want    bool
	}{
		{"MIT", false},
		{"ISC", false},
		{"non-standard", false},
		{"MIT AND Zlib", true},
		{"Apache-2.0 OR MIT", true},
		{"GPL-2.0-or-later WITH Classpath-exception-2.0", true},
		{"(MIT AND ISC)", true},
	}
	for _, tt := range tests {
		if got := spdx.IsExpression(tt.license); got != tt.want {
			t.Errorf("IsExpression(%q) = %v, want %v", tt.license, got, tt.want)
		}
	}
}
