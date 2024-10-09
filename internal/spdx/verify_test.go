package spdx

import (
	"reflect"
	"testing"
)

func Test_unrecognized(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		licenses []string
		want     []string
	}{
		{
			name:     "all recognized licenses",
			licenses: []string{"agpl-1.0", "MIT", "apache-1.0", "UNKNOWN"},
			want:     nil,
		}, {
			name:     "all unrecognized licenses",
			licenses: []string{"agpl1.0", "unrecognized license", "apache1.0"},
			want:     []string{"agpl1.0", "unrecognized license", "apache1.0"},
		}, {
			name:     "some recognized, some unrecognized licenses",
			licenses: []string{"agpl-1.0", "unrecognized license", "apache-1.0"},
			want:     []string{"unrecognized license"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Unrecognized(tt.licenses); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Unrecognized() = %v,\nwant %v", got, tt.want)
			}
		})
	}
}
