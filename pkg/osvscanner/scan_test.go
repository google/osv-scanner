package osvscanner

import (
	"path/filepath"
	"testing"
)

func Test_isDescendent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		potentialParent string
		path            string
		recursive       bool
		want            bool
	}{
		{
			name:            "same path",
			potentialParent: "/a/b",
			path:            "/a/b",
			recursive:       true,
			want:            true,
		},
		{
			name:            "direct child, recursive",
			potentialParent: "/a/b",
			path:            "/a/b/c",
			recursive:       true,
			want:            true,
		},
		{
			name:            "direct child, non-recursive",
			potentialParent: "/a/b",
			path:            "/a/b/c",
			recursive:       false,
			want:            true,
		},
		{
			name:            "grandchild, recursive",
			potentialParent: "/a/b",
			path:            "/a/b/c/d",
			recursive:       true,
			want:            true,
		},
		{
			name:            "grandchild, non-recursive",
			potentialParent: "/a/b",
			path:            "/a/b/c/d",
			recursive:       false,
			want:            false,
		},
		{
			name:            "not a descendent",
			potentialParent: "/a/b",
			path:            "/a/c",
			recursive:       true,
			want:            false,
		},
		{
			name:            "different root",
			potentialParent: "/a/b",
			path:            "/x/y",
			recursive:       true,
			want:            false,
		},
		{
			name:            "relative path, direct child, recursive",
			potentialParent: "a/b",
			path:            "a/b/c",
			recursive:       true,
			want:            true,
		},
		{
			name:            "relative path, grandchild, non-recursive",
			potentialParent: "a/b",
			path:            "a/b/c/d",
			recursive:       false,
			want:            false,
		},
		{
			name:            "relative path, not a descendent",
			potentialParent: "a/b",
			path:            "a/c",
			recursive:       true,
			want:            false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Normalize paths for the current OS
			potentialParent := filepath.FromSlash(tt.potentialParent)
			path := filepath.FromSlash(tt.path)
			if got := isDescendent(potentialParent, path, tt.recursive); got != tt.want {
				t.Errorf("isDescendent(%q, %q, %v) = %v, want %v", tt.potentialParent, tt.path, tt.recursive, got, tt.want)
			}
		})
	}
}
