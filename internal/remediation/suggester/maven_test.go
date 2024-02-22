package suggester

import (
	"context"
	"reflect"
	"testing"

	"deps.dev/util/resolve"
)

func TestMavenSuggest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	lc := resolve.NewLocalClient()
	suggester, err := GetSuggester(resolve.Maven)
	if err != nil {
		t.Fatalf("fail to get Maven suggester")
	}

	pk := resolve.PackageKey{
		System: resolve.Maven,
		Name:   "abc:xyz",
	}
	for _, version := range []string{"1.0.0", "1.0.1", "1.1.0", "1.2.3", "2.0.0", "2.2.2", "2.3.4"} {
		lc.AddVersion(resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				VersionType: resolve.Concrete,
				Version:     version,
			}}, nil)
	}

	tests := []struct {
		requirement string
		options     SuggestOptions
		want        string
	}{
		{"1.0.0", SuggestOptions{}, "2.3.4"},
		// No major updates allowed
		{"1.0.0", SuggestOptions{NoMajorUpdates: true}, "1.2.3"},
		// Version range requirement is not outdated
		{"[1.0.0,)", SuggestOptions{}, "[1.0.0,)"},
		{"[2.0.0, 2.3.4]", SuggestOptions{}, "[2.0.0, 2.3.4]"},
		// Version range requirement is outdated
		{"[2.0.0, 2.3.4)", SuggestOptions{}, "2.3.4"},
		{"[2.0.0, 2.2.2]", SuggestOptions{}, "2.3.4"},
		// Version range requirement is outdated but latest version is a major update
		{"[1.0.0,2.0.0)", SuggestOptions{}, "2.3.4"},
		{"[1.0.0,2.0.0)", SuggestOptions{NoMajorUpdates: true}, "[1.0.0,2.0.0)"},
	}
	for _, test := range tests {
		vk := resolve.VersionKey{
			PackageKey:  pk,
			VersionType: resolve.Requirement,
			Version:     test.requirement,
		}
		want := resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				VersionType: resolve.Requirement,
				Version:     test.want,
			},
		}
		got, err := suggester.Suggest(ctx, lc, resolve.RequirementVersion{VersionKey: vk}, test.options)
		if err != nil {
			t.Fatalf("fail to suggest a new version for %v: %v", vk, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("suggest new version for %v with options %v got %s want %s", vk, test.options, got, want)
		}
	}
}
