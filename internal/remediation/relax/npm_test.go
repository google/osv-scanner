package relax_test

import (
	"context"
	"testing"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/remediation/relax"
)

func TestRelaxNpm(t *testing.T) {
	t.Parallel()

	type result struct {
		version string
		ok      bool
	}
	tests := []struct {
		name       string
		versions   []string
		from       string
		allowMajor bool
		want       result
	}{
		{
			name:       "pinned-to-patch",
			versions:   []string{"1.2.3", "1.2.4", "1.2.5", "1.3.0", "2.0.0"},
			from:       "1.2.3",
			allowMajor: false,
			want: result{
				version: "~1.2.5",
				ok:      true,
			},
		},
		{
			name:       "patch-to-minor",
			versions:   []string{"1.2.3", "1.2.4", "1.3.0", "1.3.1", "2.0.0"},
			from:       "~1.2.3",
			allowMajor: false,
			want: result{
				version: "^1.3.1",
				ok:      true,
			},
		},
		{
			name:       "minor-to-next-major",
			versions:   []string{"1.2.3", "1.3.4", "2.3.4", "2.4.5", "3.0.0"},
			from:       "^1.2.3",
			allowMajor: true,
			want: result{
				version: "^2.4.5",
				ok:      true,
			},
		},
		{
			name:       "skip-missing-major",
			versions:   []string{"1.0.0", "3.0.0", "4.0.0"},
			from:       "^1.0.0",
			allowMajor: true,
			want: result{
				version: "^3.0.0",
				ok:      true,
			},
		},
		{
			name:       "no-more-versions",
			versions:   []string{"1.2.3", "1.3.4", "1.4.5"},
			from:       "^1.2.3",
			allowMajor: true,
			want: result{
				version: "^1.2.3",
				ok:      false,
			},
		},
		{
			name:       "disallow-major",
			versions:   []string{"1.2.3", "1.3.4", "2.3.4", "2.4.5", "3.0.0"},
			from:       "^1.2.3",
			allowMajor: false,
			want: result{
				version: "^1.2.3",
				ok:      false,
			},
		},
		{
			name:       "avoid-prerelease-patch",
			versions:   []string{"1.2.3", "1.2.4", "1.2.5-alpha"},
			from:       "1.2.3",
			allowMajor: false,
			want: result{
				version: "~1.2.4",
				ok:      true,
			},
		},
		{
			name:       "avoid-prerelease-minor",
			versions:   []string{"1.2.3", "1.3.4", "1.4.5-alpha"},
			from:       "~1.2.3",
			allowMajor: true,
			want: result{
				version: "^1.3.4",
				ok:      true,
			},
		},
		{
			name:       "skip-prerelease",
			versions:   []string{"1.2.3", "2.0.0-alpha", "2.0.0", "3.0.0"},
			from:       "^1.0.0",
			allowMajor: true,
			want: result{
				version: "^2.0.0",
				ok:      true,
			},
		},
		{
			name:       "choose-final-prerelease",
			versions:   []string{"1.2.3", "2.0.0-alpha.0", "2.0.0-alpha.1", "2.0.0-beta"},
			from:       "^1.0.0",
			allowMajor: true,
			want: result{
				version: "^2.0.0-beta",
				ok:      true,
			},
		},
		{
			name:       "from-prerelease",
			versions:   []string{"1.0.0-pre", "1.2.3", "2.0.0-pre", "2.3.4"},
			from:       "^1.0.0-pre",
			allowMajor: true,
			want: result{
				version: "^2.3.4",
				ok:      true,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cl := resolve.NewLocalClient()
			pk := resolve.PackageKey{
				Name:   tt.name,
				System: resolve.NPM,
			}
			for _, v := range tt.versions {
				cl.AddVersion(resolve.Version{
					VersionKey: resolve.VersionKey{
						PackageKey:  pk,
						Version:     v,
						VersionType: resolve.Concrete,
					},
				}, nil)
			}

			relaxer := relax.NpmRelaxer{}
			got, ok := relaxer.Relax(context.Background(), cl, resolve.RequirementVersion{
				VersionKey: resolve.VersionKey{
					PackageKey:  pk,
					VersionType: resolve.Requirement,
					Version:     tt.from,
				}}, tt.allowMajor)

			if got.Version != tt.want.version || ok != tt.want.ok {
				t.Errorf("Relax() = (%s, %v), want (%s, %v)", got.Version, ok, tt.want.version, tt.want.ok)
			}
		})
	}
}
