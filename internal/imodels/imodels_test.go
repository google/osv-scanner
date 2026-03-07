package imodels

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
)

func Test_Name(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		pkg  PackageInfo
		want string
	}{
		{
			name: "Regular_package",
			pkg: PackageInfo{
				Package: &extractor.Package{
					Name: "regular-pkg",
				},
			},
			want: "regular-pkg",
		},
		{
			name: "GIT_ecosystem_with_repo",
			pkg: PackageInfo{
				Package: &extractor.Package{
					Name: "openssl@3.5",
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo: "github.com/openssl/openssl",
					},
					Metadata: &osvscannerjson.Metadata{
						Ecosystem: "GIT",
					},
				},
			},
			want: "github.com/openssl/openssl",
		},
		{
			name: "GIT_ecosystem_without_repo",
			pkg: PackageInfo{
				Package: &extractor.Package{
					Name: "openssl@3.5",
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo: "",
					},
					Metadata: &osvscannerjson.Metadata{
						Ecosystem: "GIT",
					},
				},
			},
			want: "openssl@3.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Name(tt.pkg.Package); got != tt.want {
				t.Errorf("Name(PackageInfo) = %v, want %v", got, tt.want)
			}
		})
	}
}
