package purl_test

import (
	"reflect"
	"testing"

	"github.com/google/osv-scanner/v2/internal/utility/purl"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestPURLToPackage(t *testing.T) {
	// t.Parallel()
	type args struct {
		purl string
	}
	tests := []struct {
		name    string
		args    args
		want    models.PackageInfo
		wantErr bool
	}{
		{
			name: "valid PURL",
			args: args{
				purl: "pkg:cargo/memoffset@0.6.1",
			},
			want: models.PackageInfo{
				Name:      "memoffset",
				Version:   "0.6.1",
				Ecosystem: string(osvschema.EcosystemCratesIO),
			},
		},
		{
			name: "valid PURL golang",
			args: args{
				purl: "pkg:golang/github.com/gogo/protobuf@5.6.0",
			},
			want: models.PackageInfo{
				Name:      "github.com/gogo/protobuf",
				Version:   "5.6.0",
				Ecosystem: string(osvschema.EcosystemGo),
			},
		},
		{
			name: "valid PURL maven",
			args: args{
				purl: "pkg:maven/org.hdrhistogram/HdrHistogram@2.1.12",
			},
			want: models.PackageInfo{
				Name:      "org.hdrhistogram:HdrHistogram",
				Version:   "2.1.12",
				Ecosystem: string(osvschema.EcosystemMaven),
			},
		},
		{
			name: "valid PURL Debian",
			args: args{
				purl: "pkg:deb/debian/nginx@2.36.1-8+deb11u1",
			},
			want: models.PackageInfo{
				Name:      "nginx",
				Version:   "2.36.1-8+deb11u1",
				Ecosystem: string(osvschema.EcosystemDebian),
			},
		},
		{
			name: "valid PURL alpine",
			args: args{
				purl: "pkg:apk/alpine/zlib@1.2.13-r0?arch=x86_64upstream=zlib&distro=alpine-3.17.2",
			},
			want: models.PackageInfo{
				Name:      "zlib",
				Version:   "1.2.13-r0",
				Ecosystem: string(osvschema.EcosystemAlpine),
			},
		},
		{
			name: "invalid PURL",
			args: args{
				purl: "pkg-golang/github.com/gogo/protobuf.0",
			},
			want:    models.PackageInfo{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.Parallel()
			got, err := purl.ToPackage(tt.args.purl)
			if (err != nil) != tt.wantErr {
				t.Errorf("PURLToPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PURLToPackage() = %v, want %v", got, tt.want)
			}
		})
	}
}
