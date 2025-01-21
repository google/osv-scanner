package models_test

import (
	"reflect"
	"testing"

	"github.com/google/osv-scanner/pkg/models"
)

func TestPURLToPackage(t *testing.T) {
	t.Parallel()
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
				Ecosystem: string(models.EcosystemCratesIO),
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
				Ecosystem: string(models.EcosystemGo),
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
				Ecosystem: string(models.EcosystemMaven),
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
				Ecosystem: string(models.EcosystemDebian),
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
				Ecosystem: string(models.EcosystemAlpine),
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
			t.Parallel()
			got, err := models.PURLToPackage(tt.args.purl)
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
