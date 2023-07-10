package models

import (
	"reflect"
	"testing"
)

func TestPURLToPackage(t *testing.T) {
	type args struct {
		purl string
	}
	tests := []struct {
		name    string
		args    args
		want    PackageInfo
		wantErr bool
	}{
		{
			name: "valid PURL",
			args: args{
				purl: "pkg:cargo/memoffset@0.6.1",
			},
			want: PackageInfo{
				Name:      "memoffset",
				Version:   "0.6.1",
				Ecosystem: string(EcosystemCratesIO),
			},
		},
		{
			name: "valid PURL golang",
			args: args{
				purl: "pkg:golang/github.com/gogo/protobuf@5.6.0",
			},
			want: PackageInfo{
				Name:      "github.com/gogo/protobuf",
				Version:   "5.6.0",
				Ecosystem: string(EcosystemGo),
			},
		},
		{
			name: "valid PURL maven",
			args: args{
				purl: "pkg:maven/org.hdrhistogram/HdrHistogram@2.1.12",
			},
			want: PackageInfo{
				Name:      "org.hdrhistogram:HdrHistogram",
				Version:   "2.1.12",
				Ecosystem: string(EcosystemMaven),
			},
		},
		{
			name: "valid Debian maven",
			args: args{
				purl: "pkg:deb/debian/nginx@2.36.1-8+deb11u1",
			},
			want: PackageInfo{
				Name:      "nginx",
				Version:   "2.36.1-8+deb11u1",
				Ecosystem: string(EcosystemDebian),
			},
		},
		{
			name: "invalid PURL",
			args: args{
				purl: "pkg-golang/github.com/gogo/protobuf.0",
			},
			want:    PackageInfo{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PURLToPackage(tt.args.purl)
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
