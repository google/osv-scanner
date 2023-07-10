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
