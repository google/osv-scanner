package image

import (
	"reflect"
	"testing"
)

func TestScanImage(t *testing.T) {
	type args struct {
		imagePath string
	}
	tests := []struct {
		name    string
		args    args
		want    ScanResults
		wantErr bool
	}{
		struct{name string; args args; want ScanResults; wantErr bool}{
			name: "Alpine 3.10 scan",
			args: args{imagePath: ""},
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ScanImage(tt.args.imagePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScanImage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ScanImage() = %v, want %v", got, tt.want)
			}
		})
	}
}
