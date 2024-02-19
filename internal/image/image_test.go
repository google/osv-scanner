package image

import (
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/reporter"
)

func TestScanImage(t *testing.T) {
	t.Parallel()

	type args struct {
		imagePath string
	}
	tests := []struct {
		name    string
		args    args
		want    testutility.Snapshot
		wantErr bool
	}{
		{
			name:    "Alpine 3.10 scan",
			args:    args{imagePath: "fixtures/alpine-tester.tar"},
			want:    testutility.NewSnapshot(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ScanImage(&reporter.VoidReporter{}, tt.args.imagePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScanImage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			tt.want.MatchJSON(t, got)
		})
	}
}
