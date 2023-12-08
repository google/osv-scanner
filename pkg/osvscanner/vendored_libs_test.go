package osvscanner

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
)

func Test_scanDirWithVendoredLibs(t *testing.T) {
	t.Parallel()

	type args struct {
		r    reporter.Reporter
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    []scannedPackage
		wantErr bool
	}{
		{
			name: "Scan bsdiff",
			args: args{
				r:    &reporter.VoidReporter{},
				path: "./fixtures/example-vendor/",
			},
			want: []scannedPackage{
				{
					Commit: "ce07a29894acd74c52b975a42c02f11d9483566a",
					Source: models.SourceInfo{
						Type: "git",
						Path: testutility.ValueIfOnWindows(
							"fixtures\\example-vendor\\bsdiff",
							"fixtures/example-vendor/bsdiff"),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := scanDirWithVendoredLibs(tt.args.r, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("scanDirWithVendoredLibs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("scanDirWithVendoredLibs() returned unexpected result (-got +want):\n%s", diff)
			}
		})
	}
}
