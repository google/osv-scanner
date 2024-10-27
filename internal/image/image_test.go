package image_test

import (
	"errors"
	"os"
	"testing"

	"github.com/google/osv-scanner/internal/image"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/reporter"
)

func TestScanImage(t *testing.T) {
	t.Parallel()
	testutility.SkipIfNotAcceptanceTesting(t, "Not consistent on MacOS/Windows")

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
			name:    "Alpine 3.10 image tar with 3.18 version file",
			args:    args{imagePath: "fixtures/test-alpine.tar"},
			want:    testutility.NewSnapshot(),
			wantErr: false,
		},
		{
			name:    "scanning node_modules using npm with no packages",
			args:    args{imagePath: "fixtures/test-node_modules-npm-empty.tar"},
			want:    testutility.NewSnapshot(),
			wantErr: false,
		},
		{
			name:    "scanning node_modules using npm with some packages",
			args:    args{imagePath: "fixtures/test-node_modules-npm-full.tar"},
			want:    testutility.NewSnapshot(),
			wantErr: false,
		},
		{
			name:    "scanning node_modules using yarn with no packages",
			args:    args{imagePath: "fixtures/test-node_modules-yarn-empty.tar"},
			want:    testutility.NewSnapshot(),
			wantErr: false,
		},
		{
			name:    "scanning node_modules using yarn with some packages",
			args:    args{imagePath: "fixtures/test-node_modules-yarn-full.tar"},
			want:    testutility.NewSnapshot(),
			wantErr: false,
		},
		{
			name:    "scanning node_modules using pnpm with no packages",
			args:    args{imagePath: "fixtures/test-node_modules-pnpm-empty.tar"},
			want:    testutility.NewSnapshot(),
			wantErr: false,
		},
		{
			name:    "scanning node_modules using pnpm with some packages",
			args:    args{imagePath: "fixtures/test-node_modules-pnpm-full.tar"},
			want:    testutility.NewSnapshot(),
			wantErr: false,
		},
		{
			name:    "scanning go binaries that's been overwritten for package tracing",
			args:    args{imagePath: "fixtures/test-package-tracing.tar"},
			want:    testutility.NewSnapshot(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// point out that we need the images to be built and saved separately
			if _, err := os.Stat(tt.args.imagePath); errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s does not exist - have you run scripts/build_test_images.sh?", tt.args.imagePath)
			}

			got, err := image.ScanImage(&reporter.VoidReporter{}, tt.args.imagePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScanImage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for _, lockfile := range got.Lockfiles {
				for _, pkg := range lockfile.Packages {
					pkg.ImageOrigin.LayerID = "<Any value>"
				}
			}

			tt.want.MatchJSON(t, got)
		})
	}
}
