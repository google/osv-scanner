package yarnlock_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/language/javascript/yarnlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "",
			inputPath: "",
			want:      false,
		},
		{
			name:      "",
			inputPath: "yarn.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/yarn.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/yarn.lock/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/yarn.lock.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.yarn.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := yarnlock.Extractor{}
			got := e.FileRequired(tt.inputPath, sharedtesthelpers.GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}
