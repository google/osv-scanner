package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestNpmLockExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig ScanInputMockConfig
		want        bool
	}{
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "package-lock.json",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/package-lock.json",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/package-lock.json/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/package-lock.json.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.package-lock.json",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.NpmLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}
