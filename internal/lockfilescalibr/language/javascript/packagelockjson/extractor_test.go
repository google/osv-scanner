package packagelockjson_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/language/javascript/packagelockjson"
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
			inputPath: "package-lock.json",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/package-lock.json",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/package-lock.json/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/package-lock.json.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.package-lock.json",
			want:      false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := packagelockjson.Extractor{}
			got := e.FileRequired(tt.inputPath, nil)
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}