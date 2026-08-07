package output

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
)

func Test_simplifySourcePath(t *testing.T) {
	t.Parallel()

	workingDir := mustGetWorkingDirectory()

	tests := []struct {
		name       string
		sourceName string
		sourceType models.SourceType
		want       string
	}{
		{
			name:       "absolute path inside working directory with os type prefix",
			sourceName: "os:" + filepath.Join(workingDir, "testdata", "homebrew", "INSTALL_RECEIPT.json"),
			sourceType: models.SourceTypeOSPackage,
			want:       "os:testdata/homebrew/INSTALL_RECEIPT.json",
		},
		{
			name:       "absolute path outside working directory with os type prefix",
			sourceName: "os:/var/lib/dpkg/status",
			sourceType: models.SourceTypeOSPackage,
			want:       "os:/var/lib/dpkg/status",
		},
		{
			name:       "relative path with lockfile type prefix",
			sourceName: "lockfile:testdata/locks/composer.lock",
			sourceType: models.SourceTypeProjectPackage,
			want:       "lockfile:testdata/locks/composer.lock",
		},
		{
			name:       "already relative path with no type prefix",
			sourceName: "testdata/locks/composer.lock",
			sourceType: "",
			want:       "testdata/locks/composer.lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := simplifySourcePath(tt.sourceName, tt.sourceType)
			if got != tt.want {
				t.Errorf("simplifySourcePath(%q, %q) = %q, want %q", tt.sourceName, tt.sourceType, got, tt.want)
			}
		})
	}
}
