package tuxcareelsrepo

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/internal/tuxcare"
)

func TestFileRequired(t *testing.T) {
	t.Parallel()
	e := &Extractor{}
	yes := []string{"etc/yum.repos.d/centos8.4-els.repo", "etc/yum.repos.d/centos8.5-els.repo"}
	no := []string{"etc/yum.repos.d/centos.repo", "etc/os-release", "centos8.4-els.repo.bak"}
	for _, p := range yes {
		if !e.fileRequiredPath(filepath.Base(p)) {
			t.Errorf("FileRequired(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if e.fileRequiredPath(filepath.Base(p)) {
			t.Errorf("FileRequired(%q) = true, want false", p)
		}
	}
}

func TestChannelFromBase(t *testing.T) {
	t.Parallel()
	if got := tuxcare.RepoFileNames["centos8.4-els.repo"]; got != "8.4" {
		t.Errorf("channel = %q, want 8.4", got)
	}
}
