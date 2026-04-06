package osvscanner

import (
	"testing"

	"github.com/google/osv-scanner/v2/internal/clients/clientimpl/osvmatcher"
)

func TestInitializeExternalAccessorsUsesCachedMatcher(t *testing.T) {
	accessors, err := initializeExternalAccessors(ScannerActions{})
	if err != nil {
		t.Fatalf("initializeExternalAccessors() error = %v", err)
	}

	if _, ok := accessors.VulnMatcher.(*osvmatcher.CachedOSVMatcher); !ok {
		t.Fatalf("initializeExternalAccessors() matcher = %T, want *osvmatcher.CachedOSVMatcher", accessors.VulnMatcher)
	}
}

func TestInitializeExternalAccessorsUsesCachedMatcherForGitCommits(t *testing.T) {
	accessors, err := initializeExternalAccessors(ScannerActions{
		GitCommits: []string{"33dffa3909a67e1b5d22647128ab7eb6e53fd0c7"},
	})
	if err != nil {
		t.Fatalf("initializeExternalAccessors() error = %v", err)
	}

	if _, ok := accessors.VulnMatcher.(*osvmatcher.CachedOSVMatcher); !ok {
		t.Fatalf("initializeExternalAccessors() matcher = %T, want *osvmatcher.CachedOSVMatcher", accessors.VulnMatcher)
	}
}
