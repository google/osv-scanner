package builders

import (
	"testing"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
)

func TestPrintGomodName(t *testing.T) {
	t.Logf("gomod.Name = %q", gomod.Name)
}

func TestBuildExtractors_KnownName(t *testing.T) {
	names := []string{"go/gomod"}
	extractors := BuildExtractors(names)

	if len(extractors) != 1 {
		t.Fatalf("expected 1 extractor, got %d", len(extractors))
	}
	if extractors[0] == nil {
		t.Error("expected non-nil extractor for known name")
	}
}
