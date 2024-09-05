package sharedtesthelpers

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	ordercmp "cmp"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/fakefs"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
)

// ExpectErrContaining checks if a error contains a certain string, if not fail the test
func ExpectErrContaining(t *testing.T, err error, str string) {
	t.Helper()

	if err == nil {
		t.Errorf("Expected to get error, but did not")
		return
	}

	if !strings.Contains(err.Error(), str) {
		t.Errorf("Expected to get \"%s\" error, but got \"%v\"", str, err)
	}
}

// ExpectErrIs checks if a error is another error, if not fail the test
func ExpectErrIs(t *testing.T, err error, expected error) {
	t.Helper()

	if err == nil {
		t.Errorf("Expected to get error, but did not")
		return
	}

	if !errors.Is(err, expected) {
		t.Errorf("Expected to get \"%v\" error but got \"%v\" instead", expected, err)
	}
}

func packageToString(pkg *extractor.Inventory) string {
	source := pkg.SourceCode
	commit := "<no commit>"
	if source != nil && source.Commit != "" {
		commit = source.Commit
	}

	groups := "<no groups>"
	if dg, ok := pkg.Metadata.(othermetadata.DepGroups); ok {
		if depGroups := dg.DepGroups(); len(depGroups) != 0 {
			groups = strings.Join(dg.DepGroups(), "/")
		}
	}

	locations := strings.Join(pkg.Locations, ", ")

	return fmt.Sprintf("%s@%s (%s, %s) @ [%s]", pkg.Name, pkg.Version, commit, groups, locations)
}

func hasPackage(t *testing.T, packages []*extractor.Inventory, pkg *extractor.Inventory) bool {
	t.Helper()

	for _, details := range packages {
		// _test := cmp.Diff(details, pkg)
		// println(_test)
		if cmp.Equal(details, pkg) {
			return true
		}
	}

	return false
}

func findMissingPackages(t *testing.T, actualPackages []*extractor.Inventory, expectedPackages []*extractor.Inventory) []*extractor.Inventory {
	t.Helper()
	var missingPackages []*extractor.Inventory

	for _, pkg := range actualPackages {
		if !hasPackage(t, expectedPackages, pkg) {
			missingPackages = append(missingPackages, pkg)
		}
	}

	return missingPackages
}

func expectPackages(t *testing.T, actualInventories []*extractor.Inventory, expectedInventories []*extractor.Inventory) {
	t.Helper()

	if len(expectedInventories) != len(actualInventories) {
		t.Errorf(
			"Expected to get %d %s, but got %d",
			len(expectedInventories),
			Form(len(expectedInventories), "package", "packages"),
			len(actualInventories),
		)
	}

	missingActualPackages := findMissingPackages(t, actualInventories, expectedInventories)
	missingExpectedPackages := findMissingPackages(t, expectedInventories, actualInventories)

	if len(missingActualPackages) != 0 {
		for _, unexpectedPackage := range missingActualPackages {
			t.Errorf("Did not expect %s", packageToString(unexpectedPackage))
		}
	}

	if len(missingExpectedPackages) != 0 {
		for _, unexpectedPackage := range missingExpectedPackages {
			t.Errorf("Did not find   %s", packageToString(unexpectedPackage))
		}
	}
}

// func ecosystemOrEmpty(pkg *extractor.Inventory) string {
// 	ecosystem, err := pkg.Ecosystem()
// 	if err != nil {
// 		ecosystem = ""
// 	}

// 	return ecosystem
// }

type ScanInputMockConfig struct {
	Path string
	// FakeScanRoot allows you to set a custom scanRoot, can be relative or absolute,
	// and will be translated to an absolute path
	FakeScanRoot string
	FakeFileInfo *fakefs.FakeFileInfo
}

type ScanInputWrapper struct {
	fileHandle *os.File
	ScanInput  filesystem.ScanInput
}

func (siw ScanInputWrapper) Close() {
	siw.fileHandle.Close()
}

// Generate FileInfoMock will either use the fake file information if fakeFileInfo is true,
// otherwise try to run os.Stat on the path passed in and fail if the file does not exist
func GenerateFileInfoMock(t *testing.T, config ScanInputMockConfig) fs.FileInfo {
	t.Helper()

	if config.FakeFileInfo != nil {
		ret := *config.FakeFileInfo
		ret.FileName = filepath.Base(config.Path)

		return ret
	}

	fileInfo, err := os.Stat(config.Path)
	// It is intended that sometimes the config points to a path that does not exist
	// fileInfo will be nil in those cases
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Can't stat test fixture '%s' because '%s'", config.Path, err)
	}

	return fileInfo
}

// GenerateScanInputMock will try to open the file locally, and fail if the file doesn't exist
func GenerateScanInputMock(t *testing.T, config ScanInputMockConfig) ScanInputWrapper {
	t.Helper()

	var scanRoot string
	if filepath.IsAbs(config.FakeScanRoot) {
		scanRoot = config.FakeScanRoot
	} else {
		workingDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Can't get working directory because '%s'", workingDir)
		}
		scanRoot = filepath.Join(workingDir, config.FakeScanRoot)
	}

	f, err := os.Open(filepath.Join(scanRoot, config.Path))
	if err != nil {
		t.Fatalf("Can't open test fixture '%s' because '%s'", config.Path, err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Can't stat test fixture '%s' because '%s'", config.Path, err)
	}

	return ScanInputWrapper{
		fileHandle: f,
		ScanInput: filesystem.ScanInput{
			FS:     os.DirFS(scanRoot).(fs.FS),
			Path:   config.Path,
			Root:   scanRoot,
			Reader: f,
			Info:   info,
		},
	}
}

// func fillExtractorField(pkgs []*extractor.Inventory, extractor filesystem.Extractor) {
// 	for i := range pkgs {
// 		pkgs[i].Extractor = extractor
// 	}
// }

// Form returns the singular or plural form that should be used based on the given count
func Form(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}

	return plural
}

type TestTableEntry struct {
	Name              string
	InputConfig       ScanInputMockConfig
	WantInventory     []*extractor.Inventory
	WantErrIs         error
	WantErrContaining string
}

// ExtractionTester tests common properties of a extractor, and returns the raw values from running extract
func ExtractionTester(t *testing.T, extractor filesystem.Extractor, tt TestTableEntry) ([]*extractor.Inventory, error) {
	t.Helper()

	wrapper := GenerateScanInputMock(t, tt.InputConfig)
	got, err := extractor.Extract(context.Background(), &wrapper.ScanInput)
	wrapper.Close()

	if tt.WantErrContaining == "" && tt.WantErrIs == nil {
		if err != nil {
			t.Errorf("Got error when expecting none: '%s'", err)
			return got, err
		}
	} else {
		if err == nil {
			t.Errorf("Expected to get error, but did not.")
			return got, err
		}
	}

	if tt.WantErrIs != nil {
		if !errors.Is(err, tt.WantErrIs) {
			t.Errorf("Expected to get \"%v\" error but got \"%v\" instead", tt.WantErrIs, err)
		}
		return got, err
	}

	if tt.WantErrContaining != "" {
		if !strings.Contains(err.Error(), tt.WantErrContaining) {
			t.Errorf("Expected to get \"%s\" error, but got \"%v\"", tt.WantErrContaining, err)
		}
		return got, err
	}

	SortInventories(got)
	SortInventories(tt.WantInventory)
	if !cmp.Equal(got, tt.WantInventory) {
		t.Errorf("%s.Extract(%s) diff: \n%s", extractor.Name(), tt.InputConfig.Path, cmp.Diff(got, tt.WantInventory))
	}

	return got, err
}

// SortInventories sorts the incoming inventories to allow cmp matching
// This does not sort all available fields (e.g. Metadata)
func SortInventories(inv []*extractor.Inventory) {
	slices.SortFunc(inv, func(a, b *extractor.Inventory) int {
		// TODO: Is there a better way to compare SourceCode?
		sourceComparison := 0
		if a.SourceCode != nil && b.SourceCode != nil {
			sourceComparison = ordercmp.Or(
				ordercmp.Compare(a.SourceCode.Repo, b.SourceCode.Repo),
				ordercmp.Compare(a.SourceCode.Commit, b.SourceCode.Commit),
			)
		} else if a.SourceCode == nil {
			sourceComparison = -1
		} else if b.SourceCode == nil {
			sourceComparison = 1
		}

		return ordercmp.Or(
			ordercmp.Compare(strings.Join(a.Locations, "//"), strings.Join(b.Locations, "//")),
			ordercmp.Compare(a.Name, b.Name),
			ordercmp.Compare(a.Version, b.Version),
			sourceComparison,
		)
	})
}
