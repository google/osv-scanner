package lockfilescalibr_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
)

func expectErrContaining(t *testing.T, err error, str string) {
	t.Helper()

	if err == nil {
		t.Errorf("Expected to get error, but did not")
		return
	}

	if !strings.Contains(err.Error(), str) {
		t.Errorf("Expected to get \"%s\" error, but got \"%v\"", str, err)
	}
}

func expectErrIs(t *testing.T, err error, expected error) {
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
	if dg, ok := pkg.Metadata.(lockfilescalibr.DepGroups); ok {
		if depGroups := dg.DepGroups(); len(depGroups) != 0 {
			groups = strings.Join(dg.DepGroups(), "/")
		}
	}

	locations := strings.Join(pkg.Locations, ", ")

	return fmt.Sprintf("%s@%s (%s, %s, %s) @ [%s]", pkg.Name, pkg.Version, ecosystemOrEmpty(pkg), commit, groups, locations)
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

func ecosystemOrEmpty(pkg *extractor.Inventory) string {
	ecosystem, err := pkg.Ecosystem()
	if err != nil {
		ecosystem = ""
	}

	return ecosystem
}

// ---

// FakeFileInfo is a fake implementation of fs.FileInfo.
type FakeFileInfo struct {
	FileName    string
	FileSize    int64
	FileMode    fs.FileMode
	FileModTime time.Time
}

// Name returns the name of the file.
func (i FakeFileInfo) Name() string {
	return i.FileName
}

// Size returns the size of the file.
func (i FakeFileInfo) Size() int64 {
	return i.FileSize
}

// Mode returns the mode of the file.
func (i FakeFileInfo) Mode() fs.FileMode {
	return i.FileMode
}

// ModTime returns the modification time of the file.
func (i FakeFileInfo) ModTime() time.Time {
	return i.FileModTime
}

// IsDir returns true if the file is a directory.
func (i FakeFileInfo) IsDir() bool {
	return i.FileMode.IsDir()
}

// Sys is an implementation of FileInfo.Sys() that returns nothing (nil).
func (i FakeFileInfo) Sys() any {
	return nil
}

// -----

type ScanInputMockConfig struct {
	path string
	// fakeScanRoot allows you to set a custom scanRoot, can be relative or absolute,
	// and will be translated to an absolute path
	fakeScanRoot string
	fakeFileInfo *FakeFileInfo
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

	if config.fakeFileInfo != nil {
		ret := *config.fakeFileInfo
		ret.FileName = filepath.Base(config.path)

		return ret
	}

	fileInfo, err := os.Stat(config.path)
	// It is intended that sometimes the config points to a path that does not exist
	// fileInfo will be nil in those cases
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Can't stat test fixture '%s' because '%s'", config.path, err)
	}

	return fileInfo
}

// GenerateScanInputMock will try to open the file locally, and fail if the file doesn't exist
func GenerateScanInputMock(t *testing.T, config ScanInputMockConfig) ScanInputWrapper {
	t.Helper()

	var scanRoot string
	if filepath.IsAbs(config.fakeScanRoot) {
		scanRoot = config.fakeScanRoot
	} else {
		workingDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Can't get working directory because '%s'", workingDir)
		}
		scanRoot = filepath.Join(workingDir, config.fakeScanRoot)
	}

	f, err := os.Open(filepath.Join(scanRoot, config.path))
	if err != nil {
		t.Fatalf("Can't open test fixture '%s' because '%s'", config.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Can't stat test fixture '%s' because '%s'", config.path, err)
	}

	return ScanInputWrapper{
		fileHandle: f,
		ScanInput: filesystem.ScanInput{
			FS:       os.DirFS(scanRoot).(plugin.FS),
			Path:     config.path,
			ScanRoot: scanRoot,
			Reader:   f,
			Info:     info,
		},
	}
}

func fillExtractorField(pkgs []*extractor.Inventory, extractor filesystem.Extractor) {
	for i := range pkgs {
		pkgs[i].Extractor = extractor
	}
}

// Form returns the singular or plural form that should be used based on the given count
func Form(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}

	return plural
}

type testTableEntry struct {
	name              string
	inputConfig       ScanInputMockConfig
	wantInventory     []*extractor.Inventory
	wantErrIs         error
	wantErrContaining string
}

// extractionTester tests common properties of a extractor, and returns the raw values from running extract
func extractionTester(t *testing.T, extractor filesystem.Extractor, tt testTableEntry) ([]*extractor.Inventory, error) {
	t.Helper()

	wrapper := GenerateScanInputMock(t, tt.inputConfig)
	got, err := extractor.Extract(context.Background(), &wrapper.ScanInput)
	wrapper.Close()
	if tt.wantErrIs != nil {
		expectErrIs(t, err, tt.wantErrIs)
	}
	if tt.wantErrContaining != "" {
		expectErrContaining(t, err, tt.wantErrContaining)
	}

	if tt.wantErrContaining == "" && tt.wantErrIs == nil && err != nil {
		t.Errorf("Got error when expecting none: '%s'", err)
	} else {
		fillExtractorField(got, extractor)
		fillExtractorField(tt.wantInventory, extractor)

		expectPackages(t, got, tt.wantInventory)
	}

	return got, err
}
