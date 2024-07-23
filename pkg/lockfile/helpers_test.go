package lockfile_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func expectErrContaining(t *testing.T, err error, str string) {
	t.Helper()

	if err == nil {
		t.Errorf("Expected to get error, but did not")
	}

	if !strings.Contains(err.Error(), str) {
		t.Errorf("Expected to get \"%s\" error, but got \"%v\"", str, err)
	}
}

func expectErrIs(t *testing.T, err error, expected error) {
	t.Helper()

	if err == nil {
		t.Errorf("Expected to get error, but did not")
	}

	if !errors.Is(err, expected) {
		t.Errorf("Expected to get \"%v\" error but got \"%v\" instead", expected, err)
	}
}

func packageToString(pkg *lockfile.Inventory) string {
	source := pkg.SourceCode
	commit := "<no commit>"
	if source != nil {
		commit = source.Commit
	}

	groups := "<no groups>"
	if dg, ok := pkg.Metadata.(lockfile.DepGroups); ok {
		if depGroups := dg.DepGroups(); len(depGroups) != 0 {
			groups = strings.Join(dg.DepGroups(), ", ")
		}
	}

	locations := strings.Join(pkg.Locations, ", ")

	return fmt.Sprintf("%s@%s (%s, %s, %s) @ [%s]", pkg.Name, pkg.Version, ecosystemOrEmpty(pkg), commit, groups, locations)
}

func hasPackage(t *testing.T, packages []*lockfile.Inventory, pkg *lockfile.Inventory) bool {
	t.Helper()

	for _, details := range packages {
		if reflect.DeepEqual(details, pkg) {
			return true
		}
	}

	return false
}

func expectPackage(t *testing.T, packages []*lockfile.Inventory, pkg *lockfile.Inventory) {
	t.Helper()

	if !hasPackage(t, packages, pkg) {
		t.Errorf(
			"Expected packages to include %s@%s (%s), but it did not",
			pkg.Name,
			pkg.Version,
			ecosystemOrEmpty(pkg),
		)
	}
}

func findMissingPackages(t *testing.T, actualPackages []*lockfile.Inventory, expectedPackages []*lockfile.Inventory) []*lockfile.Inventory {
	t.Helper()
	var missingPackages []*lockfile.Inventory

	for _, pkg := range actualPackages {
		if !hasPackage(t, expectedPackages, pkg) {
			missingPackages = append(missingPackages, pkg)
		}
	}

	return missingPackages
}

func expectPackages(t *testing.T, actualInventories []*lockfile.Inventory, expectedInventories []*lockfile.Inventory) {
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

func createTestDir(t *testing.T) (string, func()) {
	t.Helper()

	p, err := os.MkdirTemp("", "osv-scanner-test-*")
	if err != nil {
		t.Fatalf("could not create test directory: %v", err)
	}

	return p, func() {
		_ = os.RemoveAll(p)
	}
}

func copyFile(t *testing.T, from, to string) string {
	t.Helper()

	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatalf("could not read test file: %v", err)
	}

	if err := os.WriteFile(to, b, 0600); err != nil {
		t.Fatalf("could not copy test file: %v", err)
	}

	return to
}

func ecosystemOrEmpty(pkg *lockfile.Inventory) string {
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
	path         string
	fakeFileInfo *FakeFileInfo
}

type ScanInputWrapper struct {
	fileHandle *os.File
	ScanInput  lockfile.ScanInput
}

func (siw ScanInputWrapper) Close() {
	siw.fileHandle.Close()
}

// Generate FileInfoMock will either use the fake file information if fakeFileInfo is true,
// otherwise try to run os.Stat on the path passed in and fail if the file does not exist
func GenerateFileInfoMock(t *testing.T, config ScanInputMockConfig) fs.FileInfo {
	if config.fakeFileInfo != nil {
		ret := *config.fakeFileInfo
		ret.FileName = filepath.Base(config.path)
		return ret
	} else {
		fileInfo, err := os.Stat(config.path)
		// It is intended that sometimes the config points to a path that does not exist
		// fileInfo will be nil in those cases
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Can't stat test fixture '%s' because '%s'", config.path, err)
		}
		return fileInfo
	}
}

// GenerateScanInputMock will try to open the file locally, and fail if the file doesn't exist
func GenerateScanInputMock(t *testing.T, config ScanInputMockConfig) ScanInputWrapper {
	f, err := os.Open(config.path)
	if err != nil {
		t.Fatalf("Can't open test fixture '%s' because '%s'", config.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Can't stat test fixture '%s' because '%s'", config.path, err)
	}

	return ScanInputWrapper{
		fileHandle: f,
		ScanInput: lockfile.ScanInput{
			FS:       os.DirFS("/").(lockfile.FS),
			Path:     config.path,
			ScanRoot: config.path,
			Reader:   f,
			Info:     info,
		},
	}
}

func FillExtractorField(pkgs []*lockfile.Inventory, extractor lockfile.Extractor) {
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
