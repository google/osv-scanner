package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// A simple sort utility for comparing slices of LibraryInfo
func sortLibraries(libs []*LibraryInfo) {
	sort.Slice(libs, func(i, j int) bool {
		return libs[i].Name < libs[j].Name
	})
}

func findLibByName(libs []*LibraryInfo, name string) *LibraryInfo {
	for _, l := range libs {
		if l.Name == name {
			return l
		}
	}
	return nil
}

func TestFindMainEntryPoint(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name          string
		directoryPath string
		expectedPaths []string
		expectError   bool
	}{
		{
			name:          "Happy Path - Single File",
			directoryPath: "./testdata/pythonfilewithentrypoint",
			expectedPaths: []string{"testdata/pythonfilewithentrypoint/main.py"},
			expectError:   false,
		},
		{
			name:          "Multiple Files with One Entry Point",
			directoryPath: "./testdata/multifileswithentrypoint",
			expectedPaths: []string{"testdata/multifileswithentrypoint/main.py"},
			expectError:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualPaths, err := findMainEntryPoint(tc.directoryPath)
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected an error, but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect an error, but got: %v", err)
				}
			}

			// To compare slices, we need a canonical order.
			// The expected paths also need to be joined with the temp directory path.
			expectedFullPaths := []string{}
			for _, path := range tc.expectedPaths {
				absPath, err := filepath.Abs(path)
				if err != nil {
					t.Errorf("Failed to get absolute path for %s: %v", path, err)
				}
				expectedFullPaths = append(expectedFullPaths, absPath)
			}

			if !reflect.DeepEqual(actualPaths, expectedFullPaths) {
				t.Errorf("Expected paths %v, but got %v", expectedFullPaths, actualPaths)
			}
		})
	}

	t.Run("Non-existent Directory", func(t *testing.T) {
		_, err := findMainEntryPoint("path/that/does/not/exist")
		if err == nil {
			t.Errorf("Expected an error for a non-existent directory, but got none")
		}
	})
}

func TestParsePoetryLibrary(t *testing.T) {
	testCases := []struct {
		name           string
		fpathInTestDir string // The fpath to pass to the function.
		expectedResult []*LibraryInfo
		expectError    bool
	}{
		{
			name:           "Happy Path - Valid poetry.lock",
			fpathInTestDir: "./testdata/pythonfilewithentrypoint/poetry.lock",
			expectedResult: []*LibraryInfo{
				{Name: "numpy", Version: "1.26.4"},
				{Name: "pandas", Version: "2.2.2"},
			},
			expectError: false,
		},
		{
			name:           "File Not Found - No poetry.lock",
			fpathInTestDir: "./testdata/test/poetry.lock",
			expectedResult: nil,
			expectError:    true,
		},
		{
			name:           "Malformed poetry.lock - Parser error",
			fpathInTestDir: "./testdata/multifileswithentrypoint/poetry.lock",
			expectedResult: nil,
			expectError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			absDir, err := filepath.Abs(tc.fpathInTestDir)
			if err != nil {
				t.Errorf("Failed to get absolute path for %s: %v", tc.fpathInTestDir, err)
			}
			actualResult, err := parsePoetryLock(ctx, absDir)
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected an error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect an error, but got: %v", err)
				}
			}

			// Sort both slices to ensure a consistent order for comparison.
			sortLibraries(actualResult)
			sortLibraries(tc.expectedResult)

			if !reflect.DeepEqual(actualResult, tc.expectedResult) {
				t.Errorf("Expected result %v, but got %v", tc.expectedResult, actualResult)
			}
		})
	}
}

func TestFindImportedLibraries_BasicStyles(t *testing.T) {
	src := `import os
import numpy as np
from pkg import a, b as beta
import pkg.module
from starpkg import *
`

	libs, err := findImportedLibraries(strings.NewReader(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expect at least these libraries
	if findLibByName(libs, "os") == nil {
		t.Errorf("expected os to be found")
	}
	np := findLibByName(libs, "numpy")
	if np == nil || np.Alias != "np" {
		t.Errorf("expected numpy with alias np, got %+v", np)
	}
	pkgLib := findLibByName(libs, "pkg")
	if pkgLib == nil {
		t.Fatalf("expected pkg to be found")
	}
	// Expect modules a and b (alias beta)
	foundA, foundB := false, false
	for _, m := range pkgLib.Modules {
		if m.Name == "a" {
			foundA = true
		}
		if m.Name == "b" && m.Alias == "beta" {
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Errorf("expected modules a and b as beta in pkg, got %+v", pkgLib.Modules)
	}

	// starpkg should have a Module with Name="*"
	star := findLibByName(libs, "starpkg")
	if star == nil || len(star.Modules) == 0 || star.Modules[0].Name != "*" {
		t.Errorf("expected star import for starpkg, got %+v", star)
	}
}

func TestFindLibrariesPoetryLock_Filtering(t *testing.T) {
	src := `import os
import numpy as np
from pkg import a, b
import unrelated
`

	poetry := []*LibraryInfo{
		{Name: "numpy", Version: "1.2.3"},
		{Name: "pkg", Version: "0.1.0"},
	}

	libs, err := findLibrariesPoetryLock(strings.NewReader(src), poetry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expect only numpy and pkg (unrelated and os excluded)
	if len(libs) != 2 {
		t.Fatalf("expected 2 libraries, got %d: %+v", len(libs), libs)
	}
	// Ensure versions are populated from poetry
	names := []string{libs[0].Name, libs[1].Name}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"numpy", "pkg"}) {
		t.Fatalf("unexpected names: %v", names)
	}
}

func TestGetImportedItemsFilePathsAndFindImportedLibrary(t *testing.T) {
	tmp := t.TempDir()

	// Create package folder like mypkg-1.0.0
	pkgDir := filepath.Join(tmp, "mypkg-1.0.0")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Create a file with a function definition and imports
	fpath := filepath.Join(pkgDir, "module_a.py")
	content := "import os\nfrom otherpkg import sub\n\ndef func1(arg):\n    pass\n"
	if err := os.WriteFile(fpath, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	lib := &LibraryInfo{
		Name:    "mypkg",
		Version: "1.0.0",
		Modules: []*ModuleInfo{{Name: "func1"}},
	}

	if err := getImportedItemsFilePaths(lib, tmp); err != nil {
		t.Fatalf("getImportedItemsFilePaths failed: %v", err)
	}

	// The module should have recorded the path
	if len(lib.Modules[0].SourceDefinedPaths) == 0 {
		t.Fatalf("expected SourceDefinedPaths to be set, got %+v", lib.Modules[0])
	}
	if !strings.HasSuffix(lib.Modules[0].SourceDefinedPaths[0], "module_a.py") {
		t.Fatalf("unexpected path: %s", lib.Modules[0].SourceDefinedPaths[0])
	}

	// Now test findImportedLibrary: it should detect imports inside that file
	if err := findImportedLibrary(lib); err != nil {
		t.Fatalf("findImportedLibrary failed: %v", err)
	}
	// Expect imported libraries to contain os and otherpkg
	foundOs, foundOther := false, false
	for _, name := range lib.Modules[0].ImportedLibraryNames {
		if name == "os" {
			foundOs = true
		}
		if name == "otherpkg" {
			foundOther = true
		}
	}
	if !foundOs || !foundOther {
		t.Fatalf("expected imported libs os and otherpkg, got: %v", lib.Modules[0].ImportedLibraryNames)
	}
}
func TestComputeReachability_NoModules(t *testing.T) {
	lib := &LibraryInfo{
		Name:         "testlib",
		Version:      "1.0.0",
		Dependencies: []string{"dep1", "dep2"},
		Modules:      nil,
	}

	result := computeReachability(lib)

	if result.Name != "testlib" || result.Version != "1.0.0" {
		t.Fatalf("expected name=testlib version=1.0.0, got %s %s", result.Name, result.Version)
	}
	if len(result.Modules) != 0 {
		t.Fatalf("expected no modules, got %d", len(result.Modules))
	}
	if len(result.Dependencies) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(result.Dependencies))
	}
	// When no modules, all deps should be reachable
	for _, dep := range result.Dependencies {
		if !dep.Reachable {
			t.Fatalf("expected all deps reachable when no modules, got unreachable: %s", dep.Name)
		}
	}
}

func TestComputeReachability_WithModules(t *testing.T) {
	lib := &LibraryInfo{
		Name:         "testlib",
		Version:      "1.0.0",
		Dependencies: []string{"requests", "json"},
		Modules: []*ModuleInfo{
			{
				Name:                 "fetch_data",
				SourceDefinedPaths:   []string{"/path/to/module.py"},
				ImportedLibraryNames: []string{"requests", "urllib"},
			},
			{
				Name:                 "parse_json",
				SourceDefinedPaths:   []string{"/path/to/parser.py"},
				ImportedLibraryNames: []string{"json"},
			},
		},
	}

	result := computeReachability(lib)

	if len(result.Modules) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(result.Modules))
	}

	// Check fetch_data module: requests should be reachable, json should not
	fetchModule := result.Modules[0]
	if fetchModule.Name != "fetch_data" {
		t.Fatalf("expected module name fetch_data, got %s", fetchModule.Name)
	}
	if len(fetchModule.Dependencies) != 2 {
		t.Fatalf("expected 2 dependencies in module, got %d", len(fetchModule.Dependencies))
	}

	foundReachableRequests := false
	foundUnreachableJson := false
	for _, dep := range fetchModule.Dependencies {
		if dep.Name == "requests" && dep.Reachable {
			foundReachableRequests = true
		}
		if dep.Name == "json" && !dep.Reachable {
			foundUnreachableJson = true
		}
	}
	if !foundReachableRequests || !foundUnreachableJson {
		t.Fatalf("fetch_data: expected requests reachable and json unreachable, got %+v", fetchModule.Dependencies)
	}

	// Check parse_json module: json should be reachable, requests should not
	parseModule := result.Modules[1]
	if parseModule.Name != "parse_json" {
		t.Fatalf("expected module name parse_json, got %s", parseModule.Name)
	}

	foundReachableJson := false
	foundUnreachableRequests := false
	for _, dep := range parseModule.Dependencies {
		if dep.Name == "json" && dep.Reachable {
			foundReachableJson = true
		}
		if dep.Name == "requests" && !dep.Reachable {
			foundUnreachableRequests = true
		}
	}
	if !foundReachableJson || !foundUnreachableRequests {
		t.Fatalf("parse_json: expected json reachable and requests unreachable, got %+v", parseModule.Dependencies)
	}
}

func TestComputeReachability_ModuleWithoutSourcePaths(t *testing.T) {
	lib := &LibraryInfo{
		Name:         "testlib",
		Version:      "1.0.0",
		Dependencies: []string{"dep1", "dep2"},
		Modules: []*ModuleInfo{
			{
				Name:                 "wildcard_import",
				SourceDefinedPaths:   nil,
				ImportedLibraryNames: nil,
			},
		},
	}

	result := computeReachability(lib)

	if len(result.Modules) != 1 {
		t.Fatalf("expected 1 module, got %d", len(result.Modules))
	}
	moduleResult := result.Modules[0]
	if len(moduleResult.Dependencies) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(moduleResult.Dependencies))
	}
	// When source paths not found, assume all deps reachable
	for _, dep := range moduleResult.Dependencies {
		if !dep.Reachable {
			t.Fatalf("expected all deps reachable when no source paths, got unreachable: %s", dep.Name)
		}
	}
}
