package main

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// A simple sort utility for comparing slices of LibraryInfo
func sortLibraries(libs []*LibraryInfo) {
	sort.Slice(libs, func(i, j int) bool {
		return libs[i].Name < libs[j].Name
	})
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

			sort.Strings(actualPaths)
			sort.Strings(expectedFullPaths)

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
			ctx := context.Background()
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
