package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestFindMainEntryPoint(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name          string
		filesToCreate map[string]string // map[filename]content
		expectedPaths []string
		expectError   bool
	}{
		{
			name: "Happy Path - Single File",
			filesToCreate: map[string]string{
				"main.py": "print('hello')\nif __name__ == '__main__':\n    pass",
			},
			expectedPaths: []string{"main.py"},
			expectError:   false,
		},
		{
			name: "Multiple Files with One Entry Point",
			filesToCreate: map[string]string{
				"main.py":   "if __name__ == '__main__':\n    pass",
				"utils.py":  "def helper():\n    return 1",
				"script.sh": "#!/bin/bash",
			},
			expectedPaths: []string{"main.py"},
			expectError:   false,
		},
		{
			name: "Nested Directory",
			filesToCreate: map[string]string{
				"app/main.py": "if __name__ == '__main__':\n    pass",
			},
			expectedPaths: []string{"app/main.py"},
			expectError:   false,
		},
		{
			name: "No Entry Points Found",
			filesToCreate: map[string]string{
				"utils.py": "def helper():\n    return 1",
			},
			expectedPaths: []string{},
			expectError:   false, // As per original function's logic
		},
		{
			name:          "Empty Directory",
			filesToCreate: map[string]string{},
			expectedPaths: []string{},
			expectError:   false, // As per original function's logic
		},
		{
			name: "Entry Point with Different Spacing and Quotes",
			filesToCreate: map[string]string{
				"app.py": "if __name__==\"__main__\":\n    pass",
			},
			expectedPaths: []string{"app.py"},
			expectError:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Setup: Create a temporary directory for the test
			tmpDir := t.TempDir()

			// Create all the files and subdirectories needed for the test case
			for path, content := range tc.filesToCreate {
				fullPath := filepath.Join(tmpDir, path)
				// Ensure parent directory exists
				if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
					t.Fatalf("Failed to create parent directory for %s: %v", path, err)
				}
				if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to write test file %s: %v", path, err)
				}
			}

			// 2. Execution: Call the function under test
			actualPaths, err := findMainEntryPoint(tmpDir)

			// 3. Assertion: Check the results
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
			for _, p := range tc.expectedPaths {
				expectedFullPaths = append(expectedFullPaths, filepath.Join(tmpDir, p))
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

// A simple sort utility for comparing slices of LibraryInfo
func sortLibraries(libs []*LibraryInfo) {
	sort.Slice(libs, func(i, j int) bool {
		return libs[i].Name < libs[j].Name
	})
}

func TestParsePoetryLibrary(t *testing.T) {
	// A sample valid poetry.lock content for testing.
	validPoetryLockContent := `
[[package]]
name = "numpy"
version = "1.26.4"

[[package]]
name = "pandas"
version = "2.2.2"
`
	// A poetry.lock file that is syntactically valid but has no packages.
	emptyPoetryLockContent := `
# This file is intentionally left blank
`
	// Malformed content that should cause a parsing error.
	malformedPoetryLockContent := `
[[package]]
name = "invalid"
version = 
`

	testCases := []struct {
		name              string
		poetryLockContent string // Content to write to the mock poetry.lock file.
		fpathInTestDir    string // The fpath to pass to the function.
		expectedResult    []*LibraryInfo
		expectError       bool
	}{
		{
			name:              "Happy Path - Valid poetry.lock",
			poetryLockContent: validPoetryLockContent,
			fpathInTestDir:    "anyfile.py", // The file can be anything, it's just used for its directory.
			expectedResult: []*LibraryInfo{
				{Name: "numpy", Version: "1.26.4"},
				{Name: "pandas", Version: "2.2.2"},
			},
			expectError: false,
		},
		{
			name:              "File Not Found - No poetry.lock",
			poetryLockContent: "", // An empty string means we don't create the file.
			fpathInTestDir:    "anyfile.py",
			expectedResult:    nil,
			expectError:       true,
		},
		{
			name:              "Empty poetry.lock - No packages",
			poetryLockContent: emptyPoetryLockContent,
			fpathInTestDir:    "anyfile.py",
			expectedResult:    []*LibraryInfo{},
			expectError:       false,
		},
		{
			name:              "Malformed poetry.lock - Parser error",
			poetryLockContent: malformedPoetryLockContent,
			fpathInTestDir:    "anyfile.py",
			expectedResult:    nil,
			expectError:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Setup a temporary directory for the test.
			tmpDir := t.TempDir()

			// 2. If the test case has content, create the poetry.lock file.
			if tc.poetryLockContent != "" {
				lockfilePath := filepath.Join(tmpDir, "poetry.lock")
				err := os.WriteFile(lockfilePath, []byte(tc.poetryLockContent), 0644)
				if err != nil {
					t.Fatalf("Failed to write test poetry.lock: %v", err)
				}
			}

			// 3. Call the function under test.
			fpath := filepath.Join(tmpDir, tc.fpathInTestDir)
			actualResult, err := parsePoetryLock(fpath)

			// 4. Assert the results.
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
