package exclusions_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/internal/exclusions"
	"github.com/google/osv-scanner/internal/sbom"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
)

type MockReporter struct {
	Output []string
	Error  []string
}

func (r *MockReporter) PrintText(text string) {
	r.Output = append(r.Output, text)
}
func (r *MockReporter) PrintError(text string) {
	r.Error = append(r.Error, text)
}

func (r *MockReporter) HasPrintedError() bool {
	return r.Error != nil
}
func (r *MockReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return nil
}

func TestExcludePackages(t *testing.T) {
	t.Parallel()
	type testCase struct {
		name                 string
		lockfileData         []lockfile.PackageDetails
		exclusionPatterns    []string
		expectedLockfileData []lockfile.PackageDetails
		wantErr              bool
		outputText           []string
		errorText            []string
	}
	tests := []testCase{
		{
			name:                 "Package matches regex pattern",
			lockfileData:         []lockfile.PackageDetails{{Name: "package1"}, {Name: "package2"}, {Name: "package3"}},
			exclusionPatterns:    []string{"package1"},
			expectedLockfileData: []lockfile.PackageDetails{{Name: "package2"}, {Name: "package3"}},
			wantErr:              false,
			outputText:           []string{"Regex Match Found for exclusion pattern: 'package1'\n", "Excluding package from OSV query: package1\n"},
			errorText:            nil,
		},
		{
			name:                 "Multiple packages matches regex pattern",
			lockfileData:         []lockfile.PackageDetails{{Name: "package1"}, {Name: "package2"}, {Name: "somethingDifferent"}},
			exclusionPatterns:    []string{".*package.*"},
			expectedLockfileData: []lockfile.PackageDetails{{Name: "somethingDifferent"}},
			wantErr:              false,
			outputText:           []string{"Regex Match Found for exclusion pattern: '.*package.*'\n", "Excluding package from OSV query: package1\n", "Regex Match Found for exclusion pattern: '.*package.*'\n", "Excluding package from OSV query: package2\n"},
			errorText:            nil,
		},
		{
			name:                 "No packages match regex pattern",
			lockfileData:         []lockfile.PackageDetails{{Name: "package1"}, {Name: "package2"}, {Name: "package3"}},
			exclusionPatterns:    []string{"package4"},
			expectedLockfileData: []lockfile.PackageDetails{{Name: "package1"}, {Name: "package2"}, {Name: "package3"}},
			wantErr:              false,
			outputText:           nil,
			errorText:            nil,
		},
		{
			name:                 "Invalid regex pattern",
			lockfileData:         []lockfile.PackageDetails{{Name: "package1"}, {Name: "package2"}, {Name: "package3"}},
			exclusionPatterns:    []string{"*hello*"},
			expectedLockfileData: []lockfile.PackageDetails{{Name: "package1"}, {Name: "package2"}, {Name: "package3"}},
			wantErr:              false,
			outputText:           nil,
			errorText:            []string{"invalid exclusion pattern: error parsing regexp: missing argument to repetition operator: `*`"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockReporter := &MockReporter{}
			lockfile := lockfile.Lockfile{Packages: tt.lockfileData}
			parseExclusions, err := exclusions.ParseExclusions(tt.exclusionPatterns)
			if err != nil {
				mockReporter.PrintError(err.Error())
			}
			filteredLockfile, err := exclusions.ExcludePackages(mockReporter, parseExclusions, &lockfile)

			if !cmp.Equal(err != nil, tt.wantErr) {
				t.Errorf("ExcludePackages returned an unexpected error: %v", err)
			}

			for i, pkg := range filteredLockfile.Packages {
				if !cmp.Equal(pkg.Name, tt.expectedLockfileData[i].Name) {
					t.Errorf("ExcludePackages did not filter the packages as expected. Got: %v, Want: %v", filteredLockfile.Packages, tt.expectedLockfileData)
				}
			}

			if !cmp.Equal(mockReporter.Output, tt.outputText) {
				t.Errorf("ExcludePackages did not print the expected output. Got: %v, Want: %v", mockReporter.Output, tt.outputText)
			}

			if !cmp.Equal(mockReporter.Error, tt.errorText) {
				t.Errorf("ExcludePackages did not print the expected error. Got: %v, Want: %v", mockReporter.Error, tt.errorText)
			}
		})
	}
}

func TestExcludeSBOMPackages(t *testing.T) {
	t.Parallel()
	type testCase struct {
		name              string
		SBOMData          sbom.Identifier
		exclusionPatterns []string
		wantMatch         bool
		wantErr           bool
		outputText        []string
		errorText         []string
	}

	tests := []testCase{
		{
			name:              "Package matches regex pattern",
			SBOMData:          sbom.Identifier{PURL: "package1"},
			exclusionPatterns: []string{".*package.*"},
			wantMatch:         true,
			wantErr:           false,
			outputText:        []string{"Regex Match Found for exclusion pattern: '.*package.*'\n", "Excluding package from OSV query: package1\n"},
			errorText:         nil,
		},
		{
			name:              "No packages match regex pattern",
			SBOMData:          sbom.Identifier{PURL: "package1"},
			exclusionPatterns: []string{"somethingDifferent"},
			wantMatch:         false,
			wantErr:           false,
			outputText:        nil,
			errorText:         nil,
		},
		{
			name:              "Invalid regex pattern",
			SBOMData:          sbom.Identifier{PURL: "package1"},
			exclusionPatterns: []string{"*hello*"},
			wantMatch:         false,
			wantErr:           false,
			outputText:        nil,
			errorText:         []string{"invalid exclusion pattern: error parsing regexp: missing argument to repetition operator: `*`"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockReporter := &MockReporter{}
			parsedExclusions, err := exclusions.ParseExclusions(tt.exclusionPatterns)
			if err != nil {
				mockReporter.PrintError(err.Error())
			}
			match, err := exclusions.ExcludeSBOMPackages(mockReporter, parsedExclusions, &tt.SBOMData)

			if !cmp.Equal(match, tt.wantMatch) {
				t.Errorf("Expected match: %v, got match: %v", tt.wantMatch, match)
			}

			if !cmp.Equal(err != nil, tt.wantErr) {
				t.Errorf("Expected error: %v, got error: %v", tt.wantErr, err)
			}

			if !cmp.Equal(mockReporter.Output, tt.outputText) {
				t.Errorf("ExcludeSBOMPackages did not print the expected output. Got: %v, Want: %v", mockReporter.Output, tt.outputText)
			}

			if !cmp.Equal(mockReporter.Error, tt.errorText) {
				t.Errorf("ExcludeSBOMPackages did not print the expected error. Got: %v, Want: %v", mockReporter.Error, tt.errorText)
			}
		})
	}
}

func TestIsRegexPatterns(t *testing.T) {
	t.Parallel()
	type testCase struct {
		name    string
		pattern []string
		want    bool
	}
	testCases := []testCase{
		{
			name:    "Single valid regex pattern",
			pattern: []string{".*aValidPattern"},
			want:    false,
		},
		{
			name:    "Multiple valid regex patterns",
			pattern: []string{".*aValidPattern", "another_valid_{r1}egex"},
			want:    false,
		},
		{
			name:    "Invalid regex pattern",
			pattern: []string{"*myInvalidPattern*["},
			want:    true,
		},
	}

	for _, tt := range testCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := exclusions.IsRegexPatterns(tt.pattern)
			if (err != nil) != tt.want {
				t.Errorf("IsRegexPatterns() for pattern %s = %v; want %v", tt.pattern, err, tt.want)
			}
		})
	}
}
