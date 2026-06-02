package gitlab

import (
	"testing"
)

func TestIdentifier_Vendor(t *testing.T) {
	tests := []struct {
		identifierType IdentifierType
		expectedVendor string
	}{
		{IdentifierTypeCVE, "NVD"},
		{IdentifierTypeELSA, "Oracle"},
		{IdentifierTypeGHSA, "GitHub"},
		{IdentifierTypeGLAM, "GitLab"},
		{IdentifierTypeH1, "HackerOne"},
		{IdentifierTypeMAL, "OpenSSF"},
		{IdentifierTypeOSVDB, "OSVDB"},
		{IdentifierTypeRHSA, "RedHat"},
		{IdentifierTypeUSN, "Ubuntu"},
		{IdentifierTypeCWE, "Unknown"},
		{IdentifierTypeOWASPTop10, "Unknown"},
		{IdentifierType("unknown"), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(string(tt.identifierType), func(t *testing.T) {
			id := Identifier{Type: tt.identifierType}
			if got := id.Vendor(); got != tt.expectedVendor {
				t.Errorf("Vendor() = %v, want %v", got, tt.expectedVendor)
			}
		})
	}
}

func TestParseIdentifierID(t *testing.T) {
	tests := []struct {
		input        string
		expectedType IdentifierType
		expectedOK   bool
	}{
		{"CVE-2023-1234", IdentifierTypeCVE, true},
		{"cve-2023-1234", IdentifierTypeCVE, true},
		{"CWE-79", IdentifierTypeCWE, true},
		{"CWE-invalid", IdentifierType(""), false},
		{"CWE", IdentifierType(""), false}, // No number part
		{"ELSA-2023-1234", IdentifierTypeELSA, true},
		{"GHSA-xxxx-yyyy-zzzz", IdentifierTypeGHSA, true},
		{"GLAM-12345", IdentifierTypeGLAM, true},
		{"HACKERONE-12345", IdentifierTypeH1, true},
		{"MAL-2023-1234", IdentifierTypeMAL, true},
		{"OSVDB-12345", IdentifierTypeOSVDB, true},
		{"RHSA-2023:1234", IdentifierTypeRHSA, true},
		{"USN-1234-1", IdentifierTypeUSN, true},
		{"USN", IdentifierType(""), false},       // No suffix part (must not panic)
		{"HACKERONE", IdentifierType(""), false}, // No suffix part (must not panic)
		{"INVALID-123", IdentifierType(""), false},
		{"", IdentifierType(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			id, ok := ParseIdentifierID(tt.input)
			if ok != tt.expectedOK {
				t.Errorf("ParseIdentifierID(%q) ok = %v, want %v", tt.input, ok, tt.expectedOK)
				return
			}
			if ok && id.Type != tt.expectedType {
				t.Errorf("ParseIdentifierID(%q) type = %v, want %v", tt.input, id.Type, tt.expectedType)
			}
		})
	}
}

func TestCVEIdentifier(t *testing.T) {
	id := CVEIdentifier("CVE-2023-1234")

	if id.Type != IdentifierTypeCVE {
		t.Errorf("expected type %v, got %v", IdentifierTypeCVE, id.Type)
	}
	if id.Name != "CVE-2023-1234" {
		t.Errorf("expected name CVE-2023-1234, got %v", id.Name)
	}
	if id.Value != "CVE-2023-1234" {
		t.Errorf("expected value CVE-2023-1234, got %v", id.Value)
	}
	if id.URL != "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234" {
		t.Errorf("unexpected URL: %v", id.URL)
	}
}

func TestCWEIdentifier(t *testing.T) {
	id := CWEIdentifier(79)

	if id.Type != IdentifierTypeCWE {
		t.Errorf("expected type %v, got %v", IdentifierTypeCWE, id.Type)
	}
	if id.Name != "CWE-79" {
		t.Errorf("expected name CWE-79, got %v", id.Name)
	}
	if id.Value != "79" {
		t.Errorf("expected value 79, got %v", id.Value)
	}
	if id.URL != "https://cwe.mitre.org/data/definitions/79.html" {
		t.Errorf("unexpected URL: %v", id.URL)
	}
}

func TestGHSAIdentifier(t *testing.T) {
	id := GHSAIdentifier("GHSA-xxxx-yyyy-zzzz")

	if id.Type != IdentifierTypeGHSA {
		t.Errorf("expected type %v, got %v", IdentifierTypeGHSA, id.Type)
	}
	if id.URL != "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("unexpected URL: %v", id.URL)
	}
}

func TestGLAMIdentifier(t *testing.T) {
	id := GLAMIdentifier("GLAM-12345")

	if id.Type != IdentifierTypeGLAM {
		t.Errorf("expected type %v, got %v", IdentifierTypeGLAM, id.Type)
	}
	if id.Name != "GLAM-12345" {
		t.Errorf("expected name GLAM-12345, got %v", id.Name)
	}
	if id.URL != "" {
		t.Errorf("expected no URL for GLAM, got %v", id.URL)
	}
}

func TestMALIdentifier(t *testing.T) {
	id := MALIdentifier("MAL-2023-1234")

	if id.Type != IdentifierTypeMAL {
		t.Errorf("expected type %v, got %v", IdentifierTypeMAL, id.Type)
	}
	if id.Name != "MAL-2023-1234" {
		t.Errorf("expected name MAL-2023-1234, got %v", id.Name)
	}
	if id.URL != "" {
		t.Errorf("expected no URL for MAL, got %v", id.URL)
	}
}

func TestRHSAIdentifier(t *testing.T) {
	id := RHSAIdentifier("RHSA-2023:1234")

	if id.Type != IdentifierTypeRHSA {
		t.Errorf("expected type %v, got %v", IdentifierTypeRHSA, id.Type)
	}
	if id.URL != "https://access.redhat.com/errata/RHSA-2023:1234" {
		t.Errorf("unexpected URL: %v", id.URL)
	}
}

func TestUSNIdentifier(t *testing.T) {
	id := USNIdentifier("USN-1234-1")

	if id.Type != IdentifierTypeUSN {
		t.Errorf("expected type %v, got %v", IdentifierTypeUSN, id.Type)
	}
	if id.URL != "https://usn.ubuntu.com/1234-1/" {
		t.Errorf("unexpected URL: %v", id.URL)
	}
}

func TestELSAIdentifier(t *testing.T) {
	id := ELSAIdentifier("ELSA-2023-1234")

	if id.Type != IdentifierTypeELSA {
		t.Errorf("expected type %v, got %v", IdentifierTypeELSA, id.Type)
	}
	if id.URL != "https://linux.oracle.com/errata/ELSA-2023-1234.html" {
		t.Errorf("unexpected URL: %v", id.URL)
	}
}

func TestH1Identifier(t *testing.T) {
	id := H1Identifier("HACKERONE-12345")

	if id.Type != IdentifierTypeH1 {
		t.Errorf("expected type %v, got %v", IdentifierTypeH1, id.Type)
	}
	if id.Value != "12345" {
		t.Errorf("expected value 12345, got %v", id.Value)
	}
	if id.URL != "https://hackerone.com/reports/12345" {
		t.Errorf("unexpected URL: %v", id.URL)
	}
}

func TestOSVDBIdentifier(t *testing.T) {
	id := OSVDBIdentifier("OSVDB-12345")

	if id.Type != IdentifierTypeOSVDB {
		t.Errorf("expected type %v, got %v", IdentifierTypeOSVDB, id.Type)
	}
	if id.URL != "https://cve.mitre.org/data/refs/refmap/source-OSVDB.html" {
		t.Errorf("unexpected URL: %v", id.URL)
	}
}

func TestOWASPTop10Identifier(t *testing.T) {
	id := OWASPTop10Identifier("A01:2021", "Broken Access Control")

	if id.Type != IdentifierTypeOWASPTop10 {
		t.Errorf("expected type %v, got %v", IdentifierTypeOWASPTop10, id.Type)
	}
	if id.Name != "A01:2021 - Broken Access Control" {
		t.Errorf("expected name 'A01:2021 - Broken Access Control', got %v", id.Name)
	}
	if id.Value != "A01:2021" {
		t.Errorf("expected value A01:2021, got %v", id.Value)
	}
}
