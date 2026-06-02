package gitlab

import (
	"fmt"
	"strconv"
	"strings"
)

// IdentifierType is the unique ID ("slug") for identifier "kind" bound to a certain vulnerabilities database (CVE, CWE, etc.)
type IdentifierType string

const (
	// IdentifierTypeCVE is the identifier type for CVE IDs (https://cve.mitre.org/cve/)
	IdentifierTypeCVE IdentifierType = "cve"

	// IdentifierTypeCWE is the identifier type for CWE IDs (https://cwe.mitre.org/data/index.html)
	IdentifierTypeCWE IdentifierType = "cwe"

	// IdentifierTypeOWASPTop10 is the identifier type for OWASP Top10 IDs (https://owasp.org/Top10)
	IdentifierTypeOWASPTop10 IdentifierType = "owasp"

	// IdentifierTypeOSVDB is the identifier type for OSVDB IDs (https://cve.mitre.org/data/refs/refmap/source-OSVDB.html)
	IdentifierTypeOSVDB IdentifierType = "osvdb"

	// IdentifierTypeUSN is the identifier type for Ubuntu Security Notice IDs (https://usn.ubuntu.com/)
	IdentifierTypeUSN IdentifierType = "usn"

	// IdentifierTypeRHSA is the identifier type for RHSA IDs (https://access.redhat.com/errata)
	IdentifierTypeRHSA IdentifierType = "rhsa"

	// IdentifierTypeGHSA is the identifier type for GHSA IDs (https://github.com/advisories)
	IdentifierTypeGHSA IdentifierType = "ghsa"

	// IdentifierTypeELSA is the identifier type for Oracle Linux Security Data IDs (https://linux.oracle.com/security/)
	IdentifierTypeELSA IdentifierType = "elsa"

	// IdentifierTypeH1 is the identifier type for IDs in hackerone reports (https://api.hackerone.com/core-resources/#reports)
	IdentifierTypeH1 IdentifierType = "hackerone"

	// IdentifierTypeGLAM is the identifier type for GitLab Malware Advisory IDs
	IdentifierTypeGLAM IdentifierType = "glam"

	// IdentifierTypeMAL is the identifier type for OpenSSF Malicious Package IDs
	IdentifierTypeMAL IdentifierType = "mal"
)

// Identifier holds reference and matching information about a concrete vulnerability
type Identifier struct {
	Type  IdentifierType `json:"type"`          // Type of the identifier (CVE, CWE, VENDOR_X, etc.)
	Name  string         `json:"name"`          // Name of the identifier for display purpose
	Value string         `json:"value"`         // Value of the identifier for matching purpose
	URL   string         `json:"url,omitempty"` // URL to identifier's documentation
}

// Vendor returns the canonical name of the vendor that assigned the vulnerability identifier.
func (i Identifier) Vendor() string {
	switch i.Type {
	case IdentifierTypeCVE:
		return "NVD"
	case IdentifierTypeELSA:
		return "Oracle"
	case IdentifierTypeGHSA:
		return "GitHub"
	case IdentifierTypeGLAM:
		return "GitLab"
	case IdentifierTypeH1:
		return "HackerOne"
	case IdentifierTypeMAL:
		return "OpenSSF"
	case IdentifierTypeOSVDB:
		return "OSVDB"
	case IdentifierTypeRHSA:
		return "RedHat"
	case IdentifierTypeUSN:
		return "Ubuntu"
	default:
		return "Unknown"
	}
}

// ParseIdentifierID builds an Identifier of correct IdentifierType from a human-readable ID slug
// (e.g., "CWE-1", "RHSA-01")
func ParseIdentifierID(idStr string) (Identifier, bool) {
	parts := strings.SplitN(idStr, "-", 2)
	switch strings.ToUpper(parts[0]) {
	case "CVE":
		return CVEIdentifier(idStr), true
	case "CWE":
		if len(parts) > 1 {
			if idInt, err := strconv.Atoi(parts[1]); err == nil {
				return CWEIdentifier(idInt), true
			}
		}
	case "ELSA":
		return ELSAIdentifier(idStr), true
	case "GHSA":
		return GHSAIdentifier(idStr), true
	case "GLAM":
		return GLAMIdentifier(idStr), true
	case "HACKERONE":
		// H1Identifier reads the part after the "-", so require it to avoid an out-of-range panic.
		if len(parts) > 1 {
			return H1Identifier(idStr), true
		}
	case "MAL":
		return MALIdentifier(idStr), true
	case "OSVDB":
		return OSVDBIdentifier(idStr), true
	case "RHSA":
		return RHSAIdentifier(idStr), true
	case "USN":
		// USNIdentifier reads the part after the "-", so require it to avoid an out-of-range panic.
		if len(parts) > 1 {
			return USNIdentifier(idStr), true
		}
	}
	return Identifier{}, false
}

// CVEIdentifier returns a structured Identifier for a given CVE-ID
// Given ID must follow this format: CVE-YYYY-NNNNN
func CVEIdentifier(ID string) Identifier {
	return Identifier{
		Type:  IdentifierTypeCVE,
		Name:  ID,
		Value: ID,
		URL:   fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", ID),
	}
}

// CWEIdentifier returns a structured Identifier for a given CWE ID
// Given ID must follow this format: NNN (just the number, no prefix)
func CWEIdentifier(ID int) Identifier {
	return Identifier{
		Type:  IdentifierTypeCWE,
		Name:  fmt.Sprintf("CWE-%d", ID),
		Value: strconv.Itoa(ID),
		URL:   fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", ID),
	}
}

// OWASPTop10Identifier returns a structured Identifier for a given OWASP Top10 Category
// Given ID must follow this format: "NNN:XXXX", where "XXXX" is the year designation
func OWASPTop10Identifier(ID string, desc string) Identifier {
	return Identifier{
		Type:  IdentifierType("owasp"),
		Name:  ID + " - " + desc,
		Value: ID,
	}
}

// OSVDBIdentifier returns a structured Identifier for a given OSVDB-ID
// Given ID must follow this format: OSVDB-XXXXXX
func OSVDBIdentifier(ID string) Identifier {
	return Identifier{
		Type:  IdentifierTypeOSVDB,
		Name:  ID,
		Value: ID,
		URL:   "https://cve.mitre.org/data/refs/refmap/source-OSVDB.html",
	}
}

// USNIdentifier returns a structured Identifier for a Ubuntu Security Notice.
// Given ID must follow this format: USN-XXXXXX.
func USNIdentifier(ID string) Identifier {
	parts := strings.SplitN(ID, "-", 2)
	return Identifier{
		Type:  IdentifierTypeUSN,
		Name:  ID,
		Value: ID,
		URL:   fmt.Sprintf("https://usn.ubuntu.com/%s/", parts[1]),
	}
}

// RHSAIdentifier returns a structured Identifier for a given RHSA-ID
// Given ID must follow this format: RHSA-YYYY:NNNN
func RHSAIdentifier(ID string) Identifier {
	return Identifier{
		Type:  IdentifierTypeRHSA,
		Name:  ID,
		Value: ID,
		URL:   fmt.Sprintf("https://access.redhat.com/errata/%s", ID),
	}
}

// GHSAIdentifier returns a structured Identifier for a given GHSA-ID
// Given ID must follow this format: GHSA-xxxx-xxxx-xxxx
func GHSAIdentifier(ID string) Identifier {
	return Identifier{
		Type:  IdentifierTypeGHSA,
		Name:  ID,
		Value: ID,
		URL:   fmt.Sprintf("https://github.com/advisories/%s", ID),
	}
}

// ELSAIdentifier returns a structured Identifier for a given ELSA-ID
// Given ID must follow this format: ELSA-YYYY-NNNN(-N)?$
func ELSAIdentifier(ID string) Identifier {
	return Identifier{
		Type:  IdentifierTypeELSA,
		Name:  ID,
		Value: ID,
		URL:   fmt.Sprintf("https://linux.oracle.com/errata/%s.html", ID),
	}
}

// H1Identifier returns a structured Identifier for a given hackerone report
// Given ID must follow this format: HACKERONE-XXXXXX
// The HACKERONE prefix is an internal GitLab identifier and is ignored in
// the value field
func H1Identifier(ID string) Identifier {
	parts := strings.SplitN(ID, "-", 2)
	return Identifier{
		Type:  IdentifierTypeH1,
		Name:  ID,
		Value: parts[1],
		URL:   fmt.Sprintf("https://hackerone.com/reports/%s", parts[1]),
	}
}

// GLAMIdentifier returns a structured Identifier for a GitLab Malware Advisory
// Given ID must follow this format: GLAM-XXXXXX
func GLAMIdentifier(ID string) Identifier {
	return Identifier{
		Type:  IdentifierTypeGLAM,
		Name:  ID,
		Value: ID,
	}
}

// MALIdentifier returns a structured Identifier for an OpenSSF Malicious Package
// Given ID must follow this format: MAL-YYYY-NNNN
func MALIdentifier(ID string) Identifier {
	return Identifier{
		Type:  IdentifierTypeMAL,
		Name:  ID,
		Value: ID,
	}
}
