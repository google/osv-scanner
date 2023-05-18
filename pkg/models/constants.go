package models

type Ecosystem string

const (
	EcosystemGo            Ecosystem = "Go"
	EcosystemNPM           Ecosystem = "npm"
	EcosystemOSSFuzz       Ecosystem = "OSS-Fuzz"
	EcosystemPyPI          Ecosystem = "PyPI"
	EcosystemRubyGems      Ecosystem = "RubyGems"
	EcosystemCratesIO      Ecosystem = "crates.io"
	EcosystemPackagist     Ecosystem = "Packagist"
	EcosystemMaven         Ecosystem = "Maven"
	EcosystemNuGet         Ecosystem = "NuGet"
	EcosystemLinux         Ecosystem = "Linux"
	EcosystemDebian        Ecosystem = "Debian"
	EcosystemAlpine        Ecosystem = "Alpine"
	EcosystemHex           Ecosystem = "Hex"
	EcosystemAndroid       Ecosystem = "Android"
	EcosystemGitHubActions Ecosystem = "GitHub Actions"
	EcosystemPub           Ecosystem = "Pub"
	EcosystemConanCenter   Ecosystem = "ConanCenter"
)

type SeverityType string

const (
	SeverityCVSSV2 SeverityType = "CVSS_V2"
	SeverityCVSSV3 SeverityType = "CVSS_V3"
)

type RangeType string

const (
	RangeSemVer    RangeType = "SEMVER"
	RangeEcosystem RangeType = "ECOSYSTEM"
	RangeGit       RangeType = "GIT"
)

type ReferenceType string

const (
	ReferenceAdvisory ReferenceType = "ADVISORY"
	ReferenceArticle  ReferenceType = "ARTICLE"
	ReferenceReport   ReferenceType = "REPORT"
	ReferenceFix      ReferenceType = "FIX"
	ReferencePackage  ReferenceType = "PACKAGE"
	ReferenceEvidence ReferenceType = "EVIDENCE"
	ReferenceWeb      ReferenceType = "WEB"
)

type CreditType string

const (
	CreditFinder               CreditType = "FINDER"
	CreditReporter             CreditType = "REPORTER"
	CreditAnalyst              CreditType = "ANALYST"
	CreditCoordinator          CreditType = "COORDINATOR"
	CreditRemediationDeveloper CreditType = "REMEDIATION_DEVELOPER" //nolint:gosec
	CreditRemediationReviewer  CreditType = "REMEDIATION_REVIEWER"  //nolint:gosec
	CreditRemediationVerifier  CreditType = "REMEDIATION_VERIFIER"  //nolint:gosec
	CreditTool                 CreditType = "TOOL"
	CreditSponsor              CreditType = "SPONSOR"
	CreditOther                CreditType = "OTHER"
)
