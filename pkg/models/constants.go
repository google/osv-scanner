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
	EcosystemRockyLinux    Ecosystem = "Rocky Linux"
	EcosystemAlmaLinux     Ecosystem = "AlmaLinux"
	EcosystemBitnami       Ecosystem = "Bitnami"
	EcosystemPhotonOS      Ecosystem = "Photon OS"
	EcosystemCRAN          Ecosystem = "CRAN"
	EcosystemBioconductor  Ecosystem = "Bioconductor"
	EcosystemSwiftURL      Ecosystem = "SwiftURL"
)

var Ecosystems = []Ecosystem{
	EcosystemGo,
	EcosystemNPM,
	EcosystemOSSFuzz,
	EcosystemPyPI,
	EcosystemRubyGems,
	EcosystemCratesIO,
	EcosystemPackagist,
	EcosystemMaven,
	EcosystemNuGet,
	EcosystemLinux,
	EcosystemDebian,
	EcosystemAlpine,
	EcosystemHex,
	EcosystemAndroid,
	EcosystemGitHubActions,
	EcosystemPub,
	EcosystemConanCenter,
	EcosystemRockyLinux,
	EcosystemAlmaLinux,
	EcosystemBitnami,
	EcosystemPhotonOS,
	EcosystemCRAN,
	EcosystemBioconductor,
	EcosystemSwiftURL,
}

type SeverityType string

const (
	SeverityCVSSV2 SeverityType = "CVSS_V2"
	SeverityCVSSV3 SeverityType = "CVSS_V3"
	SeverityCVSSV4 SeverityType = "CVSS_V4"
)

type RangeType string

const (
	RangeSemVer    RangeType = "SEMVER"
	RangeEcosystem RangeType = "ECOSYSTEM"
	RangeGit       RangeType = "GIT"
)

type ReferenceType string

const (
	ReferenceAdvisory   ReferenceType = "ADVISORY"
	ReferenceArticle    ReferenceType = "ARTICLE"
	ReferenceDetection  ReferenceType = "DETECTION"
	ReferenceDiscussion ReferenceType = "DISCUSSION"
	ReferenceReport     ReferenceType = "REPORT"
	ReferenceFix        ReferenceType = "FIX"
	ReferenceIntroduced ReferenceType = "INTRODUCED"
	ReferencePackage    ReferenceType = "PACKAGE"
	ReferenceEvidence   ReferenceType = "EVIDENCE"
	ReferenceWeb        ReferenceType = "WEB"
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
