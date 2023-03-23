package models

type Ecosystem string

const (
	ECOSYSTEM_GO             Ecosystem = "Go"
	ECOSYSTEM_NPM            Ecosystem = "npm"
	ECOSYSTEM_OSS_FUZZ       Ecosystem = "OSS-Fuzz"
	ECOSYSTEM_PYPI           Ecosystem = "PyPI"
	ECOSYSTEM_RUBYGEMS       Ecosystem = "RubyGems"
	ECOSYSTEM_CRATES_IO      Ecosystem = "crates.io"
	ECOSYSTEM_PACKAGIST      Ecosystem = "Packagist"
	ECOSYSTEM_MAVEN          Ecosystem = "Maven"
	ECOSYSTEM_NUGET          Ecosystem = "NuGet"
	ECOSYSTEM_LINUX          Ecosystem = "Linux"
	ECOSYSTEM_DEBIAN         Ecosystem = "Debian"
	ECOSYSTEM_ALPINE         Ecosystem = "Alpine"
	ECOSYSTEM_HEX            Ecosystem = "Hex"
	ECOSYSTEM_ANDROID        Ecosystem = "Android"
	ECOSYSTEM_GITHUB_ACTIONS Ecosystem = "GitHub Actions"
	ECOSYSTEM_PUB            Ecosystem = "Pub"
	ECOSYSTEM_CONANCENTER    Ecosystem = "ConanCenter"
)

type SeverityType string

const (
	SEVERITY_CVSS_V2 SeverityType = "CVSS_V2"
	SEVERITY_CVSS_V3 SeverityType = "CVSS_V3"
)

type RangeType string

const (
	RANGE_SEMVER    RangeType = "SEMVER"
	RANGE_ECOSYSTEM RangeType = "ECOSYSTEM"
	RANGE_GIT       RangeType = "GIT"
)

type ReferenceType string

const (
	REFERENCE_ADVISORY ReferenceType = "ADVISORY"
	REFERENCE_ARTICLE  ReferenceType = "ARTICLE"
	REFERENCE_REPORT   ReferenceType = "REPORT"
	REFERENCE_FIX      ReferenceType = "FIX"
	REFERENCE_PACKAGE  ReferenceType = "PACKAGE"
	REFERENCE_EVIDENCE ReferenceType = "EVIDENCE"
	REFERENCE_WEB      ReferenceType = "WEB"
)

type CreditType string

const (
	CREDIT_FINDER                CreditType = "FINDER"
	CREDIT_REPORTER              CreditType = "REPORTER"
	CREDIT_ANALYST               CreditType = "ANALYST"
	CREDIT_COORDINATOR           CreditType = "COORDINATOR"
	CREDIT_REMEDIATION_DEVELOPER CreditType = "REMEDIATION_DEVELOPER"
	CREDIT_REMEDIATION_REVIEWER  CreditType = "REMEDIATION_REVIEWER"
	CREDIT_REMEDIATION_VERIFIER  CreditType = "REMEDIATION_VERIFIER"
	CREDIT_TOOL                  CreditType = "TOOL"
	CREDIT_SPONSOR               CreditType = "SPONSOR"
	CREDIT_OTHER                 CreditType = "OTHER"
)
