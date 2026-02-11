// Package apiconfig provides centralized API endpoint configuration
// for the Codex Security forked osv-scanner.
//
// All external API calls should use these constants instead of upstream defaults
// to ensure requests only go to codexsecurity-owned domains.
package apiconfig

const (
	// CodexSecurityBaseURL is the base URL for vulnerability queries.
	// Replaces the upstream api.osv.dev endpoint.
	CodexSecurityBaseURL = "https://data-api.codexsecurity.io"

	// VulnerabilityDetailURL is the base URL for linking to vulnerability details in reports.
	// Replaces the upstream https://osv.dev/ links.
	VulnerabilityDetailURL = "https://osv.dev/"
)
