// Package apiconfig provides centralized API endpoint configuration
// for the Codex Security forked osv-scanner.
//
// All external API calls should use these constants instead of upstream defaults
// to ensure requests only go to codexsecurity-owned domains.
//
// The routing-backend proxy (data-api.codexsecurity.io) maps:
//
//	/osv/*                  → https://api.osv.dev/*
//	/osv-vulnerabilities/*  → https://osv-vulnerabilities.storage.googleapis.com/*
//	/deps/*                 → https://api.deps.dev/*
package apiconfig

const (
	// RoutingBackendBaseURL is the base domain of the routing proxy.
	RoutingBackendBaseURL = "https://data-api.codexsecurity.io"

	// CodexSecurityBaseURL is the base URL for vulnerability queries.
	// Routes through /osv/* on the routing-backend proxy → api.osv.dev
	CodexSecurityBaseURL = RoutingBackendBaseURL + "/osv"

	// VulnDBRemoteHost is the base URL for offline vulnerability DB downloads.
	// Routes through /osv-vulnerabilities/* on the routing-backend proxy
	// → osv-vulnerabilities.storage.googleapis.com
	VulnDBRemoteHost = RoutingBackendBaseURL + "/osv-vulnerabilities"

	// DepsDevAPIURL is the base URL for deps.dev REST API calls.
	// Routes through /deps/* on the routing-backend proxy → api.deps.dev
	DepsDevAPIURL = RoutingBackendBaseURL + "/deps"
)
