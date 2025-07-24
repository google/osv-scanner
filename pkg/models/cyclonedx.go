// Package models provides data models for osv-scanner.
package models

type CycloneDXVersion int

const (
	CycloneDXVersion14 CycloneDXVersion = iota
	CycloneDXVersion15
	CycloneDXVersion16
)
