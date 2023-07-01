module golang.org/vuln

go 1.18

require (
	// This version has one vulnerability that is imported, and
	// one that is called.
	github.com/tidwall/gjson v1.6.5
	// This version has a vulnerability that is called.
	golang.org/x/text v0.3.0
)

require (
	github.com/tidwall/match v1.1.0 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
)
