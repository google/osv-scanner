// Copied from
// https://github.com/golang/vuln/blob/267a472bf377fa105988693c2a597d2b8de36ad8/internal/govulncheck/result.go
// and modified.

package govulncheck

// Message is an entry in the output stream. It will always have exactly one
// field filled in.
type Message struct {
	Finding *Finding `json:"finding,omitempty"`

	// The Config, Progress, and OSV fields from the JSON output are removed, since they
	// are not used.
}

// Vuln represents a single OSV entry.
type Finding struct {
	// OSV contains all data from the OSV entry for this vulnerability.
	OSV string `json:"osv,omitempty"`

	// Modules contains all of the modules in the OSV entry where a
	// vulnerable package is imported by the target source code or binary.
	//
	// For example, a module M with two packages M/p1 and M/p2, where only p1
	// is vulnerable, will appear in this list if and only if p1 is imported by
	// the target source code or binary.
	Modules []*Module `json:"modules,omitempty"`
}

// Module represents a specific vulnerability relevant to a single module.
type Module struct {
	// Path is the module path of the module containing the vulnerability.
	//
	// Importable packages in the standard library will have the path "stdlib".
	Path string `json:"path,omitempty"`

	// FoundVersion is the module version where the vulnerability was found.
	FoundVersion string `json:"found_version,omitempty"`

	// FixedVersion is the module version where the vulnerability was
	// fixed. If there are multiple fixed versions in the OSV report, this will
	// be the latest fixed version.
	//
	// This is empty if a fix is not available.
	FixedVersion string `json:"fixed_version,omitempty"`

	// Packages contains all the vulnerable packages in OSV entry that are
	// imported by the target source code or binary.
	//
	// For example, given a module M with two packages M/p1 and M/p2, where
	// both p1 and p2 are vulnerable, p1 and p2 will each only appear in this
	// list they are individually imported by the target source code or binary.
	Packages []*Package `json:"packages,omitempty"`
}

// Package is a Go package with known vulnerable symbols.
type Package struct {
	// Path is the import path of the package containing the vulnerability.
	Path string `json:"path"`

	// CallStacks contains a representative call stack for each
	// vulnerable symbol that is called.
	//
	// For vulnerabilities found from binary analysis, only CallStack.Symbol
	// will be provided.
	//
	// For non-affecting vulnerabilities reported from the source mode
	// analysis, this will be empty.
	CallStacks []CallStack `json:"callstacks,omitempty"`
}

// CallStacks contains a representative call stack for a vulnerable
// symbol.
type CallStack struct {
	// Frames contains an entry for each stack in the call stack.
	//
	// Frames are sorted starting from the entry point to the
	// imported vulnerable symbol. The last frame in Frames should match
	// Symbol.
	Frames []*StackFrame `json:"frames,omitempty"`
}

// StackFrame represents a call stack entry.
type StackFrame struct {
	// Package is the import path.
	Package string `json:"package,omitempty"`

	// Function is the function name.
	Function string `json:"function,omitempty"`

	// Receiver is the fully qualified receiver type,
	// if the called symbol is a method.
	//
	// The client can create the final symbol name by
	// prepending Receiver to FuncName.
	Receiver string `json:"receiver,omitempty"`

	// Position describes an arbitrary source position
	// including the file, line, and column location.
	// A Position is valid if the line number is > 0.
	Position *Position `json:"position,omitempty"`
}

// Position is a copy of token.Position used to marshal/unmarshal
// JSON correctly.
type Position struct {
	Filename string `json:"filename,omitempty"` // filename, if any
	Offset   int    `json:"offset"`             // offset, starting at 0
	Line     int    `json:"line"`               // line number, starting at 1
	Column   int    `json:"column"`             // column number, starting at 1 (byte count)
}
