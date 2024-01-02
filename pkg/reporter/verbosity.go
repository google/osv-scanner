package reporter

// VerbosityLevel is used to determine what amount of information should be given in OSV-Scanner's runtime.
type VerbosityLevel uint8

const (
	// ErrorLevel is for unexpected problems that require attention.
	ErrorLevel = iota
	// WarnLevel is for indicating potential issues or something that should be brought to the attention of users.
	WarnLevel
	// InfoLevel is for general information about what OSV-Scanner is doing during its runtime.
	InfoLevel
	// VerboseLevel is for providing even more information compared to InfoLevel about the inner workings of OSV-Scanner.
	VerboseLevel
)
