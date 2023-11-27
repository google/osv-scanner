package lockfile

type PackageDetails struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Commit    string    `json:"commit,omitempty"`
	Ecosystem Ecosystem `json:"ecosystem,omitempty"`
	CompareAs Ecosystem `json:"compareAs,omitempty"`
	Start     FilePosition
	End       FilePosition
}

type FilePosition struct {
	Line   int
	Column int
}

type Ecosystem string

type PackageDetailsParser = func(pathToLockfile string) ([]PackageDetails, error)
