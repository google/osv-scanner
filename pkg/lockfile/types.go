package lockfile

type PackageDetails struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Commit    string    `json:"commit,omitempty"`
	Ecosystem Ecosystem `json:"ecosystem,omitempty"`
	CompareAs Ecosystem `json:"compareAs,omitempty"`
	// Optional string to specify the absolute path to the file specifying this package as a dependency
	Source string `json:"source,omitempty"`
}

type Ecosystem string

type PackageDetailsParser = func(pathToLockfile string) ([]PackageDetails, error)
