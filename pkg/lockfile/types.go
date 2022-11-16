package lockfile

type PackageDetails struct {
		Name      string    `json:"name"`
		Version   string    `json:"version"`
		Commit    string    `json:"commit,omitempty"`
		Ecosystem Ecosystem `json:"ecosystem,omitempty"`
		CompareAs Ecosystem `json:"compareAs,omitempty"`
}

type Ecosystem string

type PackageDetailsParser = func(pathToLockfile string) ([]PackageDetails, error)
