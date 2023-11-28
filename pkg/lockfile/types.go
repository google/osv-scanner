package lockfile

import "github.com/google/osv-scanner/pkg/models"

type PackageDetails struct {
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Commit     string    `json:"commit,omitempty"`
	Ecosystem  Ecosystem `json:"ecosystem,omitempty"`
	CompareAs  Ecosystem `json:"compareAs,omitempty"`
	Start      models.FilePosition
	End        models.FilePosition
	SourceFile string
}

type Ecosystem string

type PackageDetailsParser = func(pathToLockfile string) ([]PackageDetails, error)
