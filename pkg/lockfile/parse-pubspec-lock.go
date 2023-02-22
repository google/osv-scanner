package lockfile

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type PubspecLockDescription struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	Path string `yaml:"path"`
	Ref  string `yaml:"resolved-ref"`
}

var _ yaml.Unmarshaler = &PubspecLockDescription{}

func (pld *PubspecLockDescription) UnmarshalYAML(value *yaml.Node) error {
	var m struct {
		Name string `yaml:"name"`
		URL  string `yaml:"url"`
		Path string `yaml:"path"`
		Ref  string `yaml:"resolved-ref"`
	}

	err := value.Decode(&m)

	if err == nil {
		pld.Name = m.Name
		pld.Path = m.Path
		pld.URL = m.URL
		pld.Ref = m.Ref

		return nil
	}

	var str *string

	err = value.Decode(&str)

	if err != nil {
		return err
	}

	pld.Path = *str

	return nil
}

type PubspecLockPackage struct {
	Source      string                 `yaml:"source"`
	Description PubspecLockDescription `yaml:"description"`
	Version     string                 `yaml:"version"`
}

type PubspecLockfile struct {
	Packages map[string]PubspecLockPackage `yaml:"packages,omitempty"`
	Sdks     map[string]string             `yaml:"sdks"`
}

const PubEcosystem Ecosystem = "Pub"

func ParsePubspecLock(pathToLockfile string) ([]PackageDetails, error) {
	var parsedLockfile *PubspecLockfile

	lockfileContents, err := os.ReadFile(pathToLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not read %s: %w", pathToLockfile, err)
	}

	err = yaml.Unmarshal(lockfileContents, &parsedLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not parse %s: %w", pathToLockfile, err)
	}
	if parsedLockfile == nil {
		return []PackageDetails{}, nil
	}

	packages := make([]PackageDetails, 0, len(parsedLockfile.Packages))

	for name, pkg := range parsedLockfile.Packages {
		packages = append(packages, PackageDetails{
			Name:      name,
			Version:   pkg.Version,
			Commit:    pkg.Description.Ref,
			Ecosystem: PubEcosystem,
		})
	}

	return packages, nil
}
