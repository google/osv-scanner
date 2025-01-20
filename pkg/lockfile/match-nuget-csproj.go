package lockfile

import (
	"encoding/xml"
	"errors"
	"io"
	"os"

	"github.com/google/osv-scanner/internal/utility/fileposition"
	"github.com/google/osv-scanner/pkg/models"

	"path/filepath"
	"strings"
)

// NugetCsprojMatcher matches the source file of a Nuget lockfile
// https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#locking-dependencies
type NugetCsprojMatcher struct{}

type NugetCsProj struct {
	XMLName    xml.Name    `xml:"Project"`
	ItemGroups []ItemGroup `xml:"ItemGroup"`
}

type ItemGroup struct {
	XMLName           xml.Name           `xml:"ItemGroup"`
	PackageReferences []PackageReference `xml:"PackageReference"`
}

type PackageReference struct {
	XMLName           xml.Name `xml:"PackageReference"`
	IncludeAttr       *string  `xml:"Include,attr"`
	Include           *string  `xml:"Include"`
	VersionAttr       *string  `xml:"Version,attr"`
	Version           *string  `xml:"Version"`
	PrivateAssetsAttr *string  `xml:"PrivateAssets,attr"`
	PrivateAssets     *string  `xml:"PrivateAssets"`
	models.FilePosition
}

func (itemGroup *ItemGroup) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
DecodingLoop:
	for {
		lineStart, columnStart := decoder.InputPos()
		token, err := decoder.Token()
		if err != nil {
			return err
		}

		switch elem := token.(type) {
		case xml.StartElement:
			if elem.Name.Local != "PackageReference" {
				continue
			}

			packageReference := PackageReference{}
			packageReference.SetLineStart(lineStart)
			packageReference.SetColumnStart(columnStart)

			err := decoder.DecodeElement(&packageReference, &elem)
			if err != nil {
				return err
			}

			lineEnd, columnEnd := decoder.InputPos()
			packageReference.SetLineEnd(lineEnd)
			packageReference.SetColumnEnd(columnEnd)
			itemGroup.PackageReferences = append(itemGroup.PackageReferences, packageReference)

		case xml.EndElement:
			if elem.Name == start.Name {
				break DecodingLoop
			}
		}
	}

	return nil
}

func (m NugetCsprojMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	var dir = filepath.Dir(lockfile.Path())

	var dirs, err = os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range dirs {
		if strings.HasSuffix(file.Name(), ".csproj") {
			return OpenLocalDepFile(filepath.Join(dir, file.Name()))
		}
	}

	return nil, errors.New("no csproj file found")
}

func (m NugetCsprojMatcher) unmarshalProjectFile(content []byte) (map[string]PackageReference, error) {
	var project NugetCsProj
	err := xml.Unmarshal(content, &project)
	if err != nil {
		return nil, err
	}

	packageReferenceByInclude := make(map[string]PackageReference)
	for _, itemGroup := range project.ItemGroups {
		for _, packageReference := range itemGroup.PackageReferences {
			if packageReference.Include != nil {
				packageReferenceByInclude[*packageReference.Include] = packageReference
			} else if packageReference.IncludeAttr != nil {
				packageReferenceByInclude[*packageReference.IncludeAttr] = packageReference
			}
		}
	}

	return packageReferenceByInclude, nil
}

func (m NugetCsprojMatcher) Match(sourcefile DepFile, packages []PackageDetails) error {
	content, err := io.ReadAll(sourcefile)
	if err != nil {
		return err
	}

	packageReferenceByInclude, err := m.unmarshalProjectFile(content)
	if err != nil {
		return err
	}

	lines := fileposition.BytesToLines(content)

	for key, pkg := range packages {
		packageReference, ok := packageReferenceByInclude[pkg.Name]
		if !ok {
			continue
		}

		if (packageReference.PrivateAssetsAttr != nil && strings.Contains(*packageReference.PrivateAssetsAttr, "all")) ||
			(packageReference.PrivateAssets != nil && strings.Contains(*packageReference.PrivateAssets, "all")) {
			packages[key].DepGroups = []string{string(DepGroupDev)}
		} else {
			packages[key].DepGroups = []string{string(DepGroupProd)}
		}

		block := lines[packageReference.Line.Start-1 : packageReference.Line.End]

		packages[key].BlockLocation = models.FilePosition{
			Line:     models.Position{Start: packageReference.Line.Start, End: packageReference.Line.End},
			Column:   models.Position{Start: packageReference.Column.Start, End: packageReference.Column.End},
			Filename: sourcefile.Path(),
		}

		nameLocation := fileposition.ExtractStringPositionInBlock(block, pkg.Name, packageReference.Line.Start)
		if nameLocation != nil {
			nameLocation.Filename = sourcefile.Path()
			packages[key].NameLocation = nameLocation
		}

		versionLocation := fileposition.ExtractDelimitedRegexpPositionInBlock(block, ".*", packageReference.Line.Start, "Version=\"", "\"")
		if versionLocation == nil {
			versionLocation = fileposition.ExtractDelimitedRegexpPositionInBlock(block, ".*", packageReference.Line.Start, "<Version>", "</")
		}

		if versionLocation != nil {
			versionLocation.Filename = sourcefile.Path()
			packages[key].VersionLocation = versionLocation
		}
	}

	return nil
}

var _ Matcher = NugetCsprojMatcher{}
