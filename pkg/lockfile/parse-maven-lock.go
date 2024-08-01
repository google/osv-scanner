package lockfile

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/utility/fileposition"
	"golang.org/x/exp/maps"

	"github.com/google/osv-scanner/internal/utility/filereader"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/internal/cachedregexp"
)

type MavenLockDependency struct {
	XMLName    xml.Name `xml:"dependency"`
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Version    string   `xml:"version"`
	Scope      string   `xml:"scope"`
	SourceFile string
	models.FilePosition
}

type MavenLockParent struct {
	XMLName      xml.Name `xml:"parent"`
	RelativePath string   `xml:"relativePath"`
}

type MavenLockDependencyHolder struct {
	Dependencies []MavenLockDependency `xml:"dependency"`
}

func buildProjectProperties(lockfile MavenLockFile) map[string]string {
	return map[string]string{
		"project.version":      lockfile.Version,
		"project.modelVersion": lockfile.ModelVersion,
		"project.groupId":      lockfile.GroupID,
		"project.artifactId":   lockfile.ArtifactID,
	}
}

/*
You can see the regex working here : https://regex101.com/r/inAPiN/2
*/
func (mld MavenLockDependency) resolvePropertiesValue(lockfile MavenLockFile, fieldToResolve string) (string, *models.FilePosition) {
	var position *models.FilePosition
	variablesCount := 0

	interpolationReg := cachedregexp.MustCompile(`\${([^}]+)}`)
	projectProperties := buildProjectProperties(lockfile)

	result := interpolationReg.ReplaceAllFunc([]byte(fieldToResolve), func(bytes []byte) []byte {
		variablesCount += 1
		propStr := string(bytes)
		propName := propStr[2 : len(propStr)-1]
		propOpenTag := fmt.Sprintf("<%s>", propName)
		propCloseTag := fmt.Sprintf("</%s>", propName)

		var lockProperty MavenLockProperty
		var property string
		var ok bool

		if strings.HasPrefix(propName, "pom.") {
			// the pom. prefix is the legacy value of project. prefix even if it is deprecated, it is still supported
			propName = "project" + strings.TrimPrefix(propName, "pom")
		}

		// If the fieldToResolve is the internal version fieldToResolve, then lets use the one declared
		if strings.HasPrefix(propName, "project.") {
			property, ok = projectProperties[propName]
			// The property is located in the main source file...
			projectPropertySourceFile := lockfile.MainSourceFile
			// Except if it is the version -> It could be located in some parent file
			if strings.HasSuffix(propName, "version") {
				projectPropertySourceFile = lockfile.ProjectVersionSourceFile
			}
			position = fileposition.ExtractStringPositionInBlock(lockfile.Lines[projectPropertySourceFile], property, 1)
			if position != nil {
				position.Filename = projectPropertySourceFile
			}
		} else {
			lockProperty, ok = lockfile.Properties.m[propName]
			if ok {
				property = lockProperty.Property
				if interpolationReg.MatchString(property) {
					// Property uses other properties
					property, position = mld.resolvePropertiesValue(lockfile, property)
				} else {
					// We should locate the property in its source file
					propOpenTag, propCloseTag = fileposition.QuoteMetaDelimiters(propOpenTag, propCloseTag)
					position = fileposition.ExtractDelimitedRegexpPositionInBlock(lockfile.Lines[lockProperty.SourceFile], ".*", 1, propOpenTag, propCloseTag)
					position.Filename = lockProperty.SourceFile
				}
			}
		}

		if !ok {
			fmt.Fprintf(
				os.Stderr,
				"Failed to resolve a property. fieldToResolve \"%s\" could not be found for \"%s\" (%s)\n",
				string(bytes),
				lockfile.GroupID+":"+lockfile.ArtifactID,
				mld.SourceFile,
			)

			return []byte("")
		}

		return []byte(property)
	})

	if variablesCount > 1 {
		position = nil
	}

	return string(result), position
}

func (mld MavenLockDependency) ResolveVersion(lockfile MavenLockFile) (string, *models.FilePosition) {
	versionRequirementReg := cachedregexp.MustCompile(`[[(]?(.*?)(?:,|[)\]]|$)`)
	version, position := mld.resolvePropertiesValue(lockfile, mld.Version)
	results := versionRequirementReg.FindStringSubmatch(version)

	if results == nil || results[1] == "" {
		return "", nil
	}

	return results[1], position
}

func (mld MavenLockDependency) ResolveArtifactID(lockfile MavenLockFile) (string, *models.FilePosition) {
	return mld.resolvePropertiesValue(lockfile, mld.ArtifactID)
}

func (mld MavenLockDependency) ResolveGroupID(lockfile MavenLockFile) (string, *models.FilePosition) {
	return mld.resolvePropertiesValue(lockfile, mld.GroupID)
}

type MavenLockFile struct {
	XMLName                  xml.Name                  `xml:"project"`
	Parent                   MavenLockParent           `xml:"parent"`
	Version                  string                    `xml:"version"`
	ModelVersion             string                    `xml:"modelVersion"`
	GroupID                  string                    `xml:"groupId"`
	ArtifactID               string                    `xml:"artifactId"`
	Properties               MavenLockProperties       `xml:"properties"`
	Dependencies             MavenLockDependencyHolder `xml:"dependencies"`
	ManagedDependencies      MavenLockDependencyHolder `xml:"dependencyManagement>dependencies"`
	MainSourceFile           string
	ProjectVersionSourceFile string
	Lines                    map[string][]string
}

const MavenEcosystem Ecosystem = "Maven"

type MavenLockProperty struct {
	Property   string
	SourceFile string
}

type MavenLockProperties struct {
	m map[string]MavenLockProperty
}

func (p *MavenLockProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.m = map[string]MavenLockProperty{}

	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch tt := t.(type) {
		case xml.StartElement:
			var s string

			if err := d.DecodeElement(&s, &tt); err != nil {
				return fmt.Errorf("%w", err)
			}

			p.m[tt.Name.Local] = MavenLockProperty{
				Property: s,
			}

		case xml.EndElement:
			if tt.Name == start.Name {
				return nil
			}
		}
	}
}

func (dependencyHolder *MavenLockDependencyHolder) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	dependencyHolder.Dependencies = make([]MavenLockDependency, 0)
DecodingLoop:
	for {
		lineStart, columnStart := decoder.InputPos()
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch elem := token.(type) {
		case xml.StartElement:
			dependency := MavenLockDependency{}
			dependency.SetLineStart(lineStart)
			dependency.SetColumnStart(columnStart)
			err := decoder.DecodeElement(&dependency, &elem)
			if err != nil {
				return err
			}
			lineEnd, columnEnd := decoder.InputPos()
			dependency.SetLineEnd(lineEnd)
			dependency.SetColumnEnd(columnEnd)
			dependencyHolder.Dependencies = append(dependencyHolder.Dependencies, dependency)
		case xml.EndElement:
			if elem.Name == start.Name {
				break DecodingLoop
			}
		}
	}

	return nil
}

type MavenLockExtractor struct{}

func (e MavenLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "pom.xml"
}

/**
** This function merge a child lockfile into the parent one.
** It copies all information originating from the child in it, overriding any common properties/dependencies
**/
func (e MavenLockExtractor) mergeLockfiles(childLockfile *MavenLockFile, parentLockfile *MavenLockFile) *MavenLockFile {
	parentLockfile.Parent = childLockfile.Parent
	parentLockfile.ArtifactID = childLockfile.ArtifactID
	parentLockfile.GroupID = childLockfile.GroupID
	parentLockfile.ModelVersion = childLockfile.ModelVersion

	// Merge lock file lines
	maps.Copy(parentLockfile.Lines, childLockfile.Lines)

	// If child lockfile overrides the project version, let's use it instead
	if len(childLockfile.Version) > 0 {
		parentLockfile.Version = childLockfile.Version
		parentLockfile.ProjectVersionSourceFile = childLockfile.ProjectVersionSourceFile
	}

	// Keep track of the main source file
	parentLockfile.MainSourceFile = childLockfile.MainSourceFile

	// Child properties take precedence over parent defined ones
	for key, value := range childLockfile.Properties.m {
		parentLockfile.Properties.m[key] = value
	}
	// We add child dependency at the end, this way they will override the parent ones during transformation to a map
	parentLockfile.Dependencies.Dependencies = append(parentLockfile.Dependencies.Dependencies, childLockfile.Dependencies.Dependencies...)
	parentLockfile.ManagedDependencies.Dependencies = append(parentLockfile.ManagedDependencies.Dependencies, childLockfile.ManagedDependencies.Dependencies...)

	return parentLockfile
}

func (e MavenLockExtractor) enrichDependencies(f DepFile, dependencies []MavenLockDependency) MavenLockDependencyHolder {
	result := make([]MavenLockDependency, len(dependencies))
	for index, dependency := range dependencies {
		if len(dependency.SourceFile) == 0 {
			dependency.SourceFile = f.Path()
		}
		result[index] = dependency
	}

	return MavenLockDependencyHolder{Dependencies: result}
}

func (e MavenLockExtractor) enrichProperties(f DepFile, properties map[string]MavenLockProperty) MavenLockProperties {
	for key, property := range properties {
		if len(property.SourceFile) == 0 {
			property.SourceFile = f.Path()
		}
		properties[key] = property
	}

	return MavenLockProperties{m: properties}
}

func (e MavenLockExtractor) decodeMavenFile(f DepFile, depth int, visitedPath map[string]bool) (*MavenLockFile, error) {
	var parsedLockfile *MavenLockFile

	// Decoding the original lockfile and enrich its dependencies
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	decoder := xml.NewDecoder(bytes.NewReader(b))
	decoder.CharsetReader = filereader.CharsetDecoder
	err = decoder.Decode(&parsedLockfile)
	if err != nil {
		return nil, err
	}

	if parsedLockfile.Lines == nil {
		parsedLockfile.Lines = map[string][]string{}
	}
	parsedLockfile.Lines[f.Path()] = fileposition.BytesToLines(b)
	parsedLockfile.MainSourceFile = f.Path()
	parsedLockfile.ProjectVersionSourceFile = f.Path()

	if parsedLockfile.Properties.m == nil {
		parsedLockfile.Properties.m = map[string]MavenLockProperty{}
	}
	parsedLockfile.Properties = e.enrichProperties(f, parsedLockfile.Properties.m)
	parsedLockfile.Dependencies = e.enrichDependencies(f, parsedLockfile.Dependencies.Dependencies)
	parsedLockfile.ManagedDependencies = e.enrichDependencies(f, parsedLockfile.ManagedDependencies.Dependencies)
	if parsedLockfile.Parent == (MavenLockParent{}) {
		return parsedLockfile, nil
	}

	// If a parent is defined, use its relative path to find the file, then recurse to decode it properly and enrich its dependencies
	// If the relativePath is not defined, default to ../pom.xml
	parentRelativePath := parsedLockfile.Parent.RelativePath
	if len(parentRelativePath) == 0 {
		parentRelativePath = "../pom.xml"
	} else if !strings.HasSuffix(parentRelativePath, ".xml") {
		// It means we only have a path, we should append the default pom.xml
		parentRelativePath = path.Join(parentRelativePath, "pom.xml")
	}
	parentPath := filepath.FromSlash(filepath.Join(filepath.Dir(f.Path()), parentRelativePath))
	if _, err := os.Stat(parentPath); errors.Is(err, os.ErrNotExist) {
		// If the parent pom does not exist, it still can be in an external repository, but it is unreachable from the parser
		_, _ = fmt.Fprintf(os.Stderr, "Maven lockfile parser couldn't reach the parent because it is not locally defined\n")
		return parsedLockfile, nil
	}

	if ok := visitedPath[parentPath]; ok {
		// Parent has already been visited, lets stop there
		fmt.Fprintf(os.Stdout, "Already visited parent path, stopping there to avoid a circular dependency %s\n", parentPath)
		return parsedLockfile, nil
	}
	visitedPath[parentPath] = true

	parentFile, err := OpenLocalDepFile(parentPath)
	if err != nil {
		return nil, err
	}
	parentLockfile, parentErr := e.decodeMavenFile(parentFile, depth+1, visitedPath)
	if parentErr != nil {
		return nil, parentErr
	}
	parentLockfile.Properties = e.enrichProperties(f, parentLockfile.Properties.m)
	parentLockfile.Dependencies = e.enrichDependencies(parentFile, parentLockfile.Dependencies.Dependencies)
	parentLockfile.ManagedDependencies = e.enrichDependencies(parentFile, parentLockfile.ManagedDependencies.Dependencies)

	// Once everything is decoded and enriched, merge them together
	return e.mergeLockfiles(parsedLockfile, parentLockfile), nil
}

func (e MavenLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	visitedPath := make(map[string]bool)
	visitedPath[f.Path()] = true
	parsedLockfile, err := e.decodeMavenFile(f, 0, visitedPath)
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	details := map[string]PackageDetails{}

	for _, lockPackage := range parsedLockfile.Dependencies.Dependencies {
		resolvedGroupID, _ := lockPackage.ResolveGroupID(*parsedLockfile)
		resolvedArtifactID, artifactPosition := lockPackage.ResolveArtifactID(*parsedLockfile)
		resolvedVersion, versionPosition := lockPackage.ResolveVersion(*parsedLockfile)
		finalName := resolvedGroupID + ":" + resolvedArtifactID

		blockLocation := models.FilePosition{
			Line:     lockPackage.Line,
			Column:   lockPackage.Column,
			Filename: lockPackage.SourceFile,
		}
		block := parsedLockfile.Lines[lockPackage.SourceFile][lockPackage.Line.Start-1 : lockPackage.Line.End]

		// A position is null after resolving the value in case the value is directly defined in the block
		if artifactPosition == nil {
			openTag, closeTag := fileposition.QuoteMetaDelimiters("<artifactId>", "</artifactId>")
			artifactPosition = fileposition.ExtractDelimitedRegexpPositionInBlock(block, ".*", lockPackage.Line.Start, openTag, closeTag)
			artifactPosition.Filename = lockPackage.SourceFile
		}
		if versionPosition == nil {
			openTag, closeTag := fileposition.QuoteMetaDelimiters("<version>", "</version>")
			versionPosition = fileposition.ExtractDelimitedRegexpPositionInBlock(block, ".*", lockPackage.Line.Start, openTag, closeTag)
			if versionPosition != nil {
				versionPosition.Filename = lockPackage.SourceFile
			}
		}

		pkgDetails := PackageDetails{
			Name:            finalName,
			Version:         resolvedVersion,
			Ecosystem:       MavenEcosystem,
			CompareAs:       MavenEcosystem,
			BlockLocation:   blockLocation,
			NameLocation:    artifactPosition,
			VersionLocation: versionPosition,
		}
		if scope := strings.TrimSpace(lockPackage.Scope); scope != "" && scope != "compile" {
			// Only append non-default scope (compile is the default scope).
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, scope)
		}
		details[finalName] = pkgDetails
	}

	// If a dependency is declared and have not specified its version, then use the one declared in the managed dependencies
	for _, lockPackage := range parsedLockfile.ManagedDependencies.Dependencies {
		resolvedGroupID, _ := lockPackage.ResolveGroupID(*parsedLockfile)
		resolvedArtifactID, _ := lockPackage.ResolveArtifactID(*parsedLockfile)
		finalName := resolvedGroupID + ":" + resolvedArtifactID
		pkgDetails, pkgExists := details[finalName]
		if !pkgExists {
			continue
		}

		block := parsedLockfile.Lines[lockPackage.SourceFile][lockPackage.Line.Start-1 : lockPackage.Line.End]

		if pkgDetails.IsVersionEmpty() {
			resolvedVersion, versionPosition := lockPackage.ResolveVersion(*parsedLockfile)

			// A position is null after resolving the value in case the value is directly defined in the block
			if versionPosition == nil {
				openTag, closeTag := fileposition.QuoteMetaDelimiters("<version>", "</version>")
				versionPosition = fileposition.ExtractDelimitedRegexpPositionInBlock(block, ".*", lockPackage.Line.Start, openTag, closeTag)
				versionPosition.Filename = lockPackage.SourceFile
			}

			pkgDetails.Version = resolvedVersion
			pkgDetails.VersionLocation = versionPosition
		}
		if scope := strings.TrimSpace(lockPackage.Scope); scope != "" && scope != "compile" {
			// Only append non-default scope (compile is the default scope).
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, scope)
		}
		details[finalName] = pkgDetails
	}

	return maps.Values(details), nil
}

var _ Extractor = MavenLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("pom.xml", MavenLockExtractor{})
}

func ParseMavenLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, MavenLockExtractor{})
}
