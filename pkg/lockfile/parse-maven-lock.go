package lockfile

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

const MavenCentral = "https://repo.maven.apache.org/maven2"

type MavenRegistryProject struct {
	io.ReadCloser
	path string
}

var errAPIFailed = errors.New("API query failed")

func NewMavenRegistryAPIClient(url string) (DepFile, error) {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make new request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: Maven registry query failed: %w", errAPIFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: Maven registry query status: %s", errAPIFailed, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response body: %w", errAPIFailed, err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("%w: empty response body", errAPIFailed)
	}

	readCloser := io.NopCloser(bytes.NewReader(body))

	return &MavenRegistryProject{
		ReadCloser: readCloser,
		path:       url,
	}, nil
}

func (m *MavenRegistryProject) Open(path string) (NestedDepFile, error) {
	panic("Should not be called")
}

func (m *MavenRegistryProject) Path() string {
	return m.path
}

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
	GroupID      string   `xml:"groupId"`
	ArtifactID   string   `xml:"artifactId"`
	Version      string   `xml:"version"`
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
 * You can see the interpolationReg working here : https://regex101.com/r/inAPiN/2
 * You can see the isMixedReg working here : https://regex101.com/r/KG4tS6/1
 */
func (mld MavenLockDependency) resolvePropertiesValue(lockfile MavenLockFile, fieldToResolve string) (string, *models.FilePosition) {
	var position *models.FilePosition
	variablesCount := 0

	interpolationReg := cachedregexp.MustCompile(`\${([^}]+)}`)
	isMixedReg := cachedregexp.MustCompile(`.+\${[^}]+}|\$[^}]+}.+`)
	projectProperties := buildProjectProperties(lockfile)
	isMixed := isMixedReg.MatchString(fieldToResolve)

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
			// The property is located in the main source File...
			projectPropertySourceFile := lockfile.MainSourceFile
			// Except if it is the version -> It could be located in some parent File
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
					// We should locate the property in its source File
					propOpenTag, propCloseTag = fileposition.QuoteMetaDelimiters(propOpenTag, propCloseTag)
					position = fileposition.ExtractDelimitedRegexpPositionInBlock(lockfile.Lines[lockProperty.SourceFile], ".*", 1, propOpenTag, propCloseTag)
					if position != nil {
						position.Filename = lockProperty.SourceFile
					}
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

	if variablesCount > 1 || isMixed {
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

type MavenLockExtractor struct {
	ArtifactExtractor
}

func (e MavenLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "pom.xml"
}

/**
** This function merge a child lockfile into the parent one.
** It copies all information originating from the child in it, overriding any common properties/dependencies
**/
func (e MavenLockExtractor) mergeLockfiles(childLockfile *MavenLockFile, parentLockfile *MavenLockFile) *MavenLockFile {
	// We set the parent back to the definition inherited from the child
	// As the child have no restriction on putting valid information outside of the relative path, we keep the artifact / group id set by the parent
	parentLockfile.Parent = MavenLockParent{
		XMLName:      childLockfile.Parent.XMLName,
		RelativePath: childLockfile.Parent.RelativePath,
		GroupID:      parentLockfile.GroupID,
		ArtifactID:   parentLockfile.ArtifactID,
		Version:      parentLockfile.Version,
	}
	// The following fields are not mandatory, in case they are not defined in the child, the one from the parent should be kept
	if len(childLockfile.ArtifactID) > 0 {
		parentLockfile.ArtifactID = childLockfile.ArtifactID
	}
	if len(childLockfile.GroupID) > 0 {
		parentLockfile.GroupID = childLockfile.GroupID
	}
	if len(childLockfile.ModelVersion) > 0 {
		parentLockfile.ModelVersion = childLockfile.ModelVersion
	}

	// Merge lock File lines
	maps.Copy(parentLockfile.Lines, childLockfile.Lines)

	// If child lockfile overrides the project version, let's use it instead
	if len(childLockfile.Version) > 0 {
		parentLockfile.Version = childLockfile.Version
		parentLockfile.ProjectVersionSourceFile = childLockfile.ProjectVersionSourceFile
	}

	// Keep track of the main source File
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

func (e MavenLockExtractor) enrichDependencies(path string, dependencies []MavenLockDependency) MavenLockDependencyHolder {
	result := make([]MavenLockDependency, len(dependencies))
	for index, dependency := range dependencies {
		if len(dependency.SourceFile) == 0 {
			dependency.SourceFile = path
		}
		result[index] = dependency
	}

	return MavenLockDependencyHolder{Dependencies: result}
}

func (e MavenLockExtractor) enrichProperties(path string, properties map[string]MavenLockProperty) MavenLockProperties {
	for key, property := range properties {
		if len(property.SourceFile) == 0 {
			property.SourceFile = path
		}
		properties[key] = property
	}

	return MavenLockProperties{m: properties}
}

func (e MavenLockExtractor) resolveParentFilename(parent MavenLockParent, currentPath string) string {
	// If a parent is defined, use its relative path to find the File, then recurse to decode it properly and enrich its dependencies
	// If the relativePath is not defined, default to ../pom.xml
	parentRelativePath := parent.RelativePath
	if len(parentRelativePath) == 0 {
		// if the parent path exists, use that,
		// else we return an empty string to signal that we should fetch a remote pom
		parentRelativePath = "../pom.xml"

		shouldComputeURL := strings.HasPrefix(currentPath, "https")
		if !shouldComputeURL {
			localPath := filepath.Join(filepath.Dir(currentPath), parentRelativePath)
			_, err := os.Stat(localPath)
			shouldComputeURL = errors.Is(err, os.ErrNotExist)
		}

		if shouldComputeURL {
			u, err := url.JoinPath(
				MavenCentral,
				strings.ReplaceAll(parent.GroupID, ".", "/"),
				parent.ArtifactID,
				parent.Version,
				fmt.Sprintf("%s-%s.pom", parent.ArtifactID, parent.Version),
			)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Failed to construct remote path: %s\n", err)
				return ""
			}

			return u
		}
	} else if !strings.HasSuffix(parentRelativePath, ".xml") {
		// It means we only have a path, we should append the default pom.xml
		parentRelativePath = path.Join(parentRelativePath, "pom.xml")
	}

	return filepath.FromSlash(filepath.Join(filepath.Dir(currentPath), parentRelativePath))
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
	parsedLockfile.Properties = e.enrichProperties(f.Path(), parsedLockfile.Properties.m)
	parsedLockfile.Dependencies = e.enrichDependencies(f.Path(), parsedLockfile.Dependencies.Dependencies)
	parsedLockfile.ManagedDependencies = e.enrichDependencies(f.Path(), parsedLockfile.ManagedDependencies.Dependencies)
	if parsedLockfile.Parent == (MavenLockParent{}) {
		return parsedLockfile, nil
	}

	parentPath := e.resolveParentFilename(parsedLockfile.Parent, f.Path())

	if ok := visitedPath[parentPath]; ok || parentPath == "" {
		// Parent has already been visited or is empty, lets stop there
		fmt.Fprintf(os.Stdout, "Already visited parent path, stopping there to avoid a circular dependency %s\n", parentPath)
		return parsedLockfile, nil
	}

	visitedPath[parentPath] = true

	var parentLockfile *MavenLockFile
	var parentFilePath string
	var parentErr error

	// If the parent pom does not exist, it still can be in an external repository
	if strings.HasPrefix(parentPath, "https") {
		mavenRegistryClient, clientErr := NewMavenRegistryAPIClient(parentPath)
		// If the remote pom does not exist, we can't do anything.
		if clientErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to fetch parent pom from remote repository: %s\n", parentPath)
			//nolint:nilerr // we don't want to consider a network request failing for the parent as being unable to handle the lockfile
			return parsedLockfile, nil
		}

		parentLockfile, err = e.decodeMavenFile(mavenRegistryClient, depth+1, visitedPath)
		if err != nil {
			return nil, err
		}

		parentFilePath = parentPath
	} else if _, err = os.Stat(parentPath); errors.Is(err, os.ErrNotExist) {
		// If the parent pom does not exist and is not a remote file, we can't do anything.
		_, _ = fmt.Fprintf(os.Stderr, "Maven lockfile parser couldn't reach the parent because it is not locally defined: %s\n", parentPath)

		return parsedLockfile, nil
	} else {
		parentFile, err := OpenLocalDepFile(parentPath)
		if err != nil {
			return nil, err
		}
		parentLockfile, parentErr = e.decodeMavenFile(parentFile, depth+1, visitedPath)
		if parentErr != nil {
			return nil, parentErr
		}

		parentFilePath = parentFile.Path()
	}

	parentLockfile.Properties = e.enrichProperties(f.Path(), parentLockfile.Properties.m)
	parentLockfile.Dependencies = e.enrichDependencies(parentFilePath, parentLockfile.Dependencies.Dependencies)
	parentLockfile.ManagedDependencies = e.enrichDependencies(parentFilePath, parentLockfile.ManagedDependencies.Dependencies)

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
			if artifactPosition != nil {
				artifactPosition.Filename = lockPackage.SourceFile
			}
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
			PackageManager:  models.Maven,
			IsDirect:        true,
		}
		if scope := strings.TrimSpace(lockPackage.Scope); scope != "" && scope != "compile" {
			// Only append non-default scope (compile is the default scope).
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, strings.ToLower(scope))
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
				if versionPosition != nil {
					versionPosition.Filename = lockPackage.SourceFile
				}
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

func (e MavenLockExtractor) GetArtifact(f DepFile) (*models.ScannedArtifact, error) {
	visitedPath := make(map[string]bool)
	visitedPath[f.Path()] = true
	parsedLockfile, err := e.decodeMavenFile(f, 0, visitedPath)
	if err != nil {
		return nil, err
	}

	artifactName := parsedLockfile.GroupID + ":" + parsedLockfile.ArtifactID

	artifact := models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Name:      artifactName,
			Version:   parsedLockfile.Version,
			Filename:  f.Path(),
			Ecosystem: models.EcosystemMaven,
		},
	}

	if parsedLockfile.Parent != (MavenLockParent{}) {
		parentArtifact := parsedLockfile.Parent.GroupID + ":" + parsedLockfile.Parent.ArtifactID
		artifact.DependsOn = &models.ArtifactDetail{
			Name:      parentArtifact,
			Version:   parsedLockfile.Parent.Version,
			Filename:  e.resolveParentFilename(parsedLockfile.Parent, f.Path()),
			Ecosystem: models.EcosystemMaven,
		}
	}

	return &artifact, nil
}

var _ Extractor = MavenLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("pom.xml", MavenLockExtractor{})
}

func ParseMavenLock(pathToLockfile string) ([]PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, MavenLockExtractor{})
}
