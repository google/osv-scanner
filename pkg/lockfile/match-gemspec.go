package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

const gemspecFileSuffix = ".gemspec"

type gemspecMetadata struct {
	name          string
	isDev         bool
	blockLine     models.Position
	blockColumn   models.Position
	nameLine      models.Position
	nameColumn    models.Position
	versionLine   *models.Position
	versionColumn *models.Position
}

type GemspecFileMatcher struct{}

func (matcher GemspecFileMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	var dir = filepath.Dir(lockfile.Path())

	var dirs, err = os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range dirs {
		if strings.HasSuffix(file.Name(), gemspecFileSuffix) {
			return OpenLocalDepFile(filepath.Join(dir, file.Name()))
		}
	}

	return nil, errors.New("no " + gemspecFileSuffix + " file found")
}

func (matcher GemspecFileMatcher) Match(sourceFile DepFile, packages []PackageDetails) error {
	packagesByName := indexPackages(packages)

	treeResult, err := ParseFile(sourceFile, Ruby)
	if err != nil {
		return err
	}
	defer treeResult.Close()

	gems, err := matcher.findGemspecs(treeResult.node)
	if err != nil {
		return err
	}
	matcher.enrichPackagesWithLocation(sourceFile, gems, packagesByName)

	return nil
}

func (matcher GemspecFileMatcher) findGemspecs(node *Node) ([]gemspecMetadata, error) {
	dependencyQuery := `(
		(call
			receiver: (_)
			method: (identifier) @method_name
			(#any-of? @method_name
							"add_dependency"
							"add_runtime_dependency"
							"add_development_dependency")
			arguments: (argument_list
				.
				(comment)*
				.
				(string) @gem_name
				.
				[
					(array
						(string)
					)
					(string)
					(comment)
					","
				]* @gem_requirements
				.
				(comment)*
				.
			)
		) @dependency_call
	)`

	gems := make([]gemspecMetadata, 0)
	err := node.Query(dependencyQuery, func(match *MatchResult) error {
		callNode := match.FindFirstByName("dependency_call")

		methodNameNode := match.FindFirstByName("method_name")
		methodName, err := node.ctx.ExtractTextValue(methodNameNode.node)
		if err != nil {
			return err
		}

		dependencyNameNode := match.FindFirstByName("gem_name")
		dependencyName, err := node.ctx.ExtractTextValue(dependencyNameNode.node)
		if err != nil {
			return err
		}

		requirementNodes := match.FindByName("gem_requirements")

		metadata := gemspecMetadata{
			name:        dependencyName,
			isDev:       methodName == "add_development_dependency",
			blockLine:   models.Position{Start: int(callNode.node.StartPosition().Row) + 1, End: int(callNode.node.EndPosition().Row) + 1},
			blockColumn: models.Position{Start: int(callNode.node.StartPosition().Column) + 1, End: int(callNode.node.EndPosition().Column) + 1},
			nameLine:    models.Position{Start: int(dependencyNameNode.node.StartPosition().Row) + 1, End: int(dependencyNameNode.node.EndPosition().Row) + 1},
			nameColumn:  models.Position{Start: int(dependencyNameNode.node.StartPosition().Column) + 1, End: int(dependencyNameNode.node.EndPosition().Column) + 1},
		}

		if len(requirementNodes) > 0 {
			metadata.versionLine = &models.Position{Start: int(requirementNodes[0].node.StartPosition().Row) + 1, End: int(requirementNodes[len(requirementNodes)-1].node.EndPosition().Row) + 1}
			metadata.versionColumn = &models.Position{Start: int(requirementNodes[0].node.StartPosition().Column) + 3, End: int(requirementNodes[len(requirementNodes)-1].node.EndPosition().Column) + 1}
		}

		gems = append(gems, metadata)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return gems, nil
}

func (matcher GemspecFileMatcher) enrichPackagesWithLocation(sourceFile DepFile, gems []gemspecMetadata, packagesByName map[string]*PackageDetails) {
	for _, gem := range gems {
		pkg := packagesByName[gem.name]

		pkg.BlockLocation = models.FilePosition{
			Line:     gem.blockLine,
			Column:   gem.blockColumn,
			Filename: sourceFile.Path(),
		}
		pkg.NameLocation = &models.FilePosition{
			Line:     gem.nameLine,
			Column:   gem.nameColumn,
			Filename: sourceFile.Path(),
		}
		if gem.versionLine != nil && gem.versionColumn != nil {
			pkg.VersionLocation = &models.FilePosition{
				Line:     *gem.versionLine,
				Column:   *gem.versionColumn,
				Filename: sourceFile.Path(),
			}
		}
		if gem.isDev {
			pkg.DepGroups = []string{string(DepGroupDev)}
		}
	}
}
