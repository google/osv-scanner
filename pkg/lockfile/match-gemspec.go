package lockfile

import (
	"log"
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

	// .gemspec are optional, Gemfile.lock sometimes has no .gemspec and that is fine
	return nil, nil
}

func (matcher GemspecFileMatcher) Match(sourceFile DepFile, packages []PackageDetails) error {
	packagesByName := indexPackages(packages)

	treeResult, err := ParseFile(sourceFile, Ruby)
	if err != nil {
		return err
	}
	defer treeResult.Close()

	gems, err := matcher.findGemspecs(treeResult.Node)
	if err != nil {
		return err
	}
	matcher.enrichPackagesWithLocation(sourceFile, gems, packagesByName)

	return nil
}

func (matcher GemspecFileMatcher) findGemspecs(node *Node) ([]gemspecMetadata, error) {
	// Matches method calls to add_dependency, add_runtime_dependency and add_development_dependency
	// extracting the gem dependency name and gem dependency requirements
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
					(string)
					(array (string))
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
		methodName, err := node.Ctx.ExtractTextValue(methodNameNode.TSNode)
		if err != nil {
			return err
		}

		dependencyNameNode := match.FindFirstByName("gem_name")
		dependencyName, err := node.Ctx.ExtractTextValue(dependencyNameNode.TSNode)
		if err != nil {
			return err
		}

		requirementNodes := match.FindByName("gem_requirements")

		metadata := gemspecMetadata{
			name:        dependencyName,
			isDev:       methodName == "add_development_dependency",
			blockLine:   models.Position{Start: int(callNode.TSNode.StartPosition().Row) + 1, End: int(callNode.TSNode.EndPosition().Row) + 1},
			blockColumn: models.Position{Start: int(callNode.TSNode.StartPosition().Column) + 1, End: int(callNode.TSNode.EndPosition().Column) + 1},
			nameLine:    models.Position{Start: int(dependencyNameNode.TSNode.StartPosition().Row) + 1, End: int(dependencyNameNode.TSNode.EndPosition().Row) + 1},
			nameColumn:  models.Position{Start: int(dependencyNameNode.TSNode.StartPosition().Column) + 1, End: int(dependencyNameNode.TSNode.EndPosition().Column) + 1},
		}

		if len(requirementNodes) > 0 {
			metadata.versionLine = &models.Position{Start: int(requirementNodes[0].TSNode.StartPosition().Row) + 1, End: int(requirementNodes[len(requirementNodes)-1].TSNode.EndPosition().Row) + 1}
			metadata.versionColumn = &models.Position{Start: int(requirementNodes[0].TSNode.StartPosition().Column) + 3, End: int(requirementNodes[len(requirementNodes)-1].TSNode.EndPosition().Column) + 1}
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
		pkg, ok := packagesByName[gem.name]
		// If packages exist in a .gemspec but not in the Gemfile.lock, we skip the package as we treat the lockfile as
		// the source of truth
		if !ok {
			log.Printf("Skipping package %q from gemspec as it does not exist in the Gemfile.lock\n", gem.name)
			continue
		}

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
