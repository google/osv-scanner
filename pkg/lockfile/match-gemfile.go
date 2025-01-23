package lockfile

import (
	"path/filepath"

	"github.com/google/osv-scanner/pkg/models"
)

const gemfileFilename = "Gemfile"

// Source: https://www.bundler.cn/guides/groups.html
var knownBundlerDevelopmentGroups = map[string]struct{}{
	"dev":         {},
	"development": {},
	"test":        {},
	"ci":          {},
	"cucumber":    {},
	"linting":     {},
	"rubocop":     {},
}

type gemMetadata struct {
	name          string
	groups        []string
	blockLine     models.Position
	blockColumn   models.Position
	nameLine      models.Position
	nameColumn    models.Position
	versionLine   *models.Position
	versionColumn *models.Position
}

type GemfileMatcher struct{}

func (matcher GemfileMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	lockfileDir := filepath.Dir(lockfile.Path())
	sourceFilePath := filepath.Join(lockfileDir, gemfileFilename)
	file, err := OpenLocalDepFile(sourceFilePath)

	return file, err
}

func (matcher GemfileMatcher) Match(sourceFile DepFile, packages []PackageDetails) error {
	packagesByName := indexPackages(packages)

	treeResult, err := ParseRubyFile(sourceFile)
	if err != nil {
		return err
	}
	defer treeResult.Close()

	rootGems, err := findGems(treeResult.node)
	if err != nil {
		return err
	}
	enrichPackagesWithLocation(sourceFile, rootGems, packagesByName)

	remainingGems, err := findGroupedGems(treeResult.node)
	if err != nil {
		return err
	}
	enrichPackagesWithLocation(sourceFile, remainingGems, packagesByName)

	return nil
}

func findGems(node *Node) ([]gemMetadata, error) {
	gemQueryString := `(
		(call
			method: (identifier) @method_name
			(#match? @method_name "gem")
			arguments: (argument_list
				.
				(comment)*
				.
				(string) @gem_name
				.
				(comment)*
				.
				(string)? @gem_requirement
				.
				(_)*
				.
			)
		) @gem_call
	)`

	gems := make([]gemMetadata, 0)
	err := node.Query(gemQueryString, func(match *MatchResult) error {
		callNode := match.FindFirstByName("gem_call")

		dependencyNameNode := match.FindFirstByName("gem_name")
		dependencyName, err := node.ctx.ExtractTextValue(dependencyNameNode.node)
		if err != nil {
			return err
		}

		requirementNode := match.FindFirstByName("gem_requirement")

		groups, err := findGroupsInPairs(callNode)
		if err != nil {
			return err
		}

		metadata := gemMetadata{
			name:        dependencyName,
			groups:      groups,
			blockLine:   models.Position{Start: int(callNode.node.StartPosition().Row) + 1, End: int(callNode.node.EndPosition().Row) + 1},
			blockColumn: models.Position{Start: int(callNode.node.StartPosition().Column) + 1, End: int(callNode.node.EndPosition().Column) + 1},
			nameLine:    models.Position{Start: int(dependencyNameNode.node.StartPosition().Row) + 1, End: int(dependencyNameNode.node.EndPosition().Row) + 1},
			nameColumn:  models.Position{Start: int(dependencyNameNode.node.StartPosition().Column) + 1, End: int(dependencyNameNode.node.EndPosition().Column) + 1},
		}

		if requirementNode != nil {
			metadata.versionLine = &models.Position{Start: int(requirementNode.node.StartPosition().Row) + 1, End: int(requirementNode.node.EndPosition().Row) + 1}
			metadata.versionColumn = &models.Position{Start: int(requirementNode.node.StartPosition().Column) + 1, End: int(requirementNode.node.EndPosition().Column) + 1}
		}

		gems = append(gems, metadata)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return gems, nil
}

func findGroupedGems(node *Node) ([]gemMetadata, error) {
	groupQueryString := `(
		(call
			method: (identifier) @method_name
			(#match? @method_name "group")
			arguments: (argument_list
				.
				[
					(simple_symbol)
					(string)
					(comment)
					","
				]*
				.
			) @group_keys
			block: (_) @block
		)
	)`

	gems := make([]gemMetadata, 0)
	err := node.Query(groupQueryString, func(match *MatchResult) error {
		groupKeysNode := match.FindFirstByName("group_keys")
		groups, err := node.ctx.ExtractTextValues(groupKeysNode.node)
		if err != nil {
			return err
		}

		blockNode := match.FindFirstByName("block")
		blockGems, err := findGems(blockNode)
		if err != nil {
			return err
		}

		// Top-level group always applies to all gem defined groups
		for idx := range blockGems {
			blockGems[idx].groups = groups
		}

		gems = append(gems, blockGems...)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return gems, nil
}

func findGroupsInPairs(node *Node) ([]string, error) {
	pairQuery := `(
		(pair
			key: [(hash_key_symbol) (simple_symbol)] @pair_key
			(#match? @pair_key "group")
			value: [(array) (simple_symbol) (string)] @pair_value
		)
	)`

	var groups []string
	err := node.Query(pairQuery, func(match *MatchResult) error {
		pairValueNode := match.FindFirstByName("pair_value")
		pairGroups, err := node.ctx.ExtractTextValues(pairValueNode.node)
		if err != nil {
			return err
		}

		groups = append(groups, pairGroups...)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func indexPackages(packages []PackageDetails) map[string]*PackageDetails {
	result := make(map[string]*PackageDetails)
	for index, pkg := range packages {
		result[pkg.Name] = &packages[index]
	}

	return result
}

func enrichPackagesWithLocation(sourceFile DepFile, gems []gemMetadata, packagesByName map[string]*PackageDetails) {
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
		if len(gem.groups) > 0 {
			pkg.DepGroups = gem.groups
		}
	}
}
