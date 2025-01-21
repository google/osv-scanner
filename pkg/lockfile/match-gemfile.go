package lockfile

import (
	"errors"
	"github.com/google/osv-scanner/pkg/models"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	ruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"
	"io"
	"path/filepath"
	"strings"
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

var knownGrammarSeparators = map[string]struct{}{
	"[": {},
	"]": {},
	"{": {},
	"}": {},
	"(": {},
	")": {},
	",": {},
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

	parser := treesitter.NewParser()
	defer parser.Close()

	language := treesitter.NewLanguage(ruby.Language())
	err := parser.SetLanguage(language)
	if err != nil {
		return err
	}

	sourceFileContent, err := io.ReadAll(sourceFile)
	if err != nil {
		return err
	}

	tree := parser.Parse(sourceFileContent, nil)
	defer tree.Close()

	root := tree.RootNode()

	rootGems, err := findGems(language, root, sourceFileContent, true)
	if err != nil {
		return err
	}
	enrichPackagesWithLocation(sourceFile, rootGems, packagesByName)

	remainingGems, err := findGroupedGems(language, root, sourceFileContent)
	if err != nil {
		return err
	}
	enrichPackagesWithLocation(sourceFile, remainingGems, packagesByName)

	return nil
}

func findGems(language *treesitter.Language, root *treesitter.Node, sourceFileContent []byte, onlyRootDeps bool) ([]gemMetadata, error) {
	gemQueryString := `(
		(call
			method: (identifier) @method_name
			(#match? @method_name "gem")
			arguments: (argument_list
				.
				(string) @gem_name
				.
				(string)? @gem_requirement
				.
				(_)*
				.
			)
		) @gem_call
	)`

	gems := make([]gemMetadata, 0)
	err := query(language, sourceFileContent, root, gemQueryString, func(query *treesitter.Query, match *treesitter.QueryMatch) error {
		callNode := getFirstCapturedNode(query, match, "gem_call")
		if onlyRootDeps && callNode.Parent().GrammarName() != "program" {
			return nil
		}

		dependencyNameNode := getFirstCapturedNode(query, match, "gem_name").Child(1)
		dependencyName := dependencyNameNode.Utf8Text(sourceFileContent)

		requirementNode := getFirstCapturedNode(query, match, "gem_requirement")
		if requirementNode != nil && requirementNode.GrammarName() == "string" {
			requirementNode = requirementNode.Child(1)
		}

		groups, err := findGroupsInCapturedNodes(language, callNode, sourceFileContent)
		if err != nil {
			return err
		}

		metadata := gemMetadata{
			name:        dependencyName,
			groups:      groups,
			blockLine:   models.Position{Start: int(callNode.StartPosition().Row) + 1, End: int(callNode.EndPosition().Row) + 1},
			blockColumn: models.Position{Start: int(callNode.StartPosition().Column) + 1, End: int(callNode.EndPosition().Column) + 1},
			nameLine:    models.Position{Start: int(dependencyNameNode.StartPosition().Row) + 1, End: int(dependencyNameNode.EndPosition().Row) + 1},
			nameColumn:  models.Position{Start: int(dependencyNameNode.StartPosition().Column), End: int(dependencyNameNode.EndPosition().Column) + 2},
		}

		if requirementNode != nil {
			metadata.versionLine = &models.Position{Start: int(requirementNode.StartPosition().Row) + 1, End: int(requirementNode.EndPosition().Row) + 1}
			metadata.versionColumn = &models.Position{Start: int(requirementNode.StartPosition().Column), End: int(requirementNode.EndPosition().Column) + 2}
		}

		gems = append(gems, metadata)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return gems, nil
}

func findGroupedGems(language *treesitter.Language, root *treesitter.Node, sourceFileContent []byte) ([]gemMetadata, error) {
	groupQueryString := `(
		(call
			method: (identifier) @method_name
			(#match? @method_name "group")
			arguments: (argument_list . [(simple_symbol) (string)]+) @group_keys
			block: (_) @block
		)
	)`

	gems := make([]gemMetadata, 0)
	err := query(language, sourceFileContent, root, groupQueryString, func(query *treesitter.Query, match *treesitter.QueryMatch) error {
		groupKeysNode := getFirstCapturedNode(query, match, "group_keys")
		groups, err := extractGroups(groupKeysNode, sourceFileContent)
		if err != nil {
			return err
		}

		blockNode := getFirstCapturedNode(query, match, "block")
		gs, err := findGems(language, blockNode, sourceFileContent, false)
		if err != nil {
			return err
		}

		// Top-level group always applies to all gem defined groups
		for idx := range gs {
			gs[idx].groups = groups
		}

		gems = append(gems, gs...)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return gems, nil
}

func findGroupsInCapturedNodes(language *treesitter.Language, node *treesitter.Node, sourceFileContent []byte) ([]string, error) {
	pairQuery := `(
		(pair
			key: [(hash_key_symbol) (simple_symbol)] @group_key
			(#match? @group_key "group")
			value: [(array) (simple_symbol) (string)] @group_value
		)
	)`

	var groups []string
	err := query(language, sourceFileContent, node, pairQuery, func(query *treesitter.Query, match *treesitter.QueryMatch) error {
		groupValueNode := getFirstCapturedNode(query, match, "group_value")
		nodeGroups, err := extractGroups(groupValueNode, sourceFileContent)
		if err != nil {
			return err
		}

		groups = append(groups, nodeGroups...)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func query(language *treesitter.Language, sourceFileContent []byte, node *treesitter.Node, queryString string, onMatch func(query *treesitter.Query, match *treesitter.QueryMatch) error) error {
	query, err := treesitter.NewQuery(language, queryString)
	if err != nil {
		return err
	}
	defer query.Close()

	queryCursor := treesitter.NewQueryCursor()
	defer queryCursor.Close()

	matches := queryCursor.Matches(query, node, sourceFileContent)
	for {
		match := matches.Next()
		if match == nil {
			break
		}

		err := onMatch(query, match)
		if err != nil {
			return err
		}
	}

	return nil
}

func getFirstCapturedNode(query *treesitter.Query, match *treesitter.QueryMatch, name string) *treesitter.Node {
	if idx, exists := query.CaptureIndexForName(name); exists {
		for _, capture := range match.Captures {
			if uint(capture.Index) == idx {
				return &capture.Node
			}
		}
	}

	return nil
}

func extractGroups(node *treesitter.Node, sourceFileContent []byte) ([]string, error) {
	if node.GrammarName() == "simple_symbol" {
		return []string{extractGroupName(node, sourceFileContent)}, nil
	} else if node.GrammarName() == "string" {
		return []string{extractGroupName(node.Child(1), sourceFileContent)}, nil
	} else if _, skip := knownGrammarSeparators[node.GrammarName()]; skip {
		return nil, nil
	} else if node.GrammarName() == "array" || node.GrammarName() == "argument_list" {
		groups := make([]string, 0)
		for i := uint(0); i < node.ChildCount(); i++ {
			childNode := node.Child(i)
			extractedGroups, err := extractGroups(childNode, sourceFileContent)
			if err != nil {
				return nil, err
			}
			groups = append(groups, extractedGroups...)
		}
		return groups, nil
	} else {
		return nil, errors.New("found unsupported grammar type")
	}
}

func extractGroupName(node *treesitter.Node, sourceFileContent []byte) string {
	return strings.TrimPrefix(node.Utf8Text(sourceFileContent), ":")
}

func indexPackages(packages []PackageDetails) map[string]*PackageDetails {
	result := make(map[string]*PackageDetails)
	for index, pkg := range packages {
		result[pkg.Name] = &packages[index]
	}

	return result
}

func enrichPackagesWithLocation(sourceFile DepFile, remainingGems []gemMetadata, packagesByName map[string]*PackageDetails) {
	for _, gem := range remainingGems {
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
