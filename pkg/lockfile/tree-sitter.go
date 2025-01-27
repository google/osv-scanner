package lockfile

import (
	"errors"
	"io"
	"strings"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	ruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"
)

var Ruby = treesitter.NewLanguage(ruby.Language())

var knownGrammarSeparators = map[string]struct{}{
	"[":       {},
	"]":       {},
	"{":       {},
	"}":       {},
	"(":       {},
	")":       {},
	",":       {},
	"comment": {},
}

type SourceContext struct {
	language          *treesitter.Language
	sourceFileContent []byte
}

func (sc SourceContext) ExtractTextValues(node *treesitter.Node) ([]string, error) {
	if node.Kind() == "simple_symbol" || node.Kind() == "string" {
		textValue, err := sc.ExtractTextValue(node)
		if err != nil {
			return nil, err
		}

		return []string{textValue}, nil
	} else if _, skip := knownGrammarSeparators[node.Kind()]; skip {
		return nil, nil
	} else if node.Kind() == "array" || node.Kind() == "argument_list" {
		groups := make([]string, 0)

		cursor := node.Walk()
		defer cursor.Close()
		for _, childNode := range node.Children(cursor) {
			extractedGroups, err := sc.ExtractTextValues(&childNode)
			if err != nil {
				return nil, err
			}
			groups = append(groups, extractedGroups...)
		}

		return groups, nil
	}

	return nil, errors.New("found unsupported grammar type=" + node.Kind())
}

func (sc SourceContext) ExtractTextValue(node *treesitter.Node) (string, error) {
	if node.Kind() == "simple_symbol" {
		// Symbols are prefixed with a colon, so we need to remove it to get the clean text value
		return strings.TrimPrefix(node.Utf8Text(sc.sourceFileContent), ":"), nil
	} else if node.Kind() == "string" {
		// Strings are wrapped in quotes, so we need to extract the text from the inner node and check if they have content
		stringContentNode := node.NamedChild(0)
		if stringContentNode == nil {
			return "", nil
		}

		return stringContentNode.Utf8Text(sc.sourceFileContent), nil
	} else if node.Kind() == "identifier" || node.Kind() == "string_content" {
		// Strings are wrapped in quotes, so we need to extract the text from the inner node
		return node.Utf8Text(sc.sourceFileContent), nil
	}

	return "", errors.New("found unsupported grammar type='" + node.Kind() + "' to extract text value")
}

type ParseResult struct {
	Ctx  *SourceContext
	tree *treesitter.Tree
	Node *Node
}

func ParseFile(sourceFile DepFile, language *treesitter.Language) (*ParseResult, error) {
	parser := treesitter.NewParser()
	defer parser.Close()

	err := parser.SetLanguage(language)
	if err != nil {
		return nil, err
	}

	sourceFileContent, err := io.ReadAll(sourceFile)
	if err != nil {
		return nil, err
	}

	tree := parser.Parse(sourceFileContent, nil)
	if tree.RootNode().HasError() {
		return nil, errors.New("Error parsing file=" + sourceFile.Path())
	}

	ctx := &SourceContext{
		language,
		sourceFileContent,
	}

	return &ParseResult{
		Ctx:  ctx,
		tree: tree,
		Node: &Node{
			Ctx:    ctx,
			TSNode: tree.RootNode(),
		},
	}, nil
}

func (p ParseResult) Close() {
	p.tree.Close()
}

type Node struct {
	Ctx    *SourceContext
	TSNode *treesitter.Node
}

func (n Node) Query(queryString string, onMatch func(match *MatchResult) error) error {
	query, err := treesitter.NewQuery(n.Ctx.language, queryString)
	if err != nil {
		return err
	}
	defer query.Close()

	queryCursor := treesitter.NewQueryCursor()
	defer queryCursor.Close()

	matches := queryCursor.Matches(query, n.TSNode, n.Ctx.sourceFileContent)
	for {
		match := matches.Next()
		if match == nil {
			break
		}

		err := onMatch(&MatchResult{
			Ctx:   n.Ctx,
			query: query,
			match: match,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

type MatchResult struct {
	Ctx   *SourceContext
	query *treesitter.Query
	match *treesitter.QueryMatch
}

func (m MatchResult) FindFirstByName(captureName string) *Node {
	if idx, exists := m.query.CaptureIndexForName(captureName); exists {
		for _, capture := range m.match.Captures {
			if uint(capture.Index) == idx {
				return &Node{
					Ctx:    m.Ctx,
					TSNode: &capture.Node,
				}
			}
		}
	}

	return nil
}

func (m MatchResult) FindByName(captureName string) []*Node {
	var nodes []*Node
	if idx, exists := m.query.CaptureIndexForName(captureName); exists {
		for _, node := range m.match.NodesForCaptureIndex(idx) {
			nodes = append(nodes, &Node{
				Ctx:    m.Ctx,
				TSNode: &node,
			})
		}
	}

	return nodes
}
