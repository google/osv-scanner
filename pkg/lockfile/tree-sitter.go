package lockfile

import (
	"errors"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	ruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"
	"io"
	"strings"
)

var knownGrammarSeparators = map[string]struct{}{
	"[": {},
	"]": {},
	"{": {},
	"}": {},
	"(": {},
	")": {},
	",": {},
}

type SourceContext struct {
	language          *treesitter.Language
	sourceFileContent []byte
}

func (sc SourceContext) ExtractTextValues(node *treesitter.Node) ([]string, error) {
	if node.GrammarName() == "simple_symbol" || node.GrammarName() == "string" {
		textValue, err := sc.ExtractTextValue(node)
		if err != nil {
			return nil, err
		}
		return []string{textValue}, nil
	} else if _, skip := knownGrammarSeparators[node.GrammarName()]; skip {
		return nil, nil
	} else if node.GrammarName() == "array" || node.GrammarName() == "argument_list" {
		groups := make([]string, 0)
		for i := uint(0); i < node.ChildCount(); i++ {
			childNode := node.Child(i)
			extractedGroups, err := sc.ExtractTextValues(childNode)
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

func (sc SourceContext) ExtractTextValue(node *treesitter.Node) (string, error) {
	if node.GrammarName() == "simple_symbol" {
		// Symbols are prefixed with a colon, so we need to remove it to get the clean text value
		return strings.TrimPrefix(node.Utf8Text(sc.sourceFileContent), ":"), nil
	} else if node.GrammarName() == "string" {
		// Strings are wrapped in quotes, so we need to extract the text from the inner node
		return node.Child(1).Utf8Text(sc.sourceFileContent), nil
	} else {
		return "", errors.New("found unsupported grammar type to extract text value")
	}
}

type ParseResult struct {
	ctx  *SourceContext
	tree *treesitter.Tree
	node *Node
}

func ParseRubyFile(sourceFile DepFile) (*ParseResult, error) {
	parser := treesitter.NewParser()
	defer parser.Close()

	language := treesitter.NewLanguage(ruby.Language())
	err := parser.SetLanguage(language)
	if err != nil {
		return nil, err
	}

	sourceFileContent, err := io.ReadAll(sourceFile)
	if err != nil {
		return nil, err
	}

	tree := parser.Parse(sourceFileContent, nil)

	ctx := &SourceContext{
		language,
		sourceFileContent,
	}
	return &ParseResult{
		ctx:  ctx,
		tree: tree,
		node: &Node{
			ctx:  ctx,
			node: tree.RootNode(),
		},
	}, nil
}

func (p ParseResult) Close() {
	p.tree.Close()
}

type Node struct {
	ctx  *SourceContext
	node *treesitter.Node
}

func (n Node) Query(queryString string, onMatch func(match *MatchResult) error) error {
	query, err := treesitter.NewQuery(n.ctx.language, queryString)
	if err != nil {
		return err
	}
	defer query.Close()

	queryCursor := treesitter.NewQueryCursor()
	defer queryCursor.Close()

	matches := queryCursor.Matches(query, n.node, n.ctx.sourceFileContent)
	for {
		match := matches.Next()
		if match == nil {
			break
		}

		err := onMatch(&MatchResult{
			ctx:   n.ctx,
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
	ctx   *SourceContext
	query *treesitter.Query
	match *treesitter.QueryMatch
}

func (m MatchResult) FindFirstByName(captureName string) *Node {
	if idx, exists := m.query.CaptureIndexForName(captureName); exists {
		for _, capture := range m.match.Captures {
			if uint(capture.Index) == idx {
				return &Node{
					ctx:  m.ctx,
					node: &capture.Node,
				}
			}
		}
	}

	return nil
}
