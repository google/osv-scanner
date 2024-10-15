package spdx

import (
	"fmt"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

type node interface {
	satisfiedBy(licenses []string) bool
}

// nodeBranch represents a node in the tree that has two children, which should be
// evaluated with the operator to determine if the license expression is satisfied
type nodeBranch struct {
	left     node
	operator string
	right    node
}

func (n nodeBranch) satisfiedBy(licenses []string) bool {
	switch n.operator {
	case "AND":
		return n.left.satisfiedBy(licenses) && n.right.satisfiedBy(licenses)
	case "OR":
		return n.left.satisfiedBy(licenses) || n.right.satisfiedBy(licenses)
	}

	return false
}

var _ node = nodeBranch{}

// nodeLeaf represents a leaf node in the tree, which holds a single license id
type nodeLeaf struct {
	value string
}

func (n nodeLeaf) satisfiedBy(licenses []string) bool {
	v := strings.ToLower(n.value)

	for _, l := range licenses {
		if v == strings.ToLower(l) {
			return true
		}
	}

	return false
}

var _ node = nodeLeaf{}

type tokens struct {
	tokens []string
}

func (ts *tokens) peek() string {
	if len(ts.tokens) == 0 {
		return ""
	}

	return ts.tokens[0]
}

func (ts *tokens) next() string {
	if len(ts.tokens) == 0 {
		return ""
	}

	token := ts.tokens[0]
	ts.tokens = ts.tokens[1:]

	return token
}

var allowed = map[string][]string{
	"WITH": {"EXP"},
	"AND":  {"EXP", "("},
	"OR":   {"EXP", "("},
	"(":    {"EXP", "("},
	")":    {")", "AND", "OR", "END"},
	"EXP":  {"WITH", "AND", "OR", ")", "END"},
	"END":  {},
}

func (ts *tokens) nextIfValid() (string, error) {
	next := ts.next()

	return next, ts.isNextValid(next)
}

func (ts *tokens) isNextValid(cur string) error {
	allowedNext := allowed[cur]

	// license expressions are implied as being not one of the other tokens
	if allowedNext == nil {
		cur = "EXP"
		allowedNext = allowed[cur]
	}

	next := "END"

	if len(ts.tokens) > 0 {
		next = ts.peek()
	}

	// license expressions are implied as being not one of the other tokens
	if _, ok := allowed[next]; !ok {
		next = "EXP"
	}

	for _, a := range allowedNext {
		if next == a {
			return nil
		}
	}

	return fmt.Errorf("unexpected %s after %s", next, cur)
}

func tokenise(license models.License) tokens {
	var ts tokens
	current := ""

	for _, c := range string(license) {
		switch c {
		case '(', ')', ' ':
			// check if we've been accumulating a token, before processing the current character
			if current != "" {
				ts.tokens = append(ts.tokens, current)
			}
			current = ""

			// spaces are only used to separate tokens, but are not tokens themselves
			if c != ' ' {
				ts.tokens = append(ts.tokens, string(c))
			}
		default:
			current += string(c)
		}
	}

	// before returning, make sure we add the last token we were accumulating
	if current != "" {
		ts.tokens = append(ts.tokens, current)
	}

	return ts
}

func parse(tokens *tokens) (node, error) {
	return parseOr(tokens)
}

func parseOr(tokens *tokens) (node, error) {
	left, err := parseAnd(tokens)
	if err != nil {
		return nil, err
	}

	for tokens.peek() == "OR" {
		operator, err := tokens.nextIfValid()
		if err != nil {
			return nil, err
		}

		right, err := parseAnd(tokens)
		if err != nil {
			return nil, err
		}

		left = nodeBranch{
			left:     left,
			operator: operator,
			right:    right,
		}
	}

	return left, nil
}

func parseAnd(tokens *tokens) (node, error) {
	left, err := parseExpression(tokens)
	if err != nil {
		return nil, err
	}

	for tokens.peek() == "AND" {
		operator, err := tokens.nextIfValid()
		if err != nil {
			return nil, err
		}

		right, err := parseExpression(tokens)
		if err != nil {
			return nil, err
		}

		left = nodeBranch{
			left:     left,
			operator: operator,
			right:    right,
		}
	}

	return left, nil
}

func parseExpression(tokens *tokens) (node, error) {
	if tokens.peek() == "" {
		return nil, fmt.Errorf("unexpected end of expression")
	}

	next, err := tokens.nextIfValid()
	if err != nil {
		return nil, err
	}

	if next == "(" {
		expr, err := parseOr(tokens)
		if err != nil {
			return nil, err
		}

		if tokens.peek() != ")" {
			return nil, fmt.Errorf("missing closing bracket")
		}

		_, err = tokens.nextIfValid()
		if err != nil {
			return nil, err
		}

		return expr, nil
	}

	if tokens.peek() == "WITH" {
		nex2, err := tokens.nextIfValid()
		if err != nil {
			return nil, err
		}

		next += " " + nex2 + " " + tokens.next()
	}

	return nodeLeaf{value: next}, nil
}

// Satisfies checks if the given license expression is satisfied by the allowed licenses
func Satisfies(license models.License, allowlist []string) (bool, error) {
	tokens := tokenise(license)
	nod, err := parse(&tokens)

	if err != nil {
		return false, err
	}

	return nod.satisfiedBy(allowlist), nil
}
