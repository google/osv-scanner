// Package pathtree provides a tree structure for representing file paths.
// Each path segment is a node in the tree, enabling efficient storage
// and retrieval for building virtual file systems.
package pathtree

import (
	"errors"
	"fmt"
	"strings"
)

const divider string = "/"

var ErrNodeAlreadyExists = errors.New("node already exists")

// Root node represents the root directory /
type Node[V any] struct {
	value    *V
	children map[string]*Node[V]
}

func NewNode[V any]() *Node[V] {
	return &Node[V]{
		children: make(map[string]*Node[V]),
	}
}

// Insert inserts a value into the tree at the given path.
// If a node already exists at the given path, an error is returned.
//
// If a file is inserted without also inserting the parent directory
// the parent directory entry will have a nil value.
func (node *Node[V]) Insert(path string, value *V) error {
	path, err := cleanPath(path)
	if err != nil {
		return fmt.Errorf("Insert() error: %w", err)
	}

	cursor := node
	for _, segment := range strings.Split(path, divider) {
		next, ok := cursor.children[segment]
		// Create the segment if it doesn't exist
		if !ok {
			next = &Node[V]{
				value:    nil,
				children: make(map[string]*Node[V]),
			}
			cursor.children[segment] = next
		}
		cursor = next
	}

	if cursor.value != nil {
		return fmt.Errorf("%w: %v", ErrNodeAlreadyExists, divider+path)
	}

	cursor.value = value

	return nil
}

// Get retrieves the value at the given path.
// If no node exists at the given path, nil is returned.
func (node *Node[V]) Get(path string) *V {
	path, _ = cleanPath(path)

	cursor := node
	for _, segment := range strings.Split(path, divider) {
		next, ok := cursor.children[segment]
		if !ok {
			return nil
		}
		cursor = next
	}

	return cursor.value
}

// Get retrieves all the direct children of this given path
func (node *Node[V]) GetChildren(path string) []*V {
	path, _ = cleanPath(path)

	cursor := node
	for _, segment := range strings.Split(path, divider) {
		next, ok := cursor.children[segment]
		if !ok {
			return nil
		}
		cursor = next
	}

	var children = make([]*V, 0, len(cursor.children))
	for _, child := range cursor.children {
		// Some entries could be nil if a file is inserted without inserting the
		// parent directories.
		if child != nil {
			children = append(children, child.value)
		}
	}

	return children
}

// cleanPath returns a path for use in the tree
// additionally an error is returned if path is not formatted as expected
func cleanPath(inputPath string) (string, error) {
	path, found := strings.CutPrefix(inputPath, divider)
	if !found {
		return "", fmt.Errorf("path %q is not an absolute path", inputPath)
	}
	path = strings.TrimSuffix(path, "/")

	return path, nil
}

// Walk walks through all elements of this tree depths first, calling fn at every node
func (node *Node[V]) Walk(fn func(string, *V) error) error {
	return node.walk("/", fn)
}

func (node *Node[V]) walk(path string, fn func(string, *V) error) error {
	for key, node := range node.children {
		if err := fn(key, node.value); err != nil {
			return err
		}
		err := node.walk(path+divider+key, fn)
		if err != nil {
			return err
		}
	}

	return nil
}
