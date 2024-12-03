package pathtree_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scanner/internal/image/pathtree"
)

type testVal struct {
	string
}

func assertNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Errorf("%v", err)
	}
}

func testTree(t *testing.T) *pathtree.Node[testVal] {
	t.Helper()

	tree := pathtree.NewNode[testVal]()
	assertNoError(t, tree.Insert("/a", &testVal{"value1"}))
	assertNoError(t, tree.Insert("/a/b", &testVal{"value2"}))
	assertNoError(t, tree.Insert("/a/b/c", &testVal{"value3"}))
	assertNoError(t, tree.Insert("/a/b/d", &testVal{"value4"}))
	assertNoError(t, tree.Insert("/a/e", &testVal{"value5"}))
	assertNoError(t, tree.Insert("/a/e/f", &testVal{"value6"}))
	assertNoError(t, tree.Insert("/a/b/d/f", &testVal{"value7"}))
	assertNoError(t, tree.Insert("/a/g", &testVal{"value8"}))

	return tree
}

func TestNode_Insert_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tree *pathtree.Node[testVal]
		key  string
		val  *testVal
	}{
		{
			name: "duplicate node",
			tree: func() *pathtree.Node[testVal] {
				tree := pathtree.NewNode[testVal]()
				_ = tree.Insert("/a", &testVal{"value1"})

				return tree
			}(),
			key: "/a",
			val: &testVal{"value2"},
		},
		{
			name: "duplicate node in subtree",
			tree: func() *pathtree.Node[testVal] {
				tree := pathtree.NewNode[testVal]()
				_ = tree.Insert("/a", &testVal{"value1"})
				_ = tree.Insert("/a/b", &testVal{"value2"})

				return tree
			}(),
			key: "/a/b",
			val: &testVal{"value3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.tree.Insert(tt.key, tt.val)
			if err == nil {
				t.Errorf("Node.Insert() expected error, got nil")
			}
		})
	}
}

func TestNode_Get(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tree *pathtree.Node[testVal]
		key  string
		want *testVal
	}{
		{
			name: "empty tree",
			tree: pathtree.NewNode[testVal](),
			key:  "/a",
			want: nil,
		},
		{
			name: "single node",
			tree: func() *pathtree.Node[testVal] {
				tree := pathtree.NewNode[testVal]()
				_ = tree.Insert("/a", &testVal{"value"})

				return tree
			}(),
			key:  "/a",
			want: &testVal{"value"},
		},
		{
			name: "non-existent node in single node tree",
			tree: func() *pathtree.Node[testVal] {
				tree := pathtree.NewNode[testVal]()
				_ = tree.Insert("/a", &testVal{"value"})

				return tree
			}(),
			key:  "/b",
			want: nil,
		},
		{
			name: "multiple nodes",
			tree: testTree(t),
			key:  "/a/b/c",
			want: &testVal{"value3"},
		},
		{
			name: "non-existent node",
			tree: testTree(t),
			key:  "/a/b/g",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.tree.Get(tt.key)
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(testVal{})); diff != "" {
				t.Errorf("Node.Get() (-want +got): %v", diff)
			}
		})
	}
}

func TestNode_GetChildren(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tree *pathtree.Node[testVal]
		key  string
		want []*testVal
	}{
		{
			name: "empty tree",
			tree: pathtree.NewNode[testVal](),
			key:  "/a",
			want: nil,
		},
		{
			name: "single node no children",
			tree: func() *pathtree.Node[testVal] {
				tree := pathtree.NewNode[testVal]()
				_ = tree.Insert("/a", &testVal{"value"})

				return tree
			}(),
			key:  "/a",
			want: []*testVal{},
		},
		{
			name: "multiple nodes with children",
			tree: testTree(t),
			key:  "/a/b",
			want: []*testVal{
				{"value3"},
				{"value4"},
			},
		},
		{
			name: "non-existent node",
			tree: testTree(t),
			key:  "/a/b/g",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.tree.GetChildren(tt.key)
			if diff := cmp.Diff(
				tt.want,
				got,
				cmp.AllowUnexported(testVal{}),
				cmpopts.SortSlices(func(a, b *testVal) bool {
					return strings.Compare(a.string, b.string) < 0
				})); diff != "" {
				t.Errorf("Node.GetChildren() (-want +got): %v", diff)
			}
		})
	}
}

func TestNode_Walk(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tree *pathtree.Node[testVal]
		want []string
	}{
		{
			name: "empty tree",
			tree: pathtree.NewNode[testVal](),
			want: []string{},
		},
		{
			name: "single node",
			tree: func() *pathtree.Node[testVal] {
				tree := pathtree.NewNode[testVal]()
				_ = tree.Insert("/a", &testVal{"value"})

				return tree
			}(),
			want: []string{"value"},
		},
		{
			name: "multiple nodes",
			tree: testTree(t),
			want: []string{
				"value1",
				"value2",
				"value3",
				"value4",
				"value5",
				"value6",
				"value7",
				"value8",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := []string{}
			err := tt.tree.Walk(func(_ string, node *testVal) error {
				got = append(got, node.string)
				return nil
			})
			if err != nil {
				t.Errorf("Node.Walk() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(a, b string) bool {
				return strings.Compare(a, b) < 0
			})); diff != "" {
				t.Errorf("Node.Walk() (-want +got): %v", diff)
			}
		})
	}
}
