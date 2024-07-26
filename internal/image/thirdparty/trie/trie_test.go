package trie

import (
	"errors"
	"slices"
	"testing"
)

// PathTrie

func TestPathTrie(t *testing.T) {
	trie := NewPathTrie()
	testTrie(t, trie)
}

func TestPathTrieWithNilConfig(t *testing.T) {
	trie := NewPathTrieWithConfig(nil)
	testTrie(t, trie)
}

func TestPathTrieWithEmptyConfig(t *testing.T) {
	trie := NewPathTrieWithConfig(&PathTrieConfig{})
	testTrie(t, trie)
}

func TestPathTrieWithConfig(t *testing.T) {
	trie := NewPathTrieWithConfig(&PathTrieConfig{PathSegmenter})
	testTrie(t, trie)
}

func TestPathTrieNilBehavior(t *testing.T) {
	trie := NewPathTrie()
	testNilBehavior(t, trie)
}

func TestPathTrieRoot(t *testing.T) {
	trie := NewPathTrie()
	testTrieRoot(t, trie)

	trie = NewPathTrie()
	if !trie.isLeaf() {
		t.Error("root of empty tree should be leaf")
	}
	trie.Put("", "root")
	if !trie.isLeaf() {
		t.Error("root should not have children, only value")
	}
}

func TestPathTrieWalk(t *testing.T) {
	trie := NewPathTrie()
	testTrieWalk(t, trie)
}

func TestPathTrieWalkError(t *testing.T) {
	trie := NewPathTrie()
	testTrieWalkError(t, trie)
}

func TestPathTrieWalkChildren(t *testing.T) {
	trie := NewPathTrie()
	testTrieWalkChildren(t, trie)
}

func TestPathTrieWalkPath(t *testing.T) {
	trie := NewPathTrie()
	testTrieWalkPath(t, trie)
}

func TestPathTrieWalkPathError(t *testing.T) {
	trie := NewPathTrie()
	testTrieWalkPathError(t, trie)
}

func testTrie(t *testing.T, trie Trier) {
	const firstPutValue = "first put"
	cases := []struct {
		key   string
		value interface{}
	}{
		{"fish", 0},
		{"/cat", 1},
		{"/dog", 2},
		{"/cats", 3},
		{"/caterpillar", 4},
		{"/cat/gideon", 5},
		{"/cat/giddy", 6},
	}

	// get missing keys
	for _, c := range cases {
		if value := trie.Get(c.key); value != nil {
			t.Errorf("expected key %s to be missing, found value %v", c.key, value)
		}
	}

	// initial put
	for _, c := range cases {
		if isNew := trie.Put(c.key, firstPutValue); !isNew {
			t.Errorf("expected key %s to be missing", c.key)
		}
	}

	// subsequent put
	for _, c := range cases {
		if isNew := trie.Put(c.key, c.value); isNew {
			t.Errorf("expected key %s to have a value already", c.key)
		}
	}

	// get
	for _, c := range cases {
		if value := trie.Get(c.key); value != c.value {
			t.Errorf("expected key %s to have value %v, got %v", c.key, c.value, value)
		}
	}

	// delete, expect Delete to return true indicating a node was nil'd
	for _, c := range cases {
		if deleted := trie.Delete(c.key); !deleted {
			t.Errorf("expected key %s to be deleted", c.key)
		}
	}

	// delete cleaned all the way to the first character
	// expect Delete to return false bc no node existed to nil
	for _, c := range cases {
		if deleted := trie.Delete(string(c.key[0])); deleted {
			t.Errorf("expected key %s to be cleaned by delete", string(c.key[0]))
		}
	}

	// get deleted keys
	for _, c := range cases {
		if value := trie.Get(c.key); value != nil {
			t.Errorf("expected key %s to be deleted, got value %v", c.key, value)
		}
	}
}

func testNilBehavior(t *testing.T, trie Trier) {
	cases := []struct {
		key   string
		value interface{}
	}{
		{"/cat", 1},
		{"/catamaran", 2},
		{"/caterpillar", nil},
	}
	expectNilValues := []string{"/", "/c", "/ca", "/caterpillar", "/other"}

	// initial put
	for _, c := range cases {
		if isNew := trie.Put(c.key, c.value); !isNew {
			t.Errorf("expected key %s to be missing", c.key)
		}
	}

	// get nil
	for _, key := range expectNilValues {
		if value := trie.Get(key); value != nil {
			t.Errorf("expected key %s to have value nil, got %v", key, value)
		}
	}
}

func testTrieRoot(t *testing.T, trie Trier) {
	const firstPutValue = "first put"
	const putValue = "value"

	if value := trie.Get(""); value != nil {
		t.Errorf("expected key '' to be missing, found value %v", value)
	}
	if !trie.Put("", firstPutValue) {
		t.Error("expected key '' to be missing")
	}
	if trie.Put("", putValue) {
		t.Error("expected key '' to have a value already")
	}
	if value := trie.Get(""); value != putValue {
		t.Errorf("expected key '' to have value %v, got %v", putValue, value)
	}
	if !trie.Delete("") {
		t.Error("expected key '' to be deleted")
	}
	if value := trie.Get(""); value != nil {
		t.Errorf("expected key '' to be deleted, got value %v", value)
	}
}

func testTrieWalk(t *testing.T, trie Trier) {
	table := map[string]interface{}{
		"":             -1,
		"fish":         0,
		"/cat":         1,
		"/dog":         2,
		"/cats":        3,
		"/caterpillar": 4,
		"/notes":       30,
		"/notes/new":   31,
		"/notes/:id":   32,
	}
	// key -> times walked
	walked := make(map[string]int)
	for key := range table {
		walked[key] = 0
	}

	for key, value := range table {
		if isNew := trie.Put(key, value); !isNew {
			t.Errorf("expected key %s to be missing", key)
		}
	}

	walker := func(key string, value interface{}) error {
		// value for each walked key is correct
		if value != table[key] {
			t.Errorf("expected key %s to have value %v, got %v", key, table[key], value)
		}
		walked[key]++
		return nil
	}
	if err := trie.Walk(walker); err != nil {
		t.Errorf("expected error nil, got %v", err)
	}

	// each key/value walked exactly once
	for key, walkedCount := range walked {
		if walkedCount != 1 {
			t.Errorf("expected key %s to be walked exactly once, got %v", key, walkedCount)
		}
	}
}

func testTrieWalkError(t *testing.T, trie Trier) {
	table := map[string]interface{}{
		"/L1/L2A":        1,
		"/L1/L2B/L3A":    2,
		"/L1/L2B/L3B/L4": 42,
		"/L1/L2B/L3C":    4,
		"/L1/L2C":        5,
	}

	walkerError := errors.New("walker error")
	walked := 0

	for key, value := range table {
		trie.Put(key, value)
	}
	walker := func(key string, value interface{}) error {
		if value == 42 {
			return walkerError
		}
		walked++
		return nil
	}
	if err := trie.Walk(walker); err != walkerError {
		t.Errorf("expected walker error, got %v", err)
	}
	if len(table) == walked {
		t.Errorf("expected nodes walked < %d, got %d", len(table), walked)
	}
}

func testTrieWalkPath(t *testing.T, trie Trier) {
	table := map[string]interface{}{
		"fish":             0,
		"/cat":             1,
		"/dog":             2,
		"/cats":            3,
		"/caterpillar":     4,
		"/notes":           30,
		"/notes/new":       31,
		"/notes/new/noise": 32,
	}
	// key -> times walked
	walked := make(map[string]int)
	for key := range table {
		walked[key] = 0
	}

	for key, value := range table {
		if isNew := trie.Put(key, value); !isNew {
			t.Errorf("expected key %s to be missing", key)
		}
	}

	walker := func(key string, value interface{}) error {
		// value for each walked key is correct
		if value != table[key] {
			t.Errorf("expected key %s to have value %v, got %v", key, table[key], value)
		}
		walked[key]++
		return nil
	}
	if err := trie.WalkPath("/notes/new/noise", walker); err != nil {
		t.Errorf("expected error nil, got %v", err)
	}

	// expect each key/value in path walked exactly once, and not other keys
	for key, walkedCount := range walked {
		switch key {
		case "/notes", "/notes/new", "/notes/new/noise":
			if walkedCount != 1 {
				t.Errorf("expected key %s to be walked exactly once, got %v", key, walkedCount)
			}
		default:
			if walkedCount != 0 {
				t.Errorf("expected key %s to not be walked, got %v", key, walkedCount)
			}
		}
	}

	for key := range table {
		walked[key] = 0
	}
	if err := trie.WalkPath("/notes/new/nose", walker); err != nil {
		t.Errorf("expected error nil, got %v", err)
	}
	// expect each key/value in path walked exactly once, and not other keys
	for key, walkedCount := range walked {
		switch key {
		case "/notes", "/notes/new":
			if walkedCount != 1 {
				t.Errorf("expected key %s to be walked exactly once, got %v", key, walkedCount)
			}
		default:
			if walkedCount != 0 {
				t.Errorf("expected key %s to not be walked, got %v", key, walkedCount)
			}
		}
	}

	var foundRoot bool
	trie.Put("", "ROOT")
	trie.WalkPath("/notes/new/noise", func(key string, value interface{}) error {
		if key == "" && value == "ROOT" {
			foundRoot = true
		}
		return nil
	})
	if !foundRoot {
		t.Error("did not find root")
	}
}

func testTrieWalkPathError(t *testing.T, trie Trier) {
	table := map[string]interface{}{
		"/L1/L2A":        1,
		"/L1/L2A/L3B":    99,
		"/L1/L2A/L3B/L4": 2,
		"/L1/L2B/L3B":    3,
		"/L1/L2C":        4,
	}

	walkerError := errors.New("walker error")

	walked := make(map[string]int)
	for key := range table {
		walked[key] = 0
	}

	for key, value := range table {
		trie.Put(key, value)
	}
	walker := func(key string, value interface{}) error {
		if value == 99 {
			return walkerError
		}
		walked[key]++
		return nil
	}
	if err := trie.WalkPath("/L1/L2A/L3B", walker); err != walkerError {
		t.Errorf("expected walker error, got %v", err)
	}
	// expect each key/value in path, up to error and not including key with
	// value 99, walked exactly once, and not other keys
	var walkedTotal int
	for key, walkedCount := range walked {
		switch key {
		case "/L1/L2A":
			if walkedCount != 1 {
				t.Errorf("expected key %s to be walked exactly once, got %v", key, walkedCount)
			}
			walkedTotal++
		default:
			if walkedCount != 0 {
				t.Errorf("expected key %s to not be walked, got %v", key, walkedCount)
			}
		}
	}
	if walkedTotal != 1 {
		t.Errorf("expected 1 nodes walked, got %d", walkedTotal)
	}

	rootError := errors.New("error at root")
	trie.Put("", "ROOT")
	err := trie.WalkPath("/L1/L2A/L3B/L4", func(key string, value interface{}) error {
		if key == "" && value == "ROOT" {
			return rootError
		}
		return nil
	})
	if err != rootError {
		t.Errorf("expected %s, got %s", rootError, err)
	}
}

func testTrieWalkChildren(t *testing.T, trie Trier) {
	table := map[string]interface{}{
		"/L1/L2A":        1,
		"/L1/L2A/L3B":    99,
		"/L1/L2A/L3B/L4": 2,
		"/L1/L2B/L3B":    3,
		"/L1/L2C":        4,
	}

	walked := make(map[string]int)
	for key := range table {
		walked[key] = 0
	}

	for key, value := range table {
		trie.Put(key, value)
	}

	type pairs struct {
		isNil bool
		key   string
		found bool
	}

	expectedPairs := []pairs{
		{
			key:   "/L1/L2A",
			isNil: false,
		},
		{
			key:   "/L1/L2B",
			isNil: true,
		},
		{
			key:   "/L1/L2C",
			isNil: false,
		},
	}

	count := 0
	trie.WalkChildren("/L1", func(key string, value interface{}) error {
		idx := slices.Index(expectedPairs, pairs{
			key:   key,
			isNil: value == nil,
		})

		if idx == -1 {
			t.Fatalf("did not expect: (%s, %s)", key, value)
		}

		expectedPairs[idx].found = true
		count += 1

		return nil
	})

	if count != len(expectedPairs) {
		t.Errorf("only found %d entries, when expecting %d", count, len(expectedPairs))
	}
}
