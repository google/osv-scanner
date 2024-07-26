package trie

import (
	"strings"
	"testing"
)

// test splitting /path/keys/ into parts (e.g. /path, /keys, /)
func TestPathSegmenter(t *testing.T) {
	cases := []struct {
		key     string
		parts   []string
		indices []int // indexes to use as next start, in order
	}{
		{"", []string{""}, []int{-1}},
		{"/", []string{"/"}, []int{-1}},
		{"static_file", []string{"static_file"}, []int{-1}},
		{"/users/scott", []string{"/users", "/scott"}, []int{6, -1}},
		{"users/scott", []string{"users", "/scott"}, []int{5, -1}},
		{"/users/ramona/", []string{"/users", "/ramona", "/"}, []int{6, 13, -1}},
		{"users/ramona/", []string{"users", "/ramona", "/"}, []int{5, 12, -1}},
		{"//", []string{"/", "/"}, []int{1, -1}},
		{"/a/b/c", []string{"/a", "/b", "/c"}, []int{2, 4, -1}},
	}

	for _, c := range cases {
		partNum := 0
		for prefix, i := PathSegmenter(c.key, 0); ; prefix, i = PathSegmenter(c.key, i) {
			if prefix != c.parts[partNum] {
				t.Errorf("expected part %d of key '%s' to be '%s', got '%s'", partNum, c.key, c.parts[partNum], prefix)
			}
			if i != c.indices[partNum] {
				t.Errorf("in iteration %d, expected next index of key '%s' to be '%d', got '%d'", partNum, c.key, c.indices[partNum], i)
			}
			partNum++
			if i == -1 {
				break
			}
		}
		if partNum != len(c.parts) {
			t.Errorf("expected '%s' to have %d parts, got %d", c.key, len(c.parts), partNum)
		}
	}
}

func TestPathSegmenterEdgeCases(t *testing.T) {
	cases := []struct {
		path      string
		start     int
		segment   string
		nextIndex int
	}{
		{"", 0, "", -1},
		{"", 10, "", -1},
		{"/", 0, "/", -1},
		{"/", 10, "", -1},
		{"/", -10, "", -1},
		{"/", 1, "", -1},
		{"//", 0, "/", 1},
		{"//", 1, "/", -1},
		{"//", 2, "", -1},
		{" /", 0, " ", 1},
		{" /", 1, "/", -1},
	}

	for _, c := range cases {
		segment, nextIndex := PathSegmenter(c.path, c.start)
		if segment != c.segment {
			t.Errorf("expected segment %s starting at %d in path %s, got %s", c.segment, c.start, c.path, segment)
		}
		if nextIndex != c.nextIndex {
			t.Errorf("expected nextIndex %d starting at %d in path %s, got %d", c.nextIndex, c.start, c.path, nextIndex)
		}
	}
}

func testPathSegmenterDot(path string, start int) (segment string, next int) {
	if len(path) == 0 || start < 0 || start > len(path)-1 {
		return "", -1
	}
	end := strings.IndexRune(path[start+1:], '.')
	if end == -1 {
		return path[start:], -1
	}
	return path[start : start+end+1], start + end + 1
}

func TestCustomPathSegmenter(t *testing.T) {
	depthTest := map[string]bool{
		"a":          false,
		"a.b":        false,
		"a.b.c":      false,
		"a.b.c.d":    false,
		"a.b.c.d.e":  false,
		".a":         false,
		".a.b":       false,
		".a.b.c":     false,
		".a.b.c.d":   false,
		".a.b.c.d.e": false,
	}

	tie := NewPathTrieWithConfig(&PathTrieConfig{Segmenter: testPathSegmenterDot})
	for k := range depthTest {
		tie.Put(k, true)
	}

	for k := range depthTest {
		tie.WalkPath(k, func(k string, v interface{}) error {
			out := tie.Get(k)
			if out != nil {
				depthTest[k] = true
			}
			return nil
		})
	}
	for k, ok := range depthTest {
		if !ok {
			t.Errorf("did not walk thru %s node", k)
		}
	}

}
