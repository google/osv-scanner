package trie

// Trier exposes the Trie structure capabilities.
type Trier interface {
	Get(key string) interface{}
	Put(key string, value interface{}) bool
	Delete(key string) bool
	Walk(walker WalkFunc) error
	WalkPath(key string, walker WalkFunc) error
	WalkChildren(key string, walker WalkFunc) error
}
