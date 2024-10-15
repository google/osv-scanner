# Trie
[![GoDoc](https://pkg.go.dev/badge/github.com/dghubble/trie.svg)](https://pkg.go.dev/github.com/dghubble/trie)
[![Workflow](https://github.com/dghubble/trie/actions/workflows/test.yaml/badge.svg)](https://github.com/dghubble/trie/actions/workflows/test.yaml?query=branch%3Amain)
[![Sponsors](https://img.shields.io/github/sponsors/dghubble?logo=github)](https://github.com/sponsors/dghubble)
[![Mastodon](https://img.shields.io/badge/follow-news-6364ff?logo=mastodon)](https://fosstodon.org/@dghubble)

Package `trie` implements rune-wise and path-wise [Tries](https://en.wikipedia.org/wiki/Trie) optimized for `Get` performance and to allocate 0 bytes of heap memory (i.e. garbage) per `Get`.

A typical use case is to perform any `Put` or `Delete` operations upfront to populate the trie, then perform `Get` operations very quickly. The Tries do not synchronize access (not thread-safe).

When Tries are chosen over maps, it is typically for their space efficiency. However, in situations where direct key lookup is not possible (e.g. routers), tries can provide faster lookups and avoid key iteration.

## Install

```
$ go get github.com/dghubble/trie
```

## Documentation

Read [Godoc](https://godoc.org/github.com/dghubble/trie)

## Performance

RuneTrie is a typical Trie which segments strings rune-wise (i.e. by unicode code point). These benchmarks perform Puts and Gets of random string keys that are 30 bytes long and of random '/' separated paths that have 3 parts and are 30 bytes long (longer if you count the '/' seps).

```
BenchmarkRuneTriePutStringKey-8   3000000    437 ns/op     9 B/op     1 allocs/op
BenchmarkRuneTrieGetStringKey-8   3000000    411 ns/op     0 B/op     0 allocs/op
BenchmarkRuneTriePutPathKey-8     3000000    464 ns/op     9 B/op     1 allocs/op
BenchmarkRuneTrieGetPathKey-8     3000000    429 ns/op     0 B/op     0 allocs/op
```

PathTrie segments strings by forward slash separators which can boost performance
for some use cases. These benchmarks perform Puts and Gets of random string keys that are 30 bytes long and of random '/' separated paths that have 3 parts and are 30 bytes long (longer if you count the '/' seps).

```
BenchmarkPathTriePutStringKey-8   30000000   55.5 ns/op    8 B/op     1 allocs/op
BenchmarkPathTrieGetStringKey-8   50000000   37.9 ns/op    0 B/op     0 allocs/op
BenchmarkPathTriePutPathKey-8     20000000   88.7 ns/op    8 B/op     1 allocs/op
BenchmarkPathTrieGetPathKey-8     20000000   68.6 ns/op    0 B/op     0 allocs/op
```

Note that for random string Puts and Gets, the PathTrie is effectively a map as every node is a direct child of the root (except for strings that happen to have a slash).

This benchmark measures the performance of the PathSegmenter alone. It is used to segment random paths that have 3 '/' separated parts and are 30 bytes long.

```
BenchmarkPathSegmenter-8          50000000   32.0 ns/op    0 B/op     0 allocs/op
```

## License

[MIT License](LICENSE)

