/*
Package trie implements several types of performant Tries (e.g. rune-wise,
path-wise).

The implementations are optimized for Get performance and to allocate 0 bytes
of heap memory (i.e. garbage) per Get.

The Tries do not synchronize access (not thread-safe). A typical use case is
to perform Puts and Deletes upfront to populate the Trie, then perform Gets
very quickly.
*/
package trie
